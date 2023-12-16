import enum
import logging
import zoneinfo
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime
from typing import (
    Dict,
    FrozenSet,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from asn1crypto import x509
from pyhanko_certvalidator.authority import (
    Authority,
    AuthorityWithCert,
    TrustAnchor,
)
from pyhanko_certvalidator.errors import InvalidCertificateError
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.registry import TrustManager
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

from pyhanko.generated.etsi import (
    ts_119612,
    ts_119612_extra,
    ts_119612_sie,
    xades,
)
from pyhanko.sign.ades import qualified_asn1
from pyhanko.sign.validation.settings import KeyUsageConstraints

__all__ = [
    'TSPRegistry',
    'TSPTrustManager',
    'CAServiceInformation',
    'QualificationAssessor',
    'QualifiedStatus',
    'read_qualified_certificate_authorities',
    'AdditionalServiceInformation',
    'QcCertType',
    'BaseServiceInformation',
    'Criterion',
    'KeyUsageCriterion',
    'PolicySetCriterion',
    'CertSubjectDNCriterion',
    'CriteriaCombination',
    'CriteriaList',
    'Qualifier',
    'Qualification',
    'QcPrivateKeyManagementType',
    'TSPServiceParsingError',
]

logger = logging.getLogger(__name__)

# noinspection HttpUrlsUsage
_TRSTSVC_URI_BASE = 'http://uri.etsi.org/TrstSvc'
_TRUSTEDLIST_URI_BASE = f'{_TRSTSVC_URI_BASE}/TrustedList'
CA_QC_URI = f'{_TRSTSVC_URI_BASE}/Svctype/CA/QC'
QTST_URI = f'{_TRSTSVC_URI_BASE}/Svctype/TSA/QTST'
STATUS_GRANTED = f'{_TRUSTEDLIST_URI_BASE}/Svcstatus/granted'


class TSPServiceParsingError(ValueError):
    pass


@dataclass(frozen=True)
class AdditionalServiceInformation:
    uri: str
    critical: bool
    textual_info: Optional[str]


class QcCertType(enum.Enum):
    QC_ESIGN = 'qct_esign'
    QC_ESEAL = 'qct_eseal'
    QC_WEB = 'qct_web'


_SVCINFOEXT_URI_BASE = f'{_TRUSTEDLIST_URI_BASE}/SvcInfoExt'

_CERTIFICATE_TYPE_BY_URI = {
    f'{_SVCINFOEXT_URI_BASE}/ForeSignatures': QcCertType.QC_ESIGN,
    f'{_SVCINFOEXT_URI_BASE}/ForeSeals': QcCertType.QC_ESEAL,
    f'{_SVCINFOEXT_URI_BASE}/ForWebSiteAuthentication': QcCertType.QC_WEB,
}


@dataclass(frozen=True)
class BaseServiceInformation:
    service_type: str
    service_name: str
    provider_certs: Tuple[x509.Certificate, ...]
    additional_info_certificate_type: FrozenSet[QcCertType]
    other_additional_info: FrozenSet[AdditionalServiceInformation]


class Qualifier(enum.Enum):
    WITH_SSCD = 'QCWithSSCD'
    NO_SSCD = 'QCNoSSCD'
    SSCD_AS_IN_CERT = 'QCSSCDStatusAsInCert'
    WITH_QSCD = 'QCWithQSCD'
    NO_QSCD = 'QCNoQSCD'
    QSCD_AS_IN_CERT = 'QCQSCDStatusAsInCert'
    QSCD_MANAGED_ON_BEHALF = 'QCQSCDManagedOnBehalf'
    LEGAL_PERSON = 'QCForLegalPerson'
    FOR_ESIG = 'QCForEsig'
    FOR_ESEAL = 'QCForEseal'
    FOR_WSA = 'QCForWSA'
    NOT_QUALIFIED = 'NotQualified'
    QC_STATEMENT = 'QCStatement'

    @property
    def uri(self):
        return f"{_SVCINFOEXT_URI_BASE}/{self.value}"


_QUALIFIER_BY_URI = {q.uri: q for q in Qualifier}


class Criterion:
    def matches(self, cert: x509.Certificate):
        raise NotImplementedError


@dataclass(frozen=True)
class KeyUsageCriterion(Criterion):
    settings: KeyUsageConstraints

    def matches(self, cert: x509.Certificate):
        try:
            self.settings.validate(cert)
            return True
        except InvalidCertificateError:
            return False


@dataclass(frozen=True)
class PolicySetCriterion(Criterion):
    required_policy_oids: FrozenSet[str]

    def matches(self, cert: x509.Certificate):
        policy_ext = cert.certificate_policies_value or ()
        found_policies = {pol['policy_identifier'].dotted for pol in policy_ext}
        return self.required_policy_oids.issubset(found_policies)


@dataclass(frozen=True)
class CertSubjectDNCriterion(Criterion):
    required_rdn_part_oids: FrozenSet[str]

    def matches(self, cert: x509.Certificate):
        subject_dn: x509.Name = cert.subject
        found_rdn_part_oids = {
            pair['type'].dotted for rdn in subject_dn.chosen for pair in rdn
        }
        return self.required_rdn_part_oids.issubset(found_rdn_part_oids)


@enum.unique
class CriteriaCombination(enum.Enum):
    ALL = 'all'
    AT_LEAST_ONE = 'atLeastOne'
    NONE = 'none'


@dataclass(frozen=True)
class CriteriaList(Criterion):
    combine_as: CriteriaCombination
    criteria: FrozenSet[Criterion]

    def matches(self, cert: x509.Certificate):
        if self.combine_as == CriteriaCombination.ALL:
            return all(c.matches(cert) for c in self.criteria)
        elif self.combine_as == CriteriaCombination.AT_LEAST_ONE:
            return any(c.matches(cert) for c in self.criteria)
        elif self.combine_as == CriteriaCombination.NONE:
            return not any(c.matches(cert) for c in self.criteria)
        else:
            raise NotImplementedError


@dataclass(frozen=True)
class Qualification:
    qualifiers: FrozenSet[Qualifier]
    criteria_list: CriteriaList


@dataclass(frozen=True)
class CAServiceInformation:
    base_info: BaseServiceInformation
    qualifications: FrozenSet[Qualification]
    expired_certs_revocation_info: Optional[datetime]


# TODO make this somehow customisable
PREFERRED_LANGUAGE: str = 'en'


def _extract_from_intl_string(
    intl_string: Tuple[
        Union[ts_119612.MultiLangStringType, ts_119612.MultiLangNormStringType],
        ...,
    ]
):
    first_value = intl_string[0].value
    for part in intl_string:
        if part.lang == PREFERRED_LANGUAGE:
            return part.value
    return first_value


T = TypeVar('T')


def _required(thing: Optional[T], descr: str) -> T:
    if thing is None:
        raise TSPServiceParsingError(f"{descr} must be provided")
    return thing


def _as_certs(sdi: ts_119612.ServiceDigitalIdentity):
    for digital_id in sdi.digital_id:
        cert_bytes = digital_id.x509_certificate
        if cert_bytes:
            yield x509.Certificate.load(cert_bytes)


def _process_criteria_list(
    criteria: Optional[ts_119612_sie.CriteriaListType],
) -> CriteriaList:
    entries = frozenset(_process_criteria_list_entries(criteria))
    if entries:
        assert criteria is not None
        assertion_type = _required(
            criteria.assert_value, "Criteria assertion type"
        ).value
        combine_as = CriteriaCombination(str(assertion_type))
        return CriteriaList(combine_as=combine_as, criteria=entries)
    else:
        raise TSPServiceParsingError("No criteria")


def _parse_xades_oid(oid: xades.ObjectIdentifierType) -> str:
    return _required(oid.identifier, "Identifier tag in OID").value


def _process_criteria_list_entries(
    criteria_list: Optional[ts_119612_sie.CriteriaListType],
) -> Generator[Criterion, None, None]:
    if not criteria_list:
        return
    if criteria_list.policy_set:
        # TODO also take policy qualifiers into account
        for policy_set_criterion in criteria_list.policy_set:
            yield PolicySetCriterion(
                required_policy_oids=frozenset(
                    _parse_xades_oid(policy)
                    for policy in policy_set_criterion.policy_identifier
                )
            )
    if criteria_list.key_usage:
        for ku_criterion in criteria_list.key_usage:
            key_usage_must_have = frozenset(
                _required(bit.name, "Key usage bit type name").name.lower()
                for bit in ku_criterion.key_usage_bit
                if bit.value == True
            )
            key_usage_forbidden = frozenset(
                _required(bit.name, "Key usage bit type name").name.lower()
                for bit in ku_criterion.key_usage_bit
                if bit.value == False
            )
            # TODO check EKUs
            yield KeyUsageCriterion(
                settings=KeyUsageConstraints(
                    key_usage=key_usage_must_have,
                    key_usage_forbidden=key_usage_forbidden,
                )
            )
    sublists: Iterable[
        ts_119612_sie.CriteriaListType
    ] = criteria_list.criteria_list
    if sublists:
        for sublist in sublists:
            yield _process_criteria_list(sublist)
    if criteria_list.other_criteria_list:
        for el in criteria_list.other_criteria_list.content:
            if isinstance(el, ts_119612_extra.CertSubjectDNAttribute):
                yield CertSubjectDNCriterion(
                    frozenset(
                        _parse_xades_oid(oid_xml)
                        for oid_xml in el.attribute_oid
                    )
                )
            elif isinstance(el, ts_119612_extra.ExtendedKeyUsage):
                kpids = frozenset(
                    _parse_xades_oid(kpid_xml) for kpid_xml in el.key_purpose_id
                )
                yield KeyUsageCriterion(
                    settings=KeyUsageConstraints(extd_key_usage=kpids)
                )
            else:
                raise TSPServiceParsingError(
                    f"Unknown criterion {el} in qualifier definition"
                )


def _process_qualifiers(qualifiers: Iterable[ts_119612_sie.QualifierType]):
    for qual in qualifiers:
        try:
            yield _QUALIFIER_BY_URI[qual.uri]
        except KeyError:
            logger.info(f"Qualifier {qual.uri} in SDI ignored...")


def _get_qualifications(qualifications: ts_119612_sie.Qualifications):
    for qual in qualifications.qualification_element:
        quals_xml = qual.qualifiers
        if not quals_xml:
            continue
        # note: all the qualifiers we currently support only make sense
        # for qualified CAs, not other types of services
        # (qualified or otherwise).
        qualifiers = frozenset(_process_qualifiers(quals_xml.qualifier))
        criteria = _process_criteria_list(qual.criteria_list)
        if qualifiers and criteria:
            yield Qualification(qualifiers=qualifiers, criteria_list=criteria)
        else:
            logger.warning(f"Could not process qualifiers in {quals_xml}")


def _process_additional_info(
    info: ts_119612.AdditionalServiceInformation, critical: bool
):
    return AdditionalServiceInformation(
        uri=_required(info.uri, "Additional service info URI").value,
        textual_info=info.information_value,
        critical=critical,
    )


def _interpret_service_info_for_ca(
    service: ts_119612.TSPService,
):
    service_info = service.service_information
    assert service_info is not None
    certs = list(
        _as_certs(
            _required(
                service_info.service_digital_identity,
                "Service digital identity",
            )
        )
    )
    service_name = None
    if service_info.service_name:
        service_name = _extract_from_intl_string(service_info.service_name.name)
    qualifications: FrozenSet[Qualification] = frozenset()
    expired_revinfo_date = None
    additional_info = []
    extensions_xml = (
        service_info.service_information_extensions.extension
        if service_info.service_information_extensions
        else ()
    )
    asi_qc_type: Set[QcCertType] = set()
    for ext in extensions_xml:
        for ext_content in ext.content:
            if isinstance(ext_content, ts_119612_sie.Qualifications):
                qualifications = frozenset(_get_qualifications(ext_content))
            elif isinstance(ext_content, ts_119612.ExpiredCertsRevocationInfo):
                expired_revinfo_date = _required(
                    ext_content.value,
                    "Date in expired certs revocation info cutoff",
                ).to_datetime()
            elif isinstance(
                ext_content, ts_119612.AdditionalServiceInformation
            ):
                additional_info_entry = _process_additional_info(
                    ext_content, ext.critical or False
                )
                try:
                    asi_qc_type.add(
                        _CERTIFICATE_TYPE_BY_URI[additional_info_entry.uri]
                    )
                except KeyError:
                    additional_info.append(additional_info_entry)
            elif ext.critical:
                # TODO more informative exception / only ditch the current SDI
                raise TSPServiceParsingError(
                    f"Cannot process a critical extension "
                    f"in service named '{service_name}'.\n"
                    f"Content: {ext_content}"
                )
    base_service_info = BaseServiceInformation(
        service_type=_required(
            service_info.service_type_identifier, "Service type identifier"
        ),
        service_name=service_name or "unknown",
        provider_certs=tuple(certs),
        additional_info_certificate_type=frozenset(asi_qc_type),
        other_additional_info=frozenset(additional_info),
    )

    return CAServiceInformation(
        base_info=base_service_info,
        qualifications=qualifications,
        expired_certs_revocation_info=expired_revinfo_date,
    )


def _interpret_service_info_for_cas(
    services: Iterable[ts_119612.TSPService],
):
    for service in services:
        service_info = service.service_information
        if (
            not service_info
            or service_info.service_type_identifier != CA_QC_URI
        ):
            continue

        # TODO allow the user to specify if they also want to include
        #  other statuses (e.g. national level)
        # TODO evaluate historical definitions too in case of point-in-time
        #  work, store that info on the object
        if service_info.service_status != STATUS_GRANTED:
            continue
        # TODO process errors in individual services
        yield _interpret_service_info_for_ca(service)


def _raw_tl_parse(tl_xml: str) -> ts_119612.TrustServiceStatusList:
    parser = XmlParser(
        config=ParserConfig(
            load_dtd=False,
            process_xinclude=False,
            fail_on_unknown_properties=False,
            fail_on_unknown_attributes=False,
        ),
    )
    return parser.from_string(tl_xml, clazz=ts_119612.TrustServiceStatusList)


# TODO introduce a similar method for other types of service (TSAs etc)


def read_qualified_certificate_authorities(
    tl_xml: str,
) -> Generator[CAServiceInformation, None, None]:
    parse_result = _raw_tl_parse(tl_xml)
    tspl = parse_result.trust_service_provider_list
    for tsp in _required(tspl, "TSP list").trust_service_provider:
        yield from _interpret_service_info_for_cas(
            _required(tsp.tspservices, "TSP services").tspservice
        )


class TSPRegistry:
    def __init__(self: 'TSPRegistry'):
        self._cert_to_si: Dict[
            Authority, Set[CAServiceInformation]
        ] = defaultdict(set)

    def register_ca(self, ca_service_info: CAServiceInformation):
        for cert in ca_service_info.base_info.provider_certs:
            self._cert_to_si[AuthorityWithCert(cert)].add(ca_service_info)

    def applicable_service_definitions(
        self, ca: Authority
    ) -> Iterable[CAServiceInformation]:
        return tuple(self._cert_to_si[ca])

    @property
    def known_authorities(self) -> Iterable[Authority]:
        return self._cert_to_si.keys()

    # TODO take date into account (and properly track it
    #  for service definitions)
    def applicable_tsps_on_path(
        self,
        path: ValidationPath,
    ) -> Generator[CAServiceInformation, None, None]:
        for ca in path.iter_authorities():
            yield from self.applicable_service_definitions(ca)


class TSPTrustManager(TrustManager):
    def __init__(self, tsp_registry: TSPRegistry):
        self.tsp_registry = tsp_registry

    def is_root(self, cert: x509.Certificate) -> bool:
        return bool(
            self.tsp_registry.applicable_service_definitions(
                AuthorityWithCert(cert)
            )
        )

    def find_potential_issuers(
        self, cert: x509.Certificate
    ) -> Generator[TrustAnchor, None, None]:
        # TODO food for thought: can we extract qualifiers from the service
        #  definitions here? E.g. if we know that a cert can only be qualified
        #  if it has a certain policy, we could enforce that at the PKIX level.
        for authority in self.tsp_registry.known_authorities:
            if authority.is_potential_issuer_of(cert):
                yield TrustAnchor(authority)


class QcPrivateKeyManagementType(enum.Enum):
    UNKNOWN = 0
    QCSD = 1
    QCSD_DELEGATED = 2
    QCSD_BY_POLICY = 3

    @property
    def is_qcsd(self) -> bool:
        return self != QcPrivateKeyManagementType.UNKNOWN


EIDAS_START_DATE = datetime(
    2016, 7, 1, 0, 0, 0, tzinfo=zoneinfo.ZoneInfo('CET')
)

PRE_EIDAS_QCP_POLICY = '0.4.0.1456.1.1'
PRE_EIDAS_QCP_PLUS_POLICY = '0.4.0.1456.1.2'


@dataclass(frozen=True)
class QualifiedStatus:
    """
    Represents the qualified status of a certificate.
    """

    qualified: bool
    """
    Indicates whether the certificate is to be considered qualified.
    """

    qc_type: QcCertType
    """
    Type of qualified certificate.
    """

    qc_key_security: QcPrivateKeyManagementType
    """
    Indicates whether the CA declares that the private key
    corresponding to this certificate resides in a qualified
    signature creation device (QSCD) or secure signature creation device (SSCD).
    It also indicates whether the QCSD is managed on behalf of the signer,
    if applicable.

    .. warning::
        These terms are functionally interchangeable, the only difference is
        that "SSCD" is pre-eIDAS terminology.
    """


UNQUALIFIED = QualifiedStatus(
    qualified=False,
    qc_type=QcCertType.QC_ESIGN,
    qc_key_security=QcPrivateKeyManagementType.UNKNOWN,
)


class QualificationAssessor:
    def __init__(self, tsp_registry: TSPRegistry):
        self._registry = tsp_registry

    @staticmethod
    def _process_qc_statements(cert: x509.Certificate) -> QualifiedStatus:
        qcs = qualified_asn1.get_qc_statements(cert)
        qualified = False
        key_secure = False
        qc_type = QcCertType.QC_ESIGN
        for statement in qcs:
            st_type = statement['statement_id'].native
            if st_type == 'qc_compliance':
                qualified = True
            elif st_type == 'qc_sscd':
                # management delegation is not encoded by the QcStatements
                key_secure = True
            elif st_type == 'qc_type':
                qc_types: qualified_asn1.QcCertificateType = statement[
                    'statement_info'
                ]
                if len(qc_types) != 1:
                    # In theory this is not limited to one value, we have to
                    # let the TL override in a case like this.
                    # Nonetheless there's really no good reason to do this,
                    # and some ETSI specs are more strict than others,
                    # so I'll deal with this case when it presents itself
                    raise NotImplementedError("only support exactly 1 qc_type")
                qc_type = QcCertType(qc_types[0].native)
        return QualifiedStatus(
            qualified=qualified,
            qc_type=qc_type,
            qc_key_security=(
                QcPrivateKeyManagementType.QCSD
                if key_secure and qualified
                else QcPrivateKeyManagementType.UNKNOWN
            ),
        )

    @staticmethod
    def _check_cd_applicable(
        sd: CAServiceInformation, putative_status: QualifiedStatus
    ):
        sd_declared_type = sd.base_info.additional_info_certificate_type
        if sd_declared_type and putative_status.qc_type not in sd_declared_type:
            logger.info(
                f"Found matching SDI {sd.base_info.service_name} on path; "
                f"skipping because QC type does not match"
            )
            return False
        return True

    @staticmethod
    def _apply_sd_qualifications(
        cert: x509.Certificate,
        prelim_status: QualifiedStatus,
        sd: CAServiceInformation,
    ):
        applicable_qualifiers: Set[Qualifier] = set()
        for qualification in sd.qualifications:
            if not qualification.criteria_list.matches(cert):
                continue
            applicable_qualifiers.update(qualification.qualifiers)
        return QualificationAssessor._final_status(
            prelim_status, frozenset(applicable_qualifiers)
        )

    @staticmethod
    def _final_status(
        prelim_status: QualifiedStatus,
        applicable_qualifiers: FrozenSet[Qualifier],
    ):
        # TODO explicitly check consistency / contradictory qualifiers
        # (for now we just use conservative defaults)
        is_qualified: bool
        if (
            Qualifier.NOT_QUALIFIED in applicable_qualifiers
            or Qualifier.LEGAL_PERSON in applicable_qualifiers
        ):
            is_qualified = False
        elif Qualifier.QC_STATEMENT in applicable_qualifiers:
            is_qualified = True
        else:
            is_qualified = prelim_status.qualified

        qc_type: QcCertType
        if Qualifier.FOR_WSA in applicable_qualifiers:
            qc_type = QcCertType.QC_WEB
        elif Qualifier.FOR_ESIG in applicable_qualifiers:
            qc_type = QcCertType.QC_ESIGN
        elif Qualifier.FOR_ESEAL in applicable_qualifiers:
            qc_type = QcCertType.QC_ESEAL
        else:
            qc_type = prelim_status.qc_type

        key_mgmt: QcPrivateKeyManagementType
        if not is_qualified:
            key_mgmt = QcPrivateKeyManagementType.UNKNOWN
        elif (
            Qualifier.NO_SSCD in applicable_qualifiers
            or Qualifier.NO_QSCD in applicable_qualifiers
        ):
            key_mgmt = QcPrivateKeyManagementType.UNKNOWN
        elif Qualifier.QSCD_MANAGED_ON_BEHALF in applicable_qualifiers:
            key_mgmt = QcPrivateKeyManagementType.QCSD_DELEGATED
        elif (
            Qualifier.WITH_SSCD in applicable_qualifiers
            or Qualifier.WITH_QSCD in applicable_qualifiers
        ):
            key_mgmt = QcPrivateKeyManagementType.QCSD
        else:
            key_mgmt = prelim_status.qc_key_security
        return QualifiedStatus(
            qualified=is_qualified,
            qc_type=qc_type,
            qc_key_security=key_mgmt,
        )

    def check_entity_cert_qualified(
        self, path: ValidationPath, moment: Optional[datetime] = None
    ) -> QualifiedStatus:
        cert = path.leaf
        if not isinstance(cert, x509.Certificate):
            raise NotImplementedError(
                "Only public-key certs are in scope for qualification"
            )
        prelim_status = QualificationAssessor._process_qc_statements(cert)
        path_policies = path.qualified_policies()
        reference_time = moment or datetime.now(tz=zoneinfo.ZoneInfo('CET'))
        if reference_time < EIDAS_START_DATE and path_policies:
            # check QCP / QCP+ policy
            policy_oids = {q.user_domain_policy_id for q in path_policies}
            if PRE_EIDAS_QCP_PLUS_POLICY in policy_oids:
                prelim_status = replace(
                    prelim_status,
                    qualified=True,
                    qc_key_security=(
                        QcPrivateKeyManagementType.QCSD_BY_POLICY
                        if not prelim_status.qc_key_security.is_qcsd
                        else prelim_status.qc_key_security
                    ),
                )
            elif PRE_EIDAS_QCP_POLICY in policy_oids:
                prelim_status = replace(prelim_status, qualified=True)

        statuses_found: List[Tuple[CAServiceInformation, QualifiedStatus]] = []
        for sd in self._registry.applicable_tsps_on_path(path):
            # For this subtlety, see the hanging para in the beginning of
            # section 4 in the CEF eSignature DSS validation algorithm doc
            putative_status = QualificationAssessor._apply_sd_qualifications(
                cert, prelim_status, sd
            )
            if QualificationAssessor._check_cd_applicable(sd, putative_status):
                statuses_found.append((sd, putative_status))

        uniq_statuses = set(st for _, st in statuses_found)
        if len(statuses_found) == 1:
            # happy path
            return statuses_found[0][1]
        elif len(uniq_statuses) == 1:
            # TODO gather these warnings somewhere so they can be added
            #  to the validation report
            service_info = ', '.join(
                sd.base_info.service_name for sd, _ in statuses_found
            )
            logger.warning(
                f"Qualification algorithm for {cert.subject.human_friendly} "
                f"reached a consistent conclusion, but through several "
                f"different service definitions: {service_info}"
            )
            return statuses_found[0][1]
        elif not uniq_statuses:
            return UNQUALIFIED
        else:
            service_info = ', '.join(
                sd.base_info.service_name for sd, _ in statuses_found
            )
            logger.warning(
                f"Qualification algorithm for {cert.subject.human_friendly} "
                f"reached contradictory conclusions: {uniq_statuses}. "
                f"Several service definitions were found applicable: "
                f"{service_info}. This certificate will not be considered "
                f"qualified."
            )
            return UNQUALIFIED
