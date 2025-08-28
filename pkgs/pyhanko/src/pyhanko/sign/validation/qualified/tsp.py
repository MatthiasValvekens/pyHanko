import enum
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, FrozenSet, Generator, Iterable, Optional, Set, Tuple

from asn1crypto import x509
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator.authority import (
    Authority,
    AuthorityWithCert,
    TrustAnchor,
    TrustedServiceType,
    TrustQualifiers,
)
from pyhanko_certvalidator.errors import InvalidCertificateError
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.registry import TrustManager

__all__ = [
    'CA_QC_URI',
    'QTST_URI',
    'AdditionalServiceInformation',
    'BaseServiceInformation',
    'CAServiceInformation',
    'CertSubjectDNCriterion',
    'CriteriaCombination',
    'CriteriaList',
    'Criterion',
    'KeyUsageCriterion',
    'PolicySetCriterion',
    'QTSTServiceInformation',
    'QcCertType',
    'Qualification',
    'Qualification',
    'QualifiedServiceInformation',
    'Qualifier',
    'TSPRegistry',
    'TSPServiceParsingError',
    'TSPTrustManager',
]

# noinspection HttpUrlsUsage
_TRSTSVC_URI_BASE = 'http://uri.etsi.org/TrstSvc'
CA_QC_URI = f'{_TRSTSVC_URI_BASE}/Svctype/CA/QC'
QTST_URI = f'{_TRSTSVC_URI_BASE}/Svctype/TSA/QTST'
_TRUSTEDLIST_URI_BASE = f'{_TRSTSVC_URI_BASE}/TrustedList'


class TSPServiceParsingError(ValueError):
    pass


@dataclass(frozen=True)
class AdditionalServiceInformation:
    uri: str
    critical: bool
    textual_info: Optional[str]


class QcCertType(enum.Enum):
    """
    Type of qualified certificate.
    """

    QC_ESIGN = 'qct_esign'
    """
    Certificate qualified for eSignatures.
    """

    QC_ESEAL = 'qct_eseal'
    """
    Certificate qualified for eSeals.
    """

    QC_WEB = 'qct_web'
    """
    Qualified website authentication certificate (QWAC).
    """


_SVCINFOEXT_URI_BASE = f'{_TRUSTEDLIST_URI_BASE}/SvcInfoExt'


@dataclass(frozen=True)
class BaseServiceInformation:
    """
    Common information about a trusted service.
    """

    service_type: str
    """
    The type of service, specified as a URI.

    .. note::
        Corresponds to the ``ServiceTypeIdentifier`` in the trusted list data.
    """

    service_name: str
    """
    Name of the trusted service.
    """

    valid_from: datetime
    """
    Start of the service definition's validity window.
    """

    valid_until: Optional[datetime]
    """
    End of the service definition's validity window,
    if defined. If not, the service is presumed to be
    valid indefinitely.
    """

    provider_certs: Tuple[x509.Certificate, ...]
    """
    Certificates linked to this service provider.
    """

    additional_info_certificate_type: FrozenSet[QcCertType]
    """
    If non-empty, narrows the scope of the specified service type
    to the types of certificate listed.
    """

    other_additional_info: FrozenSet[AdditionalServiceInformation]
    """
    Other information that qualifies the type of service.
    """


class Qualifier(enum.Enum):
    """
    Qualifier as specified in ETSI TS 119 612, 5.5.9.2.
    """

    WITH_SSCD = 'QCWithSSCD'
    NO_SSCD = 'QCNoSSCD'
    SSCD_AS_IN_CERT = 'QCSSCDStatusAsInCert'
    WITH_QSCD = 'QCWithQSCD'
    NO_QSCD = 'QCNoQSCD'
    QSCD_AS_IN_CERT = 'QCQSCDStatusAsInCert'
    QSCD_MANAGED_ON_BEHALF = 'QCQSCDManagedOnBehalf'
    LEGAL_PERSON = 'QCForLegalPerson'
    FOR_ESIG = 'QCForESig'
    FOR_ESEAL = 'QCForESeal'
    FOR_WSA = 'QCForWSA'
    NOT_QUALIFIED = 'NotQualified'
    QC_STATEMENT = 'QCStatement'

    @property
    def uri(self):
        return f"{_SVCINFOEXT_URI_BASE}/{self.value}"


class Criterion:
    """
    Criterion for a qualifier to apply to a certificate.
    """

    def matches(self, cert: x509.Certificate) -> bool:
        """
        Evaluate a certificate against this criterion.

        :param cert:
            The certificate to evaluate.
        :return:
            ``True`` if the criterion matches, ``False`` otherwise.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class KeyUsageCriterion(Criterion):
    """
    Criterion that matches certificates that meet the specified
    key usage constraints.
    """

    settings: KeyUsageConstraints
    """
    Key usage constraint to apply.
    """

    def matches(self, cert: x509.Certificate) -> bool:
        try:
            self.settings.validate(cert)
            return True
        except InvalidCertificateError:
            return False


@dataclass(frozen=True)
class PolicySetCriterion(Criterion):
    """
    Criterion that matches certificates that meet the specified
    certificate policies.
    """

    required_policy_oids: FrozenSet[str]
    """
    Policies that must be applicable to the certificate.

    .. note::
        These OIDs are considered to be specified in the domain
        of the trust root, so they are subject to policy mapping
        in the sense of RFC 5280.
    """

    def matches(self, cert: x509.Certificate) -> bool:
        policy_ext = cert.certificate_policies_value or ()
        found_policies = {pol['policy_identifier'].dotted for pol in policy_ext}
        return self.required_policy_oids.issubset(found_policies)


@dataclass(frozen=True)
class CertSubjectDNCriterion(Criterion):
    required_rdn_part_oids: FrozenSet[str]

    def matches(self, cert: x509.Certificate) -> bool:
        subject_dn: x509.Name = cert.subject
        found_rdn_part_oids = {
            pair['type'].dotted for rdn in subject_dn.chosen for pair in rdn
        }
        return self.required_rdn_part_oids.issubset(found_rdn_part_oids)


@enum.unique
class CriteriaCombination(enum.Enum):
    """
    Defines how to combine sub-criteria.
    """

    ALL = 'all'
    """
    All sub-criteria must match for the criterion to match.
    """

    AT_LEAST_ONE = 'atLeastOne'
    """
    At least one of the sub-criteria must match for the criterion to match.
    """

    NONE = 'none'
    """
    All of the sub-criteria must fail to match for the criterion to match.
    """


@dataclass(frozen=True)
class CriteriaList(Criterion):
    """
    Combine several criteria as one.
    """

    combine_as: CriteriaCombination
    """
    Logical operation to apply to the list of sub-criteria.
    """

    criteria: FrozenSet[Criterion]
    """
    Set of sub-criteria.
    """

    def matches(self, cert: x509.Certificate) -> bool:
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
    """
    Representation of a qualification in the sense of ETSI TS 119 612, 5.5.9.2.
    """

    qualifiers: FrozenSet[Qualifier]
    """
    Set of qualifiers to apply to the certificates matching the criteria.
    """

    criteria_list: CriteriaList
    """
    List of criteria to apply.
    """


@dataclass(frozen=True)
class QualifiedServiceInformation:
    """
    Representation of a service with conditional qualifiers.
    """

    base_info: BaseServiceInformation
    """
    Basic information about the service.
    """

    qualifications: FrozenSet[Qualification]
    """
    Relevant qualifications.
    """


@dataclass(frozen=True)
class CAServiceInformation(QualifiedServiceInformation):
    """
    Qualified CA service description.
    """

    # TODO process this setting
    expired_certs_revocation_info: Optional[datetime]
    """
    See ETSI TS 119 612, 5.5.9.1.

    .. warning::
        This extension is not yet taken into account by certificate
        validation processes.
    """


@dataclass(frozen=True)
class QTSTServiceInformation(QualifiedServiceInformation):
    """
    Qualified TSA service description.
    """


def _service_sort_key(si: QualifiedServiceInformation):
    if si.base_info.valid_until is None:
        return 1, None
    else:
        return 0, si.base_info.valid_until


class TSPRegistry:
    """
    Registry of trusted service providers (TSPs), typically populated from
    a trust list.

    Currently, a TSP registry can keep track of qualified CAs and TSAs (QTSTs).
    """

    def __init__(self: 'TSPRegistry'):
        self._ca_cert_to_si: Dict[Authority, Set[CAServiceInformation]] = (
            defaultdict(set)
        )
        self._tst_cert_to_si: Dict[Authority, Set[QTSTServiceInformation]] = (
            defaultdict(set)
        )

    def register_ca(self, ca_service_info: CAServiceInformation):
        """
        Register a trusted certificate authority.

        :param ca_service_info:
            Service information about the CA.
        """
        for cert in ca_service_info.base_info.provider_certs:
            self._ca_cert_to_si[AuthorityWithCert(cert)].add(ca_service_info)

    def register_tst(self, qtst_service_info: QTSTServiceInformation):
        """
        Register a trusted time stamping authority.

        :param qtst_service_info:
            Service information about the TSA.
        """
        for cert in qtst_service_info.base_info.provider_certs:
            self._tst_cert_to_si[AuthorityWithCert(cert)].add(qtst_service_info)

    def applicable_service_definitions(
        self, authority: Authority, moment: Optional[datetime]
    ) -> Iterable[QualifiedServiceInformation]:
        """
        Retrieve the service definitions in this registry on behalf
        of which the specified authority might act.

        .. note::
            This includes all supported types of qualified services,
            not just certificate authorities.

        :param authority:
            Authority to evaluate.
        :param moment:
            Time at which to evaluate the service definitions.
            If none is specified, all matching service definitions
            will be returned, irrespective of their validity windows.
        :return:
            List of service definitions matching the authority.
        """

        all_services = tuple(self._ca_cert_to_si[authority]) + tuple(
            self._tst_cert_to_si[authority]
        )
        sorted_services = sorted(
            all_services, key=_service_sort_key, reverse=True
        )
        for service in sorted_services:
            valid_from = service.base_info.valid_from
            valid_until = service.base_info.valid_until
            if not moment or (
                valid_from <= moment
                and (not valid_until or valid_until >= moment)
            ):
                yield service

    @property
    def known_certificate_authorities(self) -> Iterable[Authority]:
        """
        List known certificate authorities identified by this registry.
        """
        return {ca for ca, sds in self._ca_cert_to_si.items() if sds}

    @property
    def known_timestamp_authorities(self) -> Iterable[Authority]:
        """
        List known time stamping authorities identified by this registry.
        """
        return {tsa for tsa, sds in self._tst_cert_to_si.items() if sds}

    def applicable_tsps_on_path(
        self, path: ValidationPath, moment: datetime
    ) -> Generator[QualifiedServiceInformation, None, None]:
        """
        List applicable trusted service providers on the provided
        validation path.

        :param path:
            The validation path to evaluate.
        :param moment:
            Time at which to evaluate the service definitions.
            If none is specified, all matching service definitions
            will be returned, irrespective of their validity windows.
        :return:
            A generator that yields any service definitions matching the
            authorities on the validation path.
        """
        for ca in path.iter_authorities():
            yield from self.applicable_service_definitions(ca, moment)


class TSPTrustManager(TrustManager):
    """
    Trust manager implementation based on a :class:`.TSPRegistry`.
    """

    def __init__(self, tsp_registry: TSPRegistry):
        self.tsp_registry = tsp_registry

    def as_trust_anchor(self, authority: Authority) -> Optional[TrustAnchor]:
        try:
            # moment = None -> pick the most recent applicable
            sd = next(
                iter(
                    self.tsp_registry.applicable_service_definitions(
                        authority, moment=None
                    )
                )
            )
        except StopIteration:
            return None
        service_type = {
            CA_QC_URI: TrustedServiceType.CERTIFICATE_AUTHORITY,
            QTST_URI: TrustedServiceType.TIME_STAMPING_AUTHORITY,
        }.get(sd.base_info.service_type, TrustedServiceType.UNSUPPORTED)
        return TrustAnchor(
            authority,
            quals=TrustQualifiers(
                trusted_service_type=service_type,
                valid_from=sd.base_info.valid_from,
                valid_until=sd.base_info.valid_until,
            ),
        )

    def find_potential_issuers(
        self, cert: x509.Certificate
    ) -> Generator[TrustAnchor, None, None]:
        for authority in self.tsp_registry.known_certificate_authorities:
            as_anchor = self.as_trust_anchor(authority)
            if as_anchor and authority.is_potential_issuer_of(cert):
                yield as_anchor
