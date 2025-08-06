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

# noinspection HttpUrlsUsage
_TRSTSVC_URI_BASE = 'http://uri.etsi.org/TrstSvc'
CA_QC_URI = f'{_TRSTSVC_URI_BASE}/Svctype/CA/QC'
QTST_URI = f'{_TRSTSVC_URI_BASE}/Svctype/TSA/QTST'
_TRUSTEDLIST_URI_BASE = f'{_TRSTSVC_URI_BASE}/TrustedList'

__all__ = [
    'QualifiedServiceInformation',
    'CAServiceInformation',
    'QTSTServiceInformation',
    'TSPRegistry',
    'TSPTrustManager',
    'QcCertType',
    'AdditionalServiceInformation',
    'BaseServiceInformation',
    'Qualifier',
    'Criterion',
    'Qualification',
    'KeyUsageCriterion',
    'PolicySetCriterion',
    'CertSubjectDNCriterion',
    'CriteriaCombination',
    'CriteriaList',
    'Qualification',
    'TSPServiceParsingError',
]


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


@dataclass(frozen=True)
class BaseServiceInformation:
    service_type: str
    service_name: str
    valid_from: datetime
    valid_until: Optional[datetime]
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
    FOR_ESIG = 'QCForESig'
    FOR_ESEAL = 'QCForESeal'
    FOR_WSA = 'QCForWSA'
    NOT_QUALIFIED = 'NotQualified'
    QC_STATEMENT = 'QCStatement'

    @property
    def uri(self):
        return f"{_SVCINFOEXT_URI_BASE}/{self.value}"


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
class QualifiedServiceInformation:
    base_info: BaseServiceInformation
    qualifications: FrozenSet[Qualification]


@dataclass(frozen=True)
class CAServiceInformation(QualifiedServiceInformation):
    expired_certs_revocation_info: Optional[datetime]


@dataclass(frozen=True)
class QTSTServiceInformation(QualifiedServiceInformation):
    pass


def _service_sort_key(si: QualifiedServiceInformation):
    if si.base_info.valid_until is None:
        return 1, None
    else:
        return 0, si.base_info.valid_until


class TSPRegistry:
    def __init__(self: 'TSPRegistry'):
        self._ca_cert_to_si: Dict[Authority, Set[CAServiceInformation]] = (
            defaultdict(set)
        )
        self._tst_cert_to_si: Dict[Authority, Set[QTSTServiceInformation]] = (
            defaultdict(set)
        )

    def register_ca(self, ca_service_info: CAServiceInformation):
        for cert in ca_service_info.base_info.provider_certs:
            self._ca_cert_to_si[AuthorityWithCert(cert)].add(ca_service_info)

    def register_tst(self, qtst_service_info: QTSTServiceInformation):
        for cert in qtst_service_info.base_info.provider_certs:
            self._tst_cert_to_si[AuthorityWithCert(cert)].add(qtst_service_info)

    def applicable_service_definitions(
        self, authority: Authority, moment: Optional[datetime]
    ) -> Iterable[QualifiedServiceInformation]:
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
        return {ca for ca, sds in self._ca_cert_to_si.items() if sds}

    @property
    def known_timestamp_authorities(self) -> Iterable[Authority]:
        return {tsa for tsa, sds in self._tst_cert_to_si.items() if sds}

    def applicable_tsps_on_path(
        self, path: ValidationPath, moment: datetime
    ) -> Generator[QualifiedServiceInformation, None, None]:
        for ca in path.iter_authorities():
            yield from self.applicable_service_definitions(ca, moment)


class TSPTrustManager(TrustManager):
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
        # FIXME: other qualifiers!
        #  - qualifiers in the TL expressed as PKIX constraints where possible

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
