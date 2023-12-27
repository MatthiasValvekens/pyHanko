import enum
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import (
    Dict,
    FrozenSet,
    Generator,
    Iterable,
    Optional,
    Set,
    Tuple,
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

from pyhanko.sign.validation.settings import KeyUsageConstraints

# noinspection HttpUrlsUsage
_TRSTSVC_URI_BASE = 'http://uri.etsi.org/TrstSvc'
_TRUSTEDLIST_URI_BASE = f'{_TRSTSVC_URI_BASE}/TrustedList'


__all__ = [
    'CAServiceInformation',
    'TSPRegistry',
    'TSPTrustManager',
    'QcCertType',
    'AdditionalServiceInformation',
    'TSPServiceParsingError',
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
    FOR_ESIG = 'QCForEsig'
    FOR_ESEAL = 'QCForEseal'
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
class CAServiceInformation:
    base_info: BaseServiceInformation
    qualifications: FrozenSet[Qualification]
    expired_certs_revocation_info: Optional[datetime]


class TSPRegistry:
    def __init__(self: 'TSPRegistry'):
        self._cert_to_si: Dict[Authority, Set[CAServiceInformation]] = (
            defaultdict(set)
        )

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
