import dataclasses
import enum
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime

from asn1crypto import x509
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, DiffPolicy
from pyhanko.sign.validation import KeyUsageConstraints
from pyhanko.sign.validation.qualified.q_status import (
    QcPrivateKeyManagementType,
)
from pyhanko.sign.validation.qualified.tsp import QcCertType
from pyhanko.sign.validation.utils import CMSAlgorithmUsagePolicy
from pyhanko_certvalidator.authority import TrustedServiceType
from pyhanko_certvalidator.context import (
    USE_DEFAULT_FETCHERS,
    CertValidationPolicySpec,
    UseDefaultFetchers,
    ValidationDataHandlers,
)
from pyhanko_certvalidator.context import (
    bootstrap_validation_data_handlers as _certvalidator_bootstrap_handlers,
)
from pyhanko_certvalidator.fetchers import FetcherBackend
from pyhanko_certvalidator.ltv.poe import (
    KnownPOE,
    POEManager,
    POEType,
    ValidationObject,
    ValidationObjectType,
    digest_for_poe,
)
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.policy_decl import NonRevokedStatusAssertion
from pyhanko_certvalidator.revinfo.archival import CRLContainer, OCSPContainer

__all__ = [
    'CMSAlgorithmUsagePolicy',
    'CertificateFetchingRule',
    'LocalKnowledge',
    'PdfSignatureValidationSpec',
    'QualificationRequirements',
    'RevinfoOnlineFetchingRule',
    'RevocationInfoGatheringSpec',
    'SignatureValidationSpec',
    'bootstrap_validation_data_handlers',
]


class RevinfoOnlineFetchingRule(enum.Enum):
    ALWAYS_FETCH = enum.auto()
    """
    Always permit fetching revocation information from online sources.
    """

    NO_HISTORICAL_FETCH = enum.auto()
    """
    Only attempt to fetch revocation information when performing validation
    of a signature at the current time, and use the local cache in past
    validation evaluation.
    """
    # TODO document precisely what this means, esp. for the legacy API

    LOCAL_ONLY = enum.auto()
    """
    Only use locally cached revocation information.
    """


class CertificateFetchingRule(enum.Enum):
    """
    .. versionadded:: 0.38.0

    Controls whether certificates may be fetched from URLs found in the
    material being validated. This is orthogonal to
    :class:`RevinfoOnlineFetchingRule`, which governs CRLs and OCSP responses.
    """

    FOLLOW_ONLINE_RULE = enum.auto()
    """
    Certificates may be fetched whenever the
    :class:`RevinfoOnlineFetchingRule` permits online fetching.
    """

    NEVER_FETCH = enum.auto()
    """
    Never fetch certificates, even if online fetching is otherwise permitted.
    This covers both AIA ``caIssuers`` chasing during path building and
    certificate fetches for CRL issuers (URLs taken from CRLs).

    CRLs and OCSP responses can still be fetched, subject to
    :class:`RevinfoOnlineFetchingRule`.

    .. warning::
        This removes the fetches whose URLs are most directly under the
        control of whoever produced the signed material, and nothing more.
        It does not make online fetching as a whole safe.

        The cost is that validation fails when intermediate certificates
        are not supplied with the signature or otherwise known locally,
        and likewise for indirect CRL issuers that are not available locally.
    """


@dataclass(frozen=True)
class RevocationInfoGatheringSpec:
    online_fetching_rule: RevinfoOnlineFetchingRule = (
        RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH
    )
    fetcher_backend: FetcherBackend | None = None
    """
    .. versionchanged:: 0.37.0
        Defaults to ``None`` now, which will result in a backend
        provisioned on-the-fly for each operation that requires one.

    Fetcher backend to gather revocation information with.

    When ``None``, a backend is provisioned for the duration of each
    validation operation and released when it ends. Supply one explicitly to
    pool resources across operations. In this case, the lifecycle management
    responsibility is yours.
    """

    certificate_fetching_rule: CertificateFetchingRule = (
        CertificateFetchingRule.FOLLOW_ONLINE_RULE
    )
    """
    .. versionadded:: 0.38.0

    Rule that determines whether certificates may be fetched online, in
    addition to the restrictions imposed by :attr:`online_fetching_rule`.
    """


@dataclass(frozen=True)
class LocalKnowledge:
    known_ocsps: list[OCSPContainer] = field(default_factory=list)
    known_crls: list[CRLContainer] = field(default_factory=list)
    known_certs: list[x509.Certificate] = field(default_factory=list)
    known_poes: list[KnownPOE] = field(default_factory=list)
    nonrevoked_assertions: list[NonRevokedStatusAssertion] = field(
        default_factory=list
    )

    def add_to_poe_manager(self, poe_manager: POEManager):
        for poe in self.known_poes:
            poe_manager.register_known_poe(poe)

    def assert_existence_known_at(
        self, dt: datetime
    ) -> Generator[KnownPOE, None, None]:
        for poe in self.known_poes:
            yield dataclasses.replace(
                poe,
                poe_time=min(poe.poe_time, dt),
                poe_type=POEType.PROVIDED,
            )
        for crl in self.known_crls:
            yield KnownPOE(
                digest=digest_for_poe(crl.crl_data.dump()),
                poe_time=dt,
                poe_type=POEType.PROVIDED,
                validation_object=ValidationObject(
                    ValidationObjectType.CRL, crl
                ),
            )
        for ocsp in self.known_ocsps:
            yield KnownPOE(
                digest=digest_for_poe(ocsp.ocsp_response_data.dump()),
                poe_time=dt,
                poe_type=POEType.PROVIDED,
                validation_object=ValidationObject(
                    ValidationObjectType.OCSP_RESPONSE, ocsp
                ),
            )
        for cert in self.known_certs:
            yield KnownPOE(
                digest=digest_for_poe(cert.dump()),
                poe_time=dt,
                poe_type=POEType.PROVIDED,
                validation_object=ValidationObject(
                    ValidationObjectType.CERTIFICATE, cert
                ),
            )


@dataclass(frozen=True)
class QualificationRequirements:
    """
    Impose qualification requirements on the validation process.

    .. note::
        This requires a ``TSPTrustManager``.
    """

    permit_key_mgmt_types: frozenset[QcPrivateKeyManagementType] | None = None
    """
    Set of key management types that is permissible for the validation.

    If ``None``, no restrictions are applied.
    """

    permit_cert_types: frozenset[QcCertType] | None = frozenset(
        [QcCertType.QC_ESIGN, QcCertType.QC_ESEAL]
    )
    """
    Set of qualified certificate types that is permissible for the validation.
    By default, eSign certificates and eSeal certificates are permitted.

    If ``None``, no restrictions are applied.
    """

    require_service_type: TrustedServiceType | str | None = None
    """
    Require the end entity to be directly listed on the trust list
    as a service of the indicated type, without going through any
    intermediate certificate authorities.

    You can also specify the required service type as an URI directly.

    .. note::
        You can use this setting to indicate that timestamps should
        come from a QTST.
    """


@dataclass(frozen=True)
class SignatureValidationSpec:
    cert_validation_policy: CertValidationPolicySpec
    revinfo_gathering_policy: RevocationInfoGatheringSpec = (
        RevocationInfoGatheringSpec()
    )
    ts_cert_validation_policy: CertValidationPolicySpec | None = None
    ac_validation_policy: CertValidationPolicySpec | None = None
    local_knowledge: LocalKnowledge = LocalKnowledge()
    key_usage_settings: KeyUsageConstraints = field(
        default_factory=KeyUsageConstraints
    )
    signature_algorithm_policy: CMSAlgorithmUsagePolicy | None = None
    qualification_requirements: QualificationRequirements | None = None
    ts_qualification_requirements: QualificationRequirements | None = None


@dataclass(frozen=True)
class PdfSignatureValidationSpec:
    signature_validation_spec: SignatureValidationSpec
    diff_policy: DiffPolicy | None = DEFAULT_DIFF_POLICY


def _backend_if_necessary(
    hist: bool, rule: RevinfoOnlineFetchingRule, backend: FetcherBackend | None
) -> FetcherBackend | UseDefaultFetchers | None:
    if (
        rule == RevinfoOnlineFetchingRule.LOCAL_ONLY
        or rule == RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH
        and hist
    ):
        return None
    elif backend is None:
        return USE_DEFAULT_FETCHERS
    else:
        return backend


def bootstrap_validation_data_handlers(
    spec: SignatureValidationSpec,
    timing_info: ValidationTimingInfo | None = None,
    is_historical: bool | None = None,
    poe_manager_override: POEManager | None = None,
) -> ValidationDataHandlers:
    if is_historical is None:
        hist = (
            timing_info.point_in_time_validation
            if timing_info is not None
            else False
        )
    else:
        hist = is_historical
    revinfo_policy = spec.revinfo_gathering_policy

    fetcher_backend = _backend_if_necessary(
        hist=hist,
        rule=revinfo_policy.online_fetching_rule,
        backend=revinfo_policy.fetcher_backend,
    )

    knowledge = spec.local_knowledge
    handlers = _certvalidator_bootstrap_handlers(
        fetchers=fetcher_backend,
        crls=knowledge.known_crls,
        ocsps=knowledge.known_ocsps,
        certs=knowledge.known_certs,
        poe_manager=poe_manager_override,
        nonrevoked_assertions=knowledge.nonrevoked_assertions,
    )
    if (
        revinfo_policy.certificate_fetching_rule
        == CertificateFetchingRule.NEVER_FETCH
    ):
        handlers.cert_registry.fetcher = None
    return handlers
