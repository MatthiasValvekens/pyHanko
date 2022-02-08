"""
.. versionadded:: 0.20.0
"""
import enum
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from pyhanko_certvalidator.name_trees import PKIXSubtrees, \
    default_permitted_subtrees, default_excluded_subtrees


@enum.unique
class RevocationCheckingRule(enum.Enum):
    """
    Rules determining in what circumstances revocation data has to be checked,
    and what kind.
    """

    # yes, this is consistently misspelled in all parts of the
    # ETSI TS 119 172 series...
    CRL_REQUIRED = "clrcheck"
    """
    Check CRLs.
    """

    OCSP_REQUIRED = "ocspcheck"
    """
    Check OCSP.
    """

    CRL_AND_OCSP_REQUIRED = "bothcheck"
    """
    Check CRL and OCSP.
    """

    CRL_OR_OCSP_REQUIRED = "eithercheck"
    """
    Check CRL or OCSP.
    """

    NO_CHECK = "nocheck"
    """
    Do not check.
    """

    CHECK_IF_DECLARED = "ifdeclaredcheck"
    """
    Check revocation information if declared in the certificate.
    
    .. warning::
        This is not an ESI check type, but is preserved for 
        compatibility with the 'hard-fail' mode in certvalidator.

    .. info::
        In this mode, cached CRLs will _not_ be checked if the certificate
        does not list any distribution points.
    """

    CHECK_IF_DECLARED_SOFT = "ifdeclaredsoftcheck"
    """
    Check revocation information if declared in the certificate, but
    do not fail validation if the check fails.

    .. warning::
        This is not an ESI check type, but is preserved for 
        compatibility with the 'soft-fail' mode in certvalidator.

    .. info::
        In this mode, cached CRLs will _not_ be checked if the certificate
        does not list any distribution points.
    """

    @property
    def strict(self) -> bool:
        # note that this is not quite the same as (not self.tolerant)!
        return self not in (
            RevocationCheckingRule.CHECK_IF_DECLARED,
            RevocationCheckingRule.CHECK_IF_DECLARED_SOFT,
            RevocationCheckingRule.NO_CHECK
        )

    @property
    def tolerant(self) -> bool:
        return self in (
            RevocationCheckingRule.CHECK_IF_DECLARED_SOFT,
            RevocationCheckingRule.NO_CHECK
        )

    @property
    def crl_mandatory(self) -> bool:
        return self in (
            RevocationCheckingRule.CRL_REQUIRED,
            RevocationCheckingRule.CRL_AND_OCSP_REQUIRED
        )

    @property
    def crl_relevant(self) -> bool:
        return self not in (
            RevocationCheckingRule.NO_CHECK,
            RevocationCheckingRule.OCSP_REQUIRED,
        )

    @property
    def ocsp_mandatory(self) -> bool:
        return self in (
            RevocationCheckingRule.OCSP_REQUIRED,
            RevocationCheckingRule.CRL_AND_OCSP_REQUIRED
        )

    @property
    def ocsp_relevant(self) -> bool:
        return self not in (
            RevocationCheckingRule.NO_CHECK,
            RevocationCheckingRule.CRL_REQUIRED
        )


@dataclass(frozen=True)
class RevocationCheckingPolicy:
    """
    Class describing a revocation checking policy
    based on the types defined in the ETSI TS 119 172 series.
    """

    ee_certificate_rule: RevocationCheckingRule
    """
    Revocation rule applied to end-entity certificates.
    """

    intermediate_ca_cert_rule: RevocationCheckingRule
    """
    Revocation rule applied to certificates further up the path.
    """

    @classmethod
    def from_legacy(cls, policy: str):
        try:
            return LEGACY_POLICY_MAP[policy]
        except KeyError:
            raise ValueError(f"'{policy}' is not a valid revocation mode")

    @property
    def essential(self) -> bool:
        return not (
            self.ee_certificate_rule.tolerant
            and self.ee_certificate_rule.tolerant
        )


LEGACY_POLICY_MAP = {
    'soft-fail': RevocationCheckingPolicy(
        RevocationCheckingRule.CHECK_IF_DECLARED_SOFT,
        RevocationCheckingRule.CHECK_IF_DECLARED_SOFT,
    ),
    'hard-fail': RevocationCheckingPolicy(
        RevocationCheckingRule.CHECK_IF_DECLARED,
        RevocationCheckingRule.CHECK_IF_DECLARED,
    ),
    'require': RevocationCheckingPolicy(
        RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
        RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
    )
}


@enum.unique
class FreshnessReqType(enum.Enum):
    DEFAULT = enum.auto()
    MAX_DIFF_REVOCATION_VALIDATION = enum.auto()
    TIME_AFTER_SIGNATURE = enum.auto()


@dataclass(frozen=True)
class CertRevTrustPolicy:
    """
    Class describing conditions for trusting revocation info.
    Based on CertificateRevTrust in ETSI TS 119 172-3.
    """

    revocation_checking_policy: RevocationCheckingPolicy
    """
    The revocation checking policy requirements.
    """

    freshness: Optional[timedelta] = None
    """
    Freshness interval. If not specified, this defaults to the distance
    between ``thisUpdate`` and ``nextUpdate`` for the given piece of revocation
    information.
    """

    freshness_req_type: FreshnessReqType = FreshnessReqType.DEFAULT
    """
    Controls whether the freshness requirement applies relatively to the
    signing time or to the validation time.
    """

    expected_post_expiry_revinfo_time: Optional[timedelta] = None
    """
    Duration for which the issuing CA is expected to supply status information
    after a certificate expires.
    """

    retroactive_revinfo: bool = False
    """
    Treat revocation info as retroactively valid, i.e. ignore the
    ``this_update`` field in CRLs and OCSP responses.
    This parameter is not taken into account for freshness policies other than
    :attr:`FreshnessReqType.DEFAULT`, and is ``False`` by default in those
    cases.

    .. warning::
        Be careful with this option, since it will cause incorrect
        behaviour for CAs that make use of certificate holds or other
        reversible revocation methods.
    """


@dataclass(frozen=True)
class PKIXValidationParams:
    user_initial_policy_set: frozenset = frozenset(['any_policy'])
    """
    Set of policies that the user is willing to accept. By default, any policy
    is acceptable.
    
    When setting this parameter to a non-default value, you probably want to
    set :attr:`initial_explicit_policy` as well.
    
    .. note::
        These are specified in the policy domain of the trust root(s), and
        subject to policy mapping by intermediate certificate authorities.
    """

    initial_policy_mapping_inhibit: bool = False
    """
    Flag indicating whether policy mapping is forbidden along the entire    
    certification chains. By default, policy mapping is permitted.
    
    .. note::
        Policy constraints on intermediate certificates may force policy mapping
        to be inhibited from some point onwards.
    """

    initial_explicit_policy: bool = False
    """
    Flag indicating whether path validation must terminate with at least one
    permissible policy; see :attr:`user_initial_policy_set`.
    By default, no such requirement is imposed.
    
    .. note::
        If :attr:`user_initial_policy_set` is set to its default value of
        ``{'any_policy'}``, the effect is that the path validation must accept
        at least one policy, without specifying which.
        
    .. warning::
        Due to widespread mis-specification of policy extensions in the wild,
        many real-world certification chains terminate with an empty set
        (or rather, tree) of valid policies. Therefore, this flag is set to 
        ``False`` by default.
    """

    initial_any_policy_inhibit: bool = False
    """
    Flag indicating whether ``anyPolicy`` should be left unprocessed when it
    appears in a certificate. By default, ``anyPolicy`` is always processed
    when it appears.
    """

    initial_permitted_subtrees: PKIXSubtrees = \
        field(default_factory=default_permitted_subtrees)
    """
    Set of permitted subtrees for each name type, indicating restrictions
    to impose on subject names (and alternative names) in the certification
    path.
    
    By default, all names are permitted.
    This behaviour can be modified by name constraints on intermediate CA
    certificates.
    """

    initial_excluded_subtrees: PKIXSubtrees = field(
        default_factory=default_excluded_subtrees
    )
    """
    Set of excluded subtrees for each name type, indicating restrictions
    to impose on subject names (and alternative names) in the certification
    path.

    By default, no names are excluded.
    This behaviour can be modified by name constraints on intermediate CA
    certificates.
    """
