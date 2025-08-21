import abc
from datetime import datetime
from typing import Optional

from asn1crypto import algos, cms, keys

from pyhanko_certvalidator.policy_decl import (
    AlgorithmUsageConstraint,
    AlgorithmUsagePolicy,
    DisallowWeakAlgorithmsPolicy,
)

from ..general import (
    MultivaluedAttributeError,
    NonexistentAttributeError,
    find_unique_cms_attribute,
)
from .errors import SignatureValidationError


def _ensure_digest_match(
    signature_algo: algos.SignedDigestAlgorithm,
    message_digest_algo: algos.DigestAlgorithm,
) -> AlgorithmUsageConstraint:
    if signature_algo['algorithm'].native == 'ed448':
        # be a bit more tolerant here, also don't check parameters because
        # we only support one length anyway
        algo = message_digest_algo['algorithm'].native
        if algo in ('shake256', 'shake256_len'):
            return AlgorithmUsageConstraint(allowed=True)
        else:
            return AlgorithmUsageConstraint(
                allowed=False,
                failure_reason=(
                    f"Digest algorithm {algo} "
                    f"does not match value implied by signature algorithm ed448"
                ),
            )

    try:
        sig_hash_algo_obj = algos.DigestAlgorithm(
            {'algorithm': signature_algo.hash_algo}
        )
    except ValueError:
        sig_hash_algo_obj = None

    if (
        sig_hash_algo_obj is not None
        and sig_hash_algo_obj.dump() != message_digest_algo.dump()
    ):
        return AlgorithmUsageConstraint(
            allowed=False,
            failure_reason=(
                f"Digest algorithm {message_digest_algo['algorithm'].native} "
                f"does not match value implied by signature algorithm "
                f"{signature_algo['algorithm'].native}"
            ),
        )
    return AlgorithmUsageConstraint(allowed=True)


class CMSAlgorithmUsagePolicy(AlgorithmUsagePolicy, abc.ABC):
    """
    Algorithm usage policy for CMS signatures.
    """

    def digest_combination_allowed(
        self,
        signature_algo: algos.SignedDigestAlgorithm,
        message_digest_algo: algos.DigestAlgorithm,
        moment: Optional[datetime],
    ) -> AlgorithmUsageConstraint:
        """
        Verify whether a digest algorithm is compatible with the digest
        algorithm implied by the provided signature algorithm, if any.

        By default, this enforces the convention (requirement in RFC 8933) that
        the message digest must be computed using the same digest algorithm
        as the one used by the signature, if applicable.

        Checking whether the individual algorithms are allowed is not the
        responsibility of this method.

        :param signature_algo:
            A signature mechanism to use
        :param message_digest_algo:
            The digest algorithm used for the message digest
        :param moment:
            The point in time for which the assessment needs to be made.
        :return:
            A usage constraint.
        """
        return _ensure_digest_match(signature_algo, message_digest_algo)

    @staticmethod
    def lift_policy(policy: AlgorithmUsagePolicy) -> 'CMSAlgorithmUsagePolicy':
        """
        Lift a 'base' :class:`.AlgorithmUsagePolicy` to a CMS usage algorithm
        policy with default settings. If the policy passed in is already
        a :class:`.CMSAlgorithmUsagePolicy`, return it as-is.

        :param policy:
            The underlying original policy
        :return:
            The lifted policy
        """
        if isinstance(policy, CMSAlgorithmUsagePolicy):
            return policy
        else:
            return _DefaultPolicyMixin(policy)


class _DefaultPolicyMixin(CMSAlgorithmUsagePolicy):
    def __init__(self, underlying_policy: AlgorithmUsagePolicy):
        self._policy = underlying_policy

    def digest_algorithm_allowed(
        self, algo: algos.DigestAlgorithm, moment: Optional[datetime]
    ) -> AlgorithmUsageConstraint:
        return self._policy.digest_algorithm_allowed(algo, moment)

    def signature_algorithm_allowed(
        self,
        algo: algos.SignedDigestAlgorithm,
        moment: Optional[datetime],
        public_key: Optional[keys.PublicKeyInfo],
    ) -> AlgorithmUsageConstraint:
        return self._policy.signature_algorithm_allowed(
            algo, moment, public_key
        )


DEFAULT_WEAK_HASH_ALGORITHMS = frozenset({'sha1', 'md5', 'md2'})

DEFAULT_ALGORITHM_USAGE_POLICY = CMSAlgorithmUsagePolicy.lift_policy(
    DisallowWeakAlgorithmsPolicy(DEFAULT_WEAK_HASH_ALGORITHMS)
)


def extract_message_digest(signer_info: cms.SignerInfo):
    try:
        embedded_digest = find_unique_cms_attribute(
            signer_info['signed_attrs'], 'message_digest'
        )
        return embedded_digest.native
    except (NonexistentAttributeError, MultivaluedAttributeError):
        raise SignatureValidationError(
            'Message digest not found in signature, or multiple message '
            'digest attributes present.'
        )
