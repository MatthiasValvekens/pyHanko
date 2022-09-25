from datetime import datetime
from typing import Optional

from asn1crypto import cms, x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pyhanko_certvalidator.policy_decl import (
    AlgorithmUsagePolicy,
    DisallowWeakAlgorithmsPolicy,
)

from ..general import (
    MultivaluedAttributeError,
    NonexistentAttributeError,
    find_unique_cms_attribute,
    get_pyca_cryptography_hash,
    process_pss_params,
)
from .errors import DisallowedAlgorithmError, SignatureValidationError

DEFAULT_WEAK_HASH_ALGORITHMS = frozenset({'sha1', 'md5', 'md2'})

DEFAULT_ALGORITHM_USAGE_POLICY = \
    DisallowWeakAlgorithmsPolicy(DEFAULT_WEAK_HASH_ALGORITHMS)


def validate_raw(
        signature: bytes, signed_data: bytes, cert: x509.Certificate,
        signature_algorithm: cms.SignedDigestAlgorithm,
        md_algorithm: str, prehashed=False,
        algorithm_policy: Optional[AlgorithmUsagePolicy]
        = DEFAULT_ALGORITHM_USAGE_POLICY,
        time_indic: Optional[datetime] = None):
    """
    Validate a raw signature. Internal API.
    """
    try:
        sig_md_algorithm = signature_algorithm.hash_algo
    except (ValueError, AttributeError):
        sig_md_algorithm = None

    if sig_md_algorithm is not None:
        if algorithm_policy is not None and not algorithm_policy\
                .digest_algorithm_allowed(sig_md_algorithm, time_indic):
            raise DisallowedAlgorithmError(md_algorithm)
        md_algorithm = sig_md_algorithm.upper()
    signature_algo = signature_algorithm.signature_algo
    if algorithm_policy is not None and not algorithm_policy \
            .signature_algorithm_allowed(signature_algo, time_indic):
        raise DisallowedAlgorithmError(signature_algo)

    verify_md = get_pyca_cryptography_hash(md_algorithm, prehashed=prehashed)

    pub_key = serialization.load_der_public_key(
        cert.public_key.dump()
    )

    sig_algo = signature_algorithm.signature_algo
    if sig_algo == 'rsassa_pkcs1v15':
        assert isinstance(pub_key, RSAPublicKey)
        pub_key.verify(signature, signed_data, padding.PKCS1v15(), verify_md)
    elif sig_algo == 'rsassa_pss':
        assert isinstance(pub_key, RSAPublicKey)
        pss_padding, hash_algo = process_pss_params(
            signature_algorithm['parameters'], md_algorithm,
            prehashed=prehashed
        )
        pub_key.verify(signature, signed_data, pss_padding, hash_algo)
    elif sig_algo == 'dsa':
        assert isinstance(pub_key, DSAPublicKey)
        pub_key.verify(signature, signed_data, verify_md)
    elif sig_algo == 'ecdsa':
        assert isinstance(pub_key, EllipticCurvePublicKey)
        pub_key.verify(signature, signed_data, ECDSA(verify_md))
    elif sig_algo in 'ed25519':
        assert isinstance(pub_key, Ed25519PublicKey)
        pub_key.verify(signature, signed_data)
    elif sig_algo in 'ed448':
        assert isinstance(pub_key, Ed448PublicKey)
        pub_key.verify(signature, signed_data)
    else:  # pragma: nocover
        raise NotImplementedError(
            f"Signature mechanism {sig_algo} is not supported."
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
