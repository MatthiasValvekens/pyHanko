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

from ..general import (
    MultivaluedAttributeError,
    NonexistentAttributeError,
    find_unique_cms_attribute,
    get_pyca_cryptography_hash,
    process_pss_params,
)
from .errors import SignatureValidationError, WeakHashAlgorithmError

DEFAULT_WEAK_HASH_ALGORITHMS = frozenset({'sha1', 'md5', 'md2'})


def validate_raw(signature: bytes, signed_data: bytes, cert: x509.Certificate,
                 signature_algorithm: cms.SignedDigestAlgorithm,
                 md_algorithm: str, prehashed=False,
                 weak_hash_algorithms=DEFAULT_WEAK_HASH_ALGORITHMS):
    """
    Validate a raw signature. Internal API.
    """
    try:
        sig_md_algorithm = signature_algorithm.hash_algo
    except (ValueError, AttributeError):
        sig_md_algorithm = None

    if sig_md_algorithm is not None:
        if sig_md_algorithm in weak_hash_algorithms:
            raise WeakHashAlgorithmError(md_algorithm)
        md_algorithm = sig_md_algorithm.upper()

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
