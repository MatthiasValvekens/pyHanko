from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

from asn1crypto import algos
from asn1crypto.keys import PublicKeyInfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)

from pyhanko_certvalidator.errors import (
    AlgorithmNotSupported,
    DSAParametersUnavailable,
    PSSParameterMismatch,
)
from pyhanko_certvalidator.util import (
    get_pyca_cryptography_hash_for_signing,
    process_pss_params,
)

__all__ = [
    'SignatureValidator',
    'SignatureValidationContext',
    'DefaultSignatureValidator',
]


@dataclass(frozen=True)
class SignatureValidationContext:
    """
    Additional context about a signature that is crucial for
    executing the cryptographic validation process.
    """

    contextual_md_algorithm: Optional[str] = None
    """
    Digest algorithm inferred from context. Used when the digest
    algorithm cannot be derived from the ASN.1 data describing the
    signature algorithm.
    """

    prehashed: bool = False
    """
    Indicates whether the payload was pre-hashed (not always possible
    depending on the signature algorithm).
    """


class SignatureValidator(abc.ABC):
    """
    Abstracts away cryptographic validation primitives.
    """

    def validate_signature(
        self,
        signature: bytes,
        signed_data: bytes,
        public_key_info: PublicKeyInfo,
        signature_algorithm: algos.SignedDigestAlgorithm,
        context: SignatureValidationContext = SignatureValidationContext(),
    ):
        """
        Validate a cryptographic signature over a piece of data.

        :param signature:
            The signature data.
        :param signed_data:
            The signed data.
        :param public_key_info:
            The public key with which to validate the signature.
        :param signature_algorithm:
            The algorithm to use when validating.
        :param context:
            Additional context that is crucial for executing the cryptographic
            validation process.
        :raises InvalidSignature:
            Raised if the signature is invalid.
        """
        raise NotImplementedError()


class DefaultSignatureValidator(SignatureValidator):
    def validate_signature(
        self,
        signature: bytes,
        signed_data: bytes,
        public_key_info: PublicKeyInfo,
        signature_algorithm: algos.SignedDigestAlgorithm,
        context: SignatureValidationContext = SignatureValidationContext(),
    ):
        return _validate_raw(
            signature,
            signed_data,
            public_key_info,
            signature_algorithm,
            context,
        )


def _validate_raw(
    signature: bytes,
    signed_data: bytes,
    public_key_info: PublicKeyInfo,
    signature_algorithm: algos.SignedDigestAlgorithm,
    context: SignatureValidationContext = SignatureValidationContext(),
):
    """
    Validate a raw signature. Internal API.
    """
    try:
        sig_algo = signature_algorithm.signature_algo
    except ValueError:
        sig_algo = signature_algorithm['algorithm'].native

    parameters = signature_algorithm['parameters']

    if (
        sig_algo == 'dsa'
        and public_key_info['algorithm']['parameters'].native is None
    ):
        raise DSAParametersUnavailable(
            "DSA public key parameters were not provided."
        )

    # pyca/cryptography can't load PSS-exclusive keys without some help:
    if public_key_info.algorithm == 'rsassa_pss':
        public_key_info = public_key_info.copy()
        assert isinstance(parameters, algos.RSASSAPSSParams)
        pss_key_params = public_key_info['algorithm']['parameters'].native
        if pss_key_params is not None and pss_key_params != parameters.native:
            raise PSSParameterMismatch(
                "Public key info includes PSS parameters that do not match "
                "those on the signature"
            )
        # set key type to generic RSA, discard parameters
        public_key_info['algorithm'] = {'algorithm': 'rsa'}

    pub_key = serialization.load_der_public_key(public_key_info.dump())
    try:
        hash_algo = signature_algorithm.hash_algo
    except ValueError:
        hash_algo = context.contextual_md_algorithm
    if sig_algo == 'rsassa_pkcs1v15':
        assert isinstance(pub_key, rsa.RSAPublicKey)
        verify_md = get_pyca_cryptography_hash_for_signing(
            hash_algo, prehashed=context.prehashed
        )
        pub_key.verify(signature, signed_data, padding.PKCS1v15(), verify_md)
    elif sig_algo == 'rsassa_pss':
        assert isinstance(pub_key, rsa.RSAPublicKey)
        pss_padding, verify_md = process_pss_params(
            signature_algorithm['parameters'], prehashed=context.prehashed
        )
        pub_key.verify(signature, signed_data, pss_padding, verify_md)
    elif sig_algo == 'dsa':
        assert isinstance(pub_key, dsa.DSAPublicKey)
        verify_md = get_pyca_cryptography_hash_for_signing(
            hash_algo, prehashed=context.prehashed
        )
        pub_key.verify(signature, signed_data, verify_md)
    elif sig_algo == 'ecdsa':
        assert isinstance(pub_key, ec.EllipticCurvePublicKey)
        verify_md = get_pyca_cryptography_hash_for_signing(
            hash_algo, prehashed=context.prehashed
        )
        pub_key.verify(signature, signed_data, ec.ECDSA(verify_md))
    elif sig_algo == 'ed25519':
        assert isinstance(pub_key, ed25519.Ed25519PublicKey)
        pub_key.verify(signature, signed_data)
    elif sig_algo == 'ed448':
        assert isinstance(pub_key, ed448.Ed448PublicKey)
        pub_key.verify(signature, signed_data)
    else:
        raise AlgorithmNotSupported(
            f"Signature mechanism {sig_algo} is not supported."
        )
