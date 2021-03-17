"""
General tools related to Cryptographic Message Syntax (CMS) signatures,
not necessarily to the extent implemented in the PDF specification.

CMS is defined in :rfc:`5652`. To parse CMS messages, pyHanko relies heavily on
`asn1crypto <https://github.com/wbond/asn1crypto>`_.
"""

import logging
from dataclasses import dataclass
from typing import ClassVar, Set, Optional, Tuple

import hashlib

from asn1crypto import x509, cms, tsp, algos, pem, keys

# noinspection PyProtectedMember
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, ECDSA
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from certvalidator.path import ValidationPath

from certvalidator import (
    CertificateValidator, InvalidCertificateError, PathBuildingError,
)
from certvalidator.errors import RevokedError, PathValidationError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


__all__ = [
    'SignatureStatus', 'simple_cms_attribute', 'find_cms_attribute',
    'CertificateStore', 'SimpleCertificateStore', 'SigningError',
    'UnacceptableSignerError',
    'load_certs_from_pemder', 'load_cert_from_pemder',
    'load_private_key_from_pemder'
]

logger = logging.getLogger(__name__)


class SignatureValidationError(ValueError):
    """Error validating a signature."""
    pass


@dataclass(frozen=True)
class KeyUsageConstraints:
    """
    Convenience class to pass around key usage requirements and validate them.
    """

    key_usage: Set[str] = None
    """
    These key usage extensions must be present in the signer's certificate.
    """

    extd_key_usage: Set[str] = None
    """
    These extended key usage extensions must be present in the signer's
    certificate.
    """

    key_usage_forbidden: Set[str] = None
    """
    These key usage extensions must not be present in the signer's certificate.
    """

    extd_key_usage_forbidden: Set[str] = None
    """
    These extended key usage extensions must not be present in the signer's
    certificate.
    """

    def validate(self, cert: x509.Certificate):

        # the PDF specification permits this type of "negative" constraint
        # in seed value dictionaries.
        # We have to validate these manually.
        key_usage = self.key_usage or set()
        extd_key_usage = self.extd_key_usage or set()
        key_usage_forbidden = self.key_usage_forbidden or set()
        extd_key_usage_forbidden = self.extd_key_usage_forbidden or set()
        cert_ku = (
            set(cert.key_usage_value.native) if cert.key_usage_value is not None
            else set()
        )
        cert_extd_ku = (
            set(cert.extended_key_usage_value.native)
            if cert.extended_key_usage_value is not None
            else set()
        )

        must_have = key_usage - cert_ku
        must_have |= extd_key_usage - cert_extd_ku

        forbidden = cert_ku & key_usage_forbidden
        forbidden |= cert_extd_ku & extd_key_usage_forbidden

        if must_have:
            rephrased = map(lambda s: s.replace('_', ' '), must_have)
            raise InvalidCertificateError(
                "The active key usage policy requires the key extensions "
                f"{', '.join(rephrased)} to be present."
            )

        if forbidden:
            rephrased = map(lambda s: s.replace('_', ' '), forbidden)
            raise InvalidCertificateError(
                "The active key usage policy explicitly bans certificates "
                f"used for {', '.join(rephrased)}."
            )


@dataclass(frozen=True)
class SignatureStatus:
    """
    Class describing the validity of a (general) CMS signature.
    """

    intact: bool
    """
    Reports whether the signature is *intact*, i.e. whether the hash of the 
    message content (which may or may not be embedded inside the CMS object
    itself) matches the hash value that was signed.
    """

    valid: bool
    """
    Reports whether the signature is *valid*, i.e. whether the hash's signature
    actually validates.
    """

    trusted: bool
    """
    Reports whether the signer's certificate is trusted w.r.t. the currently 
    relevant validation context and key usage requirements.
    """

    # TODO add a separate expired flag

    revoked: bool
    """
    Reports whether the signer's certificate has been revoked or not.
    If this field is ``True``, then obviously :attr:`trusted` will be ``False``.
    """

    signing_cert: x509.Certificate
    """
    Contains the certificate of the signer, as embedded in the CMS object.
    """

    pkcs7_signature_mechanism: str
    """
    PKCS7 signature mechanism used.
    """

    # TODO: also here some ambiguity analysis is in order
    md_algorithm: str
    """
    Message digest algorithm used.
    """

    validation_path: ValidationPath
    """
    Validation path providing a valid chain of trust from the signer's 
    certificate to a trusted root certificate.
    """

    # XXX frozenset makes more sense here, but asn1crypto doesn't allow that
    #  (probably legacy behaviour)
    key_usage: ClassVar[Set[str]] = {'non_repudiation'}
    """
    Class property indicating which key usage extensions are required to be
    present on the signer's certificate.
    The default is ``non_repudiation`` only.
    """

    extd_key_usage: ClassVar[Set[str]] = set()
    """
    Class property indicating which extended key usage extensions are required 
    to be present on the signer's certificate.
    """

    def summary_fields(self):
        if self.trusted:
            cert_status = 'TRUSTED'
        elif self.revoked:
            cert_status = 'REVOKED'
        else:
            cert_status = 'UNTRUSTED'
        yield cert_status

    # TODO explain in more detail.
    def summary(self):
        """
        Provide a textual but machine-parsable summary of the validity.
        """
        if self.intact and self.valid:
            return 'INTACT:' + ','.join(self.summary_fields())
        else:
            return 'INVALID'

    @classmethod
    def validate_cert_usage(cls, validator: CertificateValidator,
                            key_usage_settings: KeyUsageConstraints = None):
        key_usage_settings = key_usage_settings or KeyUsageConstraints()
        key_usage_settings = KeyUsageConstraints(
            key_usage=(
                cls.key_usage if key_usage_settings.key_usage is None
                else key_usage_settings.key_usage
            ),
            extd_key_usage=(
                cls.extd_key_usage if key_usage_settings.extd_key_usage is None
                else key_usage_settings.extd_key_usage
            )
        )
        cert: x509.Certificate = validator._certificate

        revoked = trusted = False
        path = None

        try:
            # validate usage without going through certvalidator
            key_usage_settings.validate(cert)
            path = validator.validate_usage(key_usage=set())
            trusted = True
        except InvalidCertificateError as e:
            # TODO accumulate these somewhere
            logger.warning(e)
        except RevokedError:
            revoked = True
        except (PathValidationError, PathBuildingError) as e:
            logger.warning(e)
        if not trusted:
            subj = cert.subject.human_friendly
            logger.warning(f"Chain of trust validation for {subj} failed.")
        return trusted, revoked, path


def simple_cms_attribute(attr_type, value):
    """
    Convenience method to quickly construct a CMS attribute object with
    one value.

    :param attr_type:
        The attribute type, as a string or OID.
    :param value:
        The value.
    :return:
        A :class:`.cms.CMSAttribute` object.
    """
    return cms.CMSAttribute({
        'type': cms.CMSAttributeType(attr_type),
        'values': (value,)
    })


def find_cms_attribute(attrs, name):
    """
    Find and return CMS attribute values of a given type.

    :param attrs:
        The :class:`.cms.CMSAttributes` object.
    :param name:
        The attribute type as a string (as defined in ``asn1crypto``).
    :return:
        The values associated with the requested type, if present.
    :raise KeyError:
        Raised when no such type entry could be found in the
        :class:`.cms.CMSAttributes` object.
    """
    for attr in attrs:
        if attr['type'].native == name:
            return attr['values']
    raise KeyError(f'Unable to locate attribute {name}.')


# TODO perhaps phasing this out in favour of ESS SigningCertificate V2
#  (which allows better hash algorithms) would be preferable.
#  See RFC 5035.

def as_signing_certificate(cert: x509.Certificate) -> tsp.SigningCertificate:
    # see RFC 2634, § 5.4.1
    return tsp.SigningCertificate({
        'certs': [
            tsp.ESSCertID({'cert_hash': hashlib.sha1(cert.dump()).digest()})
        ]
    })


class CertificateStore:
    """
    Bare-bones interface for modelling a collection of certificates.
    """

    def register(self, cert: x509.Certificate):
        """
        Add a certificate to the collection.

        :param cert:
            The certificate to add.
        """
        raise NotImplementedError

    def __iter__(self):
        """
        Iterate over all certificates in the collection.
        """
        raise NotImplementedError

    def __getitem__(self, item) -> x509.Certificate:
        """
        Retrieve a certificate by its ``issuer_serial`` value.

        :param item:
            The ``issuer_serial`` value of the certificate.
        :return:
            The certificate corresponding to the ``issuer_serial`` key
            passed in.
        :raises KeyError:
            Raised if no certificate was found.
        """
        raise NotImplementedError

    def register_multiple(self, certs):
        """
        Register multiple certificates.

        :param certs:
            Certificates to register.
        """

        for cert in certs:
            self.register(cert)


class SimpleCertificateStore(CertificateStore):
    """
    Unopinionated replacement for certvalidator's CertificateRegistry in cases
    where we explicitly don't care about whether the certs are trusted or not.
    """

    def __init__(self):
        self.certs = {}

    def register(self, cert: x509.Certificate):
        self.certs[cert.issuer_serial] = cert

    def __getitem__(self, item):
        return self.certs[item]

    def __iter__(self):
        return iter(self.certs.values())


class SigningError(ValueError):
    """
    Error encountered while signing a file.
    """
    pass


class UnacceptableSignerError(SigningError):
    """
    Error raised when a signer was judged unacceptable.
    """
    pass


def _get_pyca_cryptography_hash(algorithm, prehashed=False):
    hash_algo = getattr(hashes, algorithm.upper())()
    return Prehashed(hash_algo) if prehashed else hash_algo


def _process_pss_params(params: algos.RSASSAPSSParams, digest_algorithm,
                        prehashed=False):

    hash_algo: algos.DigestAlgorithm = params['hash_algorithm']
    md_name = hash_algo['algorithm'].native
    if md_name.casefold() != digest_algorithm.casefold():
        raise ValueError(
            f"PSS MD '{md_name}' must agree with signature "
            f"MD '{digest_algorithm}'."
        )  # pragma: nocover
    mga: algos.MaskGenAlgorithm = params['mask_gen_algorithm']
    if not mga['algorithm'].native == 'mgf1':
        raise NotImplementedError("Only MFG1 is supported")

    mgf_md_name = mga['parameters']['algorithm'].native

    if mgf_md_name != md_name:
        logger.warning(
            f"Message digest for MGF1 is {mgf_md_name}, and the one used for "
            f"signing is {md_name}. If these do not agree, some software may "
            f"refuse to validate the signature."
        )
    salt_len: int = params['salt_length'].native

    mgf_md = _get_pyca_cryptography_hash(mgf_md_name, prehashed=False)
    md = _get_pyca_cryptography_hash(md_name, prehashed=prehashed)
    pss_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=mgf_md),
        salt_length=salt_len
    )
    return pss_padding, md


def optimal_pss_params(cert: x509.Certificate, digest_algorithm: str):

    digest_algorithm = digest_algorithm.lower()

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    except ImportError:  # pragma: nocover
        raise SigningError("pyca/cryptography is required for generic PSS")

    key: RSAPublicKey = serialization.load_der_public_key(
        cert.public_key.dump()
    )
    md = getattr(hashes, digest_algorithm.upper())
    # the PSS salt calculation function is not in the .pyi file, apparently.
    # noinspection PyUnresolvedReferences
    optimal_salt_len = padding.calculate_max_pss_salt_length(key, md())
    return algos.RSASSAPSSParams({
        'hash_algorithm': algos.DigestAlgorithm({
            'algorithm': digest_algorithm
        }),
        'mask_gen_algorithm': algos.MaskGenAlgorithm({
            'algorithm': 'mgf1',
            'parameters': algos.DigestAlgorithm({
                'algorithm': digest_algorithm
            }),
        }),
        'salt_length': optimal_salt_len
    })


def load_certs_from_pemder(cert_files):
    """
    A convenience function to load PEM/DER-encoded certificates from files.

    :param cert_files:
        An iterable of file names.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """
    for ca_chain_file in cert_files:
        with open(ca_chain_file, 'rb') as f:
            ca_chain_bytes = f.read()
        # use the pattern from the asn1crypto docs
        # to distinguish PEM/DER and read multiple certs
        # from one PEM file (if necessary)
        if pem.detect(ca_chain_bytes):
            pems = pem.unarmor(ca_chain_bytes, multiple=True)
            for type_name, _, der in pems:
                if type_name is None or type_name.lower() == 'certificate':
                    yield x509.Certificate.load(der)
                else:  # pragma: nocover
                    logger.debug(
                        f'Skipping PEM block of type {type_name} in '
                        f'{ca_chain_file}.'
                    )
        else:
            # no need to unarmor, just try to load it immediately
            yield x509.Certificate.load(ca_chain_bytes)


def load_cert_from_pemder(cert_file):
    """
    A convenience function to load a single PEM/DER-encoded certificate
    from a file.

    :param cert_file:
        A file name.
    :return:
        An :class:`.asn1crypto.x509.Certificate` object.
    """
    certs = list(load_certs_from_pemder([cert_file]))
    if len(certs) != 1:
        raise ValueError(
            f"Number of certs in {cert_file} should be exactly 1"
        )
    return certs[0]


def load_private_key_from_pemder(key_file, passphrase: Optional[bytes]) \
        -> keys.PrivateKeyInfo:
    """
    A convenience function to load PEM/DER-encoded keys from files.

    :param key_file:
        File to read the key from.
    :param passphrase:
        Key passphrase.
    :return:
        A private key encoded as an unencrypted PKCS#8 PrivateKeyInfo object.
    """
    with open(key_file, 'rb') as f:
        key_bytes = f.read()
    load_fun = (
        serialization.load_pem_private_key if pem.detect(key_bytes)
        else serialization.load_der_private_key
    )
    return _translate_pyca_cryptography_key_to_asn1(
        load_fun(key_bytes, password=passphrase)
    )


def _translate_pyca_cryptography_key_to_asn1(private_key) \
        -> keys.PrivateKeyInfo:
    # Store the cert and key as generic ASN.1 structures for more
    # "standardised" introspection. This comes at the cost of some encoding/
    # decoding operations, but those should be fairly insignificant in the
    # grand scheme of things.
    #
    # Note: we're not losing any memory protections here:
    #  (https://cryptography.io/en/latest/limitations.html)
    # Arguably, memory safety is nigh impossible to obtain in a Python
    # context anyhow, and people with that kind of Serious (TM) security
    # requirements should be using HSMs to manage keys.
    return keys.PrivateKeyInfo.load(
        private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )


def _translate_pyca_cryptography_cert_to_asn1(cert) -> x509.Certificate:
    return x509.Certificate.load(
        cert.public_bytes(serialization.Encoding.DER)
    )


def _validate_raw(signature: bytes, signed_data: bytes, cert: x509.Certificate,
                  signature_algorithm: cms.SignedDigestAlgorithm,
                  md_algorithm: str, prehashed=False):
    try:
        md_algorithm = signature_algorithm.hash_algo.upper()
    except (ValueError, AttributeError):
        pass

    verify_md = _get_pyca_cryptography_hash(md_algorithm, prehashed=prehashed)

    pub_key = serialization.load_der_public_key(
        cert.public_key.dump()
    )

    sig_algo = signature_algorithm.signature_algo
    if sig_algo == 'rsassa_pkcs1v15':
        assert isinstance(pub_key, RSAPublicKey)
        pub_key.verify(signature, signed_data, padding.PKCS1v15(), verify_md)
    elif sig_algo == 'rsassa_pss':
        assert isinstance(pub_key, RSAPublicKey)
        pss_padding, hash_algo = _process_pss_params(
            signature_algorithm['parameters'], md_algorithm,
            prehashed=prehashed
        )
        pub_key.verify(signature, signed_data, pss_padding, hash_algo)
    elif sig_algo == 'ecdsa':
        assert isinstance(pub_key, EllipticCurvePublicKey)
        pub_key.verify(signature, signed_data, ECDSA(verify_md))
    else:  # pragma: nocover
        raise SignatureValidationError(
            f"Signature mechanism {sig_algo} is not supported."
        )


def validate_sig_integrity(signer_info: cms.SignedData,
                           cert: x509.Certificate,
                           expected_content_type: str,
                           actual_digest: bytes) -> Tuple[bool, bool]:
    """
    Validate the integrity of a signature for a particular signerInfo object
    inside a CMS signed data container.

    .. warning::
        This function does not do any trust checks, and is considered
        "dangerous" API because it is easy to misuse.

    :param signer_info:
        A :class:`cms.SignerInfo` object.
    :param cert:
        The signer's certificate.

        .. note::
            This function will not attempt to extract certificates from
            the signed data.
    :param expected_content_type:
        The expected value for the content type attribute (as a Python string,
        see :class:`cms.ContentType`).
    :param actual_digest:
        The actual digest to be matched to the message digest attribute.
    :return:
        A tuple of two booleans. The first indicates whether the provided
        digest matches the value in the signed attributes.
        The second indicates whether the signature of the digest is valid.
    """

    signature_algorithm: cms.SignedDigestAlgorithm = \
        signer_info['signature_algorithm']
    digest_algorithm_obj = signer_info['digest_algorithm']
    md_algorithm = digest_algorithm_obj['algorithm'].native
    signature = signer_info['signature'].native

    # signed_attrs comes with some context-specific tagging.
    # We need to re-tag it with a universal SET OF tag.
    signed_attrs = signer_info['signed_attrs'].untag()

    if not signed_attrs:
        embedded_digest = None
        prehashed = True
        signed_data = actual_digest
    else:
        prehashed = False
        # check the CMSAlgorithmProtection attr, if present
        try:
            cms_algid_protection, = find_cms_attribute(
                signed_attrs, 'cms_algorithm_protection'
            )
            signed_digest_algorithm = \
                cms_algid_protection['digest_algorithm'].native
            if signed_digest_algorithm != digest_algorithm_obj.native:
                raise SignatureValidationError(
                    "Digest algorithm does not match CMS algorithm protection "
                    "attribute."
                )
            signed_sig_algorithm = \
                cms_algid_protection['signature_algorithm'].native
            if signed_sig_algorithm is None:
                raise SignatureValidationError(
                    "CMS algorithm protection attribute not valid for signed "
                    "data"
                )
            elif signed_sig_algorithm != signature_algorithm.native:
                raise SignatureValidationError(
                    "Signature mechanism does not match CMS algorithm "
                    "protection attribute."
                )
        except KeyError:
            pass
        except SignatureValidationError:
            raise
        except ValueError:
            raise SignatureValidationError(
                'Multiple CMS protection attributes present'
            )

        try:
            content_type, = find_cms_attribute(signed_attrs, 'content_type')
            content_type = content_type.native
            if content_type != expected_content_type:
                raise SignatureValidationError(
                    f'Content type {content_type} did not match expected value '
                    f'{expected_content_type}'
                )
        except SignatureValidationError:
            raise
        except (KeyError, ValueError):
            raise SignatureValidationError(
                'Content type not found in signature, or multiple content-type '
                'attributes present.'
            )

        try:
            embedded_digest, = find_cms_attribute(
                signed_attrs, 'message_digest'
            )
            embedded_digest = embedded_digest.native
        except (KeyError, ValueError):
            raise SignatureValidationError(
                'Message digest not found in signature, or multiple message '
                'digest attributes present.'
            )

        signed_data = signed_attrs.dump()
    try:
        _validate_raw(
            signature, signed_data, cert, signature_algorithm, md_algorithm,
            prehashed=prehashed
        )
        valid = True
    except InvalidSignature:
        valid = False

    intact = (
        actual_digest == embedded_digest
        if embedded_digest is not None else valid
    )

    return intact, valid
