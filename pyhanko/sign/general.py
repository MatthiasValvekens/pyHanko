"""
General tools related to Cryptographic Message Syntax (CMS) signatures,
not necessarily to the extent implemented in the PDF specification.

CMS is defined in :rfc:`5652`. To parse CMS messages, pyHanko relies heavily on
`asn1crypto <https://github.com/wbond/asn1crypto>`_.
"""

import logging
from dataclasses import dataclass
from typing import ClassVar, Set


import hashlib

from asn1crypto import x509, cms, tsp, algos, keys
# noinspection PyProtectedMember
from certvalidator.path import ValidationPath

from certvalidator import (
    CertificateValidator, InvalidCertificateError,
    PathBuildingError,
)
from certvalidator.errors import RevokedError, PathValidationError

__all__ = [
    'SignatureStatus', 'simple_cms_attribute', 'find_cms_attribute',
    'CertificateStore', 'SimpleCertificateStore', 'SigningError',
    'UnacceptableSignerError'
]

from oscrypto.errors import SignatureError

logger = logging.getLogger(__name__)


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
            logger.warning(
                f"Chain of trust validation for {subj} failed."
            )
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


def _process_pss_params(params: algos.RSASSAPSSParams, digest_algorithm):
    # oscrypto doesn't support PSS with arbitrary parameters,
    # so we rely on pyca/cryptography for this bit

    hash_algo: algos.DigestAlgorithm = params['hash_algorithm']
    md_name = hash_algo['algorithm'].native
    if md_name != digest_algorithm:
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

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:  # pragma: nocover
        raise SigningError("pyca/cryptography is required for generic PSS")

    mgf_md = getattr(hashes, mgf_md_name.upper())
    md = getattr(hashes, md_name.upper())
    pss_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=mgf_md()),
        salt_length=salt_len
    )
    return pss_padding, md()


def _validate_pss_raw(signature: bytes, data: bytes, cert: x509.Certificate,
                      params: algos.RSASSAPSSParams, digest_algorithm: str):

    pss_padding, hash_algo = _process_pss_params(params, digest_algorithm)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.exceptions import InvalidSignature
    pub_key: RSAPublicKey = serialization.load_der_public_key(
        cert.public_key.dump()
    )

    try:
        pub_key.verify(signature, data, pss_padding, hash_algo)
    except InvalidSignature as e:
        # reraise using oscrypto-style exception
        raise SignatureError() from e


def _sign_pss_raw(data: bytes, signing_key: keys.PrivateKeyInfo,
                  params: algos.RSASSAPSSParams, digest_algorithm: str):

    pss_padding, hash_algo = _process_pss_params(params, digest_algorithm)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    priv_key: RSAPrivateKey = serialization.load_der_private_key(
        signing_key.dump(), password=None
    )

    return priv_key.sign(data=data, padding=pss_padding, algorithm=hash_algo)


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
