"""
General tools related to Cryptographic Message Syntax (CMS) signatures,
not necessarily to the extent implemented in the PDF specification.

CMS is defined in :rfc:`5652`. To parse CMS messages, pyHanko relies heavily on
`asn1crypto <https://github.com/wbond/asn1crypto>`_.
"""

import logging
from dataclasses import dataclass
from typing import ClassVar, Set, Optional, Tuple, Iterable

import hashlib

from asn1crypto import x509, cms, tsp, algos, pem, keys

# noinspection PyProtectedMember
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, ECDSA
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from pyhanko.pdf_utils.config_utils import ConfigurableMixin, \
    process_bit_string_flags, process_oids
from pyhanko_certvalidator.path import ValidationPath

from pyhanko_certvalidator import (
    CertificateValidator, InvalidCertificateError, PathBuildingError,
)
from pyhanko_certvalidator.errors import RevokedError, PathValidationError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


__all__ = [
    'SignatureStatus', 'simple_cms_attribute', 'find_cms_attribute',
    'CertificateStore', 'SimpleCertificateStore',
    'KeyUsageConstraints',
    'SigningError', 'UnacceptableSignerError', 'WeakHashAlgorithmError',
    'SignatureValidationError',
    'load_certs_from_pemder', 'load_cert_from_pemder',
    'load_private_key_from_pemder', 'get_pyca_cryptography_hash',
    'DEFAULT_WEAK_HASH_ALGORITHMS'
]

logger = logging.getLogger(__name__)


DEFAULT_WEAK_HASH_ALGORITHMS = frozenset({'sha1', 'md5', 'md2'})


class SignatureValidationError(ValueError):
    """Error validating a signature."""
    pass


class WeakHashAlgorithmError(SignatureValidationError):
    pass


def _match_usages(required: set, present: set, need_all: bool):

    if need_all:
        return not (required - present)
    else:
        # intersection must be non-empty
        return bool(required & present)


@dataclass(frozen=True)
class KeyUsageConstraints(ConfigurableMixin):
    """
    Convenience class to pass around key usage requirements and validate them.
    Intended to be flexible enough to handle both PKIX and ISO 32000 certificate
    seed value constraint semantics.

    .. versionchanged:: 0.6.0
        Bring extended key usage semantics in line with :rfc:`5280` (PKIX).
    """

    key_usage: Set[str] = None
    """
    All or some (depending on :attr:`match_all_key_usage`) of these key usage
    extensions must be present in the signer's certificate.
    If not set or empty, all key usages are considered acceptable.
    """

    key_usage_forbidden: Set[str] = None
    """
    These key usage extensions must not be present in the signer's certificate.
    
    .. note:: 
        This behaviour is undefined in :rfc:`5280` (PKIX), but included for
        compatibility with certificate seed value settings in ISO 32000.
    """

    extd_key_usage: Set[str] = None
    """
    List of acceptable key purposes that can appear in an extended key 
    usage extension in the signer's certificate, if such an extension is at all
    present. If not set, all extended key usages are considered acceptable.
    
    If no extended key usage extension is present, or the
    ``anyExtendedKeyUsage`` key purpose ID is present the resulting behaviour
    depends on :attr:`explicit_extd_key_usage_required`.
    
    Setting this option to the empty set (as opposed to ``None``) effectively
    bans all (presumably unrecognised) extended key usages.
    
    .. warning::
        Note the difference in behaviour with :attr:`key_usage` for empty
        sets of valid usages.
    
    .. warning::
        Contrary to what some CAs seem to believe, the criticality of the     
        extended key usage extension is irrelevant here.
        Even a non-critical EKU extension **must** be enforced according to
        :rfc:`5280` § 4.2.1.12.
        
        In practice, many certificate authorities issue non-repudiation certs
        that can also be used for TLS authentication by only including the
        TLS client authentication key purpose ID in the EKU extension.
        Interpreted strictly, :rfc:`5280` bans such certificates from being
        used to sign documents, and pyHanko will enforce these semantics
        if :attr:`extd_key_usage` is not ``None``.
    """

    explicit_extd_key_usage_required: bool = True
    """
    .. versionadded:: 0.6.0
    
    Require an extended key usage extension with the right key usages to be
    present if :attr:`extd_key_usage` is non-empty.
    
    If this flag is ``True``, at least one key purpose in :attr:`extd_key_usage`
    must appear in the certificate's extended key usage, and
    ``anyExtendedKeyUsage`` will be ignored.
    """

    match_all_key_usages: bool = False
    """
    .. versionadded:: 0.6.0
    
    If ``True``, all key usages indicated in :attr:`key_usage` must be present
    in the certificate. If ``False``, one match suffices.
    
    If :attr:`key_usage` is empty or ``None``, this option has no effect.
    """

    def validate(self, cert: x509.Certificate):
        self._validate_key_usage(cert.key_usage_value)
        self._validate_extd_key_usage(cert.extended_key_usage_value)

    def _validate_key_usage(self, key_usage_extension_value):
        if not self.key_usage:
            return
        key_usage = self.key_usage or set()
        key_usage_forbidden = self.key_usage_forbidden or set()

        # First, check the "regular" key usage extension
        cert_ku = (
            set(key_usage_extension_value.native)
            if key_usage_extension_value is not None else set()
        )

        # check blacklisted key usages (ISO 32k)
        forbidden_ku = cert_ku & key_usage_forbidden
        if forbidden_ku:
            rephrased = map(lambda s: s.replace('_', ' '), forbidden_ku)
            raise InvalidCertificateError(
                "The active key usage policy explicitly bans certificates "
                f"used for {', '.join(rephrased)}."
            )

        # check required key usage extension values
        need_all_ku = self.match_all_key_usages
        if not _match_usages(key_usage, cert_ku, need_all_ku):
            rephrased = map(lambda s: s.replace('_', ' '), key_usage)
            raise InvalidCertificateError(
                "The active key usage policy requires "
                f"{'' if need_all_ku else 'at least one of '}the key "
                f"usage extensions {', '.join(rephrased)} to be present."
            )

    def _validate_extd_key_usage(self, eku_extension_value):
        if self.extd_key_usage is None:
            return
        # check extended key usage
        has_extd_key_usage_ext = eku_extension_value is not None
        cert_eku = (
            set(eku_extension_value.native)
            if has_extd_key_usage_ext else set()
        )

        if 'any_extended_key_usage' in cert_eku and \
                not self.explicit_extd_key_usage_required:
            return  # early out, cert is valid for all EKUs

        extd_key_usage = self.extd_key_usage or set()
        if not has_extd_key_usage_ext:
            if self.explicit_extd_key_usage_required:
                raise InvalidCertificateError(
                    "The active key usage policy requires an extended "
                    "key usage extension."
                )
            return  # early out, cert is (presumably?) valid for all EKUs

        if not _match_usages(extd_key_usage, cert_eku, need_all=False):
            if extd_key_usage:
                rephrased = map(lambda s: s.replace('_', ' '), extd_key_usage)
                ok_list = f"Relevant key purposes are {', '.join(rephrased)}."
            else:
                ok_list = "There are no acceptable extended key usages."
            raise InvalidCertificateError(
                "The extended key usages for which this certificate is valid "
                f"do not match the active key usage policy. {ok_list}"
            )

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)

        # Deal with KeyUsage values first
        # might as well expose key_usage_forbidden while we're at it
        for key_usage_sett in ('key_usage', 'key_usage_forbidden'):
            affected_flags = config_dict.get(key_usage_sett, None)
            if affected_flags is not None:
                config_dict[key_usage_sett] = set(
                    process_bit_string_flags(
                        x509.KeyUsage, affected_flags,
                        key_usage_sett.replace('_', '-')
                    )
                )

        extd_key_usage = config_dict.get('extd_key_usage', None)
        if extd_key_usage is not None:
            config_dict['extd_key_usage'] = set(
                process_oids(
                    x509.KeyPurposeId, extd_key_usage, 'extd-key-usage'
                )
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

    extd_key_usage: ClassVar[Optional[Set[str]]] = None
    """
    Class property indicating which extended key usage extensions are required 
    to be present on the signer's certificate.
    
    See :attr:`.KeyUsageConstraints.extd_key_usage`.
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
            # validate usage without going through pyhanko_certvalidator
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
    Unopinionated replacement for pyhanko_certvalidator's CertificateRegistry in cases
    where we explicitly don't care about whether the certs are trusted or not.
    """

    @classmethod
    def from_certs(cls, certs: Iterable[x509.Certificate]):
        s = SimpleCertificateStore()
        s.certs = {cert.issuer_serial: cert for cert in certs}
        return s

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


def get_pyca_cryptography_hash(algorithm, prehashed=False):
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

    mgf_md = get_pyca_cryptography_hash(mgf_md_name, prehashed=False)
    md = get_pyca_cryptography_hash(md_name, prehashed=prehashed)
    pss_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=mgf_md),
        salt_length=salt_len
    )
    return pss_padding, md


def optimal_pss_params(cert: x509.Certificate, digest_algorithm: str):

    digest_algorithm = digest_algorithm.lower()

    key: RSAPublicKey = serialization.load_der_public_key(
        cert.public_key.dump()
    )
    md = get_pyca_cryptography_hash(digest_algorithm)
    # the PSS salt calculation function is not in the .pyi file, apparently.
    # noinspection PyUnresolvedReferences
    optimal_salt_len = padding.calculate_max_pss_salt_length(key, md)
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
                  md_algorithm: str, prehashed=False,
                  weak_hash_algorithms=DEFAULT_WEAK_HASH_ALGORITHMS):
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


def validate_sig_integrity(signer_info: cms.SignerInfo,
                           cert: x509.Certificate,
                           expected_content_type: str,
                           actual_digest: bytes,
                           weak_hash_algorithms=DEFAULT_WEAK_HASH_ALGORITHMS) \
        -> Tuple[bool, bool]:
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
    :param weak_hash_algorithms:
        List, tuple or set of weak hashing algorithms.
    :return:
        A tuple of two booleans. The first indicates whether the provided
        digest matches the value in the signed attributes.
        The second indicates whether the signature of the digest is valid.
    """

    signature_algorithm: cms.SignedDigestAlgorithm = \
        signer_info['signature_algorithm']
    digest_algorithm_obj = signer_info['digest_algorithm']
    md_algorithm = digest_algorithm_obj['algorithm'].native
    if md_algorithm in weak_hash_algorithms:
        raise WeakHashAlgorithmError(md_algorithm)
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
            prehashed=prehashed, weak_hash_algorithms=weak_hash_algorithms
        )
        valid = True
    except InvalidSignature:
        valid = False

    intact = (
        actual_digest == embedded_digest
        if embedded_digest is not None else valid
    )

    return intact, valid
