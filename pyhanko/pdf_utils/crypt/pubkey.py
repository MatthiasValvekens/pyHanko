import abc
import enum
import logging
import secrets
import struct
from hashlib import sha1, sha256
from typing import Dict, List, Optional, Set, Tuple, Union

from asn1crypto import algos, cms, core, x509
from asn1crypto.keys import PrivateKeyInfo, PublicKeyAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.serialization import pkcs12

from .. import generic, misc
from ._util import aes_cbc_decrypt, aes_cbc_encrypt, as_signed, rc4_encrypt
from .api import (
    ALL_PERMS,
    AuthResult,
    AuthStatus,
    CryptFilter,
    CryptFilterBuilder,
    CryptFilterConfiguration,
    IdentityCryptFilter,
    SecurityHandler,
    SecurityHandlerVersion,
    build_crypt_filter,
)
from .cred_ser import SerialisableCredential, SerialisedCredential
from .filter_mixins import AESCryptFilterMixin, RC4CryptFilterMixin

logger = logging.getLogger(__name__)


class PubKeyCryptFilter(CryptFilter, abc.ABC):
    """
    Crypt filter for use with public key security handler.
    These are a little more independent than their counterparts for
    the standard security handlers, since different crypt filters
    can cater to different sets of recipients.

    :param recipients:
        List of CMS objects encoding recipient information for this crypt
        filters.
    :param acts_as_default:
        Indicates whether this filter is intended to be used in
        ``/StrF`` or ``/StmF``.
    :param encrypt_metadata:
        Whether this crypt filter should encrypt document-level metadata.

        .. warning::
            See :class:`.SecurityHandler` for some background on the
            way pyHanko interprets this value.
    """

    _handler: Optional['PubKeySecurityHandler'] = None

    def __init__(
        self,
        *,
        recipients=None,
        acts_as_default=False,
        encrypt_metadata=True,
        **kwargs,
    ):
        self.recipients = recipients
        self.acts_as_default = acts_as_default
        self.encrypt_metadata = encrypt_metadata
        self._pubkey_auth_failed = False
        self._shared_key = self._recp_key_seed = None
        super().__init__(**kwargs)

    @property
    def _auth_failed(self) -> bool:
        return self._pubkey_auth_failed

    def _set_security_handler(self, handler):
        if not isinstance(handler, PubKeySecurityHandler):
            raise TypeError  # pragma: nocover
        super()._set_security_handler(handler)
        self._shared_key = self._recp_key_seed = None

    def add_recipients(
        self,
        certs: List[x509.Certificate],
        perms=ALL_PERMS,
        ignore_key_usage=False,
    ):
        """
        Add recipients to this crypt filter.
        This always adds one full CMS object to the Recipients array

        :param certs:
            A list of recipient certificates.
        :param perms:
            The permission bits to assign to the listed recipients.
        :param ignore_key_usage:
            If ``False``, the *keyEncipherment* key usage extension is required.
        """

        if not self.acts_as_default and self.recipients:
            raise misc.PdfError(
                "A non-default crypt filter cannot have multiple sets of "
                "recipients."
            )
        if self.recipients is None:
            # assume that this is a freshly created pubkey crypt filter,
            # so set up the shared seed
            self._recp_key_seed = secrets.token_bytes(20)
            self.recipients = []

        if self._shared_key is not None or self._recp_key_seed is None:
            raise misc.PdfError(
                "Adding recipients after deriving the shared key or "
                "before authenticating is not possible."
            )
        new_cms = construct_recipient_cms(
            certs,
            self._recp_key_seed,
            as_signed(perms),
            include_permissions=self.acts_as_default,
            ignore_key_usage=ignore_key_usage,
        )
        self.recipients.append(new_cms)

    def authenticate(self, credential) -> AuthResult:
        """
        Authenticate to this crypt filter in particular.
        If used in ``/StmF`` or ``/StrF``, you don't need to worry about
        calling this method directly.

        :param credential:
            The :class:`.EnvelopeKeyDecrypter` to authenticate with.
        :return:
            An :class:`AuthResult` object indicating the level of access
            obtained.
        """
        for recp in self.recipients:
            seed, perms = read_seed_from_recipient_cms(recp, credential)
            if seed is not None:
                self._recp_key_seed = seed
                return AuthResult(AuthStatus.USER, perms)
        return AuthResult(AuthStatus.FAILED)

    def derive_shared_encryption_key(self) -> bytes:
        assert self._handler is not None
        if self._recp_key_seed is None:
            raise misc.PdfError("No seed available; authenticate first.")
        if self._handler.version >= SecurityHandlerVersion.AES256:
            md = sha256()
        else:
            md = sha1()
        md.update(self._recp_key_seed)
        for recp in self.recipients:
            md.update(recp.dump())
        if not self.encrypt_metadata and self.acts_as_default:
            md.update(b'\xff\xff\xff\xff')
        return md.digest()[: self.keylen]

    def as_pdf_object(self):
        result = super().as_pdf_object()
        result['/Length'] = generic.NumberObject(self.keylen * 8)
        recipients = generic.ArrayObject(
            generic.ByteStringObject(recp.dump()) for recp in self.recipients
        )
        if self.acts_as_default:
            result['/Recipients'] = recipients
        else:
            # non-default crypt filters can only have one recipient object
            result['/Recipients'] = recipients[0]
        result['/EncryptMetadata'] = generic.BooleanObject(
            self.encrypt_metadata
        )
        return result


class PubKeyAESCryptFilter(PubKeyCryptFilter, AESCryptFilterMixin):
    """
    AES crypt filter for public key security handlers.
    """

    pass


class PubKeyRC4CryptFilter(PubKeyCryptFilter, RC4CryptFilterMixin):
    """
    RC4 crypt filter for public key security handlers.
    """

    pass


"""
Default name to use for the default crypt filter in the standard security
handler.
"""

DEFAULT_CRYPT_FILTER = generic.NameObject('/DefaultCryptFilter')
"""
Default name to use for the default crypt filter in public key security
handlers.
"""

DEF_EMBEDDED_FILE = generic.NameObject('/DefEmbeddedFile')
"""
Default name to use for the EFF crypt filter in public key security
handlers for documents where only embedded files are encrypted.
"""

"""
Name of the identity crypt filter.
"""


def _pubkey_rc4_config(keylen, recipients=None, encrypt_metadata=True):
    return CryptFilterConfiguration(
        {
            DEFAULT_CRYPT_FILTER: PubKeyRC4CryptFilter(
                keylen=keylen,
                acts_as_default=True,
                recipients=recipients,
                encrypt_metadata=encrypt_metadata,
            )
        },
        default_stream_filter=DEFAULT_CRYPT_FILTER,
        default_string_filter=DEFAULT_CRYPT_FILTER,
    )


def _pubkey_aes_config(keylen, recipients=None, encrypt_metadata=True):
    return CryptFilterConfiguration(
        {
            DEFAULT_CRYPT_FILTER: PubKeyAESCryptFilter(
                keylen=keylen,
                acts_as_default=True,
                recipients=recipients,
                encrypt_metadata=encrypt_metadata,
            )
        },
        default_stream_filter=DEFAULT_CRYPT_FILTER,
        default_string_filter=DEFAULT_CRYPT_FILTER,
    )


"""
Type alias for a callable that produces a crypt filter from a dictionary.
"""


@enum.unique
class PubKeyAdbeSubFilter(enum.Enum):
    """
    Enum describing the different subfilters that can be used for public key
    encryption in the PDF specification.
    """

    S3 = generic.NameObject('/adbe.pkcs7.s3')
    S4 = generic.NameObject('/adbe.pkcs7.s4')
    S5 = generic.NameObject('/adbe.pkcs7.s5')


def construct_envelope_content(
    seed: bytes, perms: int, include_permissions=True
):
    assert len(seed) == 20
    return seed + (struct.pack('<i', perms) if include_permissions else b'')


def _recipient_info(
    envelope_key: bytes, cert: x509.Certificate, ignore_key_usage=False
):
    pubkey = cert.public_key
    pubkey_algo_info: PublicKeyAlgorithm = pubkey['algorithm']
    algorithm_name = pubkey_algo_info['algorithm'].native
    if algorithm_name != 'rsa':
        raise NotImplementedError(
            f"Certificate public key must be of type 'rsa', "
            f"not '{algorithm_name}'."
        )

    assert len(envelope_key) == 32

    if not ignore_key_usage:
        key_usage = cert.key_usage_value
        if key_usage is None or 'key_encipherment' not in key_usage.native:
            raise misc.PdfWriteError(
                f"Certificate for subject {cert.subject.human_friendly} does "
                f"not have the 'key_encipherment' key usage bit set."
            )

    pub_key = serialization.load_der_public_key(cert.public_key.dump())

    assert isinstance(pub_key, RSAPublicKey)
    # having support for OAEP here would be cool, but I have it on good
    #  authority that there's some kind of tacit understanding to use
    #  PKCS#1 v1.5 padding here.
    encrypted_data = pub_key.encrypt(envelope_key, padding=PKCS1v15())

    # TODO support subjectKeyIdentifier here (requiring version 2)
    rid = cms.RecipientIdentifier(
        {
            'issuer_and_serial_number': cms.IssuerAndSerialNumber(
                {'issuer': cert.issuer, 'serial_number': cert.serial_number}
            )
        }
    )
    algo = cms.KeyEncryptionAlgorithm(
        {'algorithm': cms.KeyEncryptionAlgorithmId('rsaes_pkcs1v15')}
    )
    return cms.RecipientInfo(
        {
            'ktri': cms.KeyTransRecipientInfo(
                {
                    'version': 0,
                    'rid': rid,
                    'key_encryption_algorithm': algo,
                    'encrypted_key': encrypted_data,
                }
            )
        }
    )


def construct_recipient_cms(
    certificates: List[x509.Certificate],
    seed: bytes,
    perms: int,
    include_permissions=True,
    ignore_key_usage=False,
) -> cms.ContentInfo:
    # The content of the generated ContentInfo object
    # is an object of type EnvelopedData, containing a 20 byte seed (+ perms).
    #
    # This seed is shared among all recipients (including those occurring in
    # other CMS objects, if relevant), and is the only secret part of the
    # key derivation procedure used to obtain the file encryption key.
    #
    # The envelope content is then encrypted using an envelope key,
    # which is in turn encrypted using the public key of each recipient and
    # stored in a RecipientInfo object (more precisely, a
    # KeyTransRecipientInfo object). PyHanko always uses AES-256 to encrypt
    # the envelope content, even if the chosen PDF encryption is weaker.
    #
    # The RecipientInfo objects, algorithm specification and envelope content
    # are then bundled into an EnvelopedData object.
    envelope_content = construct_envelope_content(
        seed, perms, include_permissions=include_permissions
    )
    # 256-bit key used to encrypt the envelope
    envelope_key = secrets.token_bytes(32)
    # encrypt the envelope content with the envelope key
    iv, encrypted_envelope_content = aes_cbc_encrypt(
        envelope_key, envelope_content, iv=None
    )

    # encrypt the envelope key for each recipient
    rec_infos = [
        _recipient_info(envelope_key, cert, ignore_key_usage=ignore_key_usage)
        for cert in certificates
    ]

    algo = cms.EncryptionAlgorithm(
        {
            'algorithm': algos.EncryptionAlgorithmId('aes256_cbc'),
            'parameters': iv,
        }
    )
    encrypted_content_info = cms.EncryptedContentInfo(
        {
            'content_type': cms.ContentType('data'),
            'content_encryption_algorithm': algo,
            'encrypted_content': encrypted_envelope_content,
        }
    )

    # version 0 because no originatorInfo, no attribute certs
    # and all recipientinfo structures have version 0 (and aren't' pwri)
    enveloped_data = cms.EnvelopedData(
        {
            'version': 0,
            'recipient_infos': rec_infos,
            'encrypted_content_info': encrypted_content_info,
        }
    )

    # finally, package up the whole thing into a ContentInfo object
    return cms.ContentInfo(
        {
            'content_type': cms.ContentType('enveloped_data'),
            'content': enveloped_data,
        }
    )


# TODO implement a PKCS#11 version of this interface
class EnvelopeKeyDecrypter:
    """
    General credential class for use with public key security handlers.

    This allows the key decryption process to happen offline, e.g. on a smart
    card.

    :param cert:
        The recipient's certificate.
    """

    def __init__(self, cert: x509.Certificate):
        self.cert = cert

    def decrypt(
        self, encrypted_key: bytes, algo_params: cms.KeyEncryptionAlgorithm
    ) -> bytes:
        """
        Invoke the actual key decryption algorithm.

        :param encrypted_key:
            Payload to decrypt.
        :param algo_params:
            Specification of the encryption algorithm as a CMS object.
        :return:
            The decrypted payload.
        """
        raise NotImplementedError


class _PrivKeyAndCert(core.Sequence):
    _fields = [('key', PrivateKeyInfo), ('cert', x509.Certificate)]


class SimpleEnvelopeKeyDecrypter(EnvelopeKeyDecrypter, SerialisableCredential):
    """
    Implementation of :class:`.EnvelopeKeyDecrypter` where the private key
    is an RSA key residing in memory.

    :param cert:
        The recipient's certificate.
    :param private_key:
        The recipient's private key.
    """

    @classmethod
    def get_name(cls) -> str:
        return 'raw_privkey'

    def _ser_value(self) -> bytes:
        values = {'key': self.private_key, 'cert': self.cert}
        return _PrivKeyAndCert(values).dump()

    @classmethod
    def _deser_value(cls, data: bytes):
        try:
            decoded = _PrivKeyAndCert.load(data)
            key = decoded['key']
            cert = decoded['cert']
        except ValueError as e:
            raise misc.PdfReadError(
                "Failed to decode serialised pubkey credential"
            ) from e
        return SimpleEnvelopeKeyDecrypter(cert=cert, private_key=key)

    def __init__(self, cert: x509.Certificate, private_key: PrivateKeyInfo):
        super().__init__(cert)
        self.private_key: PrivateKeyInfo = private_key

    @staticmethod
    def load(key_file, cert_file, key_passphrase=None):
        """
        Load a key decrypter using key material from files on disk.

        :param key_file:
            File containing the recipient's private key.
        :param cert_file:
            File containing the recipient's certificate.
        :param key_passphrase:
            Passphrase for the key file, if applicable.
        :return:
            An instance of :class:`.SimpleEnvelopeKeyDecrypter`.
        """
        from ...keys import load_private_key_from_pemder

        try:
            private_key = load_private_key_from_pemder(
                key_file, passphrase=key_passphrase
            )
            from ...keys import load_cert_from_pemder

            cert = load_cert_from_pemder(cert_file)
        except (IOError, ValueError, TypeError) as e:  # pragma: nocover
            logger.error('Could not load cryptographic material', exc_info=e)
            return None
        return SimpleEnvelopeKeyDecrypter(cert=cert, private_key=private_key)

    @classmethod
    def load_pkcs12(cls, pfx_file, passphrase=None):
        """
        Load a key decrypter using key material from a PKCS#12 file on disk.

        :param pfx_file:
            Path to the PKCS#12 file containing the key material.
        :param passphrase:
            Passphrase for the private key, if applicable.
        :return:
            An instance of :class:`.SimpleEnvelopeKeyDecrypter`.
        """

        try:
            with open(pfx_file, 'rb') as f:
                pfx_bytes = f.read()
            (private_key, cert, other_certs) = pkcs12.load_key_and_certificates(
                pfx_bytes, passphrase
            )

            from ...keys import (
                _translate_pyca_cryptography_cert_to_asn1,
                _translate_pyca_cryptography_key_to_asn1,
            )

            cert = _translate_pyca_cryptography_cert_to_asn1(cert)
            private_key = _translate_pyca_cryptography_key_to_asn1(private_key)
        except (IOError, ValueError, TypeError) as e:  # pragma: nocover
            logger.error(f'Could not open PKCS#12 file {pfx_file}.', exc_info=e)
            return None

        return SimpleEnvelopeKeyDecrypter(cert=cert, private_key=private_key)

    def decrypt(
        self, encrypted_key: bytes, algo_params: cms.KeyEncryptionAlgorithm
    ) -> bytes:
        """
        Decrypt the payload using RSA with PKCS#1 v1.5 padding.
        Other schemes are not (currently) supported by this implementation.

        :param encrypted_key:
            Payload to decrypt.
        :param algo_params:
            Specification of the encryption algorithm as a CMS object.
            Must use ``rsaes_pkcs1v15``.
        :return:
            The decrypted payload.
        """
        algo_name = algo_params['algorithm'].native
        if algo_name != 'rsaes_pkcs1v15':
            raise NotImplementedError(
                f"Only 'rsaes_pkcs1v15' is supported for envelope encryption, "
                f"not '{algo_name}'."
            )
        priv_key = serialization.load_der_private_key(
            self.private_key.dump(), password=None
        )
        if not isinstance(priv_key, RSAPrivateKey):
            raise NotImplementedError(
                "The loaded key does not seem to be an RSA private key"
            )
        return priv_key.decrypt(encrypted_key, padding=PKCS1v15())


SerialisableCredential.register(SimpleEnvelopeKeyDecrypter)


def read_seed_from_recipient_cms(
    recipient_cms: cms.ContentInfo, decrypter: EnvelopeKeyDecrypter
) -> Tuple[Optional[bytes], Optional[int]]:
    content_type = recipient_cms['content_type'].native
    if content_type != 'enveloped_data':
        raise misc.PdfReadError(
            "Recipient CMS content type must be enveloped data, not "
            + content_type
        )
    ed: cms.EnvelopedData = recipient_cms['content']
    encrypted_content_info = ed['encrypted_content_info']
    rec_info: cms.RecipientInfo
    for rec_info in ed['recipient_infos']:
        ktri = rec_info.chosen
        if not isinstance(ktri, cms.KeyTransRecipientInfo):
            raise NotImplementedError(
                "RecipientInfo must be of type KeyTransRecipientInfo."
            )
        issuer_and_serial = ktri['rid'].chosen
        if not isinstance(issuer_and_serial, cms.IssuerAndSerialNumber):
            raise NotImplementedError(
                "Recipient identifier must be of type IssuerAndSerialNumber."
            )
        issuer = issuer_and_serial['issuer']
        serial = issuer_and_serial['serial_number'].native
        if (
            decrypter.cert.issuer == issuer
            and decrypter.cert.serial_number == serial
        ):
            # we have a match!
            # use the decrypter passed in to decrypt the envelope key
            # for this recipient.
            try:
                envelope_key = decrypter.decrypt(
                    ktri['encrypted_key'].native,
                    ktri['key_encryption_algorithm'],
                )
            except Exception as e:
                raise misc.PdfReadError("Failed to decrypt envelope key") from e
            break
    else:
        return None, None

    # we have the envelope key
    # next up: decrypting the envelope

    algo: cms.EncryptionAlgorithm = encrypted_content_info[
        'content_encryption_algorithm'
    ]
    encrypted_envelope_content = encrypted_content_info[
        'encrypted_content'
    ].native

    # the spec says that we have to support rc4 (<=256 bits),
    # des, triple des, rc2 (<=128 bits)
    # and AES-CBC (128, 192, 256 bits)
    try:
        cipher_name = algo.encryption_cipher
    except (ValueError, KeyError):
        cipher_name = algo['algorithm'].native

    with_iv = {'aes': aes_cbc_decrypt}
    try:
        # noinspection PyUnresolvedReferences
        from oscrypto import symmetric

        # The spec mandates that we support these, but pyca/cryptography
        # doesn't offer implementations.
        # (DES and 3DES have fortunately gone out of style, but some libraries
        #  still rely on RC2)
        with_iv.update(
            {
                'des': symmetric.des_cbc_pkcs5_decrypt,
                'tripledes': symmetric.tripledes_cbc_pkcs5_decrypt,
                'rc2': symmetric.rc2_cbc_pkcs5_decrypt,
            }
        )
    except ImportError:  # pragma: nocover
        if cipher_name in ('des', 'tripledes', 'rc2'):
            raise NotImplementedError(
                "DES, 3DES and RC2 require oscrypto to be present"
            )

    if cipher_name in with_iv:
        decryption_fun = with_iv[cipher_name]
        iv = algo.encryption_iv
        content = decryption_fun(envelope_key, encrypted_envelope_content, iv)
    elif cipher_name == 'rc4':
        content = rc4_encrypt(envelope_key, encrypted_envelope_content)
    else:
        raise misc.PdfReadError(
            f"Cipher {cipher_name} is not allowed in PDF 2.0."
        )

    seed = content[:20]
    perms: Optional[int] = None
    if len(content) == 24:
        # permissions are included
        perms = struct.unpack('<i', content[20:])[0]
    return seed, perms


def _read_generic_pubkey_cf_info(cfdict: generic.DictionaryObject):
    try:
        recipients = cfdict['/Recipients']
    except KeyError:
        raise misc.PdfReadError(
            "PubKey CF dictionary must have /Recipients key"
        )
    if isinstance(recipients, generic.ByteStringObject):
        recipients = (recipients,)
    recipient_objs = [
        cms.ContentInfo.load(x.original_bytes) for x in recipients
    ]
    encrypt_metadata = cfdict.get('/EncryptMetadata', True)
    return {'recipients': recipient_objs, 'encrypt_metadata': encrypt_metadata}


def _build_legacy_pubkey_cf(cfdict, acts_as_default):
    keylen_bits = cfdict.get('/Length', 40)
    return PubKeyRC4CryptFilter(
        keylen=keylen_bits // 8,
        acts_as_default=acts_as_default,
        **_read_generic_pubkey_cf_info(cfdict),
    )


def _build_aes128_pubkey_cf(cfdict, acts_as_default):
    return PubKeyAESCryptFilter(
        keylen=16,
        acts_as_default=acts_as_default,
        **_read_generic_pubkey_cf_info(cfdict),
    )


def _build_aes256_pubkey_cf(cfdict, acts_as_default):
    return PubKeyAESCryptFilter(
        keylen=32,
        acts_as_default=acts_as_default,
        **_read_generic_pubkey_cf_info(cfdict),
    )


@SecurityHandler.register
class PubKeySecurityHandler(SecurityHandler):
    """
    Security handler for public key encryption in PDF.

    As with the standard security handler, you essentially shouldn't ever
    have to instantiate these yourself (see :meth:`build_from_certs`).
    """

    _known_crypt_filters: Dict[generic.NameObject, CryptFilterBuilder] = {
        generic.NameObject('/V2'): _build_legacy_pubkey_cf,
        generic.NameObject('/AESV2'): _build_aes128_pubkey_cf,
        generic.NameObject('/AESV3'): _build_aes256_pubkey_cf,
        generic.NameObject('/Identity'): lambda _, __: IdentityCryptFilter(),
    }

    @classmethod
    def build_from_certs(
        cls,
        certs: List[x509.Certificate],
        keylen_bytes=16,
        version=SecurityHandlerVersion.AES256,
        use_aes=True,
        use_crypt_filters=True,
        perms: int = ALL_PERMS,
        encrypt_metadata=True,
        ignore_key_usage=False,
        **kwargs,
    ) -> 'PubKeySecurityHandler':
        """
        Create a new public key security handler.

        This method takes many parameters, but only ``certs`` is mandatory.
        The default behaviour is to create a public key encryption handler
        where the underlying symmetric encryption is provided by AES-256.
        Any remaining keyword arguments will be passed to the constructor.

        :param certs:
            The recipients' certificates.
        :param keylen_bytes:
            The key length (in bytes). This is only relevant for legacy
            security handlers.
        :param version:
            The security handler version to use.
        :param use_aes:
            Use AES-128 instead of RC4 (only meaningful if the ``version``
            parameter is :attr:`~.SecurityHandlerVersion.RC4_OR_AES128`).
        :param use_crypt_filters:
            Whether to use crypt filters. This is mandatory for security
            handlers of version :attr:`~.SecurityHandlerVersion.RC4_OR_AES128`
            or higher.
        :param perms:
            Permission flags (as a 4-byte signed integer).
        :param encrypt_metadata:
            Whether to encrypt document metadata.

            .. warning::
                See :class:`.SecurityHandler` for some background on the
                way pyHanko interprets this value.
        :param ignore_key_usage:
            If ``False``, the *keyEncipherment* key usage extension is required.
        :return:
            An instance of :class:`.PubKeySecurityHandler`.
        """
        subfilter = (
            PubKeyAdbeSubFilter.S5
            if use_crypt_filters
            else PubKeyAdbeSubFilter.S4
        )
        cfc = None
        if version == SecurityHandlerVersion.RC4_OR_AES128:
            # only in this case we need a CFC, otherwise the constructor
            # takes care of it
            if use_aes:
                cfc = _pubkey_aes_config(
                    16, encrypt_metadata=encrypt_metadata, recipients=None
                )
            else:
                cfc = _pubkey_rc4_config(
                    keylen_bytes,
                    recipients=None,
                    encrypt_metadata=encrypt_metadata,
                )
        # noinspection PyArgumentList
        sh = cls(
            version,
            subfilter,
            keylen_bytes,
            encrypt_metadata=encrypt_metadata,
            crypt_filter_config=cfc,
            recipient_objs=None,
            **kwargs,
        )
        sh.add_recipients(certs, perms=perms, ignore_key_usage=ignore_key_usage)
        return sh

    def __init__(
        self,
        version: SecurityHandlerVersion,
        pubkey_handler_subfilter: PubKeyAdbeSubFilter,
        legacy_keylen,
        encrypt_metadata=True,
        crypt_filter_config: Optional['CryptFilterConfiguration'] = None,
        recipient_objs: Optional[list] = None,
        compat_entries=True,
    ):
        # I don't see how it would be possible to handle V4 without
        # crypt filters in an unambiguous way. V5 should be possible in
        # principle, but Adobe Reader rejects that combination, so meh.
        if (
            version >= SecurityHandlerVersion.RC4_OR_AES128
            and pubkey_handler_subfilter != PubKeyAdbeSubFilter.S5
        ):
            raise misc.PdfError(
                "Subfilter /adbe.pkcs7.s5 is required for security handlers "
                "beyond V4."
            )

        if crypt_filter_config is None:
            if version == SecurityHandlerVersion.RC4_40:
                crypt_filter_config = _pubkey_rc4_config(
                    keylen=5,
                    encrypt_metadata=encrypt_metadata,
                    recipients=recipient_objs,
                )
            elif version == SecurityHandlerVersion.RC4_LONGER_KEYS:
                crypt_filter_config = _pubkey_rc4_config(
                    keylen=legacy_keylen,
                    encrypt_metadata=encrypt_metadata,
                    recipients=recipient_objs,
                )
            elif version >= SecurityHandlerVersion.AES256:
                # there's a reasonable default config that we can fall back to
                # here
                crypt_filter_config = _pubkey_aes_config(
                    keylen=32,
                    encrypt_metadata=encrypt_metadata,
                    recipients=recipient_objs,
                )
            else:
                raise misc.PdfError(
                    "Failed to impute a reasonable crypt filter config"
                )
        super().__init__(
            version,
            legacy_keylen,
            crypt_filter_config,
            encrypt_metadata=encrypt_metadata,
            compat_entries=compat_entries,
        )
        self.subfilter = pubkey_handler_subfilter
        self.encrypt_metadata = encrypt_metadata
        self._shared_key = None

    @classmethod
    def get_name(cls) -> str:
        return generic.NameObject('/Adobe.PubSec')

    @classmethod
    def support_generic_subfilters(cls) -> Set[str]:
        return {x.value for x in PubKeyAdbeSubFilter}

    @classmethod
    def read_cf_dictionary(
        cls, cfdict: generic.DictionaryObject, acts_as_default: bool
    ) -> CryptFilter:
        cf = build_crypt_filter(
            cls._known_crypt_filters, cfdict, acts_as_default
        )
        if cf is None:
            raise misc.PdfReadError(
                "An absent CFM or CFM of /None doesn't make sense in a "
                "PubSec CF dictionary"
            )
        return cf

    @classmethod
    def process_crypt_filters(
        cls, encrypt_dict: generic.DictionaryObject
    ) -> Optional['CryptFilterConfiguration']:
        cfc = super().process_crypt_filters(encrypt_dict)
        subfilter = cls._determine_subfilter(encrypt_dict)

        if cfc is not None and subfilter != PubKeyAdbeSubFilter.S5:
            raise misc.PdfReadError(
                "Crypt filters require /adbe.pkcs7.s5 as the declared "
                "handler."
            )
        elif cfc is None and subfilter == PubKeyAdbeSubFilter.S5:
            raise misc.PdfReadError(
                "/adbe.pkcs7.s5 handler requires crypt filters."
            )
        return cfc

    @classmethod
    def gather_pub_key_metadata(cls, encrypt_dict: generic.DictionaryObject):
        keylen_bits = encrypt_dict.get('/Length', 128)
        if (keylen_bits % 8) != 0:
            raise misc.PdfError("Key length must be a multiple of 8")
        keylen = keylen_bits // 8

        recipients = misc.get_and_apply(
            encrypt_dict,
            '/Recipients',
            lambda lst: [cms.ContentInfo.load(x.original_bytes) for x in lst],
        )

        # TODO get encrypt_metadata handling in line with ISO 32k
        #  (needs to happen at the crypt filter level instead)
        encrypt_metadata = encrypt_dict.get_and_apply(
            '/EncryptMetadata', bool, default=True
        )
        return dict(
            legacy_keylen=keylen,
            recipient_objs=recipients,
            encrypt_metadata=encrypt_metadata,
        )

    @classmethod
    def _determine_subfilter(cls, encrypt_dict: generic.DictionaryObject):
        try:
            return misc.get_and_apply(
                encrypt_dict,
                '/SubFilter',
                PubKeyAdbeSubFilter,
                default=(
                    PubKeyAdbeSubFilter.S5
                    if '/CF' in encrypt_dict
                    else PubKeyAdbeSubFilter.S4
                ),
            )
        except ValueError:
            raise misc.PdfReadError(
                "Invalid /SubFilter in public key encryption dictionary: "
                + encrypt_dict['/SubFilter']
            )

    @classmethod
    def instantiate_from_pdf_object(
        cls, encrypt_dict: generic.DictionaryObject
    ):
        v = SecurityHandlerVersion.from_number(encrypt_dict['/V'])

        return PubKeySecurityHandler(
            version=v,
            pubkey_handler_subfilter=cls._determine_subfilter(encrypt_dict),
            crypt_filter_config=cls.process_crypt_filters(encrypt_dict),
            **cls.gather_pub_key_metadata(encrypt_dict),
        )

    def as_pdf_object(self):
        result = generic.DictionaryObject()
        result['/Filter'] = generic.NameObject(self.get_name())
        result['/SubFilter'] = self.subfilter.value
        result['/V'] = self.version.as_pdf_object()
        if (
            self._compat_entries
            or self.version == SecurityHandlerVersion.RC4_LONGER_KEYS
        ):
            result['/Length'] = generic.NumberObject(self.keylen * 8)
        if self.version > SecurityHandlerVersion.RC4_LONGER_KEYS:
            result['/EncryptMetadata'] = generic.BooleanObject(
                self.encrypt_metadata
            )
        if self.subfilter == PubKeyAdbeSubFilter.S5:
            # include crypt filter config
            result.update(self.crypt_filter_config.as_pdf_object())
        else:
            # load recipients from default crypt filter into the encryption dict
            default_cf = self.get_stream_filter()
            if not isinstance(default_cf, PubKeyCryptFilter):
                raise TypeError  # pragma: nocover
            result['/Recipients'] = generic.ArrayObject(
                generic.ByteStringObject(recp.dump())
                for recp in default_cf.recipients
            )
        return result

    def add_recipients(
        self,
        certs: List[x509.Certificate],
        perms=ALL_PERMS,
        ignore_key_usage=False,
    ):
        # add recipients to all *default* crypt filters
        # callers that want to do this more granularly are welcome to, but
        # then they have to do the legwork themselves.

        for cf in self.crypt_filter_config.standard_filters():
            if not isinstance(cf, PubKeyCryptFilter):
                continue
            cf.add_recipients(
                certs, perms=perms, ignore_key_usage=ignore_key_usage
            )

    def authenticate(
        self,
        credential: Union[EnvelopeKeyDecrypter, SerialisedCredential],
        id1=None,
    ) -> AuthResult:
        """
        Authenticate a user to this security handler.

        :param credential:
            The credential to use (an instance of :class:`.EnvelopeKeyDecrypter`
            in this case).
        :param id1:
            First part of the document ID.
            Public key encryption handlers ignore this key.
        :return:
            An :class:`AuthResult` object indicating the level of access
            obtained.
        """

        actual_credential: EnvelopeKeyDecrypter
        if isinstance(credential, SerialisedCredential):
            deser_credential = SerialisableCredential.deserialise(credential)
            if not isinstance(deser_credential, EnvelopeKeyDecrypter):
                raise misc.PdfReadError(
                    f"Pubkey authentication credential must be an instance of "
                    f"EnvelopeKeyDecrypter, not {type(deser_credential)}."
                )
            actual_credential = deser_credential
        else:
            actual_credential = credential

        perms = 0xFFFFFFFF
        for cf in self.crypt_filter_config.standard_filters():
            if not isinstance(cf, PubKeyCryptFilter):
                continue
            recp: cms.ContentInfo
            result = cf.authenticate(actual_credential)
            if result.status == AuthStatus.FAILED:
                return result
            # these should really be the same for both filters, but hey,
            # you never know. ANDing them seems to be the most reasonable
            # course of action
            if result.permission_flags is not None:
                perms &= result.permission_flags
        if isinstance(actual_credential, SerialisableCredential):
            self._credential = actual_credential
        return AuthResult(AuthStatus.USER, as_signed(perms))

    def get_file_encryption_key(self) -> bytes:
        # just grab the key from the default stream filter
        return self.crypt_filter_config.get_for_stream().shared_key
