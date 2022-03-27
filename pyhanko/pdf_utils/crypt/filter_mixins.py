import abc
import secrets

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.crypt._util import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    rc4_encrypt,
)
from pyhanko.pdf_utils.crypt.api import CryptFilter, SecurityHandlerVersion

from ._legacy import legacy_derive_object_key


class RC4CryptFilterMixin(CryptFilter, abc.ABC):
    """
    Mixin for RC4-based crypt filters.

    :param keylen:
        Key length, in bytes. Defaults to 5.
    """

    method = generic.NameObject('/V2')
    keylen = None

    def __init__(self, *, keylen=5, **kwargs):
        self.keylen = keylen
        super().__init__(**kwargs)

    def encrypt(self, key, plaintext: bytes, params=None) -> bytes:
        """
        Encrypt data using RC4.

        :param key:
            Local encryption key.
        :param plaintext:
            Plaintext to encrypt.
        :param params:
            Ignored.
        :return:
            Ciphertext.
        """
        return rc4_encrypt(key, plaintext)

    def decrypt(self, key, ciphertext: bytes, params=None) -> bytes:
        """
        Decrypt data using RC4.

        :param key:
            Local encryption key.
        :param ciphertext:
            Ciphertext to decrypt.
        :param params:
            Ignored.
        :return:
            Plaintext.
        """
        return rc4_encrypt(key, ciphertext)

    def derive_object_key(self, idnum, generation) -> bytes:
        """
        Derive the local key for the given object ID and generation number,
        by calling :func:`.legacy_derive_object_key`.

        :param idnum:
            ID of the object being encrypted.
        :param generation:
            Generation number of the object being encrypted.
        :return:
            The local key.
        """
        return legacy_derive_object_key(self.shared_key, idnum, generation)


class AESCryptFilterMixin(CryptFilter, abc.ABC):
    """Mixin for AES-based crypt filters."""
    keylen = None
    method = None

    def __init__(self, *, keylen, **kwargs):
        if keylen not in (16, 32):
            raise NotImplementedError("Only AES-128 and AES-256 are supported")
        self.keylen = keylen
        self.method = (
            generic.NameObject('/AESV2') if keylen == 16 else
            generic.NameObject('/AESV3')
        )
        super().__init__(**kwargs)

    def encrypt(self, key, plaintext: bytes, params=None):
        """
        Encrypt data using AES in CBC mode, with PKCS#7 padding.

        :param key:
            The key to use.
        :param plaintext:
            The plaintext to be encrypted.
        :param params:
            Ignored.
        :return:
            The resulting ciphertext, prepended with a 16-byte initialisation
            vector.
        """
        iv, ciphertext = aes_cbc_encrypt(
            key, plaintext, secrets.token_bytes(16)
        )
        return iv + ciphertext

    def decrypt(self, key, ciphertext: bytes, params=None) -> bytes:
        """
        Decrypt data using AES in CBC mode, with PKCS#7 padding.

        :param key:
            The key to use.
        :param ciphertext:
            The ciphertext to be decrypted, prepended with a 16-byte
            initialisation vector.
        :param params:
            Ignored.
        :return:
            The resulting plaintext.
        """
        iv, data = ciphertext[:16], ciphertext[16:]
        return aes_cbc_decrypt(key, data, iv)

    def derive_object_key(self, idnum, generation) -> bytes:
        """
        Derive the local key for the given object ID and generation number.

        If the associated handler is of version
        :attr:`.SecurityHandlerVersion.AES256` or greater, this method
        simply returns the global key as-is.
        If not, the computation is carried out by
        :func:`.legacy_derive_object_key`.

        :param idnum:
            ID of the object being encrypted.
        :param generation:
            Generation number of the object being encrypted.
        :return:
            The local key.
        """
        if self._handler.version >= SecurityHandlerVersion.AES256:
            return self.shared_key
        else:
            return legacy_derive_object_key(
                self.shared_key, idnum, generation, use_aes=True
            )