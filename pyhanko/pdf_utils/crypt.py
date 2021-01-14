"""
Legacy encryption implementation based on PyPDF2 see (License.PyPDF2)
with additions for pyHanko:

 * The :class:`SignatureHandler` abstraction is new.
 * The AES-256 implementation for PDF 2.0 is also new.

The members of this module are all considered internal API, and are therefore
subject to change without notice.

One should also be aware that the legacy encryption scheme implemented here is
(very) weak, and we only support it for compatibility reasons. Under no
circumstances should it still be used to encrypt new files.
"""
import abc
import struct
import secrets
import enum
from dataclasses import dataclass
from hashlib import md5, sha256, sha384, sha512
from typing import Dict, Type, Optional, Tuple, Union
from oscrypto import symmetric

from . import generic, misc


# ref: pdf1.8 spec section 3.5.2 algorithm 3.2
_encryption_padding = (
    b'\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56'
    b'\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c'
    b'\xa9\xfe\x64\x53\x69\x7a'
)


# Implementation of algorithm 3.2 of the PDF standard security handler,
# section 3.5.2 of the PDF 1.6 reference.
def _derive_legacy_file_key(password, rev, keylen, owner_entry, p_entry,
                            id1_entry, metadata_encrypt=True):
    # 1. Pad or truncate the password string to exactly 32 bytes.  If the
    # password string is more than 32 bytes long, use only its first 32 bytes;
    # if it is less than 32 bytes long, pad it by appending the required number
    # of additional bytes from the beginning of the padding string
    # (_encryption_padding).
    password = (password + _encryption_padding)[:32]
    # 2. Initialize the MD5 hash function and pass the result of step 1 as
    # input to this function.
    m = md5(password)
    # 3. Pass the value of the encryption dictionary's /O entry to the MD5 hash
    # function.
    m.update(owner_entry)
    # 4. Treat the value of the /P entry as an unsigned 4-byte integer and pass
    # these bytes to the MD5 hash function, low-order byte first.
    p_entry = struct.pack('<i', p_entry)
    m.update(p_entry)
    # 5. Pass the first element of the file's file identifier array to the MD5
    # hash function.
    m.update(id1_entry)
    # 6. (Revision 4 or greater) If document metadata is not being encrypted,
    # pass 4 bytes with the value 0xFFFFFFFF to the MD5 hash function.
    if rev >= 4 and not metadata_encrypt:
        m.update(b"\xff\xff\xff\xff")
    # 7. Finish the hash.
    md5_hash = m.digest()
    # 8. (Revision 3 or greater) Do the following 50 times: Take the output
    # from the previous MD5 hash and pass the first n bytes of the output as
    # input into a new MD5 hash, where n is the number of bytes of the
    # encryption key as defined by the value of the encryption dictionary's
    # /Length entry.
    if rev >= 3:
        for i in range(50):
            md5_hash = md5(md5_hash[:keylen]).digest()
    # 9. Set the encryption key to the first n bytes of the output from the
    # final MD5 hash, where n is always 5 for revision 2 but, for revision 3 or
    # greater, depends on the value of the encryption dictionary's /Length
    # entry.
    return md5_hash[:keylen]


@dataclass
class R6KeyEntry:
    hash_value: bytes
    validation_salt: bytes
    key_salt: bytes

    @classmethod
    def from_bytes(cls, entry: bytes) -> 'R6KeyEntry':
        assert len(entry) == 48
        return R6KeyEntry(entry[:32], entry[32:40], entry[40:48])


def _legacy_normalise_pw(password: Union[str, bytes]) -> bytes:
    if isinstance(password, str):
        return generic.encode_pdfdocencoding(password[:32])
    else:
        return password[:32]


def _r6_normalise_pw(password: Union[str, bytes]) -> bytes:
    if isinstance(password, str):
        from ._saslprep import saslprep
        password = saslprep(password).encode('utf-8')
    return password[:127]


def _r6_password_authenticate(pw_bytes: bytes, entry: R6KeyEntry,
                              u_entry: Optional[bytes] = None):
    purported_hash = _r6_hash_algo(pw_bytes, entry.validation_salt, u_entry)
    return purported_hash == entry.hash_value


def _r6_derive_file_key(pw_bytes: bytes, entry: R6KeyEntry, e_entry: bytes,
                        u_entry: Optional[bytes] = None):
    interm_key = _r6_hash_algo(pw_bytes, entry.key_salt, u_entry)
    assert len(e_entry) == 32
    return symmetric.aes_cbc_no_padding_decrypt(
        key=interm_key, data=e_entry, iv=bytes(16)
    )


_EXPECTED_PERMS_8 = {
    0x54: True,  # 'T'
    0x46: False  # 'F'
}


def _bytes_mod_3(input_bytes: bytes):
    # 256 is 1 mod 3, so we can just sum 'em
    return sum(b % 3 for b in input_bytes) % 3


# Algorithm 2.B in ISO 32000-2 § 7.6.4.3.4
def _r6_hash_algo(pw_bytes: bytes, current_salt: bytes,
                  u_entry: Optional[bytes] = None) -> bytes:
    initial_hash = sha256(pw_bytes)
    assert len(current_salt) == 8
    initial_hash.update(current_salt)
    if u_entry:
        assert len(u_entry) == 48
        initial_hash.update(u_entry)
    k = initial_hash.digest()
    hashes = (sha256, sha384, sha512)
    round_no = last_byte_val = 0
    while round_no < 64 or last_byte_val > round_no - 32:
        k1 = (pw_bytes + k + (u_entry or b'')) * 64
        e = symmetric.aes_cbc_no_padding_encrypt(
            key=k[:16], data=k1, iv=k[16:32]
        )[1]
        # compute the first 16 bytes of e, interpreted as an unsigned integer
        # mod 3
        next_hash = hashes[_bytes_mod_3(e[:16])]
        k = next_hash(e).digest()
        last_byte_val = e[len(e) - 1]
        round_no += 1
    return k[:32]


# Implementation of algorithm 3.3 of the PDF standard security handler,
# section 3.5.2 of the PDF 1.6 reference.
def _compute_o_value_legacy(owner_pwd, user_pwd, rev, keylen):
    # steps 1 - 4
    key = _compute_o_value_legacy_prep(owner_pwd, rev, keylen)
    # 5. Pad or truncate the user password string as described in step 1 of
    # algorithm 3.2.
    user_pwd = (user_pwd + _encryption_padding)[:32]
    # 6. Encrypt the result of step 5, using an RC4 encryption function with
    # the encryption key obtained in step 4.
    val = rc4_encrypt(key, user_pwd)
    # 7. (Revision 3 or greater) Do the following 19 times: Take the output
    # from the previous invocation of the RC4 function and pass it as input to
    # a new invocation of the function; use an encryption key generated by
    # taking each byte of the encryption key obtained in step 4 and performing
    # an XOR operation between that byte and the single-byte value of the
    # iteration counter (from 1 to 19).
    if rev >= 3:
        for i in range(1, 20):
            new_key = bytes(b ^ i for b in key)
            val = rc4_encrypt(new_key, val)
    # 8. Store the output from the final invocation of the RC4 as the value of
    # the /O entry in the encryption dictionary.
    return val


# Steps 1-4 of algorithm 3.3
def _compute_o_value_legacy_prep(password, rev, keylen):
    # 1. Pad or truncate the owner password string as described in step 1 of
    # algorithm 3.2.  If there is no owner password, use the user password
    # instead.
    password = (password + _encryption_padding)[:32]
    # 2. Initialize the MD5 hash function and pass the result of step 1 as
    # input to this function.
    m = md5(password)
    # 3. (Revision 3 or greater) Do the following 50 times: Take the output
    # from the previous MD5 hash and pass it as input into a new MD5 hash.
    md5_hash = m.digest()
    if rev >= 3:
        for i in range(50):
            md5_hash = md5(md5_hash).digest()
    # 4. Create an RC4 encryption key using the first n bytes of the output
    # from the final MD5 hash, where n is always 5 for revision 2 but, for
    # revision 3 or greater, depends on the value of the encryption
    # dictionary's /Length entry.
    key = md5_hash[:keylen]
    return key


# Implementation of algorithm 3.4 of the PDF standard security handler,
# section 3.5.2 of the PDF 1.6 reference.
def _compute_u_value_r2(password, owner_entry, p_entry, id1_entry):
    # 1. Create an encryption key based on the user password string, as
    # described in algorithm 3.2.
    key = _derive_legacy_file_key(password, 2, 5, owner_entry, p_entry,
                                  id1_entry)
    # 2. Encrypt the 32-byte padding string shown in step 1 of algorithm 3.2,
    # using an RC4 encryption function with the encryption key from the
    # preceding step.
    u = rc4_encrypt(key, _encryption_padding)
    # 3. Store the result of step 2 as the value of the /U entry in the
    # encryption dictionary.
    return u, key


# Implementation of algorithm 3.4 of the PDF standard security handler,
# section 3.5.2 of the PDF 1.6 reference.
def _compute_u_value_r34(password, rev, keylen, owner_entry, p_entry,
                         id1_entry):
    # 1. Create an encryption key based on the user password string, as
    # described in Algorithm 3.2.
    key = _derive_legacy_file_key(password, rev, keylen, owner_entry, p_entry,
                                  id1_entry)
    # 2. Initialize the MD5 hash function and pass the 32-byte padding string
    # shown in step 1 of Algorithm 3.2 as input to this function.
    m = md5()
    m.update(_encryption_padding)
    # 3. Pass the first element of the file's file identifier array (the value
    # of the ID entry in the document's trailer dictionary; see Table 3.13 on
    # page 73) to the hash function and finish the hash.  (See implementation
    # note 25 in Appendix H.)
    m.update(id1_entry)
    md5_hash = m.digest()
    # 4. Encrypt the 16-byte result of the hash, using an RC4 encryption
    # function with the encryption key from step 1.
    val = rc4_encrypt(key, md5_hash)
    # 5. Do the following 19 times: Take the output from the previous
    # invocation of the RC4 function and pass it as input to a new invocation
    # of the function; use an encryption key generated by taking each byte of
    # the original encryption key (obtained in step 2) and performing an XOR
    # operation between that byte and the single-byte value of the iteration
    # counter (from 1 to 19).
    for i in range(1, 20):
        new_key = bytes(b ^ i for b in key)
        val = rc4_encrypt(new_key, val)
    # 6. Append 16 bytes of arbitrary padding to the output from the final
    # invocation of the RC4 function and store the 32-byte result as the value
    # of the U entry in the encryption dictionary.
    # (implementator note: I don't know what "arbitrary padding" is supposed to
    # mean, so I have used null bytes.  This seems to match a few other
    # people's implementations)
    return val + (b'\x00' * 16), key


class RC4:

    def __init__(self, key):
        sigma = bytearray(range(256))
        j = 0
        for i in range(256):
            j = (j + sigma[i] + key[i % len(key)]) % 256
            sigma[i], sigma[j] = sigma[j], sigma[i]

        self.sigma = sigma
        self.i = self.j = 0

    def __next__(self):
        sigma = self.sigma
        self.i = i = (self.i + 1) % 256
        self.j = j = (self.j + sigma[i]) % 256
        sigma[i], sigma[j] = sigma[j], sigma[i]
        t = sigma[(sigma[i] + sigma[j]) % 256]
        return t

    def __iter__(self):
        return self

    def crypt(self, data):
        return bytearray(b ^ t for b, t in zip(data, self))


def rc4_encrypt(key, plaintext):
    return RC4(key).crypt(plaintext)


def legacy_derive_object_key(shared_key: bytes, idnum: int, generation: int) \
        -> bytes:
    pack1 = struct.pack("<i", idnum)[:3]
    pack2 = struct.pack("<i", generation)[:2]
    key = shared_key + pack1 + pack2
    assert len(key) == (len(shared_key) + 5)
    md5_hash = md5(key).digest()
    return md5_hash[:min(16, len(shared_key) + 5)]


class AuthResult(misc.OrderedEnum):
    UNKNOWN = 0
    USER = 1
    OWNER = 2


class SecurityHandler:

    __registered_subclasses: Dict[str, Type['SecurityHandler']] = dict()

    @staticmethod
    def register(cls: Type['SecurityHandler']):
        # don't put this in __init_subclass__, so that people can override
        # security handlers if they want
        SecurityHandler.__registered_subclasses[cls.get_name()] = cls
        return cls

    @staticmethod
    def build(encrypt_dict: generic.DictionaryObject) -> 'SecurityHandler':
        # TODO allow selecting by subfilter
        handler_name = encrypt_dict.get('/Filter', '/Standard')
        try:
            cls = SecurityHandler.__registered_subclasses[handler_name]
        except KeyError:
            raise misc.PdfError(
                f"There is no security handler named {handler_name}"
            )
        return cls.instantiate_from_pdf_object(encrypt_dict)

    @classmethod
    def get_name(cls) -> str:
        raise NotImplementedError

    @classmethod
    def instantiate_from_pdf_object(cls,
                                    encrypt_dict: generic.DictionaryObject):
        raise NotImplementedError

    def as_pdf_object(self):
        raise NotImplementedError

    def get_file_encryption_key(self) -> bytes:
        raise NotImplementedError

    def derive_object_key(self, idnum, generation) -> bytes:
        raise NotImplementedError

    def authenticate(self, id1, password) -> AuthResult:
        raise NotImplementedError

    def get_string_filter(self) -> 'CryptFilter':
        raise NotImplementedError

    def get_stream_filter(self, name=None) -> 'CryptFilter':
        raise NotImplementedError


@enum.unique
class StandardSecurityHandlerVersion(misc.OrderedEnum):
    RC4_40 = 1
    RC4_LONGER_KEYS = 2
    RC4_OR_AES128 = 4
    AES256 = 5


@enum.unique
class StandardSecuritySettingsRevision(misc.OrderedEnum):
    RC4_BASIC = 2
    RC4_EXTENDED = 3
    RC4_OR_AES128 = 4
    AES256 = 6


# TODO handle /AuthEvent

class CryptFilter:
    _handler: 'SecurityHandler' = None
    _shared_key: Optional[bytes] = None

    def set_security_handler(self, handler):
        self._handler = handler
        self._shared_key = None

    def encrypt(self, key, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, key, ciphertext: bytes) -> bytes:
        raise NotImplementedError

    @property
    def shared_key(self) -> bytes:
        result = self._shared_key
        if result is None:
            result = self._shared_key = self._handler.get_file_encryption_key()
        return result

    def derive_object_key(self, idnum, generation) -> bytes:
        raise NotImplementedError

    def as_pdf_object(self):
        raise NotImplementedError


class IdentityCryptFilter(CryptFilter, metaclass=misc.Singleton):

    def set_security_handler(self, handler):
        return

    @property
    def shared_key(self) -> bytes:
        return b''

    def derive_object_key(self, idnum, generation):
        return b''

    def as_pdf_object(self):
        return generic.NullObject()

    def encrypt(self, key, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, key, ciphertext: bytes) -> bytes:
        return ciphertext


class RC4CryptFilter(CryptFilter):

    def __init__(self, keylen):
        self.keylen = keylen

    def derive_object_key(self, idnum, generation) -> bytes:
        return legacy_derive_object_key(self.shared_key, idnum, generation)

    def encrypt(self, key, plaintext: bytes) -> bytes:
        return rc4_encrypt(key, plaintext)

    def decrypt(self, key, ciphertext: bytes) -> bytes:
        return rc4_encrypt(key, ciphertext)

    def as_pdf_object(self):
        return generic.DictionaryObject({
            generic.NameObject('/CFM'): generic.NameObject('/V2'),
            generic.NameObject('/AuthEvent'): generic.NameObject('/DocOpen'),
            # this is wrong per the 2017 spec, but the 2020 revision mandates
            # doing it this way
            generic.NameObject('/Length'): generic.NumberObject(self.keylen)
        })


class AESCryptFilter(CryptFilter, abc.ABC):

    def encrypt(self, key, plaintext: bytes):
        iv, ciphertext = symmetric.aes_cbc_pkcs7_encrypt(
            key, plaintext, secrets.token_bytes(16)
        )
        return iv + ciphertext

    def decrypt(self, key, ciphertext: bytes) -> bytes:
        iv, data = ciphertext[:16], ciphertext[16:]
        return symmetric.aes_cbc_pkcs7_decrypt(key, data, iv)


class AESV2CryptFilter(AESCryptFilter):

    def derive_object_key(self, idnum, generation) -> bytes:
        return legacy_derive_object_key(self.shared_key, idnum, generation)

    def as_pdf_object(self):
        return generic.DictionaryObject({
            generic.NameObject('/CFM'): generic.NameObject('/AESV2'),
            generic.NameObject('/AuthEvent'): generic.NameObject('/DocOpen'),
            # this is wrong per the 2017 spec, but the 2020 revision mandates
            # doing it this way
            generic.NameObject('/Length'): generic.NumberObject(16),
        })


class AESV3CryptFilter(AESCryptFilter):

    def derive_object_key(self, idnum, generation) -> bytes:
        return self.shared_key

    def as_pdf_object(self):
        return generic.DictionaryObject({
            generic.NameObject('/CFM'): generic.NameObject('/AESV3'),
            generic.NameObject('/AuthEvent'): generic.NameObject('/DocOpen'),
            # this is wrong per the 2017 spec, but the 2020 revision mandates
            # doing it this way
            generic.NameObject('/Length'): generic.NumberObject(32),
        })


STD_CF = generic.NameObject('/StdCF')
IDENTITY = generic.NameObject('/Identity')


class CryptFilterConfiguration:

    def __init__(self, crypt_filters: Dict[str, CryptFilter] = None,
                 default_stream_filter=IDENTITY, default_string_filter=IDENTITY,
                 default_file_filter=None):
        def _select(name) -> CryptFilter:
            if name == IDENTITY:
                return IdentityCryptFilter()
            else:
                return crypt_filters[name]

        self._crypt_filters = crypt_filters
        self._default_string_filter_name = default_string_filter
        self._default_stream_filter_name = default_stream_filter
        self._default_file_filter_name = default_file_filter
        self._default_stream_filter = _select(default_stream_filter)
        self._default_string_filter = _select(default_string_filter)
        default_file_filter = default_file_filter or default_stream_filter
        self._default_file_filter = _select(default_file_filter)

    def __getitem__(self, item):
        if item == generic.NameObject('/Identity'):
            return IdentityCryptFilter()
        return self._crypt_filters[item]

    def set_security_handler(self, handler: 'SecurityHandler'):
        for cf in self._crypt_filters.values():
            cf.set_security_handler(handler)

    def get_for_stream(self):
        return self._default_stream_filter

    def get_for_string(self):
        return self._default_string_filter

    def get_for_embedded_file(self):
        return self._default_file_filter

    def as_pdf_object(self):
        result = generic.DictionaryObject()
        result['/StmF'] = self._default_stream_filter_name
        result['/StrF'] = self._default_string_filter_name
        if self._default_file_filter_name is not None:
            result['/EFF'] = self._default_file_filter_name
        result['/CF'] = generic.DictionaryObject({
            key: value.as_pdf_object()
            for key, value in self._crypt_filters.items() if key != IDENTITY
        })
        return result


def _rc4_config(keylen):
    return CryptFilterConfiguration(
        {STD_CF: RC4CryptFilter(keylen)},
        default_stream_filter=STD_CF,
        default_string_filter=STD_CF
    )


AES128_CONFIG = CryptFilterConfiguration(
    {STD_CF: AESV2CryptFilter()},
    default_stream_filter=STD_CF,
    default_string_filter=STD_CF
)


AES256_CONFIG = CryptFilterConfiguration(
    {STD_CF: AESV3CryptFilter()},
    default_stream_filter=STD_CF,
    default_string_filter=STD_CF
)


@SecurityHandler.register
class StandardSecurityHandler(SecurityHandler):

    def get_file_encryption_key(self) -> bytes:
        return self.shared_key

    @classmethod
    def get_name(cls) -> str:
        return generic.NameObject('/Standard')

    @classmethod
    def build_from_pw_legacy(cls, rev: StandardSecuritySettingsRevision,
                             id1, desired_owner_pass, desired_user_pass=None,
                             keylen_bytes=16, use_aes128=True):
        desired_owner_pass = _legacy_normalise_pw(desired_owner_pass)
        desired_user_pass = (
            _legacy_normalise_pw(desired_user_pass)
            if desired_user_pass is not None else desired_owner_pass
        )
        if rev > StandardSecuritySettingsRevision.RC4_OR_AES128:
            raise ValueError(
                f"{rev} is not supported by this bootstrapping method."
            )
        if rev == StandardSecuritySettingsRevision.RC4_BASIC:
            keylen_bytes = 5
        elif use_aes128 and \
                rev == StandardSecuritySettingsRevision.RC4_OR_AES128:
            keylen_bytes = 16
        o_entry = _compute_o_value_legacy(
            desired_owner_pass, desired_user_pass, rev.value, keylen_bytes
        )

        # TODO allow user to set perms, force unavailable perms to 1 if
        #  encrypting with RC4_BASIC
        perms_bytes = b'\xfc\xff\xff\xff'
        perms = struct.unpack('<i', perms_bytes)[0]

        if rev == StandardSecuritySettingsRevision.RC4_BASIC:
            u_entry, key = _compute_u_value_r2(
                desired_user_pass, o_entry, perms, id1
            )
        else:
            u_entry, key = _compute_u_value_r34(
                desired_user_pass, rev.value, keylen_bytes, o_entry, perms, id1
            )

        if rev == StandardSecuritySettingsRevision.RC4_OR_AES128:
            version = StandardSecurityHandlerVersion.RC4_OR_AES128
            if use_aes128:
                cfc = AES128_CONFIG
            else:
                cfc = _rc4_config(keylen_bytes)
        elif rev == StandardSecuritySettingsRevision.RC4_BASIC:
            version = StandardSecurityHandlerVersion.RC4_40
            cfc = None
        else:
            version = StandardSecurityHandlerVersion.RC4_LONGER_KEYS
            cfc = None

        sh = StandardSecurityHandler(
            version=version, revision=rev, legacy_keylen=keylen_bytes,
            perm_flags=perms, odata=o_entry,
            udata=u_entry, encrypt_metadata=True, crypt_filter_config=cfc,
        )
        sh._shared_key = key
        return sh

    @classmethod
    def build_from_pw(cls, desired_owner_pass, desired_user_pass=None):
        import secrets
        owner_pw_bytes = _r6_normalise_pw(desired_owner_pass)
        user_pw_bytes = (
            _r6_normalise_pw(desired_user_pass)
            if desired_user_pass is not None
            else owner_pw_bytes
        )
        encryption_key = secrets.token_bytes(32)
        u_validation_salt = secrets.token_bytes(8)
        u_key_salt = secrets.token_bytes(8)
        u_hash = _r6_hash_algo(user_pw_bytes, u_validation_salt)
        u_entry = u_hash + u_validation_salt + u_key_salt
        u_interm_key = _r6_hash_algo(user_pw_bytes, u_key_salt)
        _, ue_seed = symmetric.aes_cbc_no_padding_encrypt(
            u_interm_key, encryption_key, bytes(16)
        )
        assert len(ue_seed) == 32

        o_validation_salt = secrets.token_bytes(8)
        o_key_salt = secrets.token_bytes(8)
        o_hash = _r6_hash_algo(owner_pw_bytes, o_validation_salt, u_entry)
        o_entry = o_hash + o_validation_salt + o_key_salt
        o_interm_key = _r6_hash_algo(owner_pw_bytes, o_key_salt, u_entry)
        _, oe_seed = symmetric.aes_cbc_no_padding_encrypt(
            o_interm_key, encryption_key, bytes(16)
        )
        assert len(oe_seed) == 32

        # TODO allow user to set perms
        perms_bytes = b'\xfc\xff\xff\xff'
        extd_perms_bytes = (
            perms_bytes + (b'\xff' * 4) + b'Tadb' + secrets.token_bytes(4)
        )
        perms = struct.unpack('<i', perms_bytes)[0]
        _, encrypted_perms = symmetric.aes_cbc_no_padding_encrypt(
            encryption_key, extd_perms_bytes, bytes(16)
        )
        sh = StandardSecurityHandler(
            version=StandardSecurityHandlerVersion.AES256,
            revision=StandardSecuritySettingsRevision.AES256,
            legacy_keylen=32, perm_flags=perms, odata=o_entry,
            udata=u_entry, oeseed=oe_seed, ueseed=ue_seed,
            encrypted_perms=encrypted_perms, encrypt_metadata=True
        )
        sh._shared_key = encryption_key
        return sh

    def __init__(self, version: StandardSecurityHandlerVersion,
                 revision: StandardSecuritySettingsRevision,
                 legacy_keylen,  # in bytes, not bits
                 perm_flags: int, odata, udata, oeseed=None,
                 ueseed=None, encrypted_perms=None, encrypt_metadata=True,
                 crypt_filter_config: CryptFilterConfiguration = None):
        self.version = version
        self.revision = revision
        self.perms = perm_flags
        if version == StandardSecurityHandlerVersion.RC4_40:
            legacy_keylen = 5
            crypt_filter_config = _rc4_config(5)
        elif not (5 <= legacy_keylen <= 16) \
                and version <= StandardSecurityHandlerVersion.RC4_OR_AES128:
            raise misc.PdfError("Key length must be between 5 and 16")
        elif version == StandardSecurityHandlerVersion.RC4_LONGER_KEYS:
            crypt_filter_config = _rc4_config(legacy_keylen)
        elif version == StandardSecurityHandlerVersion.AES256 \
                and crypt_filter_config is None:
            # there's a reasonable default config that we can fall back to here
            crypt_filter_config = AES256_CONFIG
            legacy_keylen = 32

        if crypt_filter_config is None:
            raise misc.PdfError(
                "Specifying a crypt filter configuration is mandatory for "
                "/Encrypt dictionaries of version 4."
            )

        self.keylen = legacy_keylen
        self.crypt_filter_config = crypt_filter_config
        if revision == StandardSecuritySettingsRevision.AES256:
            if not (len(udata) == len(odata) == 48):
                raise misc.PdfError(
                    "/U and /O entries must be 48 bytes long in a "
                    "rev. 6 security handler"
                )  # pragma: nocover
            if not oeseed or not ueseed or \
                    not (len(oeseed) == len(ueseed) == 32):
                raise misc.PdfError(
                    "/UE and /OE must be present and be 32 bytes long in a "
                    "rev. 6 security handler"
                )  # pragma: nocover
            self.oeseed = oeseed
            self.ueseed = ueseed
            if not encrypted_perms or len(encrypted_perms) != 16:
                raise misc.PdfError(
                    "/Perms must be present and be 16 bytes long in a "
                    "rev. 6 security handler"
                )  # pragma: nocover
            self.encrypted_perms = encrypted_perms
        else:
            if not (len(udata) == len(odata) == 32):
                raise misc.PdfError(
                    "/U and /O entries must be 32 bytes long in a "
                    "legacy security handler"
                )  # pragma: nocover
            self.oeseed = self.ueseed = self.encrypted_perms = None
        self.odata = odata
        self.udata = udata
        self.encrypt_metadata = encrypt_metadata
        self._shared_key = None
        self._auth_failed = False

    @property
    def shared_key(self):
        key = self._shared_key
        if key is None:
            raise misc.PdfError(
                "Authentication failed." if self._auth_failed else
                "Shared key not available. Authenticate first."
            )
        return key

    @staticmethod
    def read_standard_cf_dictionary(cfdict):
        # TODO does a V4 handler default to /Identity unless the /Encrypt
        #  dictionary specifies a custom filter?
        try:
            cfm = cfdict['/CFM']
        except KeyError:
            return None
        if cfm == '/None':
            return None
        elif cfm == '/V2':
            keylen_bits = cfdict.get('/Length', 40)
            return RC4CryptFilter(keylen_bits // 8)
        elif cfm == '/AESV2':
            return AESV2CryptFilter()
        elif cfm == '/AESV3':
            return AESV3CryptFilter()
        else:
            raise NotImplementedError("No such crypt filter method: " + cfm)

    @classmethod
    def instantiate_from_pdf_object(cls,
                                    encrypt_dict: generic.DictionaryObject):
        v = StandardSecurityHandlerVersion(encrypt_dict['/V'])
        r = StandardSecuritySettingsRevision(encrypt_dict['/R'])
        keylen_bits = encrypt_dict.get('/Length', 40)
        if (keylen_bits % 8) != 0:
            raise misc.PdfError("Key length must be a multiple of 8")
        keylen = keylen_bits // 8
        stmf = encrypt_dict.get('/StmF', IDENTITY)
        strf = encrypt_dict.get('/StrF', IDENTITY)
        eff = encrypt_dict.get('/EFF', stmf)

        try:
            crypt_filters = {
                name: StandardSecurityHandler.read_standard_cf_dictionary(
                    cfdict
                )
                for name, cfdict in encrypt_dict['/CF'].items()
            }
            cfc = CryptFilterConfiguration(
                crypt_filters=crypt_filters, default_stream_filter=stmf,
                default_string_filter=strf, default_file_filter=eff
            )
        except KeyError:
            cfc = None
        return StandardSecurityHandler(
            version=v, revision=r, legacy_keylen=keylen,
            crypt_filter_config=cfc, perm_flags=int(encrypt_dict['/P']),
            odata=encrypt_dict['/O'].original_bytes[:48],
            udata=encrypt_dict['/U'].original_bytes[:48],
            oeseed=encrypt_dict.get_and_apply(
                '/OE', lambda x: x.original_bytes
            ),
            ueseed=encrypt_dict.get_and_apply(
                '/UE', lambda x: x.original_bytes
            ),
            encrypted_perms=encrypt_dict.get_and_apply(
                '/Perms', lambda x: x.original_bytes
            ),
            encrypt_metadata=encrypt_dict.get_and_apply(
                '/EncryptMetadata', bool, default=True
            )
        )

    def as_pdf_object(self):
        result = generic.DictionaryObject()
        result['/Filter'] = generic.NameObject('/Standard')
        result['/O'] = generic.ByteStringObject(self.odata)
        result['/U'] = generic.ByteStringObject(self.udata)
        result['/P'] = generic.NumberObject(self.perms)
        result['/V'] = generic.NumberObject(self.version.value)
        result['/R'] = generic.NumberObject(self.revision.value)
        # this shouldn't be necessary for V5 handlers, but Adobe Reader
        # requires it anyway ...sigh...
        result['/Length'] = generic.NumberObject(self.keylen * 8)
        if self.version > StandardSecurityHandlerVersion.RC4_LONGER_KEYS:
            result['/EncryptMetadata'] \
                = generic.BooleanObject(self.encrypt_metadata)
            result.update(self.crypt_filter_config.as_pdf_object())
        if self.revision == StandardSecuritySettingsRevision.AES256:
            result['/OE'] = generic.ByteStringObject(self.oeseed)
            result['/UE'] = generic.ByteStringObject(self.ueseed)
            result['/Perms'] = generic.ByteStringObject(self.encrypted_perms)
        return result

    def _auth_user_password_legacy(self, id1: bytes, password):
        rev = self.revision
        user_token = self.udata
        if rev == StandardSecuritySettingsRevision.RC4_BASIC:
            user_tok_supplied, key = _compute_u_value_r2(
                password, self.odata, self.perms, id1
            )
        else:
            user_tok_supplied, key = _compute_u_value_r34(
                password, rev.value, self.keylen, self.odata, self.perms, id1
            )
            user_tok_supplied = user_tok_supplied[:16]
            user_token = user_token[:16]

        return user_tok_supplied == user_token, key

    def _authenticate_legacy(self, id1: bytes, password):
        user_password, key = self._auth_user_password_legacy(id1, password)
        if user_password:
            return AuthResult.USER, key
        else:
            rev = self.revision
            key = _compute_o_value_legacy_prep(password, rev.value, self.keylen)
            if rev == StandardSecuritySettingsRevision.RC4_BASIC:
                userpass = rc4_encrypt(key, self.odata)
            else:
                val = self.odata
                for i in range(19, -1, -1):
                    new_key = bytes(b ^ i for b in key)
                    val = rc4_encrypt(new_key, val)
                userpass = val
            owner_password, key = self._auth_user_password_legacy(id1, userpass)
            if owner_password:
                return AuthResult.OWNER, key
        return AuthResult.UNKNOWN, None

    def authenticate(self, id1: bytes, password):
        rev = self.revision
        if rev == StandardSecuritySettingsRevision.AES256:
            res, key = self._authenticate_r6(password)
        else:
            password = _legacy_normalise_pw(password)
            res, key = self._authenticate_legacy(id1, password)
        if key is not None:
            self._shared_key = key
        else:
            self._auth_failed = True
        return res

    # Algorithm 2.A in ISO 32000-2 § 7.6.4.3.3
    def _authenticate_r6(self, password) -> Tuple[AuthResult, Optional[bytes]]:
        pw_bytes = _r6_normalise_pw(password)
        o_entry_split = R6KeyEntry.from_bytes(self.odata)
        u_entry_split = R6KeyEntry.from_bytes(self.udata)

        if _r6_password_authenticate(pw_bytes, o_entry_split, self.udata):
            result = AuthResult.OWNER
            key = _r6_derive_file_key(
                pw_bytes, o_entry_split, self.oeseed, self.udata
            )
        elif _r6_password_authenticate(pw_bytes, u_entry_split):
            result = AuthResult.USER
            key = _r6_derive_file_key(pw_bytes, u_entry_split, self.ueseed)
        else:
            return AuthResult.UNKNOWN, None

        # check the file key against the perms entry

        # Standard says ECB (which oscrypto doesn't support),
        # but one round of CBC with IV = 0 is equivalent to ECB
        decrypted_p_entry = symmetric.aes_cbc_no_padding_decrypt(
            key, self.encrypted_perms, bytes(16)
        )

        # known plaintext mandated in the standard ...sigh...
        perms_ok = decrypted_p_entry[9:12] == b'adb'
        perms_ok &= self.perms == struct.unpack('<i', decrypted_p_entry[:4])[0]
        try:
            # check encrypt_metadata flag
            decr_metadata_flag = _EXPECTED_PERMS_8[decrypted_p_entry[8]]
            perms_ok &= decr_metadata_flag == self.encrypt_metadata
        except KeyError:
            perms_ok = False

        if not perms_ok:
            raise misc.PdfError(
                "File decryption key didn't decrypt permission flags "
                "correctly -- file permissions may have been tampered with."
            )
        return result, key

    def derive_object_key(self, idnum, generation):
        if self.version == StandardSecurityHandlerVersion.AES256:
            return self.shared_key
        else:
            return legacy_derive_object_key(self.shared_key, idnum, generation)

    def get_string_filter(self) -> CryptFilter:
        return self.crypt_filter_config.get_for_string()

    def get_stream_filter(self, name=None) -> CryptFilter:
        if name is None:
            return self.crypt_filter_config.get_for_stream()
        return self.crypt_filter_config[name]
