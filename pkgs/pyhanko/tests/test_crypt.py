import binascii
import os
from io import BytesIO
from typing import Optional

import pytest
from asn1crypto import cms, x509
from certomancer.registry import ArchLabel, CertLabel, KeyLabel
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils import generic, misc, writer
from pyhanko.pdf_utils.crypt import (
    DEFAULT_CRYPT_FILTER,
    STD_CF,
    AuthStatus,
    CryptFilterConfiguration,
    IdentityCryptFilter,
    PdfKeyNotAvailableError,
    PubKeyAdbeSubFilter,
    PubKeyAESCryptFilter,
    PubKeyRC4CryptFilter,
    PubKeySecurityHandler,
    SecurityHandler,
    SecurityHandlerVersion,
    SerialisedCredential,
    SimpleEnvelopeKeyDecrypter,
    StandardAESCryptFilter,
    StandardRC4CryptFilter,
    StandardSecurityHandler,
    StandardSecuritySettingsRevision,
    build_crypt_filter,
    pubkey,
)
from pyhanko.pdf_utils.crypt.permissions import (
    PubKeyPermissions,
    StandardPermissions,
)
from pyhanko.pdf_utils.crypt.standard import StandardAESGCMCryptFilter
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from .samples import (
    CERTOMANCER,
    MINIMAL,
    MINIMAL_AES256,
    MINIMAL_ONE_FIELD,
    MINIMAL_ONE_FIELD_AES256,
    PDF_DATA_DIR,
    PUBKEY_SELFSIGNED_DECRYPTER,
    PUBKEY_TEST_DECRYPTER,
    PUBKEY_TEST_DECRYPTER_OLD,
    TEST_DIR,
    TESTING_CA_DIR,
    VECTOR_IMAGE_PDF,
)

STD_PERMS = (
    ~StandardPermissions.ALLOW_MODIFICATION_GENERIC
    & ~StandardPermissions.ALLOW_ANNOTS_FORM_FILLING
)

PUBKEY_PERMS = (
    ~PubKeyPermissions.ALLOW_ENCRYPTION_CHANGE
    & ~PubKeyPermissions.ALLOW_MODIFICATION_GENERIC
    & ~PubKeyPermissions.ALLOW_ANNOTS_FORM_FILLING
)


def _produce_legacy_encrypted_file(rev, keylen_bytes, use_aes):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()
    sh = StandardSecurityHandler.build_from_pw_legacy(
        rev,
        w._document_id[0].original_bytes,
        "ownersecret",
        "usersecret",
        keylen_bytes=keylen_bytes,
        use_aes128=use_aes,
        perms=STD_PERMS,
    )
    w._assign_security_handler(sh)
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    return out


@pytest.mark.parametrize(
    "use_owner_pass,rev,keylen_bytes,use_aes",
    [
        (True, StandardSecuritySettingsRevision.RC4_BASIC, 5, False),
        (False, StandardSecuritySettingsRevision.RC4_BASIC, 5, False),
        (True, StandardSecuritySettingsRevision.RC4_EXTENDED, 5, False),
        (False, StandardSecuritySettingsRevision.RC4_EXTENDED, 5, False),
        (True, StandardSecuritySettingsRevision.RC4_EXTENDED, 16, False),
        (False, StandardSecuritySettingsRevision.RC4_EXTENDED, 16, False),
        (True, StandardSecuritySettingsRevision.RC4_OR_AES128, 5, False),
        (False, StandardSecuritySettingsRevision.RC4_OR_AES128, 5, False),
        (True, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, False),
        (False, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, False),
        (True, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, True),
        (False, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, True),
    ],
)
def test_legacy_encryption(use_owner_pass, rev, keylen_bytes, use_aes):
    out = _produce_legacy_encrypted_file(rev, keylen_bytes, use_aes)
    r = PdfFileReader(out)
    result = r.decrypt("ownersecret" if use_owner_pass else "usersecret")
    if use_owner_pass:
        assert result.status == AuthStatus.OWNER
    else:
        assert result.status == AuthStatus.USER
    assert result.permission_flags.as_sint32() == -44
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert r.trailer['/Encrypt']['/P'] == -44
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data


@pytest.mark.parametrize("legacy", [True, False])
def test_wrong_password(legacy):
    w = writer.PdfFileWriter()
    ref = w.add_object(generic.TextStringObject("Blah blah"))
    if legacy:
        sh = StandardSecurityHandler.build_from_pw_legacy(
            StandardSecuritySettingsRevision.RC4_OR_AES128,
            w._document_id[0].original_bytes,
            "ownersecret",
            "usersecret",
            keylen_bytes=16,
            use_aes128=True,
        )
    else:
        sh = StandardSecurityHandler.build_from_pw("ownersecret", "usersecret")
    w.security_handler = sh
    w._encrypt = w.add_object(sh.as_pdf_object())
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    with pytest.raises(misc.PdfReadError):
        r.get_object(ref.reference)
    assert r.decrypt("thispasswordiswrong").status == AuthStatus.FAILED
    assert r.security_handler._auth_failed
    assert r.security_handler.get_string_filter()._auth_failed
    with pytest.raises(misc.PdfReadError):
        r.get_object(ref.reference)


def test_identity_crypt_filter_api():
    # confirm that the CryptFilter API of the identity filter doesn't do
    # anything unexpected, even though we typically don't invoke it explicitly.
    idf: IdentityCryptFilter = IdentityCryptFilter()
    idf._set_security_handler(None)
    assert not idf._auth_failed
    assert isinstance(idf.derive_shared_encryption_key(), bytes)
    assert isinstance(idf.derive_object_key(1, 2), bytes)
    assert isinstance(idf.method, generic.NameObject)
    assert isinstance(idf.keylen, int)
    assert idf.decrypt(None, b'abc') == b'abc'
    assert idf.encrypt(None, b'abc') == b'abc'

    # can't serialise /Identity
    with pytest.raises(misc.PdfError):
        idf.as_pdf_object()


@pytest.mark.parametrize(
    "use_alias, with_never_decrypt",
    [(True, False), (False, True), (False, False)],
)
def test_identity_crypt_filter(use_alias, with_never_decrypt):
    w = writer.PdfFileWriter()
    sh = StandardSecurityHandler.build_from_pw("secret")
    w.security_handler = sh
    idf: IdentityCryptFilter = IdentityCryptFilter()
    assert sh.crypt_filter_config[pdf_name("/Identity")] is idf
    if use_alias:
        sh.crypt_filter_config._crypt_filters[pdf_name("/IdentityAlias")] = idf
        assert sh.crypt_filter_config[pdf_name("/IdentityAlias")] is idf
    if use_alias:
        # identity filter can't be serialised, so this should throw an error
        with pytest.raises(misc.PdfError):
            w._assign_security_handler(sh)
        return
    else:
        w._assign_security_handler(sh)
    test_bytes = b'This is some test data that should remain unencrypted.'
    test_stream = generic.StreamObject(stream_data=test_bytes, handler=sh)
    test_stream.apply_filter(
        "/Crypt", params={pdf_name("/Name"): pdf_name("/Identity")}
    )
    ref = w.add_object(test_stream).reference
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    r.decrypt("secret")
    the_stream = r.get_object(ref, never_decrypt=with_never_decrypt)
    assert the_stream.encoded_data == test_bytes
    assert the_stream.data == test_bytes


def _produce_pubkey_encrypted_file(
    version,
    keylen,
    use_aes,
    use_crypt_filters,
    policy: pubkey.RecipientEncryptionPolicy = pubkey.RecipientEncryptionPolicy(),
    cert: Optional[x509.Certificate] = None,
):
    if cert is None:
        cert = PUBKEY_TEST_DECRYPTER.cert
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs(
        [cert],
        keylen_bytes=keylen,
        version=version,
        use_aes=use_aes,
        use_crypt_filters=use_crypt_filters,
        perms=PUBKEY_PERMS,
        policy=policy,
        pdf_mac=False,
    )
    w._assign_security_handler(sh)
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    return out


def _validate_pubkey_decryption(r, result):
    assert result.status == AuthStatus.USER
    assert result.permission_flags == PUBKEY_PERMS
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data


def _extract_ktri_kea(r: PdfFileReader):
    recp_bytes = r.encrypt_dict['/CF']['/DefaultCryptFilter']['/Recipients'][0]
    content_info = cms.ContentInfo.load(recp_bytes)
    ktri = content_info['content']['recipient_infos'][0].chosen
    return ktri['key_encryption_algorithm']['algorithm'].native


@pytest.mark.parametrize(
    "version, keylen, use_aes, use_crypt_filters",
    [
        (SecurityHandlerVersion.AES256, 32, True, True),
        (SecurityHandlerVersion.RC4_OR_AES128, 16, True, True),
        (SecurityHandlerVersion.RC4_OR_AES128, 16, False, True),
        (SecurityHandlerVersion.RC4_OR_AES128, 5, False, True),
        (SecurityHandlerVersion.RC4_40, 5, False, True),
        (SecurityHandlerVersion.RC4_40, 5, False, False),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, True),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, False),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, True),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, False),
    ],
)
def test_pubkey_encryption(version, keylen, use_aes, use_crypt_filters):
    out = _produce_pubkey_encrypted_file(
        version, keylen, use_aes, use_crypt_filters
    )
    r = PdfFileReader(out)
    if version == SecurityHandlerVersion.AES256:
        assert r.input_version == (2, 0)
    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    _validate_pubkey_decryption(r, result)
    if version == SecurityHandlerVersion.AES256:
        kea = _extract_ktri_kea(r)
        assert kea == 'rsaes_pkcs1v15'


@pytest.mark.parametrize(
    'lbl',
    [
        'decrypter1',
        'decrypter2',
        'decrypter3',
        'decrypter-x25519',
        'decrypter-x448',
    ],
)
def test_ecdh_encryption(lbl):
    pki_arch = CERTOMANCER.get_pki_arch(
        ArchLabel('ecc-testing-ca-with-decrypters')
    )
    cert = pki_arch.get_cert(CertLabel(lbl))
    out = _produce_pubkey_encrypted_file(
        version=SecurityHandlerVersion.AES256,
        keylen=32,
        use_aes=True,
        use_crypt_filters=True,
        cert=cert,
    )
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(
        SimpleEnvelopeKeyDecrypter(
            cert, pki_arch.key_set.get_private_key(KeyLabel(lbl))
        )
    )
    _validate_pubkey_decryption(r, result)


def test_oaep_encryption():
    out = _produce_pubkey_encrypted_file(
        version=SecurityHandlerVersion.AES256,
        keylen=32,
        use_aes=True,
        use_crypt_filters=True,
        policy=pubkey.RecipientEncryptionPolicy(prefer_oaep=True),
    )
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    _validate_pubkey_decryption(r, result)
    kea = _extract_ktri_kea(r)
    assert kea == 'rsaes_oaep'


def test_ecdh_decryption_smoke():
    pki_arch = CERTOMANCER.get_pki_arch(
        ArchLabel('ecc-testing-ca-with-decrypters')
    )
    cert = pki_arch.get_cert(CertLabel('decrypter3'))
    decrypter = SimpleEnvelopeKeyDecrypter(
        cert, pki_arch.key_set.get_private_key(KeyLabel('decrypter3'))
    )
    with open(f'{PDF_DATA_DIR}/pubkey-ecc-test.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        result = r.decrypt_pubkey(decrypter)
        assert result.status == AuthStatus.USER
        assert result.permission_flags == PubKeyPermissions.allow_everything()


def test_ecdh_decryption_wrong_key_type():
    pki_arch = CERTOMANCER.get_pki_arch(
        ArchLabel('ecc-testing-ca-with-decrypters')
    )
    cert = pki_arch.get_cert(CertLabel('decrypter3'))
    with open(f'{PDF_DATA_DIR}/pubkey-ecc-test.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        decrypter = SimpleEnvelopeKeyDecrypter(
            cert=cert, private_key=PUBKEY_TEST_DECRYPTER.private_key
        )
        with pytest.raises(pubkey.InappropriateCredentialError):
            r.decrypt_pubkey(decrypter)


def test_ecdh_decryption_wrong_curve():
    pki_arch = CERTOMANCER.get_pki_arch(
        ArchLabel('ecc-testing-ca-with-decrypters')
    )
    cert = pki_arch.get_cert(CertLabel('decrypter3'))
    with open(f'{PDF_DATA_DIR}/pubkey-ecc-test.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        decrypter = SimpleEnvelopeKeyDecrypter(
            cert=cert,
            private_key=pki_arch.key_set.get_private_key(
                KeyLabel('decrypter1')
            ),
        )
        with pytest.raises(misc.PdfReadError, match='Failed to decrypt'):
            r.decrypt_pubkey(decrypter)


def test_rsa_decryption_wrong_key_type():
    pki_arch = CERTOMANCER.get_pki_arch(
        ArchLabel('ecc-testing-ca-with-decrypters')
    )
    key = pki_arch.key_set.get_private_key(KeyLabel('decrypter1'))
    with open(f'{PDF_DATA_DIR}/minimal-pubkey-rc4-envelope.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        decrypter = SimpleEnvelopeKeyDecrypter(
            cert=PUBKEY_TEST_DECRYPTER_OLD.cert, private_key=key
        )
        with pytest.raises(pubkey.InappropriateCredentialError):
            r.decrypt_pubkey(decrypter)


@pytest.mark.parametrize(
    'lbl', ['decrypter1', 'decrypter-x25519', 'decrypter-x448']
)
def test_invalid_originator_key(monkeypatch, lbl):
    pki_arch = CERTOMANCER.get_pki_arch(
        ArchLabel('ecc-testing-ca-with-decrypters')
    )
    cert = pki_arch.get_cert(CertLabel(lbl))
    priv_key = pki_arch.key_set.get_private_key(KeyLabel(lbl))

    def _format_kari(
        rid,
        originator_key,
        algo,
        ukm,
        encrypted_data,
    ):
        return cms.RecipientInfo(
            name='kari',
            value=cms.KeyAgreeRecipientInfo(
                {
                    'version': 3,
                    'originator': cms.OriginatorIdentifierOrKey(
                        name='originator_key',
                        value=PUBKEY_TEST_DECRYPTER.cert.public_key,
                    ),
                    'ukm': ukm,
                    'key_encryption_algorithm': algo,
                    'recipient_encrypted_keys': [
                        cms.RecipientEncryptedKey(
                            {'rid': rid, 'encrypted_key': encrypted_data}
                        )
                    ],
                }
            ),
        )

    monkeypatch.setattr(pubkey, '_format_kari', _format_kari)
    out = _produce_pubkey_encrypted_file(
        version=SecurityHandlerVersion.AES256,
        keylen=32,
        use_aes=True,
        use_crypt_filters=True,
        cert=cert,
    )

    r = PdfFileReader(out)
    decrypter = SimpleEnvelopeKeyDecrypter(
        cert=cert,
        private_key=priv_key,
    )
    with pytest.raises(misc.PdfReadError):
        r.decrypt_pubkey(decrypter)


def test_key_encipherment_requirement():
    with pytest.raises(misc.PdfWriteError):
        PubKeySecurityHandler.build_from_certs(
            [PUBKEY_SELFSIGNED_DECRYPTER.cert],
            keylen_bytes=32,
            version=SecurityHandlerVersion.AES256,
            use_aes=True,
            use_crypt_filters=True,
            perms=PUBKEY_PERMS,
            pdf_mac=False,
        )


@pytest.mark.parametrize(
    "version, keylen, use_aes, use_crypt_filters",
    [
        (SecurityHandlerVersion.AES256, 32, True, True),
        (SecurityHandlerVersion.RC4_OR_AES128, 16, True, True),
        (SecurityHandlerVersion.RC4_OR_AES128, 16, False, True),
        (SecurityHandlerVersion.RC4_OR_AES128, 5, False, True),
        (SecurityHandlerVersion.RC4_40, 5, False, True),
        (SecurityHandlerVersion.RC4_40, 5, False, False),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, True),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, False),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, True),
        (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, False),
    ],
)
def test_key_encipherment_requirement_override(
    version, keylen, use_aes, use_crypt_filters
):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_SELFSIGNED_DECRYPTER.cert],
        keylen_bytes=keylen,
        version=version,
        use_aes=use_aes,
        use_crypt_filters=use_crypt_filters,
        perms=PUBKEY_PERMS,
        policy=pubkey.RecipientEncryptionPolicy(ignore_key_usage=True),
        pdf_mac=False,
    )
    w._assign_security_handler(sh)
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(PUBKEY_SELFSIGNED_DECRYPTER)
    _validate_pubkey_decryption(r, result)


def test_pubkey_alternative_filter():
    w = writer.PdfFileWriter()

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    # subfilter should be picked up
    w._encrypt.get_object()['/Filter'] = pdf_name('/FooBar')
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert isinstance(r.security_handler, PubKeySecurityHandler)


@pytest.mark.parametrize('delete_subfilter', [True, False])
def test_pubkey_unsupported_filter(delete_subfilter):
    w = writer.PdfFileWriter()

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    encrypt = w._encrypt.get_object()
    encrypt['/Filter'] = pdf_name('/FooBar')
    if delete_subfilter:
        del encrypt['/SubFilter']
    else:
        encrypt['/SubFilter'] = pdf_name('/baz.quux')
    out = BytesIO()
    w.write(out)
    with pytest.raises(misc.PdfReadError):
        # noinspection PyStatementEffect
        PdfFileReader(out).root['/Pages']['/Kids'][0]['/Content'].data


def test_pubkey_encryption_block_cfs_s4():
    w = writer.PdfFileWriter()

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    encrypt = w._encrypt.get_object()
    encrypt['/SubFilter'] = pdf_name('/adbe.pkcs7.s4')
    out = BytesIO()
    w.write(out)
    with pytest.raises(misc.PdfReadError):
        # noinspection PyStatementEffect
        PdfFileReader(out).root['/Pages']['/Kids'][0]['/Content'].data


def test_pubkey_encryption_s5_requires_cfs():
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs([PUBKEY_TEST_DECRYPTER.cert])
    w._assign_security_handler(sh)
    encrypt = w._encrypt.get_object()
    del encrypt['/CF']
    out = BytesIO()
    w.write(out)
    with pytest.raises(misc.PdfReadError):
        # noinspection PyStatementEffect
        PdfFileReader(out).root['/Pages']['/Kids'][0]['/Content'].data


def test_pubkey_encryption_dict_errors():
    sh = PubKeySecurityHandler.build_from_certs([PUBKEY_TEST_DECRYPTER.cert])

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    encrypt['/SubFilter'] = pdf_name('/asdflakdsjf')
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    encrypt['/Length'] = generic.NumberObject(13)
    with pytest.raises(misc.PdfError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    del encrypt['/CF']['/DefaultCryptFilter']['/CFM']
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    del encrypt['/CF']['/DefaultCryptFilter']['/Recipients']
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    encrypt['/CF']['/DefaultCryptFilter']['/CFM'] = pdf_name('/None')
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)


@pytest.mark.parametrize(
    'with_hex_filter, main_unencrypted',
    [(True, False), (True, True), (False, True), (False, False)],
)
def test_custom_crypt_filter(with_hex_filter, main_unencrypted):
    w = writer.PdfFileWriter()
    custom = pdf_name('/Custom')
    crypt_filters = {
        custom: StandardRC4CryptFilter(keylen=16),
    }
    if main_unencrypted:
        # streams/strings are unencrypted by default
        cfc = CryptFilterConfiguration(crypt_filters=crypt_filters)
        assert len(cfc.filters()) == 1
    else:
        crypt_filters[STD_CF] = StandardAESCryptFilter(keylen=16)
        cfc = CryptFilterConfiguration(
            crypt_filters=crypt_filters,
            default_string_filter=STD_CF,
            default_stream_filter=STD_CF,
        )
        assert len(cfc.filters()) == 2
    sh = StandardSecurityHandler.build_from_pw_legacy(
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        id1=w.document_id[0],
        desired_user_pass="usersecret",
        desired_owner_pass="ownersecret",
        keylen_bytes=16,
        crypt_filter_config=cfc,
    )
    w._assign_security_handler(sh)
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    dummy_stream.add_crypt_filter(name=custom, handler=sh)
    ref = w.add_object(dummy_stream)
    dummy_stream2 = generic.StreamObject(stream_data=test_data)
    ref2 = w.add_object(dummy_stream2)

    if with_hex_filter:
        dummy_stream.apply_filter(pdf_name('/AHx'))
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    r.decrypt("ownersecret")
    obj: generic.StreamObject = r.get_object(ref.reference)
    assert obj.data == test_data
    if with_hex_filter:
        cf_dict = obj['/DecodeParms'][1]
    else:
        cf_dict = obj['/DecodeParms']

    assert cf_dict['/Name'] == pdf_name('/Custom')

    obj2: generic.DecryptedObjectProxy = r.get_object(
        ref2.reference, transparent_decrypt=False
    )
    raw = obj2.raw_object
    assert isinstance(raw, generic.StreamObject)
    if main_unencrypted:
        assert raw.encoded_data == test_data
    else:
        assert raw.encoded_data != test_data


@pytest.mark.parametrize(
    'with_hex_filter, main_unencrypted',
    [(True, False), (True, True), (False, True), (False, False)],
)
def test_custom_pubkey_crypt_filter(with_hex_filter, main_unencrypted):
    w = writer.PdfFileWriter()
    custom = pdf_name('/Custom')
    crypt_filters = {
        custom: PubKeyRC4CryptFilter(keylen=16),
    }
    if main_unencrypted:
        # streams/strings are unencrypted by default
        cfc = CryptFilterConfiguration(crypt_filters=crypt_filters)
    else:
        crypt_filters[DEFAULT_CRYPT_FILTER] = PubKeyAESCryptFilter(
            keylen=16, acts_as_default=True
        )
        cfc = CryptFilterConfiguration(
            crypt_filters=crypt_filters,
            default_string_filter=DEFAULT_CRYPT_FILTER,
            default_stream_filter=DEFAULT_CRYPT_FILTER,
        )
    sh = PubKeySecurityHandler(
        version=SecurityHandlerVersion.RC4_OR_AES128,
        pubkey_handler_subfilter=PubKeyAdbeSubFilter.S5,
        legacy_keylen=16,
        crypt_filter_config=cfc,
    )

    # if main_unencrypted, these should be no-ops
    sh.add_recipients([PUBKEY_TEST_DECRYPTER.cert])
    # (this is always pointless, but it should be allowed)
    sh.add_recipients([PUBKEY_TEST_DECRYPTER.cert])

    crypt_filters[custom].add_recipients(
        [PUBKEY_TEST_DECRYPTER.cert], policy=pubkey.RecipientEncryptionPolicy()
    )
    w._assign_security_handler(sh)

    encrypt_dict = w._encrypt.get_object()
    cfs = encrypt_dict['/CF']
    # no /Recipients in S5 mode
    assert '/Recipients' not in encrypt_dict
    assert isinstance(cfs[custom]['/Recipients'], generic.ByteStringObject)
    if main_unencrypted:
        assert DEFAULT_CRYPT_FILTER not in cfs
    else:
        default_rcpts = cfs[DEFAULT_CRYPT_FILTER]['/Recipients']
        assert isinstance(default_rcpts, generic.ArrayObject)
        assert len(default_rcpts) == 2

    # custom crypt filters can only have one set of recipients
    with pytest.raises(misc.PdfError):
        crypt_filters[custom].add_recipients(
            [PUBKEY_TEST_DECRYPTER.cert],
            policy=pubkey.RecipientEncryptionPolicy(),
        )

    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    dummy_stream.add_crypt_filter(name=custom, handler=sh)
    ref = w.add_object(dummy_stream)
    dummy_stream2 = generic.StreamObject(stream_data=test_data)
    ref2 = w.add_object(dummy_stream2)

    if with_hex_filter:
        dummy_stream.apply_filter(pdf_name('/AHx'))
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)

    # the custom test filter shouldn't have been decrypted yet
    # so attempting to decode the stream should cause the crypt filter
    # to throw an error
    obj: generic.StreamObject = r.get_object(ref.reference)
    with pytest.raises(misc.PdfError):
        # noinspection PyStatementEffect
        obj.data

    r.security_handler.crypt_filter_config[custom].authenticate(
        PUBKEY_TEST_DECRYPTER
    )
    assert obj.data == test_data
    if with_hex_filter:
        cf_dict = obj['/DecodeParms'][1]
    else:
        cf_dict = obj['/DecodeParms']

    assert cf_dict['/Name'] == pdf_name('/Custom')

    obj2: generic.DecryptedObjectProxy = r.get_object(
        ref2.reference, transparent_decrypt=False
    )
    raw = obj2.raw_object
    assert isinstance(raw, generic.StreamObject)
    if main_unencrypted:
        assert raw.encoded_data == test_data
    else:
        assert raw.encoded_data != test_data


def test_custom_crypt_filter_errors():
    w = writer.PdfFileWriter()
    custom = pdf_name('/Custom')
    crypt_filters = {
        custom: StandardRC4CryptFilter(keylen=16),
        STD_CF: StandardAESCryptFilter(keylen=16),
    }
    cfc = CryptFilterConfiguration(
        crypt_filters=crypt_filters,
        default_string_filter=STD_CF,
        default_stream_filter=STD_CF,
    )
    sh = StandardSecurityHandler.build_from_pw_legacy(
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        id1=w.document_id[0],
        desired_user_pass="usersecret",
        desired_owner_pass="ownersecret",
        keylen_bytes=16,
        crypt_filter_config=cfc,
    )
    w._assign_security_handler(sh)
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    with pytest.raises(misc.PdfStreamError):
        dummy_stream.add_crypt_filter(name='/Idontexist', handler=sh)

    # no handler
    dummy_stream.add_crypt_filter(name=custom)
    dummy_stream._handler = None
    w.add_object(dummy_stream)

    out = BytesIO()
    with pytest.raises(misc.PdfStreamError):
        w.write(out)


@pytest.mark.parametrize('pdf_mac', [True, False])
def test_continue_encrypted_file_without_auth(pdf_mac):
    w = writer.PdfFileWriter()
    w.root["/Test"] = generic.TextStringObject("Blah blah")
    w.encrypt("ownersecret", "usersecret", pdf_mac=pdf_mac)
    out = BytesIO()
    w.write(out)
    incr_w = IncrementalPdfFileWriter(out)
    incr_w.root["/Test"] = generic.TextStringObject("Bluh bluh")
    incr_w.update_root()
    with pytest.raises(PdfKeyNotAvailableError):
        incr_w.write_in_place()


def test_continue_encrypted_file_without_auth_disable_meta():
    w = writer.PdfFileWriter()
    w.root["/Test"] = generic.TextStringObject("Blah blah")
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    incr_w = IncrementalPdfFileWriter(out)
    incr_w._update_meta = lambda: None
    incr_w.root["/Test"] = generic.TextStringObject("Bluh bluh")
    incr_w.update_root()
    with pytest.raises(PdfKeyNotAvailableError):
        incr_w.write_in_place()


def test_continue_encrypted_file_without_auth_disable_meta_and_mac():
    w = writer.PdfFileWriter()
    w.root["/Test"] = generic.TextStringObject("Blah blah")
    w.encrypt("ownersecret", "usersecret", pdf_mac=False)
    out = BytesIO()
    w.write(out)
    incr_w = IncrementalPdfFileWriter(out)
    incr_w._update_meta = lambda: None
    incr_w.root["/Test"] = generic.TextStringObject("Bluh bluh")
    incr_w.update_root()
    with pytest.raises(misc.PdfWriteError, match="Cannot update"):
        incr_w.write_in_place()


def test_continue_encrypted_file_from_reader():
    w = writer.PdfFileWriter()
    w.root["/Test"] = generic.TextStringObject("Blah blah")
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    # first decrypt, then extend
    r.decrypt("usersecret")
    incr_w = IncrementalPdfFileWriter.from_reader(r)
    incr_w.root["/Test"] = generic.TextStringObject("Bluh bluh")
    incr_w.update_root()
    incr_w.write_in_place()

    r = PdfFileReader(out)
    r.decrypt("usersecret")
    assert r.root['/Test'] == generic.TextStringObject("Bluh bluh")


def test_aes256_perm_read():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_AES256))
    result = r.decrypt("ownersecret")
    assert result.status == AuthStatus.OWNER
    assert result.permission_flags == StandardPermissions.allow_everything()
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_AES256))
    result = r.decrypt("usersecret")
    assert result.status == AuthStatus.USER
    assert result.permission_flags == StandardPermissions.allow_everything()

    assert r.trailer['/Encrypt']['/P'] == -4


def test_copy_encrypted_file():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_AES256))
    r.decrypt("ownersecret")
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1


def test_copy_to_encrypted_file():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt("ownersecret")
    assert result.status == AuthStatus.OWNER
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1


def test_correctly_align_perms():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    perms = ~StandardPermissions.allow_everything()
    w.encrypt("ownersecret", "usersecret", perms=perms)
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt("usersecret")
    assert result.status == AuthStatus.USER
    assert result.permission_flags == perms


def test_default_no_gcm():
    # document the fact that we don't yet apply ISO/TS 32003 by default
    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r)
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.decrypt("usersecret").status == AuthStatus.USER
    assert isinstance(
        r.security_handler.get_stream_filter(), StandardAESCryptFilter
    )


def test_gcm_via_encrypt_call():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r)
    w.encrypt("ownersecret", "usersecret", use_gcm=True)
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.decrypt("usersecret").status == AuthStatus.USER
    assert isinstance(
        r.security_handler.get_stream_filter(), StandardAESGCMCryptFilter
    )


def test_empty_user_pass():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    w.encrypt('ownersecret', '')
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt('')
    assert result.status == AuthStatus.USER
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1
    assert r.root['/AcroForm']['/Fields'][0]['/T'] == 'Sig1'


def test_load_pkcs12():
    sedk = SimpleEnvelopeKeyDecrypter.load_pkcs12(
        f"{TEST_DIR}/data/crypto/selfsigned.pfx", b'exportsecret'
    )
    assert sedk.cert.subject == PUBKEY_SELFSIGNED_DECRYPTER.cert.subject


def test_pubkey_wrong_content_type():
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_TEST_DECRYPTER.cert],
        version=SecurityHandlerVersion.RC4_40,
        keylen_bytes=16,
        use_aes=True,
        use_crypt_filters=False,
    )
    w.security_handler = sh
    enc_dict = sh.as_pdf_object()
    from asn1crypto import cms

    cms_bytes = cms.ContentInfo(
        {
            'content_type': cms.ContentType('data'),
            'content': cms.OctetString(b"\xde\xad\xbe\xef"),
        }
    ).dump()
    enc_dict['/Recipients'][0] = generic.ByteStringObject(cms_bytes)
    w._encrypt = w.add_object(enc_dict)
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    with pytest.raises(misc.PdfReadError, match="must be enveloped"):
        r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)


def test_pubkey_wrong_cert():
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    recpt_cert = load_cert_from_pemder(
        TESTING_CA_DIR + '/interm/decrypter2.cert.pem'
    )
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    ref = w.add_object(dummy_stream)
    w.encrypt_pubkey([recpt_cert])
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    assert result.status == AuthStatus.FAILED

    with pytest.raises(misc.PdfError):
        r.get_object(ref.reference)


def test_crypt_filter_build_failures():
    cfdict = generic.DictionaryObject()
    assert build_crypt_filter({}, cfdict, False) is None
    cfdict['/CFM'] = generic.NameObject('/None')
    assert build_crypt_filter({}, cfdict, False) is None

    with pytest.raises(NotImplementedError):
        cfdict['/CFM'] = generic.NameObject('/NoSuchCF')
        build_crypt_filter({}, cfdict, False)


@pytest.mark.parametrize('on_subclass', [True, False])
def test_custom_crypt_filter_type(on_subclass):
    w = writer.PdfFileWriter()
    custom_cf_type = pdf_name('/CustomCFType')

    class CustomCFClass(StandardRC4CryptFilter):
        def __init__(self):
            super().__init__(keylen=16)

        method = custom_cf_type

    if on_subclass:

        class NewStandardSecurityHandler(StandardSecurityHandler):
            pass

        sh_class = NewStandardSecurityHandler
        assert (
            sh_class._known_crypt_filters
            is not StandardSecurityHandler._known_crypt_filters
        )
        assert '/V2' in sh_class._known_crypt_filters
        SecurityHandler.register(sh_class)
    else:
        sh_class = StandardSecurityHandler

    sh_class.register_crypt_filter(
        custom_cf_type,
        lambda _, __: CustomCFClass(),
    )
    cfc = CryptFilterConfiguration(
        crypt_filters={STD_CF: CustomCFClass()},
        default_string_filter=STD_CF,
        default_stream_filter=STD_CF,
    )
    sh = sh_class.build_from_pw_legacy(
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        id1=w.document_id[0],
        desired_user_pass="usersecret",
        desired_owner_pass="ownersecret",
        keylen_bytes=16,
        crypt_filter_config=cfc,
    )
    assert isinstance(sh, sh_class)
    w._assign_security_handler(sh)
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    ref = w.add_object(dummy_stream)

    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    r.decrypt("ownersecret")

    cfc = r.security_handler.crypt_filter_config
    assert cfc.stream_filter_name == cfc.string_filter_name
    obj: generic.StreamObject = r.get_object(ref.reference)
    assert obj.data == test_data

    obj: generic.DecryptedObjectProxy = r.get_object(
        ref.reference, transparent_decrypt=False
    )
    assert isinstance(obj.raw_object, generic.StreamObject)
    assert obj.raw_object.encoded_data != test_data

    # restore security handler registry state
    del sh_class._known_crypt_filters[custom_cf_type]
    if on_subclass:
        SecurityHandler.register(StandardSecurityHandler)


def test_security_handler_version_deser():
    assert (
        SecurityHandlerVersion.from_number(5) == SecurityHandlerVersion.AES256
    )
    assert SecurityHandlerVersion.from_number(0) == SecurityHandlerVersion.OTHER
    assert (
        SecurityHandlerVersion.from_number(None) == SecurityHandlerVersion.OTHER
    )

    assert (
        StandardSecuritySettingsRevision.from_number(6)
        == StandardSecuritySettingsRevision.AES256
    )
    assert (
        StandardSecuritySettingsRevision.from_number(0)
        == StandardSecuritySettingsRevision.OTHER
    )


def test_key_len():
    with pytest.raises(misc.PdfError):
        SecurityHandlerVersion.RC4_OR_AES128.check_key_length(20)
    assert SecurityHandlerVersion.RC4_OR_AES128.check_key_length(6) == 6
    assert SecurityHandlerVersion.AES256.check_key_length(6) == 32
    assert SecurityHandlerVersion.RC4_40.check_key_length(32) == 5
    assert SecurityHandlerVersion.RC4_LONGER_KEYS.check_key_length(16) == 16


@pytest.mark.parametrize('pw', ['usersecret', 'ownersecret'])
def test_ser_deser_credential_standard_sh(pw):
    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    r.decrypt(pw)
    cred = r.security_handler.extract_credential()
    assert cred['pwd_bytes'].native == pw.encode('utf8')
    cred_data = cred.serialise()

    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    result = r.security_handler.authenticate(cred_data)
    exp_status = AuthStatus.USER if pw.startswith('user') else AuthStatus.OWNER
    assert result.status == exp_status


def test_ser_deser_credential_standard_sh_extract_from_builder():
    sh = StandardSecurityHandler.build_from_pw("ownersecret", "usersecret")
    cred = sh.extract_credential()
    assert cred['pwd_bytes'].native == b'ownersecret'
    assert cred['id1'].native is None


def test_ser_deser_credential_wrong_pw():
    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    r.decrypt("ownersecret")
    cred = r.security_handler.extract_credential()
    cred['pwd_bytes'] = b'This is the wrong password'
    cred_data = cred.serialise()

    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    result = r.security_handler.authenticate(cred_data)
    assert result.status == AuthStatus.FAILED


def test_ser_deser_credential_standard_corrupted():
    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    r.decrypt("ownersecret")
    cred = r.security_handler.extract_credential()
    cred_data = SerialisedCredential(
        credential_type=cred.serialise().credential_type,
        data=b'\xde\xad\xbe\xef',
    )

    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    with pytest.raises(
        misc.PdfReadError, match="Failed to deserialise password"
    ):
        r.security_handler.authenticate(cred_data)


def test_ser_deser_credential_unknown_cred_type():
    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    r.decrypt("ownersecret")
    cred = r.security_handler.extract_credential()
    cred_data = SerialisedCredential(
        credential_type='foobar', data=cred.serialise().data
    )

    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    with pytest.raises(
        misc.PdfReadError, match="credential type 'foobar' not known"
    ):
        r.security_handler.authenticate(cred_data)


@pytest.mark.parametrize('pw', ['usersecret', 'ownersecret'])
def test_ser_deser_credential_standard_sh_legacy(pw):
    out = _produce_legacy_encrypted_file(
        StandardSecuritySettingsRevision.RC4_OR_AES128, 16, True
    )
    r = PdfFileReader(out)
    r.decrypt(pw)
    cred = r.security_handler.extract_credential()
    assert cred['pwd_bytes'].native == pw.encode('utf8')
    assert cred['id1'].native is not None
    cred_data = cred.serialise()

    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    result = r.security_handler.authenticate(cred_data)
    exp_status = AuthStatus.USER if pw.startswith('user') else AuthStatus.OWNER
    assert result.status == exp_status


@pytest.mark.parametrize('pw', ['usersecret', 'ownersecret'])
def test_ser_deser_credential_standard_sh_legacy_no_id1(pw):
    out = _produce_legacy_encrypted_file(
        StandardSecuritySettingsRevision.RC4_OR_AES128, 16, True
    )
    r = PdfFileReader(out)
    r.decrypt(pw)
    cred = r.security_handler.extract_credential()
    del cred['id1']
    cred_data = cred.serialise()

    r = PdfFileReader(out)
    with pytest.raises(misc.PdfReadError, match="id1"):
        r.security_handler.authenticate(cred_data)


def test_ser_deser_credential_standard_legacy_sh_extract_from_builder():
    sh = StandardSecurityHandler.build_from_pw_legacy(
        desired_owner_pass=b'ownersecret',
        desired_user_pass=b'usersecret',
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        keylen_bytes=16,
        id1=b'\xde\xad\xbe\xef',
    )
    cred = sh.extract_credential()
    assert cred['pwd_bytes'].native == b'ownersecret'
    assert cred['id1'].native == b'\xde\xad\xbe\xef'


def test_ser_deser_credential_pubkey():
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    cred_data = r.security_handler.extract_credential().serialise()

    r = PdfFileReader(out)
    result = r.security_handler.authenticate(cred_data)
    assert result.status == AuthStatus.USER


def test_ser_deser_credential_pubkey_sh_cannot_extract_from_builder():
    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_TEST_DECRYPTER.cert],
        keylen_bytes=16,
        version=SecurityHandlerVersion.RC4_OR_AES128,
        use_aes=True,
        use_crypt_filters=True,
        perms=PUBKEY_PERMS,
    )
    assert sh.extract_credential() is None


def test_ser_deser_credential_wrong_cred_type_pubkey():
    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    r.decrypt("ownersecret")
    cred_data = r.security_handler.extract_credential().serialise()

    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)
    with pytest.raises(misc.PdfReadError, match="must be an instance of"):
        r.security_handler.authenticate(cred_data)


def test_ser_deser_credential_wrong_cred_type_standard():
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    cred_data = r.security_handler.extract_credential().serialise()

    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    with pytest.raises(misc.PdfReadError, match="Standard auth.*must be a"):
        r.security_handler.authenticate(cred_data)


def test_ser_deser_credential_pubkey_corrupted():
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    cred = r.security_handler.extract_credential()
    cred_data = SerialisedCredential(
        credential_type=cred.serialise().credential_type,
        data=b'\xde\xad\xbe\xef',
    )

    r = PdfFileReader(out)
    with pytest.raises(
        misc.PdfReadError, match="Failed to decode serialised pubkey credential"
    ):
        r.security_handler.authenticate(cred_data)


def test_ser_deser_credential_wrong_cert():
    wrong_cert_cred_data = SimpleEnvelopeKeyDecrypter(
        cert=PUBKEY_SELFSIGNED_DECRYPTER.cert,
        private_key=PUBKEY_TEST_DECRYPTER.private_key,
    ).serialise()
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)

    result = r.security_handler.authenticate(wrong_cert_cred_data)
    assert result.status == AuthStatus.FAILED


def test_ser_deser_credential_wrong_key():
    wrong_key_cred_data = SimpleEnvelopeKeyDecrypter(
        cert=PUBKEY_TEST_DECRYPTER.cert,
        private_key=PUBKEY_SELFSIGNED_DECRYPTER.private_key,
    ).serialise()
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)

    # we're OK with this being an error, since a certificate match with a wrong
    # key is almost certainly indicative of something that shouldn't happen
    # in regular usage.
    with pytest.raises(misc.PdfReadError, match="envelope key"):
        r.security_handler.authenticate(wrong_key_cred_data)


@pytest.mark.parametrize('legacy', [True, False])
def test_encrypt_skipping_metadata(legacy):
    # we need to manually flag the metadata streams, since
    # pyHanko's PDF reader is (currently) not metadata-aware
    from pyhanko.pdf_utils.writer import copy_into_new_writer

    with open(
        os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb'
    ) as inf:
        w = copy_into_new_writer(PdfFileReader(inf))

    if legacy:
        sh = StandardSecurityHandler.build_from_pw_legacy(
            StandardSecuritySettingsRevision.RC4_OR_AES128,
            w._document_id[0].original_bytes,
            desired_owner_pass="secret",
            desired_user_pass="secret",
            keylen_bytes=16,
            use_aes128=True,
            perms=STD_PERMS,
            encrypt_metadata=False,
        )
        w._assign_security_handler(sh)
    else:
        w.encrypt("secret", "secret", encrypt_metadata=False)
    w.root['/Metadata'].apply_filter(
        "/Crypt", params={pdf_name("/Name"): pdf_name("/Identity")}
    )

    out = BytesIO()
    w.write(out)

    out.seek(0)
    r = PdfFileReader(out)
    mtd = r.root['/Metadata']
    assert not r.trailer['/Encrypt']['/EncryptMetadata']
    assert b'Test document' in mtd.encoded_data
    assert b'Test document' in mtd.data
    result = r.decrypt("secret")
    assert result.status == AuthStatus.OWNER

    assert r.trailer['/Info']['/Title'] == 'Test document'


def test_encrypt_skipping_metadata_pubkey():
    # we need to manually flag the metadata streams, since
    # pyHanko's PDF reader is (currently) not metadata-aware
    from pyhanko.pdf_utils.writer import copy_into_new_writer

    with open(
        os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb'
    ) as inf:
        w = copy_into_new_writer(PdfFileReader(inf))

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert], encrypt_metadata=False)
    w.root['/Metadata'].apply_filter(
        "/Crypt", params={pdf_name("/Name"): pdf_name("/Identity")}
    )

    out = BytesIO()
    w.write(out)

    out.seek(0)
    r = PdfFileReader(out)
    mtd = r.root['/Metadata']
    assert b'Test document' in mtd.encoded_data
    assert b'Test document' in mtd.data
    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    assert result.status == AuthStatus.USER

    assert r.trailer['/Info']['/Title'] == 'Test document'


def test_pubkey_rc4_envelope():
    fname = os.path.join(PDF_DATA_DIR, "minimal-pubkey-rc4-envelope.pdf")
    with open(fname, 'rb') as inf:
        r = PdfFileReader(inf)
        result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER_OLD)
        assert result.status == AuthStatus.USER
        assert b'Hello' in r.root['/Pages']['/Kids'][0]['/Contents'].data


def test_unknown_envelope_enc_type():
    fname = os.path.join(
        PDF_DATA_DIR, "minimal-pubkey-unknown-envelope-alg.pdf"
    )
    with open(fname, 'rb') as inf:
        r = PdfFileReader(inf)
        with pytest.raises(misc.PdfError, match="Cipher.*not allowed"):
            r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER_OLD)


BASIC_R6_ENC_DICT = generic.DictionaryObject(
    {
        pdf_name('/Filter'): pdf_name('/Standard'),
        pdf_name('/O'): generic.ByteStringObject(
            binascii.unhexlify(
                "047761f7f568bfacb096382f2fc7cc94ffd87f33dc472ca4"
                "a3a3a78c739c77df26a794a7819aff59b3b85780c0fafe9f"
            )
        ),
        pdf_name('/U'): generic.ByteStringObject(
            binascii.unhexlify(
                "446ea469061c56060b56fa0296bfd32cc54fa9175e92ef5c"
                "0b945f4c810e309a03af4a2ff103bbd4db065e036f78ac4c"
            )
        ),
        pdf_name('/OE'): generic.ByteStringObject(
            binascii.unhexlify(
                "65012afdd09b34431117b9fa5f557202"
                "940dece9758d53c61fc5ff436cf2515c"
            )
        ),
        pdf_name('/UE'): generic.ByteStringObject(
            binascii.unhexlify(
                "71071c8c117abc19d26b5efc44a08066"
                "7ef3c3665ad3bc8f5f5b58126a15d931"
            )
        ),
        pdf_name('/Perms'): generic.ByteStringObject(
            binascii.unhexlify("b8729f735b0976d80f61d16bcfe09273")
        ),
        pdf_name('/P'): generic.NumberObject(-4),
        pdf_name('/V'): generic.NumberObject(5),
        pdf_name('/R'): generic.NumberObject(6),
        pdf_name('/Length'): generic.NumberObject(256),
        pdf_name('/EncryptMetadata'): generic.BooleanObject(True),
        pdf_name('/StmF'): pdf_name('/StdCF'),
        pdf_name('/StrF'): pdf_name('/StdCF'),
        pdf_name('/CF'): generic.DictionaryObject(
            {
                pdf_name('/StdCF'): generic.DictionaryObject(
                    {
                        pdf_name('/AuthEvent'): pdf_name('/DocOpen'),
                        pdf_name('/CFM'): pdf_name('/AESV3'),
                        pdf_name('/Length'): generic.NumberObject(32),
                    }
                )
            }
        ),
    }
)


@pytest.mark.parametrize(
    'enc_entry,delete,err',
    [
        ('/OE', False, "be 32 bytes long"),
        ('/OE', True, "be 32 bytes long"),
        ('/UE', False, "be 32 bytes long"),
        ('/UE', True, "be 32 bytes long"),
        ('/O', False, "be 48 bytes long"),
        ('/O', True, "be present"),
        ('/U', False, "be 48 bytes long"),
        ('/U', True, "be present"),
        ('/Perms', False, "be 16 bytes long"),
        ('/Perms', True, "be 16 bytes long"),
    ],
)
def test_r6_values(enc_entry, delete, err):
    enc_dict = generic.DictionaryObject(BASIC_R6_ENC_DICT)
    if delete:
        del enc_dict[enc_entry]
    else:
        enc_dict[enc_entry] = generic.ByteStringObject(b'\xde\xad\xbe\xef')
    with pytest.raises(misc.PdfError, match=err):
        StandardSecurityHandler.instantiate_from_pdf_object(enc_dict)


@pytest.mark.parametrize('entry', ["/U", "/O"])
def test_legacy_o_u_values(entry):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()
    sh = StandardSecurityHandler.build_from_pw_legacy(
        StandardSecuritySettingsRevision.RC4_OR_AES128,
        w._document_id[0].original_bytes,
        "ownersecret",
        "usersecret",
        keylen_bytes=True,
        use_aes128=True,
        perms=STD_PERMS,
    )
    w.security_handler = sh
    enc_dict = sh.as_pdf_object()
    enc_dict[entry] = generic.ByteStringObject(b"\xde\xad\xbe\xef")
    w._encrypt = w.add_object(enc_dict)
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)

    with pytest.raises(misc.PdfError, match="be 32 bytes long"):
        # noinspection PyStatementEffect
        PdfFileReader(out).root['/Pages']['/Kids'][0]['/Content'].data


def test_key_length_constraint():
    enc_dict = generic.DictionaryObject(BASIC_R6_ENC_DICT)
    enc_dict['/Length'] = generic.NumberObject(333)
    with pytest.raises(misc.PdfError, match="must be a multiple of 8"):
        StandardSecurityHandler.instantiate_from_pdf_object(enc_dict)


def test_perms_decrypt_bogus():
    enc_dict = generic.DictionaryObject(BASIC_R6_ENC_DICT)
    enc_dict['/Perms'] = generic.ByteStringObject(b'\xde\xad\xbe\xef' * 4)
    sh = StandardSecurityHandler.instantiate_from_pdf_object(enc_dict)
    with pytest.raises(misc.PdfError, match="tampered"):
        sh.authenticate("usersecret")


def test_legacy_no_r6():
    with pytest.raises(ValueError, match="not supported"):
        _produce_legacy_encrypted_file(
            StandardSecuritySettingsRevision.AES256, 32, True
        )


def test_legacy_cf_req():
    with pytest.raises(misc.PdfError, match="s5 is required"):
        PubKeySecurityHandler.build_from_certs(
            [PUBKEY_TEST_DECRYPTER.cert],
            keylen_bytes=16,
            version=SecurityHandlerVersion.RC4_OR_AES128,
            use_aes=True,
            use_crypt_filters=False,
        )


def test_add_recp_before_auth_fail():
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)
    cf = r.security_handler.get_stream_filter()
    with pytest.raises(misc.PdfError, match="before authenticating"):
        cf.add_recipients(
            [PUBKEY_SELFSIGNED_DECRYPTER.cert],
            policy=pubkey.RecipientEncryptionPolicy(),
        )


def test_add_recp_after_key_deriv():
    out = _produce_pubkey_encrypted_file(
        SecurityHandlerVersion.RC4_OR_AES128, 16, True, True
    )
    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    cf = r.security_handler.get_stream_filter()
    assert cf.shared_key is not None
    with pytest.raises(misc.PdfError, match="after deriving.*shared key"):
        cf.add_recipients(
            [PUBKEY_SELFSIGNED_DECRYPTER.cert],
            policy=pubkey.RecipientEncryptionPolicy(),
        )


def test_encrypted_obj_stm():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r, writer_kwargs={'stream_xrefs': True})
    obj_stm = w.prepare_object_stream()
    objref = w.add_object(
        generic.TextStringObject("Hello there"), obj_stream=obj_stm
    )
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt("ownersecret")
    assert result.status == AuthStatus.OWNER

    # assert that the content was present in the actual content stream
    # in unencrypted form (after decrypting the wrapping object stream)
    new_objref = generic.Reference(objref.idnum, objref.generation, pdf=r)
    xref_data = r.xrefs[new_objref]
    stm = r.get_object(
        generic.Reference(xref_data.obj_stream_id, pdf=r),
        transparent_decrypt=False,
    )
    assert b"(Hello there)" in stm.decrypted.data

    # assert that the object can be correctly retrieved
    assert new_objref.get_object() == "Hello there"


def test_add_crypt_filter_to_stream_without_security_handler():
    dummy_stream = generic.StreamObject(stream_data=b"1001")
    with pytest.raises(misc.PdfStreamError, match="no security handler"):
        dummy_stream.add_crypt_filter()


@pytest.mark.parametrize(
    "fname,strict",
    [
        ("malformed-encrypt-dict1.pdf", True),
        ("malformed-encrypt-dict2.pdf", True),
        ("malformed-encrypt-dict2.pdf", False),
    ],
)
def test_malformed_crypt(fname, strict):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        r = PdfFileReader(inf, strict=strict)
        with pytest.raises(misc.PdfReadError, match='Encryption settings'):
            r.encrypt_dict


def test_tolerate_direct_encryption_dict_in_nonstrict():
    fname = 'malformed-encrypt-dict1.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        r = PdfFileReader(inf, strict=False)
        r.decrypt('ownersecret')
        data = r.root['/Pages']['/Kids'][0]['/Contents'].data
        assert b'Hello' in data


def test_gcm_standard():
    w = writer.copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))

    sh = StandardSecurityHandler.build_from_pw(
        "secret", pdf_mac=False, use_gcm=True
    )
    w._assign_security_handler(sh)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    r.decrypt("secret")
    page_content = r.root['/Pages']['/Kids'][0]['/Contents'].data
    assert b"Hello" in page_content

    iso_exts = {
        int(ext.get_object()['/ExtensionLevel'])
        for ext in r.root['/Extensions']['/ISO_']
    }
    assert iso_exts == {32003}


def _gcm_standard_tamper(tamperer):
    w = writer.copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))

    sh = StandardSecurityHandler.build_from_pw(
        "secret", pdf_mac=False, use_gcm=True
    )
    w._assign_security_handler(sh)
    out = BytesIO()
    w.write(out)

    class NeverDecryptReader(PdfFileReader):
        def __init__(self):
            super().__init__(out)

        @property
        def security_handler(self):
            return None

    r = NeverDecryptReader()
    w = IncrementalPdfFileWriter.from_reader(r)
    page_dict = w.root['/Pages']['/Kids'][0]
    content: generic.StreamObject = page_dict['/Contents']
    content._encoded_data = tamperer(content.encoded_data)
    w.update_container(content)
    w._update_meta = lambda: None
    w.write_in_place()

    r = PdfFileReader(out)
    r.decrypt("secret")

    # this should work
    assert "https" in r.root['/Extensions']['/ISO_'][0]['/URL']

    # this shouldn't
    with pytest.raises(misc.PdfReadError, match="Invalid GCM tag"):
        len(r.root['/Pages']['/Kids'][0]['/Contents'].data)


def test_gcm_change_content():
    def tamper(ciphertext):
        out = BytesIO()
        out.write(ciphertext)
        out.seek(14)
        out.write(b"\xde\xad\xbe\xef")
        return out.getvalue()

    _gcm_standard_tamper(tamper)


def test_gcm_remove_tag():
    def tamper(ciphertext):
        return ciphertext[:-16]

    _gcm_standard_tamper(tamper)


def test_gcm_change_nonce():
    def tamper(ciphertext):
        out = BytesIO()
        out.write(ciphertext)
        out.seek(0)
        out.write(bytes(12))
        return out.getvalue()

    _gcm_standard_tamper(tamper)


def test_gcm_pubkey():
    w = writer.copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))

    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_TEST_DECRYPTER.cert],
        version=SecurityHandlerVersion.AES_GCM,
        pdf_mac=False,
    )
    w._assign_security_handler(sh)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    page_content = r.root['/Pages']['/Kids'][0]['/Contents'].data
    assert b"Hello" in page_content

    iso_exts = {
        int(ext.get_object()['/ExtensionLevel'])
        for ext in r.root['/Extensions']['/ISO_']
    }
    assert iso_exts == {32003}


def test_tolerate_empty_encrypted_string():
    with open(
        os.path.join(PDF_DATA_DIR, 'minimal-aes256-empty-encrypted-string.pdf'),
        'rb',
    ) as inf:
        r = PdfFileReader(inf)
        r.decrypt('secret')
        obj = r.root.raw_get('/Blah', decrypt=generic.EncryptedObjAccess.PROXY)
        assert isinstance(obj, generic.DecryptedObjectProxy)
        decrypted = obj.decrypted
        assert isinstance(
            decrypted, (generic.TextStringObject, generic.ByteStringObject)
        )
        assert decrypted.original_bytes == b""


def test_process_malformed_p_entry():
    with open(
        f'{PDF_DATA_DIR}/minimal-aes256-malformed-perms.pdf', 'rb'
    ) as inf:
        r = PdfFileReader(inf)
        with pytest.raises(
            misc.PdfReadError, match="Cannot parse.*as a permission"
        ):
            r.decrypt("usersecret")


def test_process_malformed_oe_entry():
    with open(f'{PDF_DATA_DIR}/minimal-aes256-malformed-oe.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        with pytest.raises(misc.PdfReadError, match="Expected string"):
            r.decrypt("usersecret")


@pytest.mark.parametrize(
    ['perm', 'expected_sint', 'expected_bytes'],
    (
        (StandardPermissions.allow_everything(), -4, b"\xff\xff\xff\xfc"),
        (STD_PERMS, -44, b"\xff\xff\xff\xd4"),
    ),
)
def test_std_permission_transformations(perm, expected_sint, expected_bytes):
    assert (perm.as_sint32(), perm.as_bytes()) == (
        expected_sint,
        expected_bytes,
    )


@pytest.mark.parametrize(
    ['perm', 'expected_bytes'],
    (
        (PubKeyPermissions.allow_everything(), b"\xff\xff\xff\xff"),
        (PUBKEY_PERMS, b"\xff\xff\xff\xd5"),
    ),
)
def test_pubkey_permission_transformations(perm, expected_bytes):
    assert perm.as_bytes() == expected_bytes


def test_pubkey_3des_decryption():
    with open(f"{PDF_DATA_DIR}/pubkey-3des-test.pdf", "rb") as inf:
        r = PdfFileReader(inf)
        result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
        _validate_pubkey_decryption(r, result)


def test_pubkey_rc2_decryption():
    with open(f"{PDF_DATA_DIR}/pubkey-rc2-test.pdf", "rb") as inf:
        r = PdfFileReader(inf)
        result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
        _validate_pubkey_decryption(r, result)
