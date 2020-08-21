import pytest
from io import BytesIO

from certvalidator import ValidationContext
from oscrypto import keys as oskeys

from pdf_utils.reader import PdfFileReader
from pdfstamp import sign
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from .samples import *


SELF_SIGN = sign.SimpleSigner.load(
    CRYPTO_DATA_DIR + '/selfsigned.key.pem',
    CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
    key_passphrase=b'secret'
)

FROM_CA = sign.SimpleSigner.load(
    CRYPTO_DATA_DIR + '/signer.key.pem',
    CRYPTO_DATA_DIR + '/signer.cert.pem',
    ca_chain_files=(CRYPTO_DATA_DIR + '/ca-chain.pem',),
    key_passphrase=b'secret'
)


ROOT_CERT = oskeys.parse_certificate(read_all(CRYPTO_DATA_DIR + '/ca.cert.pem'))
NOTRUST_V_CONTEXT = ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = ValidationContext(trust_roots=[ROOT_CERT])

DUMMY_TS = sign.DummyTimeStamper(
    tsa_cert=oskeys.parse_certificate(
        read_all(CRYPTO_DATA_DIR + '/tsa.cert.pem')
    ),
    tsa_key=oskeys.parse_private(
        read_all(CRYPTO_DATA_DIR + '/tsa.key.pem'), password=b'secret'
    ),
    ca_chain=FROM_CA.ca_chain,
)

FROM_CA_TS = sign.SimpleSigner(
    signing_cert=FROM_CA.signing_cert, ca_chain=FROM_CA.ca_chain,
    signing_key=FROM_CA.signing_key, timestamper=DUMMY_TS
)


def val_trusted(r, sig_obj, extd=False):
    val_status = sign.validate_pdf_signature(r, sig_obj, SIMPLE_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    if not extd:
        assert val_status.complete_document
    return val_status


# validate a signature, don't care about trust
def val_untrusted(r, sig_obj, extd=False):
    val_status = sign.validate_pdf_signature(r, sig_obj, NOTRUST_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    if not extd:
        assert val_status.complete_document
    return val_status


def test_simple_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = sign.sign_pdf(w, sign.PdfSignatureMetadata(field_name='Sig1'),
                        signer=SELF_SIGN)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_untrusted(r, sig_obj)


def test_sign_with_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = sign.sign_pdf(w, sign.PdfSignatureMetadata(field_name='Sig1'),
                        signer=FROM_CA)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    status = val_untrusted(r, sig_obj)
    assert not status.trusted

    val_trusted(r, sig_obj)


def test_sign_field_unclear():
    # test error on signing attempt where the signature field to be used
    # is not clear
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    with pytest.raises(ValueError):
        sign.sign_pdf(w, sign.PdfSignatureMetadata(), signer=FROM_CA)

    with pytest.raises(ValueError):
        sign.sign_pdf(w, sign.PdfSignatureMetadata(), signer=FROM_CA,
                      existing_fields_only=True)


def test_sign_field_infer():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    with pytest.raises(ValueError):
        sign.sign_pdf(w, sign.PdfSignatureMetadata(), signer=FROM_CA)

    out = sign.sign_pdf(
        w, sign.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_obj)


def test_sign_field_filled():
    w1 = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    out1 = sign.sign_pdf(
        w1, sign.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        existing_fields_only=True
    )

    # can't sign the same field twice
    w2 = IncrementalPdfFileWriter(out1)
    with pytest.raises(ValueError):
        sign.sign_pdf(
            w2, sign.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
            existing_fields_only=True
        )
    out1.seek(0)

    def val2(out_buf):
        r = PdfFileReader(out_buf)
        sig_fields = sign.enumerate_sig_fields(r)
        field_name, sig_obj, _ = next(sig_fields)
        assert field_name == 'Sig1'
        val_trusted(r, sig_obj, extd=True)

        field_name, sig_obj, _ = next(sig_fields)
        assert field_name == 'Sig2'
        val_trusted(r, sig_obj)

    w2 = IncrementalPdfFileWriter(out1)
    # autodetect remaining open field
    out2 = sign.sign_pdf(
        w2, sign.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )
    out1.seek(0)
    val2(out2)

    w2 = IncrementalPdfFileWriter(out1)
    out2 = sign.sign_pdf(
        w2, sign.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
        existing_fields_only=True
    )
    out1.seek(0)
    val2(out2)


@pytest.mark.parametrize('file', [MINIMAL, MINIMAL_ONE_FIELD])
def test_sign_new(file):
    w = IncrementalPdfFileWriter(BytesIO(file))
    out = sign.sign_pdf(
        w, sign.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    field_name = sig_obj = None
    sig_fields = sign.enumerate_sig_fields(r)
    while field_name != 'SigNew':
        field_name, sig_obj, _ = next(sig_fields)
    val_trusted(r, sig_obj)


def test_dummy_timestamp():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = sign.sign_pdf(
        w, sign.PdfSignatureMetadata(), signer=FROM_CA_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    validity = val_trusted(r, sig_obj)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


# try both the user password and the owner password
@pytest.mark.parametrize('password', [b'usersecret', b'ownersecret'])
def test_sign_crypt_rc4(password):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD_RC4))
    w.encrypt(password)
    out = sign.sign_pdf(
        w, sign.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt(password)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    val_trusted(r, sig_obj)


sign_crypt_rc4_new_params = [
    [b'usersecret', MINIMAL_RC4],
    [b'usersecret', MINIMAL_ONE_FIELD_RC4],
    [b'ownersecret', MINIMAL_RC4],
    [b'ownersecret', MINIMAL_ONE_FIELD_RC4]
]


@pytest.mark.parametrize('password, file', sign_crypt_rc4_new_params)
def test_sign_crypt_rc4_new(password, file):
    w = IncrementalPdfFileWriter(BytesIO(file))
    w.encrypt(password)
    out = sign.sign_pdf(
        w, sign.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    out.seek(0)
    r = PdfFileReader(out)
    r.decrypt(password)
    field_name = sig_obj = None
    sig_fields = sign.enumerate_sig_fields(r)
    while field_name != 'SigNew':
        field_name, sig_obj, _ = next(sig_fields)
    val_trusted(r, sig_obj)
