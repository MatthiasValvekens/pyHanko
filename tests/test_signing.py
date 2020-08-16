from io import BytesIO

from certvalidator import ValidationContext
from oscrypto import keys as oskeys

from pdf_utils.reader import PdfFileReader
from pdfstamp import sign
from pdf_utils.incremental_writer import IncrementalPdfFileWriter

CRYPTO_DATA_DIR = 'tests/data/crypto'
PDF_DATA_DIR = 'tests/data/pdf'
MINIMAL = PDF_DATA_DIR + '/minimal.pdf'
MINIMAL_ONE_FIELD = PDF_DATA_DIR + '/minimal-with-field.pdf'
MINIMAL_TWO_FIELDS = PDF_DATA_DIR + '/minimal-two-fields.pdf'

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


with open(CRYPTO_DATA_DIR + '/ca.cert.pem', 'rb') as f:
    ROOT_CERT = oskeys.parse_certificate(f.read())

NOTRUST_V_CONTEXT = ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = ValidationContext(trust_roots=[ROOT_CERT])


def test_simple_sign():
    with open(MINIMAL, 'rb') as f:
        indata = f.read()

    w = IncrementalPdfFileWriter(BytesIO(indata))
    out = sign.sign_pdf(w, sign.PdfSignatureMetadata(field_name='Sig1'),
                        signer=SELF_SIGN)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_status = sign.validate_signature(r, sig_obj, NOTRUST_V_CONTEXT)
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'UNTOUCHED' in summ


def test_sign_with_trust():
    with open(MINIMAL, 'rb') as f:
        indata = f.read()

    w = IncrementalPdfFileWriter(BytesIO(indata))
    out = sign.sign_pdf(w, sign.PdfSignatureMetadata(field_name='Sig1'),
                        signer=FROM_CA)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(sign.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_status = sign.validate_signature(r, sig_obj, NOTRUST_V_CONTEXT)
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'UNTOUCHED' in summ
    assert 'UNTRUSTED' in summ

    val_status = sign.validate_signature(r, sig_obj, SIMPLE_V_CONTEXT)
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'UNTOUCHED' in summ
    assert 'TRUSTED' in summ
