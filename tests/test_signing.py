import pytest
from io import BytesIO

from certvalidator import ValidationContext
from oscrypto import keys as oskeys

from pdf_utils import generic
from pdf_utils.font import pdf_name
from pdf_utils.writer import PdfFileWriter
from pdfstamp.sign import timestamps, fields, signers
from pdfstamp.sign.validation import validate_pdf_signature
from pdf_utils.reader import PdfFileReader
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from .samples import *


SELF_SIGN = signers.SimpleSigner.load(
    CRYPTO_DATA_DIR + '/selfsigned.key.pem',
    CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
    key_passphrase=b'secret'
)

FROM_CA = signers.SimpleSigner.load(
    CRYPTO_DATA_DIR + '/signer.key.pem',
    CRYPTO_DATA_DIR + '/signer.cert.pem',
    ca_chain_files=(CRYPTO_DATA_DIR + '/ca-chain.pem',),
    key_passphrase=b'secret'
)


ROOT_CERT = oskeys.parse_certificate(read_all(CRYPTO_DATA_DIR + '/ca.cert.pem'))
NOTRUST_V_CONTEXT = ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = ValidationContext(trust_roots=[ROOT_CERT])

DUMMY_TS = timestamps.DummyTimeStamper(
    tsa_cert=oskeys.parse_certificate(
        read_all(CRYPTO_DATA_DIR + '/tsa.cert.pem')
    ),
    tsa_key=oskeys.parse_private(
        read_all(CRYPTO_DATA_DIR + '/tsa.key.pem'), password=b'secret'
    ),
    ca_chain=FROM_CA.ca_chain,
)

FROM_CA_TS = signers.SimpleSigner(
    signing_cert=FROM_CA.signing_cert, ca_chain=FROM_CA.ca_chain,
    signing_key=FROM_CA.signing_key, timestamper=DUMMY_TS
)

DUMMY_HTTP_TS = timestamps.HTTPTimeStamper(
    'http://example.com/tsa', https=False
)
FROM_CA_HTTP_TS = signers.SimpleSigner(
    signing_cert=FROM_CA.signing_cert, ca_chain=FROM_CA.ca_chain,
    signing_key=FROM_CA.signing_key, timestamper=DUMMY_HTTP_TS
)


def val_trusted(r, sig_obj, extd=False):
    val_status = validate_pdf_signature(r, sig_obj, SIMPLE_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    if not extd:
        assert val_status.complete_document
    return val_status


# validate a signature, don't care about trust
def val_untrusted(r, sig_obj, extd=False):
    val_status = validate_pdf_signature(r, sig_obj, NOTRUST_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    if not extd:
        assert val_status.complete_document
    return val_status


def test_simple_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=SELF_SIGN
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_untrusted(r, sig_obj)


def test_sign_with_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    status = val_untrusted(r, sig_obj)
    assert not status.trusted

    val_trusted(r, sig_obj)


def test_sign_field_unclear():
    # test error on signing attempt where the signature field to be used
    # is not clear
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    with pytest.raises(ValueError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    with pytest.raises(ValueError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA,
            existing_fields_only=True
        )


def test_sign_field_infer():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    with pytest.raises(ValueError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_obj)


def test_sign_field_filled():
    w1 = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    out1 = signers.sign_pdf(
        w1, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        existing_fields_only=True
    )

    # can't sign the same field twice
    w2 = IncrementalPdfFileWriter(out1)
    with pytest.raises(ValueError):
        signers.sign_pdf(
            w2, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
            existing_fields_only=True
        )
    out1.seek(0)

    def val2(out_buf):
        r = PdfFileReader(out_buf)
        sig_fields = fields.enumerate_sig_fields(r)
        field_name, sig_obj, _ = next(sig_fields)
        assert field_name == 'Sig1'
        val_trusted(r, sig_obj, extd=True)

        field_name, sig_obj, _ = next(sig_fields)
        assert field_name == 'Sig2'
        val_trusted(r, sig_obj)

    w2 = IncrementalPdfFileWriter(out1)
    # autodetect remaining open field
    out2 = signers.sign_pdf(
        w2, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )
    out1.seek(0)
    val2(out2)

    w2 = IncrementalPdfFileWriter(out1)
    out2 = signers.sign_pdf(
        w2, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
        existing_fields_only=True
    )
    out1.seek(0)
    val2(out2)


sign_test_files = (MINIMAL, MINIMAL_ONE_FIELD)


@pytest.mark.parametrize('file', [0, 1])
def test_sign_new(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    field_name = sig_obj = None
    sig_fields = fields.enumerate_sig_fields(r)
    while field_name != 'SigNew':
        field_name, sig_obj, _ = next(sig_fields)
    val_trusted(r, sig_obj)


def test_dummy_timestamp():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    validity = val_trusted(r, sig_obj)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


def test_http_timestamp(requests_mock):
    from asn1crypto import tsp
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    def response_callback(request, _context):
        req = tsp.TimeStampReq.load(request.body)
        return DUMMY_TS.request_tsa_response(req=req).dump()

    # bad content-type
    requests_mock.post(DUMMY_HTTP_TS.url, content=response_callback)
    from pdfstamp.sign.timestamps import TimestampRequestError
    with pytest.raises(TimestampRequestError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA_HTTP_TS,
            existing_fields_only=True,
        )

    requests_mock.post(
        DUMMY_HTTP_TS.url, content=response_callback,
        headers={'Content-Type': 'application/timestamp-reply'}
    )
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA_HTTP_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    validity = val_trusted(r, sig_obj)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


# try both the user password and the owner password
@pytest.mark.parametrize('password', [b'usersecret', b'ownersecret'])
def test_sign_crypt_rc4(password):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD_RC4))
    w.encrypt(password)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt(password)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    val_trusted(r, sig_obj)


sign_crypt_rc4_files = (MINIMAL_RC4, MINIMAL_ONE_FIELD_RC4)
sign_crypt_rc4_new_params = [
    [b'usersecret', 0], [b'usersecret', 1],
    [b'ownersecret', 0], [b'ownersecret', 1]
]


@pytest.mark.parametrize('password, file', sign_crypt_rc4_new_params)
def test_sign_crypt_rc4_new(password, file):
    w = IncrementalPdfFileWriter(BytesIO(sign_crypt_rc4_files[file]))
    w.encrypt(password)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    out.seek(0)
    r = PdfFileReader(out)
    r.decrypt(password)
    field_name = sig_obj = None
    sig_fields = fields.enumerate_sig_fields(r)
    while field_name != 'SigNew':
        field_name, sig_obj, _ = next(sig_fields)
    val_trusted(r, sig_obj)


def test_append_simple_sig_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec('InvisibleSig')
    fields.append_signature_fields(w, [sp])
    assert len(w.root['/AcroForm']['/Fields']) == 1
    out = BytesIO()
    w.write(out)
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(ValueError):
        fields.append_signature_fields(w, [sp])

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    fields.append_signature_fields(w, [sp])
    assert len(w.root['/AcroForm']['/Fields']) == 3


def test_append_sig_field_acro_update():
    # test different configurations of the AcroForm
    w = PdfFileWriter()
    w.root['/AcroForm'] = generic.DictionaryObject({
        pdf_name('/Fields'): generic.ArrayObject()
    })
    w.insert_page(simple_page(w, 'Hello world'))
    out = BytesIO()
    w.write(out)
    out.seek(0)

    sp = fields.SigFieldSpec('InvisibleSig')
    w = IncrementalPdfFileWriter(out)
    fields.append_signature_fields(w, [sp])
    assert len(w.root['/AcroForm']['/Fields']) == 1

    w = PdfFileWriter()
    # Technically, this is not standards-compliant, but our routine
    # shouldn't care
    w.root['/AcroForm'] = generic.DictionaryObject()
    w.insert_page(simple_page(w, 'Hello world'))
    out = BytesIO()
    w.write(out)
    out.seek(0)

    sp = fields.SigFieldSpec('InvisibleSig')
    w = IncrementalPdfFileWriter(out)
    fields.append_signature_fields(w, [sp])
    assert len(w.root['/AcroForm']['/Fields']) == 1


def test_cert_constraint_deserialisation():
    signer1 = FROM_CA.signing_cert
    signer2 = SELF_SIGN.signing_cert
    constr = fields.SigCertConstraints(subjects=[signer1, signer2])
    constr_parsed = fields.SigCertConstraints.from_pdf_object(
        constr.as_pdf_object()
    )
    signer1_parsed, signer2_parsed = constr_parsed.subjects
    assert signer1_parsed.dump() == signer1.dump()
    assert signer2_parsed.dump() == signer2.dump()
    assert not constr_parsed.issuers

    issuer1 = FROM_CA.signing_cert
    issuer2 = SELF_SIGN.signing_cert
    constr = fields.SigCertConstraints(issuers=[issuer1, issuer2])
    constr_parsed = fields.SigCertConstraints.from_pdf_object(
        constr.as_pdf_object()
    )
    issuer1_parsed, issuer2_parsed = constr_parsed.issuers
    assert issuer1_parsed.dump() == issuer1.dump()
    assert issuer2_parsed.dump() == issuer2.dump()
    assert not constr_parsed.subjects

    constr = fields.SigCertConstraints(subject_dns=[signer1.subject])
    constr_ser = constr.as_pdf_object()
    assert '/C' in constr_ser['/SubjectDN'][0]
    constr_parsed = fields.SigCertConstraints.from_pdf_object(constr_ser)
    assert constr_parsed.subject_dns[0].dump() == signer1.subject.dump()
    assert len(constr_parsed.subject_dns) == 1
