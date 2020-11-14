import re
from datetime import datetime

import pytest
from io import BytesIO

import pytz
from asn1crypto import ocsp, tsp
from certvalidator.errors import PathValidationError

import pdfstamp.sign.fields
from certvalidator import ValidationContext, CertificateValidator
from ocspbuilder import OCSPResponseBuilder
from oscrypto import keys as oskeys

from pdf_utils import generic
from pdf_utils.font import pdf_name
from pdf_utils.writer import PdfFileWriter
from pdfstamp.sign import timestamps, fields, signers
from pdfstamp.sign.general import UnacceptableSignerError, SigningError
from pdfstamp.sign.validation import (
    validate_pdf_signature, read_certification_data, DocumentSecurityStore,
    EmbeddedPdfSignature, apply_adobe_revocation_info,
    validate_pdf_ltv_signature, RevocationInfoValidationType,
    SignatureCoverageLevel, ModificationLevel, SignatureValidationError,
)
from pdf_utils.reader import PdfFileReader
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from .samples import *


SELF_SIGN = signers.SimpleSigner.load(
    CRYPTO_DATA_DIR + '/selfsigned.key.pem',
    CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
    ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
    key_passphrase=b'secret'
)

FROM_CA = signers.SimpleSigner.load(
    TESTING_CA_DIR + '/keys/signer.key.pem',
    TESTING_CA_DIR + '/intermediate/newcerts/signer.cert.pem',
    ca_chain_files=(TESTING_CA_DIR + '/intermediate/certs/ca-chain.cert.pem',),
    key_passphrase=b'secret'
)

ROOT_PATH = TESTING_CA_DIR + '/root/certs/ca.cert.pem'
INTERM_PATH = TESTING_CA_DIR + '/intermediate/certs/ca.cert.pem'
OCSP_PATH = TESTING_CA_DIR + '/intermediate/newcerts/ocsp.cert.pem'
REVOKED_CERT_PATH = TESTING_CA_DIR + '/intermediate/newcerts/1002.pem'
TRUST_ROOTS = list(signers.load_ca_chain((ROOT_PATH,)))

FROM_CA_PKCS12 = signers.SimpleSigner.load_pkcs12(
    TESTING_CA_DIR + '/intermediate/newcerts/signer.pfx',
    passphrase=b'exportsecret'
)

ROOT_CERT = oskeys.parse_certificate(read_all(ROOT_PATH))
INTERM_CERT = oskeys.parse_certificate(read_all(INTERM_PATH))
OCSP_CERT = oskeys.parse_certificate(read_all(OCSP_PATH))
REVOKED_CERT = oskeys.parse_certificate(read_all(REVOKED_CERT_PATH))
NOTRUST_V_CONTEXT = ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = ValidationContext(trust_roots=[ROOT_CERT])
OCSP_KEY = oskeys.parse_private(
    read_all(TESTING_CA_DIR + '/keys/ocsp.key.pem'), b"secret"
)

TSA_CERT = oskeys.parse_certificate(
    read_all(TESTING_CA_DIR + '/root/newcerts/tsa.cert.pem')
)
DUMMY_TS = timestamps.DummyTimeStamper(
    tsa_cert=TSA_CERT,
    tsa_key=oskeys.parse_private(
        read_all(TESTING_CA_DIR + '/keys/tsa.key.pem'), password=b'secret'
    ),
    certs_to_embed=FROM_CA.cert_registry,
)

DUMMY_HTTP_TS = timestamps.HTTPTimeStamper(
    'http://example.com/tsa', https=False
)

# with the testing CA setup update, this OCSP response is totally
#  unrelated to the keys being used, so it should fail any sort of real
#  validation
FIXED_OCSP = ocsp.OCSPResponse.load(
    read_all(CRYPTO_DATA_DIR + '/ocsp.resp.der')
)


# TODO rewrite tests using new in-place signing mechanism

def dummy_ocsp_vc():
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS, crls=[], ocsps=[FIXED_OCSP],
        other_certs=list(FROM_CA.cert_registry), allow_fetching=False
    )
    return vc


def live_testing_vc(requests_mock):
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS, allow_fetching=True,
        other_certs=[]
    )

    def serve_ca_file(request, _context):
        fpath = request.url.replace("http://ca.example.com", TESTING_CA_DIR)
        with open(fpath, 'rb') as f:
            content = f.read()
        return content

    requests_mock.register_uri(
        'GET', re.compile(r"^http://ca\.example\.com/"), content=serve_ca_file
    )

    def serve_ocsp_response(request, _context):
        req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(request.body)
        nonce = req.nonce_value.native
        # we only look at the serial number, this is a dummy responder
        # the return data is hardcoded (for now)
        # TODO read it off from the OpenSSL CA index
        for req_item in req['tbs_request']['request_list']:
            serial = req_item['req_cert']['serial_number'].native
            if serial == 0x1001:
                bld = OCSPResponseBuilder('successful', FROM_CA.signing_cert,
                                           'good')
            elif serial == 0x1002:
                revocation_date = datetime(2021, 1, 1, 0, 0, 0, tzinfo=pytz.utc)
                bld = OCSPResponseBuilder('successful', REVOKED_CERT,
                                           'key_compromise', revocation_date)
            else:
                bld = OCSPResponseBuilder('unauthorized')

            bld.nonce = nonce
            bld.certificate_issuer = INTERM_CERT
            return bld.build(
                responder_certificate=OCSP_CERT, responder_private_key=OCSP_KEY
            ).dump()
        raise ValueError

    requests_mock.register_uri(
        'POST', re.compile(r"^http://ocsp\.example\.com/"),
        content=serve_ocsp_response
    )

    return vc


def val_trusted(r, sig_field, extd=False):
    val_status = validate_pdf_signature(r, sig_field, SIMPLE_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'TRUSTED' in summ
    if not extd:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert val_status.modification_level == ModificationLevel.NONE
    else:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
        assert val_status.modification_level <= ModificationLevel.FORM_FILLING
    assert val_status.bottom_line
    return val_status


# validate a signature, don't care about trust
def val_untrusted(r, sig_field, extd=False):
    val_status = validate_pdf_signature(r, sig_field, NOTRUST_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    if not extd:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert val_status.modification_level == ModificationLevel.NONE
    else:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
        assert val_status.modification_level <= ModificationLevel.FORM_FILLING
    summ = val_status.summary()
    assert 'INTACT' in summ
    return val_status


def val_trusted_but_modified(r, sig_field):
    val_status = validate_pdf_signature(r, sig_field, SIMPLE_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
    assert val_status.modification_level == ModificationLevel.OTHER
    assert not val_status.docmdp_ok
    assert not val_status.bottom_line
    return val_status


@pytest.mark.parametrize('incl_signed_time', [True, False])
def test_simple_sign(incl_signed_time):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', include_signedtime_attr=incl_signed_time
    )
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)
    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(r, emb.sig_field)

    # try tampering with the file
    out.seek(0x9d)
    # this just changes the size of the media box, so the file should remain
    # a valid PDF.
    out.write(b'4')
    out.seek(0)
    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    tampered = validate_pdf_signature(r, emb.sig_field, SIMPLE_V_CONTEXT)
    assert not tampered.intact
    assert not tampered.valid
    assert tampered.summary() == 'INVALID'


def test_null_sign():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    with pytest.raises(ValueError):
        val_untrusted(r, sig_field)


def test_sign_with_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    status = val_untrusted(r, sig_field)
    assert not status.trusted

    val_trusted(r, sig_field)


def test_sign_with_trust_pkcs12():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA_PKCS12
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    status = val_untrusted(r, sig_field)
    assert not status.trusted

    val_trusted(r, sig_field)


def test_sign_field_unclear():
    # test error on signing attempt where the signature field to be used
    # is not clear
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    with pytest.raises(SigningError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA,
            existing_fields_only=True
        )

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigExtra'),
            signer=FROM_CA, existing_fields_only=True
        )


def test_sign_field_infer():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    with pytest.raises(SigningError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field)


def test_sign_field_filled():
    w1 = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    out1 = signers.sign_pdf(
        w1, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        existing_fields_only=True
    )

    # can't sign the same field twice
    w2 = IncrementalPdfFileWriter(out1)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w2, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
            existing_fields_only=True
        )
    out1.seek(0)

    def val2(out_buf):
        r = PdfFileReader(out_buf)
        sig_fields = fields.enumerate_sig_fields(r)
        field_name, sig_obj, sig_field = next(sig_fields)
        assert field_name == 'Sig1'
        val_trusted(r, sig_field, extd=True)

        field_name, sig_obj, sig_field = next(sig_fields)
        assert field_name == 'Sig2'
        val_trusted(r, sig_field)

    w2 = IncrementalPdfFileWriter(out1)
    # autodetect remaining open field
    out2 = signers.sign_pdf(
        w2, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )
    val2(out2)

    out1.seek(0)
    w2 = IncrementalPdfFileWriter(out1)
    out2 = signers.sign_pdf(
        w2, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
        existing_fields_only=True
    )
    val2(out2)


sign_test_files = (MINIMAL, MINIMAL_ONE_FIELD)


@pytest.mark.parametrize('file', [0, 1])
def test_sign_new(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    field_name = sig_field = None
    sig_fields = fields.enumerate_sig_fields(r)
    while field_name != 'SigNew':
        field_name, sig_obj, sig_field = next(sig_fields)
    val_trusted(r, sig_field)


def test_double_sig_add_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA,
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)
    # throw in an /Info update for good measure
    dt = generic.pdf_date(datetime(2020, 10, 10, tzinfo=pytz.utc))
    info = generic.DictionaryObject({pdf_name('/CreationDate'): dt})
    w.trailer['/Info'] = w.add_object(info)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )

    r = PdfFileReader(out)
    sig_fields = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    status = val_trusted(r, sig_field, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'SigNew'
    val_trusted(r, sig_field)


def test_double_sig_add_visible_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ), signer=FROM_CA
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)

    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134)
    )
    fields.append_signature_fields(w, [sp])
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    sig_fields = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    status = val_trusted(r, sig_field, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'SigNew'
    val_trusted(r, sig_field)


@pytest.mark.parametrize('include_docmdp', [True, False])
def test_add_sigfield_with_lock(include_docmdp):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fields.FieldMDPSpec(
            fields.FieldMDPAction.INCLUDE, fields=['blah']
        ),
        doc_mdp_update_value=(
            fields.MDPPerm.NO_CHANGES if include_docmdp else None
        )
    )
    fields.append_signature_fields(w, [sp])
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    sig_fields = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'SigNew'
    refs = sig_obj.get_object()['/Reference']
    assert len(refs) == (2 if include_docmdp else 1)
    ref = refs[0]
    assert ref['/TransformMethod'] == '/FieldMDP'
    assert ref['/TransformParams']['/Fields'] == ['blah']
    assert ref.raw_get('/Data').reference == r.root_ref
    assert '/Perms' not in r.root
    if include_docmdp:
        ref = refs[1]
        assert ref['/TransformMethod'] == '/DocMDP'
        assert ref['/TransformParams']['/P'] == 1
    val_trusted(r, sig_field)


def test_enumerate_empty():

    with pytest.raises(StopIteration):
        next(fields.enumerate_sig_fields(PdfFileReader(BytesIO(MINIMAL))))


@pytest.mark.parametrize('file', [0, 1])
def test_sign_new_existingonly(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigNew'),
            signer=FROM_CA, existing_fields_only=True
        )


def test_dummy_timestamp():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA, timestamper=DUMMY_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    validity = val_trusted(r, sig_field)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


def ts_response_callback(request, _context):
    req = tsp.TimeStampReq.load(request.body)
    return DUMMY_TS.request_tsa_response(req=req).dump()


def test_http_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    # bad content-type
    requests_mock.post(DUMMY_HTTP_TS.url, content=ts_response_callback)
    from pdfstamp.sign.timestamps import TimestampRequestError
    with pytest.raises(TimestampRequestError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA, timestamper=DUMMY_HTTP_TS,
            existing_fields_only=True,
        )

    requests_mock.post(
        DUMMY_HTTP_TS.url, content=ts_response_callback,
        headers={'Content-Type': 'application/timestamp-reply'}
    )
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA, timestamper=DUMMY_HTTP_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    validity = val_trusted(r, sig_field)
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
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    val_trusted(r, sig_field)


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
    field_name = sig_field = None
    sig_fields = fields.enumerate_sig_fields(r)
    while field_name != 'SigNew':
        field_name, sig_obj, sig_field = next(sig_fields)
    val_trusted(r, sig_field)


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


def test_append_visible_sig_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec(
        'VisibleSig', box=(10, 0, 50, 8)
    )
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


def test_sv_deserialisation():
    sv = fields.SigSeedValueSpec.from_pdf_object(
        generic.DictionaryObject(
            {'/SubFilter': ['/foo', '/adbe.pkcs7.detached', '/bleh']}
        )
    )
    assert len(sv.subfilters) == 1
    bad_filter = generic.DictionaryObject(
        {'/Filter': pdf_name('/unsupported')}
    )
    # this should run
    fields.SigSeedValueSpec.from_pdf_object(bad_filter)
    with pytest.raises(SigningError):
        bad_filter[pdf_name('/Ff')] = \
            generic.NumberObject(fields.SigSeedValFlags.FILTER.value)
        fields.SigSeedValueSpec.from_pdf_object(bad_filter)

    fields.SigSeedValueSpec.from_pdf_object(
        generic.DictionaryObject(
            {'/Ff': fields.SigSeedValFlags.V, '/V': generic.NumberObject(1)}
        )
    )
    fields.SigSeedValueSpec.from_pdf_object(
        generic.DictionaryObject({'/Ff': fields.SigSeedValFlags.V})
    )
    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {'/Ff': fields.SigSeedValFlags.V, '/V': generic.NumberObject(2)}
            )
        )


def test_append_sig_field_with_simple_sv():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sv = fields.SigSeedValueSpec(
        reasons=['a', 'b', 'c'],
        cert=fields.SigCertConstraints(
            subject_dn=FROM_CA.signing_cert.subject,
            issuers=[INTERM_CERT],
            subjects=[FROM_CA.signing_cert]
        ),
        digest_methods=['ssh256'],
        add_rev_info=True,
        subfilters=[fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED],
        timestamp_server_url='https://tsa.example.com',
    )
    sp = fields.SigFieldSpec('InvisibleSig', seed_value_dict=sv)
    fields.append_signature_fields(w, [sp])
    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    _, _, sig_field_ref = next(fields.enumerate_sig_fields(r))
    sv_dict = sig_field_ref.get_object()['/SV']
    recovered_sv = fields.SigSeedValueSpec.from_pdf_object(sv_dict)
    # x509.Certificate doesn't have an __eq__ implementation apparently,
    # so for the purposes of the test, we replace them by byte dumps
    issuers1 = recovered_sv.cert.issuers
    issuers2 = sv.cert.issuers
    issuers1[0] = issuers1[0].dump()
    issuers2[0] = issuers2[0].dump()

    subjects1 = recovered_sv.cert.subjects
    subjects2 = sv.cert.subjects
    subjects1[0] = subjects1[0].dump()
    subjects2[0] = subjects2[0].dump()
    assert recovered_sv == sv


def test_cert_constraint_subject_dn():

    from asn1crypto import x509
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT_DN,
        subject_dn=x509.Name.build({'common_name': 'Lord Testerino'}),
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT_DN,
        subject_dn=x509.Name.build(
            {'common_name': 'Lord Testerino', 'country_name': 'BE'}
        )
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT_DN,
        subject_dn=x509.Name.build(
            {'common_name': 'Alice & Bob', 'country_name': 'BE'}
        )
    )
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, None)

    # without the SUBJECT_DN flag, this should pass
    scc = fields.SigCertConstraints(
        subject_dn=x509.Name.build(
            {'common_name': 'Alice & Bob', 'country_name': 'BE'}
        )
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)


def test_cert_constraint_subject():

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT,
        subjects=[FROM_CA.signing_cert]
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT,
        subjects=[FROM_CA.signing_cert, SELF_SIGN.signing_cert]
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        subjects=[FROM_CA.signing_cert, SELF_SIGN.signing_cert]
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    scc.satisfied_by(DUMMY_TS.tsa_cert, None)


def test_cert_constraint_issuer(requests_mock):
    vc = live_testing_vc(requests_mock)
    signer_validation_path = CertificateValidator(
        FROM_CA.signing_cert, FROM_CA.cert_registry, validation_context=vc
    ).validate_usage(set())
    tsa_validation_path = CertificateValidator(
        DUMMY_TS.tsa_cert, FROM_CA.cert_registry, validation_context=vc
    ).validate_usage(set())

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER,
        issuers=[ROOT_CERT]
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER,
        issuers=[INTERM_CERT]
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER,
        issuers=[INTERM_CERT, SELF_SIGN.signing_cert]
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)

    scc = fields.SigCertConstraints(issuers=[INTERM_CERT])
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)


def test_cert_constraint_composite(requests_mock):
    vc = live_testing_vc(requests_mock)
    signer_validation_path = CertificateValidator(
        FROM_CA.signing_cert, FROM_CA.cert_registry, validation_context=vc
    ).validate_usage(set())
    tsa_validation_path = CertificateValidator(
        DUMMY_TS.tsa_cert, FROM_CA.cert_registry, validation_context=vc
    ).validate_usage(set())

    from asn1crypto import x509
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER | fields.SigCertConstraintFlags.SUBJECT_DN,
        issuers=[INTERM_CERT],
        subject_dn=x509.Name.build(
            {'common_name': 'Lord Testerino', 'country_name': 'BE'}
        )
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)

    from asn1crypto import x509
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER | fields.SigCertConstraintFlags.SUBJECT_DN,
        issuers=[INTERM_CERT],
        subject_dn=x509.Name.build(
            {'common_name': 'Alice & Bob', 'country_name': 'BE'}
        )
    )
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)


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
    with pytest.raises(ValueError):
        fields.append_signature_fields(w, [sp])


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

    constr = fields.SigCertConstraints(subject_dn=signer1.subject)
    constr_ser = constr.as_pdf_object()
    assert '/C' in constr_ser['/SubjectDN'][0]
    constr_parsed = fields.SigCertConstraints.from_pdf_object(constr_ser)
    assert constr_parsed.subject_dn == signer1.subject


def test_certify_blank():
    r = PdfFileReader(BytesIO(MINIMAL))
    assert read_certification_data(r) is None


def test_certify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=pdfstamp.sign.fields.MDPPerm.NO_CHANGES
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field)

    info = read_certification_data(r)
    assert info.author_sig == sig_obj.get_object()
    assert info.permission_bits == pdfstamp.sign.fields.MDPPerm.NO_CHANGES

    # with NO_CHANGES, we shouldn't be able to append an approval signature
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA
        )


def test_no_double_certify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field)

    info = read_certification_data(r)
    assert info.author_sig == sig_obj.get_object()
    assert info.permission_bits == pdfstamp.sign.fields.MDPPerm.FILL_FORMS

    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig2', certify=True,
                docmdp_permissions=pdfstamp.sign.fields.MDPPerm.FILL_FORMS
            ), signer=FROM_CA
        )


def test_approval_sig():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
        ), signer=FROM_CA
    )
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA
    )

    out.seek(0)

    r = PdfFileReader(out)
    sigs = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sigs)
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)

    info = read_certification_data(r)
    assert info.author_sig == sig_obj.get_object()
    assert info.permission_bits == pdfstamp.sign.fields.MDPPerm.FILL_FORMS

    field_name, sig_obj, sig_field = next(sigs)
    assert field_name == 'Sig2'
    val_trusted(r, sig_field)


def test_approval_sig_md_match_author_sig():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            md_algorithm='sha256'
        ), signer=FROM_CA
    )
    out.seek(0)
    w = IncrementalPdfFileWriter(out)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA
    )
    out.seek(0)
    r = PdfFileReader(out)
    sigs = fields.enumerate_sig_fields(r)
    next(sigs)
    field_name, sig_obj, sig_field = next(sigs)
    assert EmbeddedPdfSignature(r, sig_field).md_algorithm == 'sha256'


def test_ocsp_embed():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            embed_validation_info=True
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    status = val_untrusted(r, sig_field)
    assert not status.trusted

    val_trusted(r, sig_field)

    embedded_sig = EmbeddedPdfSignature(r, sig_field)
    vc = apply_adobe_revocation_info(embedded_sig.signer_info)
    assert len(vc.ocsps) == 1


PADES = fields.SigSeedSubFilter.PADES

def test_pades_flag():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
        signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'


def test_pades_revinfo_dummydata():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'

    dss = DocumentSecurityStore.read_dss(handler=r)
    assert dss is not None
    assert len(dss.certs) == 4
    assert len(dss.ocsps) == 1


def test_pades_revinfo_nodata():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    with pytest.raises(SigningError):
        # noinspection PyTypeChecker
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=None,
                subfilter=PADES, embed_validation_info=True
            ), signer=FROM_CA
        )


def test_pades_revinfo_ts_dummydata():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'

    dss = DocumentSecurityStore.read_dss(handler=r)
    assert dss is not None
    assert len(dss.certs) == 5
    assert len(dss.ocsps) == 1


def test_pades_revinfo_http_ts_dummydata(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    requests_mock.post(
        DUMMY_HTTP_TS.url, content=ts_response_callback,
        headers={'Content-Type': 'application/timestamp-reply'}
    )
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_HTTP_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'

    dss = DocumentSecurityStore.read_dss(handler=r)
    assert dss is not None
    assert len(dss.certs) == 5
    assert len(dss.ocsps) == 1


# TODO freeze time for these tests, test revocation

def test_pades_revinfo_live_no_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    rivt_pades = RevocationInfoValidationType.PADES_LT
    with pytest.raises(ValueError):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS}
        )


def test_pades_revinfo_live(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    dss = DocumentSecurityStore.read_dss(handler=r)
    vc = dss.as_validation_context({})
    assert dss is not None
    assert len(dss.vri_entries) == 1
    assert len(dss.certs) == 5
    assert len(dss.ocsps) == len(vc.ocsps) == 1
    assert len(dss.crls) == len(vc.crls) == 1
    rivt_pades = RevocationInfoValidationType.PADES_LT
    status = validate_pdf_ltv_signature(r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS})
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES

    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    with pytest.raises(ValueError):
        validate_pdf_ltv_signature(r.embedded_signatures[0], rivt_adobe, {'trust_roots': TRUST_ROOTS})


def test_adobe_revinfo_live(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    status = validate_pdf_ltv_signature(r.embedded_signatures[0], rivt_adobe, {'trust_roots': TRUST_ROOTS})
    assert status.valid and status.trusted


def test_pades_revinfo_live_nofullchain():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    rivt_pades = RevocationInfoValidationType.PADES_LT

    # with the same dumb settings, the timestamp doesn't validate at all,
    # which causes LTV validation to fail to bootstrap
    with pytest.raises(SignatureValidationError):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades,
            {'trust_roots': TRUST_ROOTS, 'ocsps': [FIXED_OCSP],
             'allow_fetching': False}
        )

    # now set up live testing
    from requests_mock import Mocker
    with Mocker() as m:
        live_testing_vc(m)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades, {
                'trust_roots': TRUST_ROOTS, 'allow_fetching': True
            }
        )
        # .. which should still fail because the chain of trust is broken, but
        # at least the timestamp should initially validate
        assert status.valid and not status.trusted, status.summary()


def test_meta_tsa_verify():
    # check if my testing setup works
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS, allow_fetching=False, crls=[],
        ocsps=[FIXED_OCSP], revocation_mode='hard-fail'
    )
    with pytest.raises(PathValidationError):
        CertificateValidator(TSA_CERT, validation_context=vc).validate_usage(
            {'time_stamping'}
        )


def test_adobe_revinfo_live_nofullchain():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    # same as for the pades test above
    with pytest.raises(SignatureValidationError):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_adobe, {
                'trust_roots': TRUST_ROOTS, 'allow_fetching': False,
                'ocsps': [FIXED_OCSP]
            }
        )
    from requests_mock import Mocker
    with Mocker() as m:
        live_testing_vc(m)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_adobe, {
                'trust_roots': TRUST_ROOTS, 'allow_fetching': True
            }
        )
        assert status.valid and not status.trusted, status.summary()


def test_pades_revinfo_live_lta(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    _test_pades_revinfo_live_lta(w, vc, in_place=False)


def test_pades_revinfo_live_lta_in_place(requests_mock, tmp_path):
    from pathlib import Path
    inout_file: Path = tmp_path / "test.pdf"
    inout_file.write_bytes(MINIMAL_ONE_FIELD)
    vc = live_testing_vc(requests_mock)
    with inout_file.open('r+b') as f:
        w = IncrementalPdfFileWriter(f)
        _test_pades_revinfo_live_lta(w, vc, in_place=True)


def _test_pades_revinfo_live_lta(w, vc, in_place):
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True,
            use_pades_lta=True
        ), signer=FROM_CA, timestamper=DUMMY_TS, in_place=in_place
    )
    r = PdfFileReader(out)
    dss = DocumentSecurityStore.read_dss(handler=r)
    vc = dss.as_validation_context({'trust_roots': TRUST_ROOTS})
    assert dss is not None
    assert len(dss.vri_entries) == 2
    assert len(dss.certs) == 5
    assert len(dss.ocsps) == len(vc.ocsps) == 1
    assert len(dss.crls) == len(vc.crls) == 1
    rivt_pades = RevocationInfoValidationType.PADES_LT
    status = validate_pdf_ltv_signature(
        r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES

    sig_obj = r.embedded_signatures[1].sig_object
    assert sig_obj.get_object()['/Type'] == pdf_name('/DocTimeStamp')

    rivt_pades_lta = RevocationInfoValidationType.PADES_LTA
    status = validate_pdf_ltv_signature(
        r.embedded_signatures[0], rivt_pades_lta, {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES


# TODO test multiple PAdES signatures


def prepare_sv_field(sv_spec):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec('Sig', seed_value_dict=sv_spec)
    fields.append_signature_fields(w, [sp])
    out = BytesIO()
    w.write(out)
    out.seek(0)
    return out


# passing test_violation=False tests the signer, while test_violation=True
#  instructs the signer to ignore all SV requirements, thus testing whether
#  the validator catches the violations properly
def sign_with_sv(sv_spec, sig_meta, signer=FROM_CA, timestamper=DUMMY_TS, test_violation=False):
    w = IncrementalPdfFileWriter(prepare_sv_field(sv_spec))

    pdf_signer = signers.PdfSigner(sig_meta, signer, timestamper=timestamper)
    pdf_signer._ignore_sv = test_violation
    out = pdf_signer.sign_pdf(w)
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    status = validate_pdf_signature(r, sig_field, dummy_ocsp_vc())
    if test_violation:
        assert not status.seed_value_ok
    else:
        assert status.seed_value_ok
    return EmbeddedPdfSignature(r, sig_field)


def test_sv_sign_md_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.DIGEST_METHOD,
        digest_methods=['sha256', 'sha512'],
    )
    with pytest.raises(SigningError):
        sign_with_sv(
            sv, signers.PdfSignatureMetadata(
                md_algorithm='sha1', field_name='Sig'
            )
        )
    sign_with_sv(
        sv, signers.PdfSignatureMetadata(md_algorithm='sha1', field_name='Sig'),
        test_violation=True
    )
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.md_algorithm == 'sha256'
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(
            md_algorithm='sha512', field_name='Sig'
        )
    )
    assert emb_sig.md_algorithm == 'sha512'


def test_sv_sign_md_hint():
    sv = fields.SigSeedValueSpec(digest_methods=['sha256', 'sha512'])
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(
            md_algorithm='sha1', field_name='Sig'
        )
    )
    assert emb_sig.md_algorithm == 'sha1'
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.md_algorithm == 'sha256'
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(
            md_algorithm='sha512', field_name='Sig'
        )
    )
    assert emb_sig.md_algorithm == 'sha512'


def test_sv_sign_subfilter_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.SUBFILTER, subfilters=[PADES]
    )
    with pytest.raises(SigningError):
        sign_with_sv(
            sv, signers.PdfSignatureMetadata(
                md_algorithm='sha1', field_name='Sig',
                subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED
            )
        )
    sign_with_sv(
        sv, signers.PdfSignatureMetadata(
            md_algorithm='sha1', field_name='Sig',
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED
        ), test_violation=True
    )
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.sig_object['/SubFilter'] == PADES.value


def test_sv_sign_subfilter_hint():
    sv = fields.SigSeedValueSpec(subfilters=[PADES])
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(
            md_algorithm='sha1', field_name='Sig',
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED
        )
    )
    assert emb_sig.sig_object['/SubFilter'] == '/adbe.pkcs7.detached'
    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.sig_object['/SubFilter'] == PADES.value


def test_sv_sign_addrevinfo_req(requests_mock):
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.ADD_REV_INFO,
        add_rev_info=True
    )
    vc = live_testing_vc(requests_mock)
    meta = signers.PdfSignatureMetadata(
        field_name='Sig', validation_context=vc,
        subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        embed_validation_info=True
    )
    emb_sig = sign_with_sv(sv, meta)
    status = validate_pdf_ltv_signature(
        emb_sig, RevocationInfoValidationType.ADOBE_STYLE,
        {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted
    assert emb_sig.sig_object['/SubFilter'] == '/adbe.pkcs7.detached'

    meta = signers.PdfSignatureMetadata(
        field_name='Sig', validation_context=vc,
        subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        embed_validation_info=False
    )
    with pytest.raises(SigningError):
        sign_with_sv(sv, meta)
    sign_with_sv(sv, meta, test_violation=True)
    meta = signers.PdfSignatureMetadata(
        field_name='Sig', validation_context=vc,
        subfilter=fields.SigSeedSubFilter.PADES,
        embed_validation_info=True
    )
    # this shouldn't work with PAdES
    with pytest.raises(SigningError):
        sign_with_sv(sv, meta)
    sign_with_sv(sv, meta, test_violation=True)


def test_sv_sign_addrevinfo_subfilter_conflict():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.ADD_REV_INFO,
        subfilters=[PADES], add_rev_info=True
    )
    with pytest.raises(SigningError):
        meta = signers.PdfSignatureMetadata(
            field_name='Sig', validation_context=dummy_ocsp_vc(),
            embed_validation_info=True
        )
        sign_with_sv(sv, meta)

    revinfo_and_subfilter = (
        fields.SigSeedValFlags.ADD_REV_INFO | fields.SigSeedValFlags.SUBFILTER
    )
    sv = fields.SigSeedValueSpec(
        flags=revinfo_and_subfilter, subfilters=[PADES], add_rev_info=True
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig', validation_context=dummy_ocsp_vc(),
        embed_validation_info=True
    )
    with pytest.raises(SigningError):
        sign_with_sv(sv, meta)
    sign_with_sv(sv, meta, test_violation=True)

    sv = fields.SigSeedValueSpec(
        flags=revinfo_and_subfilter, subfilters=[PADES], add_rev_info=False
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig', validation_context=dummy_ocsp_vc(),
    )
    sign_with_sv(sv, meta)


def test_sv_sign_cert_constraint():
    # this is more thoroughly unit tested at a lower level (see further up),
    # so we simply try two basic scenarios here for now
    from asn1crypto import x509
    sv = fields.SigSeedValueSpec(
        cert=fields.SigCertConstraints(
            flags=fields.SigCertConstraintFlags.SUBJECT_DN,
            subject_dn=x509.Name.build({'common_name': 'Lord Testerino'}),
        )
    )
    sign_with_sv(sv, signers.PdfSignatureMetadata(field_name='Sig'))
    sv = fields.SigSeedValueSpec(
        cert=fields.SigCertConstraints(
            flags=fields.SigCertConstraintFlags.SUBJECT_DN,
            subject_dn=x509.Name.build({'common_name': 'Not Lord Testerino'}),
        )
    )
    with pytest.raises(SigningError):
        sign_with_sv(sv, signers.PdfSignatureMetadata(field_name='Sig'))
    sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig'), test_violation=True
    )


def test_sv_flag_unsupported():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.APPEARANCE_FILTER,
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(NotImplementedError):
        sign_with_sv(sv, meta)


def test_sv_subfilter_unsupported():
    sv_spec = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.SUBFILTER,
        subfilters=[PADES]
    )
    w = IncrementalPdfFileWriter(prepare_sv_field(sv_spec))
    field_name, _, sig_field = next(fields.enumerate_sig_fields(w))
    sig_field = sig_field.get_object()
    sv_ref = sig_field.raw_get('/SV')
    w.mark_update(sv_ref)
    sv_ref.get_object()['/SubFilter'][0] = pdf_name('/this.doesnt.exist')
    out = BytesIO()
    w.write(out)
    out.seek(0)
    frozen = out.getvalue()

    with pytest.raises(NotImplementedError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(field_name='Sig'),
            signer=FROM_CA, timestamper=DUMMY_TS
        )
    with pytest.raises(NotImplementedError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(
                field_name='Sig', subfilter=PADES
            ),
            signer=FROM_CA, timestamper=DUMMY_TS
        )


def test_sv_subfilter_unsupported_partial():
    sv_spec = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.SUBFILTER,
        subfilters=[fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED, PADES]
    )
    w = IncrementalPdfFileWriter(prepare_sv_field(sv_spec))
    field_name, _, sig_field = next(fields.enumerate_sig_fields(w))
    sig_field = sig_field.get_object()
    sv_ref = sig_field.raw_get('/SV')
    w.mark_update(sv_ref)
    sv_ref.get_object()['/SubFilter'][0] = pdf_name('/this.doesnt.exist')
    out = BytesIO()
    w.write(out)
    out.seek(0)
    frozen = out.getvalue()

    signers.sign_pdf(
        IncrementalPdfFileWriter(BytesIO(frozen)),
        signers.PdfSignatureMetadata(field_name='Sig'),
        signer=FROM_CA, timestamper=DUMMY_TS
    )
    with pytest.raises(SigningError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(
                field_name='Sig',
                subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED
            ),
            signer=FROM_CA, timestamper=DUMMY_TS
        )


def test_sv_timestamp_url(requests_mock):
    # state issues (see comment in signers.py), so create a fresh signer
    sv = fields.SigSeedValueSpec(
        timestamp_server_url=DUMMY_HTTP_TS.url,
        timestamp_required=True
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    ts_requested = False

    def ts_callback(*args, **kwargs):
        nonlocal ts_requested
        ts_requested = True
        return ts_response_callback(*args, **kwargs)

    requests_mock.post(
        DUMMY_HTTP_TS.url, content=ts_callback,
        headers={'Content-Type': 'application/timestamp-reply'}
    )
    # noinspection PyTypeChecker
    sign_with_sv(sv, meta, timestamper=None)
    assert ts_requested


def test_sv_sign_reason_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.REASONS,
        reasons=['I agree', 'Works for me']
    )
    aw_yiss = signers.PdfSignatureMetadata(reason='Aw yiss', field_name='Sig')
    with pytest.raises(SigningError):
        sign_with_sv(sv, aw_yiss)
    sign_with_sv(sv, aw_yiss, test_violation=True)

    with pytest.raises(SigningError):
        sign_with_sv(sv, signers.PdfSignatureMetadata(field_name='Sig'))
    sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig'),
        test_violation=True
    )

    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig', reason='I agree')
    )
    assert emb_sig.sig_object['/Reason'] == 'I agree'


@pytest.mark.parametrize('reasons_param', [None, [], ["."]])
def test_sv_sign_reason_prohibited(reasons_param):
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.REASONS, reasons=reasons_param
    )
    aw_yiss = signers.PdfSignatureMetadata(reason='Aw yiss', field_name='Sig')
    with pytest.raises(SigningError):
        sign_with_sv(sv, aw_yiss)
    sign_with_sv(sv, aw_yiss, test_violation=True)

    dot = signers.PdfSignatureMetadata(reason='.', field_name='Sig')
    with pytest.raises(SigningError):
        sign_with_sv(sv, dot)
    sign_with_sv(sv, dot, test_violation=True)

    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert pdf_name('/Reason') not in emb_sig.sig_object


# helper function for filling in the text field in the SIMPLE_FORM example
def set_text_field(writer, val):
    tf = writer.root['/AcroForm']['/Fields'][1].get_object()

    appearance = generic.RawContent(
        parent=None, box=generic.BoxConstraints(height=60, width=130),
        data=b'q 0 0 1 rg BT /Ti 12 Tf (%s) Tj ET Q' % val.encode(
            'ascii')
    )
    tf['/V'] = generic.pdf_string(val)

    tf['/AP'] = generic.DictionaryObject({
        generic.pdf_name('/N'): writer.add_object(
            appearance.as_form_xobject()
        )
    })
    writer.update_container(tf)


def test_form_field_postsign_fill():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


def test_form_field_postsign_modify():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # fill in, then sign
    set_text_field(w, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


# helper function for filling in the text field in the TEXTFIELD_GROUP example
def set_text_field_in_group(writer, ix, val):
    tf_parent = writer.root['/AcroForm']['/Fields'][1].get_object()
    tf = tf_parent['/Kids'][ix].get_object()
    appearance = generic.RawContent(
        parent=None, box=generic.BoxConstraints(height=60, width=130),
        data=b'''q 0 0 1 rg BT /Ti 12 Tf (%s) Tj ET Q''' % val.encode(
            'ascii')
    )
    tf['/V'] = generic.pdf_string(val)

    tf['/AP'] = generic.DictionaryObject({
        generic.pdf_name('/N'): writer.add_object(
            appearance.as_form_xobject()
        )
    })
    writer.update_container(tf)


GROUP_VARIANTS = (TEXTFIELD_GROUP, TEXTFIELD_GROUP_VAR)


@pytest.mark.parametrize('variant, existing_only', [(0, True), (1, True), (0, False), (1, False)])
def test_deep_non_sig_field(variant, existing_only):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))
    meta = signers.PdfSignatureMetadata(field_name='TextInput.TextField1')
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, meta, signer=FROM_CA, existing_fields_only=existing_only
        )


@pytest.mark.parametrize('variant', [0, 1])
def test_deep_non_sig_field_nocreate(variant):
    # this case might be supported in the future, but for now we check for
    # a NotImplementedError (since creating fields with dots in their (partial)
    # names is not compliant with the standard)
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))
    meta = signers.PdfSignatureMetadata(field_name='TextInput.NewSig')
    with pytest.raises(NotImplementedError):
        signers.sign_pdf(w, meta, signer=FROM_CA)


@pytest.mark.parametrize('variant', [0, 1])
def test_form_field_in_group_postsign_fill(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


@pytest.mark.parametrize('variant', [0, 1])
def test_form_field_in_group_postsign_fill_other_field(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))

    # fill in, then sign, then fill other field
    set_text_field_in_group(w, 0, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 1, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


@pytest.mark.parametrize('variant', [0, 1])
def test_form_field_in_group_postsign_modify(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))

    # fill in, then sign, then override
    set_text_field_in_group(w, 0, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some other text")
    set_text_field_in_group(w, 1, "Yet other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


test_form_field_in_group_postsign_modify_failure_matrix = [
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.ALL)),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.ALL)),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE, fields=['Sig1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE, fields=['Sig1'])),
]

@pytest.mark.parametrize('field_filled, fieldmdp_spec', test_form_field_in_group_postsign_modify_failure_matrix)
def test_form_field_in_group_locked_postsign_modify_failure(field_filled, fieldmdp_spec):
    # the field that is filled in after signing is always the same,
    # but the initial one varies
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[0]))


    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fieldmdp_spec,
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_fields(w, [sp])
    set_text_field_in_group(w, field_filled, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='SigNew')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r, filled_status=True))
    assert field_name == 'SigNew'
    val_trusted_but_modified(r, sig_field)


test_form_field_in_group_postsign_modify_success_matrix = [
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE, fields=['Sig1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE, fields=['Sig1'])),
]


@pytest.mark.parametrize('field_filled, fieldmdp_spec', test_form_field_in_group_postsign_modify_success_matrix)
def test_form_field_in_group_locked_postsign_modify_success(field_filled, fieldmdp_spec):
    # the field that is filled in after signing is always the same,
    # but the initial one varies
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[0]))


    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fieldmdp_spec,
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_fields(w, [sp])
    set_text_field_in_group(w, field_filled, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='SigNew')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 1, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r, filled_status=True))
    assert field_name == 'SigNew'
    val_trusted(r, sig_field, extd=True)

def test_form_field_postsign_fill_pades_lt(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    vc = live_testing_vc(requests_mock)
    meta =signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=vc,
        subfilter=PADES, embed_validation_info=True,
    )

    # sign, then fill
    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


def test_form_field_postsign_modify_pades_lt(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    vc = live_testing_vc(requests_mock)
    meta =signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=vc,
        subfilter=PADES, embed_validation_info=True,
    )

    # sign, then fill
    set_text_field(w, "Some text")
    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)


def test_pades_double_sign(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    meta2 = signers.PdfSignatureMetadata(
        field_name='Sig2', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)

    r = PdfFileReader(out)
    sig_fields = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    val_trusted(r, sig_field, extd=True)

    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig2'
    val_trusted(r, sig_field, extd=True)


def test_pades_double_sign_delete_dss(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    meta2 = signers.PdfSignatureMetadata(
        field_name='Sig2', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    # DSS is now covered by the second signature, so this is illegal
    del w.root['/DSS']
    w.update_root()
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert '/DSS' not in r.root
    sig_fields = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    # first signature is still valid, since the DSS was initialised after
    # it was created.
    val_trusted(r, sig_field, extd=True)

    field_name, sig_obj, sig_field = next(sig_fields)
    # however, the second signature is violated by the deletion of the /DSS key
    assert field_name == 'Sig2'
    val_trusted_but_modified(r, sig_field)


def test_pades_dss_object_clobber(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    dummy_ref = w.add_object(generic.pdf_string("Hi there")).reference

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    # We're going to reassign the DSS object to another object ID, namely
    #  one that clobbers the dummy_ref object. This should be ample cause
    #  for suspicion.
    dss = w.root['/DSS']
    w.objects[(dummy_ref.generation, dummy_ref.idnum)] = dss
    w.root['/DSS'] = generic.IndirectObject(
        idnum=dummy_ref.idnum, generation=dummy_ref.generation, pdf=w
    )
    w.update_root()
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    sig_fields = fields.enumerate_sig_fields(r)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    val_trusted_but_modified(r, sig_field)


def test_form_field_structure_modification():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    meta =signers.PdfSignatureMetadata(field_name='Sig1')

    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    field_arr = w.root['/AcroForm']['/Fields']
    # shallow copy the text field
    tf = generic.DictionaryObject(field_arr[1].get_object())
    field_arr.append(w.add_object(tf))
    w.update_container(field_arr)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted_but_modified(r, sig_field)


def test_delete_signature():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    # first, we simply sign the two fields
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        existing_fields_only=True
    )

    w = IncrementalPdfFileWriter(out)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
        existing_fields_only=True
    )

    # after that, we add an incremental update that deletes the first signature
    # This should invalidate the remaining one.
    w = IncrementalPdfFileWriter(out)
    sig_fields = fields.enumerate_sig_fields(w)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    del sig_field.get_object()['/V']
    w.mark_update(sig_field)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    sig_fields = fields.enumerate_sig_fields(r, filled_status=True)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig2'
    val_trusted_but_modified(r, sig_field)


def test_tamper_sig_obj():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1'
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    w = IncrementalPdfFileWriter(out)
    sig_obj = w.prev.embedded_signatures[0].sig_object
    sig_obj['/Bleh'] = generic.BooleanObject(False)
    w.update_container(sig_obj)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    emb.compute_integrity_info()
    assert emb.modification_level == ModificationLevel.OTHER


def test_rogue_backreferences():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    # intentionally refer back to the contents of the first page
    w.root['/DSS'] = w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    w.update_root()
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    # pretend to add a new form field, but actually secretly do a page
    #  tree modification.
    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    w = IncrementalPdfFileWriter(out)
    fields.append_signature_fields(w, [sp])
    w.write_in_place()

    w = IncrementalPdfFileWriter(out)
    contents_ref = w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    content_stream: generic.StreamObject = contents_ref.get_object()
    content_stream._data = content_stream.data + b"q Q"
    content_stream._encoded_data = None
    w.mark_update(contents_ref)
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    emb.compute_integrity_info()
    assert emb.modification_level == ModificationLevel.OTHER
