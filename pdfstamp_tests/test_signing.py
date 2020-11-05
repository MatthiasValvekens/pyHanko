import re
from datetime import datetime

import pytest
from io import BytesIO

import pytz
from asn1crypto import ocsp, tsp
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
    EmbeddedPdfSignature, read_adobe_revocation_info,
    validate_pdf_ltv_signature, RevocationInfoValidationType
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

DUMMY_TS = timestamps.DummyTimeStamper(
    tsa_cert=oskeys.parse_certificate(
        read_all(TESTING_CA_DIR + '/root/newcerts/tsa.cert.pem')
    ),
    tsa_key=oskeys.parse_private(
        read_all(TESTING_CA_DIR + '/keys/tsa.key.pem'), password=b'secret'
    ),
    certs_to_embed=FROM_CA.cert_registry,
)

FROM_CA_TS = signers.SimpleSigner(
    signing_cert=FROM_CA.signing_cert, cert_registry=FROM_CA.cert_registry,
    signing_key=FROM_CA.signing_key, timestamper=DUMMY_TS
)

DUMMY_HTTP_TS = timestamps.HTTPTimeStamper(
    'http://example.com/tsa', https=False
)
FROM_CA_HTTP_TS = signers.SimpleSigner(
    signing_cert=FROM_CA.signing_cert, cert_registry=FROM_CA.cert_registry,
    signing_key=FROM_CA.signing_key, timestamper=DUMMY_HTTP_TS
)

# with the testing CA setup update, this OCSP response is totally
#  unrelated to the keys being used, so it should fail any sort of real
#  validation
FIXED_OCSP = ocsp.OCSPResponse.load(
    read_all(CRYPTO_DATA_DIR + '/ocsp.resp.der')
)


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
    # FIXME this is all moot since certvalidator uses urlopen()

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


def val_trusted(r, sig_obj, extd=False):
    val_status = validate_pdf_signature(r, sig_obj, SIMPLE_V_CONTEXT)
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'TRUSTED' in summ
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
    summ = val_status.summary()
    assert 'INTACT' in summ
    return val_status


@pytest.mark.parametrize('incl_signed_time', [True, False])
def test_simple_sign(incl_signed_time):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', include_signedtime_attr=incl_signed_time
    )
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_untrusted(r, sig_obj)

    # try tampering with the file
    out.seek(0x9d)
    # this just changes the size of the media box, so the file should remain
    # a valid PDF.
    out.write(b'4')
    out.seek(0)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    tampered = validate_pdf_signature(r, sig_obj, SIMPLE_V_CONTEXT)
    assert not tampered.intact
    assert not tampered.valid
    assert tampered.summary() == 'INVALID'


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


def test_sign_with_trust_pkcs12():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA_PKCS12
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
    with pytest.raises(SigningError):
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
        w, signers.PdfSignatureMetadata(), signer=FROM_CA_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    validity = val_trusted(r, sig_obj)
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
            w, signers.PdfSignatureMetadata(), signer=FROM_CA_HTTP_TS,
            existing_fields_only=True,
        )

    requests_mock.post(
        DUMMY_HTTP_TS.url, content=ts_response_callback,
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
            docmdp_permissions=signers.DocMDPPerm.NO_CHANGES
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_obj)

    info = read_certification_data(r)
    assert info.author_sig.sig_object == sig_obj.get_object()
    assert info.permission_bits == signers.DocMDPPerm.NO_CHANGES

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
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    val_trusted(r, sig_obj)

    info = read_certification_data(r)
    assert info.author_sig.sig_object == sig_obj.get_object()
    assert info.permission_bits == signers.DocMDPPerm.FILL_FORMS

    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig2', certify=True,
                docmdp_permissions=signers.DocMDPPerm.FILL_FORMS
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
    field_name, sig_obj, _ = next(sigs)
    assert field_name == 'Sig1'
    val_trusted(r, sig_obj, extd=True)

    info = read_certification_data(r)
    assert info.author_sig.sig_object == sig_obj.get_object()
    assert info.permission_bits == signers.DocMDPPerm.FILL_FORMS

    field_name, sig_obj, _ = next(sigs)
    assert field_name == 'Sig2'
    val_trusted(r, sig_obj)


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
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig2', md_algorithm='sha1'
            ), signer=FROM_CA
        )

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA
    )
    out.seek(0)
    r = PdfFileReader(out)
    sigs = fields.enumerate_sig_fields(r)
    next(sigs)
    field_name, sig_obj, _ = next(sigs)
    assert EmbeddedPdfSignature(r, sig_obj).md_algorithm == 'sha256'


def test_ocsp_embed():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            embed_validation_info=True
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    status = val_untrusted(r, sig_obj)
    assert not status.trusted

    val_trusted(r, sig_obj)

    embedded_sig = EmbeddedPdfSignature(r, sig_obj)
    vc = read_adobe_revocation_info(embedded_sig.signer_info)
    assert len(vc.ocsps) == 1


PADES = fields.SigSeedSubFilter.PADES

def test_pades_flag():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
        signer=FROM_CA
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
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
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'

    dss, vc = DocumentSecurityStore.read_dss(handler=r)
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
        ), signer=FROM_CA_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'

    dss, vc = DocumentSecurityStore.read_dss(handler=r)
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
        ), signer=FROM_CA_HTTP_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'

    dss, vc = DocumentSecurityStore.read_dss(handler=r)
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
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    rivt_pades = RevocationInfoValidationType.PADES_LT
    with pytest.raises(ValueError):
        validate_pdf_ltv_signature(r, sig_obj, rivt_pades)


def test_pades_revinfo_live(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA_TS
    )
    r = PdfFileReader(out)
    dss, vc = DocumentSecurityStore.read_dss(handler=r)
    assert dss is not None
    assert len(dss.vri_entries) == 1
    assert len(dss.certs) == 5
    assert len(dss.ocsps) == len(vc.ocsps) == 1
    assert len(dss.crls) == len(vc.crls) == 1
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    rivt_pades = RevocationInfoValidationType.PADES_LT
    status = validate_pdf_ltv_signature(r, sig_obj, rivt_pades, {'trust_roots': TRUST_ROOTS})
    assert status.valid and status.trusted

    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    with pytest.raises(ValueError):
        validate_pdf_ltv_signature(r, sig_obj, rivt_adobe, {'trust_roots': TRUST_ROOTS})


def test_adobe_revinfo_live(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=True
        ), signer=FROM_CA_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    status = validate_pdf_ltv_signature(r, sig_obj, rivt_adobe, {'trust_roots': TRUST_ROOTS})
    assert status.valid and status.trusted


def test_pades_revinfo_live_nofullchain():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    rivt_pades = RevocationInfoValidationType.PADES_LT
    status = validate_pdf_ltv_signature(r, sig_obj, rivt_pades)
    assert status.valid and not status.trusted


def test_adobe_revinfo_live_nofullchain():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=True
        ), signer=FROM_CA_TS
    )
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    status = validate_pdf_ltv_signature(r, sig_obj, rivt_adobe)
    assert status.valid and not status.trusted


def test_pades_revinfo_live_lta(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True,
            use_pades_lta=True
        ), signer=FROM_CA_TS
    )
    r = PdfFileReader(out)
    dss, vc = DocumentSecurityStore.read_dss(handler=r)
    assert dss is not None
    assert len(dss.vri_entries) == 2
    assert len(dss.certs) == 5
    assert len(dss.ocsps) == len(vc.ocsps) == 1
    assert len(dss.crls) == len(vc.crls) == 1
    field_iter = fields.enumerate_sig_fields(r)
    field_name, sig_obj, _ = next(field_iter)
    rivt_pades = RevocationInfoValidationType.PADES_LT
    status = validate_pdf_ltv_signature(r, sig_obj, rivt_pades, {'trust_roots': TRUST_ROOTS})
    assert status.valid and status.trusted

    field_name, sig_obj, _ = next(field_iter)
    assert sig_obj.get_object()['/Type'] == pdf_name('/DocTimeStamp')
    # TODO implement and run actual LTA verification checks

# TODO test multiple PAdES signatures


def prepare_sv_field(sv_spec):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec('Sig', seed_value_dict=sv_spec)
    fields.append_signature_fields(w, [sp])
    out = BytesIO()
    w.write(out)
    out.seek(0)
    return out


def sign_with_sv(sv_spec, sig_meta, signer=FROM_CA_TS):
    w = IncrementalPdfFileWriter(prepare_sv_field(sv_spec))
    out = signers.sign_pdf(w, sig_meta, signer=signer)
    r = PdfFileReader(out)
    field_name, sig_obj, _ = next(fields.enumerate_sig_fields(r))
    return EmbeddedPdfSignature(r, sig_obj)


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
        emb_sig.reader, emb_sig.sig_object,
        RevocationInfoValidationType.ADOBE_STYLE,
        {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted
    assert emb_sig.sig_object['/SubFilter'] == '/adbe.pkcs7.detached'

    with pytest.raises(SigningError):
        meta = signers.PdfSignatureMetadata(
            field_name='Sig', validation_context=vc,
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=False
        )
        sign_with_sv(sv, meta)

    # this shouldn't work with PAdES
    with pytest.raises(SigningError):
        meta = signers.PdfSignatureMetadata(
            field_name='Sig', validation_context=vc,
            subfilter=fields.SigSeedSubFilter.PADES,
            embed_validation_info=True
        )
        sign_with_sv(sv, meta)


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
    with pytest.raises(SigningError):
        meta = signers.PdfSignatureMetadata(
            field_name='Sig', validation_context=dummy_ocsp_vc(),
            embed_validation_info=True
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


def test_sv_flag_unsupported():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.APPEARANCE_FILTER,
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(SigningError):
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

    with pytest.raises(SigningError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(field_name='Sig'),
            signer=FROM_CA_TS
        )
    with pytest.raises(SigningError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(
                field_name='Sig', subfilter=PADES
            ),
            signer=FROM_CA_TS
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
        signer=FROM_CA_TS
    )
    with pytest.raises(SigningError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(
                field_name='Sig',
                subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED
            ),
            signer=FROM_CA_TS
        )


def test_sv_timestamp_url(requests_mock):
    # state issues (see comment in signers.py), so create a fresh signer
    signer = signers.SimpleSigner.load(
        TESTING_CA_DIR + '/keys/signer.key.pem',
        TESTING_CA_DIR + '/intermediate/newcerts/signer.cert.pem',
        ca_chain_files=(
            TESTING_CA_DIR + '/intermediate/certs/ca-chain.cert.pem',),
        key_passphrase=b'secret'
    )
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
    sign_with_sv(sv, meta, signer=signer)
    assert ts_requested


def test_sv_sign_reason_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.REASONS,
        reasons=['I agree', 'Works for me']
    )
    with pytest.raises(SigningError):
        sign_with_sv(
            sv, signers.PdfSignatureMetadata(
                reason='Aw yiss', field_name='Sig'
            )
        )
    with pytest.raises(SigningError):
        sign_with_sv(
            sv, signers.PdfSignatureMetadata(field_name='Sig')
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
    with pytest.raises(SigningError):
        sign_with_sv(
            sv, signers.PdfSignatureMetadata(
                reason='Aw yiss', field_name='Sig'
            )
        )
    with pytest.raises(SigningError):
        sign_with_sv(
            sv, signers.PdfSignatureMetadata(
                reason='.', field_name='Sig'
            )
        )

    emb_sig = sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert pdf_name('/Reason') not in emb_sig.sig_object
