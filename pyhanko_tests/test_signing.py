import re
from datetime import datetime

import pytest
from io import BytesIO

import pytz
from asn1crypto import ocsp, tsp
from asn1crypto.algos import (
    SignedDigestAlgorithm, RSASSAPSSParams,
    MaskGenAlgorithm, DigestAlgorithm,
)
import tzlocal

import pyhanko.pdf_utils.content
from certvalidator.errors import PathValidationError

import pyhanko.sign.fields
from certvalidator import ValidationContext, CertificateValidator
from ocspbuilder import OCSPResponseBuilder
from oscrypto import keys as oskeys

from pyhanko import stamp
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.font import pdf_name
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.misc import PdfWriteError
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import timestamps, fields, signers
from pyhanko.sign.general import SigningError
from pyhanko.sign.signers import PdfTimeStamper
from pyhanko.sign.validation import (
    validate_pdf_signature, read_certification_data, DocumentSecurityStore,
    EmbeddedPdfSignature, apply_adobe_revocation_info,
    validate_pdf_ltv_signature, RevocationInfoValidationType,
    SignatureCoverageLevel, SignatureValidationError,
)
from pyhanko.sign.diff_analysis import (
    ModificationLevel, DiffResult,
    NO_CHANGES_DIFF_POLICY,
)
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import QRStampStyle
from .samples import *

from freezegun import freeze_time


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

FROM_ECC_CA = signers.SimpleSigner.load(
    ECC_TESTING_CA_DIR + '/keys/signer.key.pem',
    ECC_TESTING_CA_DIR + '/intermediate/newcerts/signer.cert.pem',
    ca_chain_files=(ECC_TESTING_CA_DIR + '/intermediate/certs/ca-chain.cert.pem',),
    key_passphrase=b'secret'
)

REVOKED_SIGNER = signers.SimpleSigner.load(
    TESTING_CA_DIR + '/keys/signer2.key.pem',
    TESTING_CA_DIR + '/intermediate/newcerts/signer2.cert.pem',
    ca_chain_files=(TESTING_CA_DIR + '/intermediate/certs/ca-chain.cert.pem',),
    key_passphrase=b'secret'
)

ROOT_PATH = TESTING_CA_DIR + '/root/certs/ca.cert.pem'
ECC_ROOT_PATH = ECC_TESTING_CA_DIR + '/root/certs/ca.cert.pem'
INTERM_PATH = TESTING_CA_DIR + '/intermediate/certs/ca.cert.pem'
OCSP_PATH = TESTING_CA_DIR + '/intermediate/newcerts/ocsp.cert.pem'
REVOKED_CERT_PATH = TESTING_CA_DIR + '/intermediate/newcerts/1002.pem'
TRUST_ROOTS = list(signers.load_certs_from_pemder((ROOT_PATH,)))

FROM_CA_PKCS12 = signers.SimpleSigner.load_pkcs12(
    TESTING_CA_DIR + '/intermediate/newcerts/signer.pfx',
    passphrase=b'exportsecret'
)

ROOT_CERT = oskeys.parse_certificate(read_all(ROOT_PATH))
ECC_ROOT_CERT = oskeys.parse_certificate(read_all(ECC_ROOT_PATH))
INTERM_CERT = oskeys.parse_certificate(read_all(INTERM_PATH))
OCSP_CERT = oskeys.parse_certificate(read_all(OCSP_PATH))
REVOKED_CERT = oskeys.parse_certificate(read_all(REVOKED_CERT_PATH))
NOTRUST_V_CONTEXT = lambda: ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = lambda: ValidationContext(trust_roots=[ROOT_CERT])
SIMPLE_ECC_V_CONTEXT = lambda: ValidationContext(trust_roots=[ECC_ROOT_CERT])
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

TSA2_CERT = oskeys.parse_certificate(
    read_all(TESTING_CA_DIR + '/root/newcerts/tsa2.cert.pem')
)
DUMMY_TS2 = timestamps.DummyTimeStamper(
    tsa_cert=TSA2_CERT,
    tsa_key=oskeys.parse_private(
        read_all(TESTING_CA_DIR + '/keys/tsa2.key.pem'), password=b'secret'
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


def val_trusted(embedded_sig: EmbeddedPdfSignature, extd=False,
                vc=None):
    if vc is None:
        vc = SIMPLE_V_CONTEXT()
    val_status = validate_pdf_signature(embedded_sig, vc, skip_diff=not extd)
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    val_status.pretty_print_details()
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
def val_untrusted(embedded_sig: EmbeddedPdfSignature, extd=False):
    val_status = validate_pdf_signature(embedded_sig, NOTRUST_V_CONTEXT())
    assert val_status.intact
    assert val_status.valid
    if not extd:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert val_status.modification_level == ModificationLevel.NONE
    else:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
        assert val_status.modification_level <= ModificationLevel.FORM_FILLING
    summ = val_status.summary()
    val_status.pretty_print_details()
    assert 'INTACT' in summ
    return val_status


def val_trusted_but_modified(embedded_sig: EmbeddedPdfSignature):
    val_status = validate_pdf_signature(embedded_sig, SIMPLE_V_CONTEXT())
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
    assert val_status.modification_level == ModificationLevel.OTHER
    assert not val_status.docmdp_ok
    assert not val_status.bottom_line
    return val_status


def test_simple_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)

    # try tampering with the file
    out.seek(0x9d)
    # this just changes the size of the media box, so the file should remain
    # a valid PDF.
    out.write(b'4')
    out.seek(0)
    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    tampered = validate_pdf_signature(emb, SIMPLE_V_CONTEXT())
    assert not tampered.intact
    assert not tampered.valid
    assert tampered.summary() == 'INVALID'


@pytest.mark.parametrize('policy, skip_diff',
                         [(None, False),
                          (NO_CHANGES_DIFF_POLICY, False),
                          (None, True)])
def test_diff_fallback_ok(policy, skip_diff):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    status = validate_pdf_signature(
        emb, diff_policy=policy, skip_diff=skip_diff
    )
    if skip_diff:
        assert emb.diff_result is None
        # docmdp should still be OK without the diff check
        # because the signature covers the entire file
        assert status.docmdp_ok
        assert status.modification_level == ModificationLevel.NONE
    else:
        assert isinstance(emb.diff_result, DiffResult)
        assert status.modification_level == ModificationLevel.NONE
        assert status.docmdp_ok


@freeze_time('2020-11-01')
def test_sign_with_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/AP' not in s.sig_field
    status = val_untrusted(s)
    assert not status.trusted

    val_trusted(s)


@freeze_time('2020-11-01')
def test_sign_with_ecdsa_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_ECC_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, vc=SIMPLE_ECC_V_CONTEXT())


@freeze_time('2020-11-01')
def test_sign_with_explicit_ecdsa():
    signer = signers.SimpleSigner.load(
        ECC_TESTING_CA_DIR + '/keys/signer.key.pem',
        ECC_TESTING_CA_DIR + '/intermediate/newcerts/signer.cert.pem',
        ca_chain_files=(
            ECC_TESTING_CA_DIR + '/intermediate/certs/ca-chain.cert.pem',),
        key_passphrase=b'secret', signature_mechanism=SignedDigestAlgorithm(
            {'algorithm': 'ecdsa'}
        )
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=signer
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, vc=SIMPLE_ECC_V_CONTEXT())


def test_sign_with_new_field_spec():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    spec = fields.SigFieldSpec(sig_field_name='Sig1', box=(20, 20, 80, 40))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        new_field_spec=spec
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/AP' in s.sig_field

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    spec = fields.SigFieldSpec(sig_field_name='Sig1', box=(20, 20, 80, 40))

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
            new_field_spec=spec
        )

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
            new_field_spec=spec, existing_fields_only=True
        )


@freeze_time('2020-11-01')
def test_sign_with_revoked(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=REVOKED_SIGNER
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]

    vc = live_testing_vc(requests_mock)
    val_status = validate_pdf_signature(s, vc)
    assert val_status.intact
    assert val_status.valid
    assert val_status.revoked
    assert not val_status.trusted
    assert 'revoked' in val_status.pretty_print_details()
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'REVOKED' in summ
    assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
    assert val_status.modification_level == ModificationLevel.NONE
    assert not val_status.bottom_line

    # should refuse to sign with a known revoked cert
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=vc
            ),
            signer=REVOKED_SIGNER
        )


def test_sign_with_later_revoked_nots(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with freeze_time('2020-01-20'):
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=REVOKED_SIGNER
        )
        r = PdfFileReader(out)
        s = r.embedded_signatures[0]

    # there's no way to do a timestamp validation check here, so the checker
    # should assume the timestamp to be invalid
    with freeze_time('2020-11-01'):

        r = PdfFileReader(out)
        s = r.embedded_signatures[0]
        vc = live_testing_vc(requests_mock)
        val_status = validate_pdf_signature(s, vc)
        assert val_status.intact
        assert val_status.valid
        assert val_status.revoked
        assert not val_status.trusted

        summ = val_status.summary()
        assert 'INTACT' in summ
        assert 'REVOKED' in summ
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert val_status.modification_level == ModificationLevel.NONE
        assert not val_status.bottom_line


@freeze_time('2020-11-01')
def test_sign_with_trust_pkcs12():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA_PKCS12
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_untrusted(s)
    assert not status.trusted

    val_trusted(s)


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


@freeze_time('2020-11-01')
def test_sign_field_infer():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    with pytest.raises(SigningError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s)


@freeze_time('2020-11-01')
def test_sign_with_bitmap_bg():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.PdfSigner(
        signers.PdfSignatureMetadata(), signer=FROM_CA,
        stamp_style=stamp.TextStampStyle(
            background=PdfImage('pyhanko_tests/data/img/stamp-indexed.png'),
        )
    ).sign_pdf(w, existing_fields_only=True)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s)


@freeze_time('2020-11-01')
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
        s = r.embedded_signatures[0]
        assert s.field_name == 'Sig1'
        val_trusted(s, extd=True)

        s = r.embedded_signatures[1]
        assert s.field_name == 'Sig2'
        val_trusted(s)

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
@freeze_time('2020-11-01')
def test_sign_new(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    e = r.embedded_signatures[0]
    assert e.field_name == 'SigNew'
    val_trusted(e)


def field_with_lock_sp(include_docmdp):
    return fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fields.FieldMDPSpec(
            fields.FieldMDPAction.INCLUDE, fields=['blah']
        ),
        doc_mdp_update_value=(
            fields.MDPPerm.NO_CHANGES if include_docmdp else None
        )
    )


@pytest.mark.parametrize('include_docmdp', [True, False])
@freeze_time('2020-11-01')
def test_add_sigfield_with_lock(include_docmdp):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(w, field_with_lock_sp(include_docmdp))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    refs = s.sig_object.get_object()['/Reference']
    assert len(refs) == (2 if include_docmdp else 1)
    ref = refs[0]
    assert ref['/TransformMethod'] == '/FieldMDP'
    assert ref['/TransformParams']['/Fields'] == generic.ArrayObject(['blah'])
    assert ref.raw_get('/Data').reference == r.root_ref
    assert '/Perms' not in r.root
    if include_docmdp:
        ref = refs[1]
        assert ref['/TransformMethod'] == '/DocMDP'
        assert ref['/TransformParams']['/P'] == 1
    val_trusted(s)


@freeze_time('2020-11-01')
def test_double_sign_lock_second():
    # test if the difference analysis correctly processes /Reference
    # on a newly added signature object

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(w, field_with_lock_sp(True))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigFirst'), signer=FROM_CA,
    )
    w = IncrementalPdfFileWriter(out)

    # now sign the locked field
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s, extd=True)

    s = r.embedded_signatures[1]
    assert len(s.sig_object.get_object()['/Reference']) == 2

    val_trusted(s)


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


@freeze_time('2020-11-01')
def test_dummy_timestamp():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA, timestamper=DUMMY_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


def ts_response_callback(request, _context):
    req = tsp.TimeStampReq.load(request.body)
    return DUMMY_TS.request_tsa_response(req=req).dump()


@freeze_time('2020-11-01')
def test_http_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    # bad content-type
    requests_mock.post(DUMMY_HTTP_TS.url, content=ts_response_callback)
    from pyhanko.sign.timestamps import TimestampRequestError
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


# try both the user password and the owner password
@pytest.mark.parametrize('password', [b'usersecret', b'ownersecret'])
@freeze_time('2020-11-01')
def test_sign_crypt_rc4(password):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD_RC4))
    w.encrypt(password)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt(password)
    s = r.embedded_signatures[0]
    val_trusted(s)


@pytest.mark.parametrize('password', ['usersecret', 'ownersecret'])
@freeze_time('2020-11-01')
def test_sign_crypt_aes256(password):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD_AES256))
    w.encrypt(password)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt(password)
    s = r.embedded_signatures[0]
    val_trusted(s)


@freeze_time('2020-11-01')
def test_sign_crypt_pubkey_aes256():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_PUBKEY_ONE_FIELD_AES256))
    w.encrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    s = r.embedded_signatures[0]
    val_trusted(s)


@freeze_time('2020-11-01')
def test_sign_crypt_pubkey_rc4():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_PUBKEY_ONE_FIELD_RC4))
    w.encrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    s = r.embedded_signatures[0]
    val_trusted(s)


sign_crypt_rc4_files = (MINIMAL_RC4, MINIMAL_ONE_FIELD_RC4)
sign_crypt_rc4_new_params = [
    [b'usersecret', 0], [b'usersecret', 1],
    [b'ownersecret', 0], [b'ownersecret', 1]
]


@pytest.mark.parametrize('password, file', sign_crypt_rc4_new_params)
@freeze_time('2020-11-01')
def test_sign_crypt_rc4_new(password, file):
    w = IncrementalPdfFileWriter(BytesIO(sign_crypt_rc4_files[file]))
    w.encrypt(password)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    out.seek(0)
    r = PdfFileReader(out)
    r.decrypt(password)

    s = r.embedded_signatures[0]
    val_trusted(s)


sign_crypt_aes256_files = (MINIMAL_AES256, MINIMAL_ONE_FIELD_AES256)

@pytest.mark.parametrize('password, file', sign_crypt_rc4_new_params)
@freeze_time('2020-11-01')
def test_sign_crypt_aes256_new(password, file):
    w = IncrementalPdfFileWriter(BytesIO(sign_crypt_aes256_files[file]))
    w.encrypt(password)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    out.seek(0)
    r = PdfFileReader(out)
    r.decrypt(password)

    s = r.embedded_signatures[0]
    val_trusted(s)


def test_append_simple_sig_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec('InvisibleSig')
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 1
    out = BytesIO()
    w.write(out)
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(PdfWriteError):
        fields.append_signature_field(w, sp)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 3


def test_append_visible_sig_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec(
        'VisibleSig', box=(10, 0, 50, 8)
    )
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 1
    out = BytesIO()
    w.write(out)
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(PdfWriteError):
        fields.append_signature_field(w, sp)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    fields.append_signature_field(w, sp)
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
    fields.append_signature_field(w, sp)
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
        fields.append_signature_field(w, sp)


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


@freeze_time('2020-11-01')
def test_certify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=pyhanko.sign.fields.MDPPerm.NO_CHANGES
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    refs = s.sig_object.get_object()['/Reference']
    assert len(refs) == 1
    assert s.field_name == 'Sig1'
    val_trusted(s)

    info = read_certification_data(r)
    assert info.author_sig == s.sig_object.get_object()
    assert info.permission == pyhanko.sign.fields.MDPPerm.NO_CHANGES

    # with NO_CHANGES, we shouldn't be able to append an approval signature
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA
        )


@freeze_time('2020-11-01')
def test_no_double_certify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s)

    info = read_certification_data(r)
    assert info.author_sig == s.sig_object.get_object()
    assert info.permission == pyhanko.sign.fields.MDPPerm.FILL_FORMS

    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig2', certify=True,
                docmdp_permissions=pyhanko.sign.fields.MDPPerm.FILL_FORMS
            ), signer=FROM_CA
        )


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)

    info = read_certification_data(r)
    assert info.author_sig == s.sig_object.get_object()
    assert info.permission == pyhanko.sign.fields.MDPPerm.FILL_FORMS

    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted(s)


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


@freeze_time('2020-11-01')
def test_ocsp_embed():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=dummy_ocsp_vc(),
            embed_validation_info=True
        ), signer=FROM_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_untrusted(s)
    assert not status.trusted

    val_trusted(s)

    vc = apply_adobe_revocation_info(s.signer_info)
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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

    with freeze_time('2020-11-01'):
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

    # test post-expiration, but before timestamp expires
    with freeze_time('2025-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS})
        assert status.valid and status.trusted

    # test after timestamp expires: this is beyond the scope of the "basic" LTV
    #  mechanism, but failing to validate seems to be the conservative thing
    #  to do.
    with freeze_time('2040-11-01'):
        r = PdfFileReader(out)
        with pytest.raises(SignatureValidationError):
            validate_pdf_ltv_signature(r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS})


@freeze_time('2020-11-01')
def test_pades_revinfo_live_update(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    rivt_pades_lta = RevocationInfoValidationType.PADES_LTA
    # check if updates work
    out = PdfTimeStamper(DUMMY_TS).update_archival_timestamp_chain(r, vc)
    r = PdfFileReader(out)
    status = validate_pdf_ltv_signature(
        r.embedded_signatures[0], rivt_pades_lta, {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES


def test_update_no_sigs():
    r = PdfFileReader(BytesIO(MINIMAL))
    rivt_pades_lta = RevocationInfoValidationType.PADES_LTA
    # check if updates work
    with pytest.raises(SigningError):
        PdfTimeStamper(DUMMY_TS).update_archival_timestamp_chain(
            r, dummy_ocsp_vc()
        )


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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
    _test_pades_revinfo_live_lta(w, requests_mock)


def test_pades_revinfo_live_lta_in_place(requests_mock, tmp_path):
    from pathlib import Path
    inout_file: Path = tmp_path / "test.pdf"
    inout_file.write_bytes(MINIMAL_ONE_FIELD)
    with inout_file.open('r+b') as f:
        w = IncrementalPdfFileWriter(f)
        _test_pades_revinfo_live_lta(w, requests_mock, in_place=True)


def test_pades_revinfo_live_lta_direct_flush(requests_mock, tmp_path):
    from pathlib import Path
    in_file: Path = tmp_path / "test.pdf"
    in_file.write_bytes(MINIMAL_ONE_FIELD)
    out_file: Path = tmp_path / "test-out.pdf"
    with in_file.open('rb') as inf:
        out_file.touch()
        with out_file.open('r+b') as out:
            w = IncrementalPdfFileWriter(inf)
            _test_pades_revinfo_live_lta(w, requests_mock, output=out)


def _test_pades_revinfo_live_lta(w, requests_mock, **kwargs):
    with freeze_time('2020-11-01'):
        vc = live_testing_vc(requests_mock)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=vc,
                subfilter=PADES, embed_validation_info=True,
                use_pades_lta=True
            ), signer=FROM_CA, timestamper=DUMMY_TS, **kwargs
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
        for bootstrap_vc in (None, vc):
            status = validate_pdf_ltv_signature(
                r.embedded_signatures[0], rivt_pades_lta,
                {'trust_roots': TRUST_ROOTS},
                bootstrap_validation_context=bootstrap_vc
            )
            assert status.valid and status.trusted
            assert status.modification_level == ModificationLevel.LTA_UPDATES

    # test post-expiration, but before timestamp expires
    with freeze_time('2025-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades_lta,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock)
        )
        assert status.valid and status.trusted

    # test after timestamp expires: this should fail when doing LTA testing
    with freeze_time('2035-11-01'):
        r = PdfFileReader(out)
        with pytest.raises(SignatureValidationError):
            validate_pdf_ltv_signature(
                r.embedded_signatures[0], rivt_pades_lta,
                {'trust_roots': TRUST_ROOTS},
                bootstrap_validation_context=live_testing_vc(requests_mock)
            )

    # check if updates work: use a second TSA for timestamp rollover
    with freeze_time('2028-12-01'):
        r = PdfFileReader(out)

        vc = live_testing_vc(requests_mock)
        out = PdfTimeStamper(DUMMY_TS2).update_archival_timestamp_chain(r, vc)
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades_lta,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=vc
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES

    # the test that previously failed should now work
    with freeze_time('2035-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades_lta,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock)
        )
        assert status.valid and status.trusted

    # test after timestamp expires: this should fail when doing LTA testing
    with freeze_time('2040-11-01'):
        r = PdfFileReader(out)
        with pytest.raises(SignatureValidationError):
            validate_pdf_ltv_signature(
                r.embedded_signatures[0], rivt_pades_lta,
                {'trust_roots': TRUST_ROOTS},
                bootstrap_validation_context=live_testing_vc(requests_mock)
            )


# passing test_violation=False tests the signer, while test_violation=True
#  instructs the signer to ignore all SV requirements, thus testing whether
#  the validator catches the violations properly


# helper function for filling in the text field in the SIMPLE_FORM example


# helper function for filling in the text field in the TEXTFIELD_GROUP example


@freeze_time('2020-11-01')
def test_simple_qr_sign():
    style = QRStampStyle(stamp_text="Hi, it's\n%(ts)s")
    signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='Sig1'), FROM_CA,
        stamp_style=style
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signer.sign_pdf(
        w, existing_fields_only=True,
        appearance_text_params={'url': 'https://example.com'}
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/QR' in s.sig_field['/AP']['/N']['/Resources']['/XObject']

    val_trusted(s)


@pytest.mark.parametrize('params_value', [None, {}, {'some': 'value'}])
def test_qr_sign_enforce_url_param(params_value):
    style = QRStampStyle(stamp_text="Hi, it's\n%(ts)s")
    signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='Sig1'), FROM_CA,
        stamp_style=style
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    with pytest.raises(SigningError):
        signer.sign_pdf(
            w, existing_fields_only=True, appearance_text_params=params_value
        )


@freeze_time('2020-11-01')
def test_overspecify_cms_digest_algo():
    # TODO this behaviour is not ideal, but at least this test documents it

    signer = signers.SimpleSigner.load(
        TESTING_CA_DIR + '/keys/signer.key.pem',
        TESTING_CA_DIR + '/intermediate/newcerts/signer.cert.pem',
        ca_chain_files=(
            TESTING_CA_DIR + '/intermediate/certs/ca-chain.cert.pem',),
        key_passphrase=b'secret',
        # specify an algorithm object that also mandates a specific
        # message digest
        signature_mechanism=SignedDigestAlgorithm(
            {'algorithm': 'sha256_rsa'}
        )
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    # digest methods agree, so that should be OK
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1', md_algorithm='sha256'),
        signer=signer

    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', md_algorithm='sha512'
            ), signer=signer
        )


def test_sign_pss():
    signer = signers.SimpleSigner.load(
        CRYPTO_DATA_DIR + '/selfsigned.key.pem',
        CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
        ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
        key_passphrase=b'secret', prefer_pss=True
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    sda: SignedDigestAlgorithm = emb.signer_info['signature_algorithm']
    assert sda.signature_algo == 'rsassa_pss'
    val_untrusted(emb)


def test_sign_pss_md_discrepancy():
    # Acrobat refuses to validate PSS signatures where the internal
    # hash functions disagree, but mathematically speaking, that shouldn't
    # be an issue.
    signer = signers.SimpleSigner.load(
        CRYPTO_DATA_DIR + '/selfsigned.key.pem',
        CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
        ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
        key_passphrase=b'secret', signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pss',
            'parameters': RSASSAPSSParams({
                'mask_gen_algorithm': MaskGenAlgorithm({
                    'algorithm': 'mgf1',
                    'parameters': DigestAlgorithm({'algorithm': 'sha512'})
                }),
                'hash_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
                'salt_length': 478
            })
        })
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    sda: SignedDigestAlgorithm = emb.signer_info['signature_algorithm']
    assert sda.signature_algo == 'rsassa_pss'
    val_untrusted(emb)


@freeze_time('2020-11-01')
def test_direct_pdfcmsembedder_usage():
    # CMS-agnostic signing example
    #
    # write an in-place certification signature using the PdfCMSEmbedder
    # low-level API directly.

    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)

    # Phase 1: coroutine sets up the form field
    cms_writer = signers.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    sig_field_ref = next(cms_writer)

    # just for kicks, let's check
    assert sig_field_ref.get_object()['/T'] == 'Signature'

    # Phase 2: make a placeholder signature object,
    # wrap it up together with the MDP config we want, and send that
    # on to cms_writer
    timestamp = datetime.now(tz=tzlocal.get_localzone())
    sig_obj = signers.SignatureObject(timestamp=timestamp, bytes_reserved=8192)

    md_algorithm = 'sha256'
    cms_writer.send(
        signers.SigObjSetup(
            sig_placeholder=sig_obj,
            mdp_setup=signers.SigMDPSetup(
                md_algorithm=md_algorithm, certify=True,
                docmdp_perms=fields.MDPPerm.NO_CHANGES
            )
        )
    )

    # Phase 3: write & hash the document (with placeholder)
    document_hash = cms_writer.send(
        signers.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    # Phase 4: construct CMS signature object, and pass it on to cms_writer

    # NOTE: I'm using a regular SimpleSigner here, but you can substitute
    # whatever CMS supplier you want.

    signer: signers.SimpleSigner = FROM_CA
    # let's supply the CMS object as a raw bytestring
    cms_bytes = signer.sign(
        data_digest=document_hash, digest_algorithm=md_algorithm,
        timestamp=timestamp
    ).dump()
    output, sig_contents = cms_writer.send(cms_bytes)

    # we requested in-place output
    assert output is input_buf

    r = PdfFileReader(input_buf)
    val_trusted(r.embedded_signatures[0])
