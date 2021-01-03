import re
from datetime import datetime

import pytest
from io import BytesIO

import pytz
from asn1crypto import ocsp, tsp
from asn1crypto.algos import SignedDigestAlgorithm

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
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.misc import PdfWriteError
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import timestamps, fields, signers
from pyhanko.sign.general import UnacceptableSignerError, SigningError
from pyhanko.sign.signers import PdfTimeStamper
from pyhanko.sign.validation import (
    validate_pdf_signature, read_certification_data, DocumentSecurityStore,
    EmbeddedPdfSignature, apply_adobe_revocation_info,
    validate_pdf_ltv_signature, RevocationInfoValidationType,
    SignatureCoverageLevel, SignatureValidationError,
)
from pyhanko.sign.diff_analysis import (
    ModificationLevel, NoChangesDiffPolicy,
    SuspiciousModification, DiffResult,
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
                          (NoChangesDiffPolicy(), False),
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


@freeze_time('2020-11-01')
def test_no_changes_policy():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA,
    )

    w = IncrementalPdfFileWriter(out)
    # do an /Info update
    dt = generic.pdf_date(datetime(2020, 10, 10, tzinfo=pytz.utc))
    info = generic.DictionaryObject({pdf_name('/CreationDate'): dt})

    w.trailer['/Info'] = w.add_object(info)
    w.write_in_place()

    # check with normal diff policy
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert status.docmdp_ok

    # now check with the ultra-strict no-op policy
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = validate_pdf_signature(s, diff_policy=NoChangesDiffPolicy())
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


@freeze_time('2020-11-01')
def test_double_sig_add_field_annots_indirect():
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
    # ... but first make the /Annots entry of the first page an indirect one
    first_page = w.root['/Pages']['/Kids'][0]
    annots_copy = generic.ArrayObject(first_page['/Annots'])
    first_page['/Annots'] = annots_ref = w.add_object(annots_copy)
    annots_copy.container_ref = annots_ref
    w.update_container(first_page)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='SigNew'
        ), signer=FROM_CA, new_field_spec=fields.SigFieldSpec(
            sig_field_name='SigNew', box=(10, 10, 10, 10)
        )
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


@freeze_time('2020-11-01')
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
    fields.append_signature_field(w, sp)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


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
    validity = val_trusted(s)


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
    fields.append_signature_field(w, sp)
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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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
    _test_pades_revinfo_live_lta(w, requests_mock, in_place=False)


def test_pades_revinfo_live_lta_in_place(requests_mock, tmp_path):
    from pathlib import Path
    inout_file: Path = tmp_path / "test.pdf"
    inout_file.write_bytes(MINIMAL_ONE_FIELD)
    with inout_file.open('r+b') as f:
        w = IncrementalPdfFileWriter(f)
        _test_pades_revinfo_live_lta(w, requests_mock, in_place=True)


def _test_pades_revinfo_live_lta(w, requests_mock, in_place):
    with freeze_time('2020-11-01'):
        vc = live_testing_vc(requests_mock)
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


def prepare_sv_field(sv_spec):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec('Sig', seed_value_dict=sv_spec)
    fields.append_signature_field(w, sp)
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
    s = r.embedded_signatures[0]
    status = validate_pdf_signature(s, dummy_ocsp_vc())
    if test_violation:
        assert not status.seed_value_ok
    else:
        assert status.seed_value_ok
    return EmbeddedPdfSignature(r, s.sig_field)


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


@freeze_time('2020-11-01')
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


@freeze_time('2020-11-01')
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

    appearance = pyhanko.pdf_utils.content.RawContent(
        box=BoxConstraints(height=60, width=130),
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


@freeze_time('2020-11-01')
def test_form_field_ft_tamper():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    tf = w.root['/AcroForm']['/Fields'][1].get_object()
    tf['/FT'] = pdf_name('/Sig')
    w.update_container(tf)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


BOGUS_KIDS_VALUES = [
    (generic.NullObject(), False),
    (generic.ArrayObject(), False),
    (generic.ArrayObject([generic.NullObject()]), False),
    (generic.ArrayObject([generic.NullObject()]), True),
]


@freeze_time('2020-11-01')
@pytest.mark.parametrize('bogus_kids, indirectify', BOGUS_KIDS_VALUES)
def test_form_field_kids_tamper(bogus_kids, indirectify):
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    tf = w.root['/AcroForm']['/Fields'][1].get_object()
    if indirectify:
        bogus_kids = generic.ArrayObject(map(w.add_object, bogus_kids))
    tf['/Kids'] = bogus_kids
    w.update_container(tf)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
@pytest.mark.parametrize('bogus_kids, indirectify',
                         BOGUS_KIDS_VALUES + [(None, False)])
def test_pages_kids_tamper(bogus_kids, indirectify):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)

    # add an empty sig field to trigger the annotation parsing logic
    # in the difference analysis tool
    fields.append_signature_field(
        w, sig_field_spec=fields.SigFieldSpec(sig_field_name="Extra")
    )
    page_root = w.root['/Pages']
    if indirectify:
        bogus_kids = generic.ArrayObject(map(w.add_object, bogus_kids))
    if bogus_kids is not None:
        page_root['/Kids'] = bogus_kids
    else:
        del page_root['/Kids']
    w.update_container(page_root)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


# helper function for filling in the text field in the TEXTFIELD_GROUP example
def set_text_field_in_group(writer, ix, val):
    tf_parent = writer.root['/AcroForm']['/Fields'][1].get_object()
    tf = tf_parent['/Kids'][ix].get_object()
    appearance = pyhanko.pdf_utils.content.RawContent(
        box=BoxConstraints(height=60, width=130),
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
@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@pytest.mark.parametrize('variant', [0, 1])
@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@pytest.mark.parametrize('variant', [0, 1])
@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


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
@freeze_time('2020-11-01')
def test_form_field_in_group_locked_postsign_modify_failure(field_filled, fieldmdp_spec):
    # the field that is filled in after signing is always the same,
    # but the initial one varies
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[0]))


    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fieldmdp_spec,
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_field(w, sp)
    set_text_field_in_group(w, field_filled, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='SigNew')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    val_trusted_but_modified(s)


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
@freeze_time('2020-11-01')
def test_form_field_in_group_locked_postsign_modify_success(field_filled, fieldmdp_spec):
    # the field that is filled in after signing is always the same,
    # but the initial one varies
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[0]))


    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fieldmdp_spec,
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_field(w, sp)
    set_text_field_in_group(w, field_filled, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='SigNew')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 1, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
@pytest.mark.parametrize('certify_first', [True, False])
def test_pades_double_sign(requests_mock, certify_first):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True, certify=certify_first
    )
    meta2 = signers.PdfSignatureMetadata(
        field_name='Sig2', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    if certify_first:
        assert len(s.sig_object['/Reference']) == 1
    val_trusted(s, extd=True)

    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)

    # however, the second signature is violated by the deletion of the /DSS key
    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


BOGUS_DSS_VALUES = [
    generic.pdf_string("Hi there"),
    generic.DictionaryObject({pdf_name('/Blah'): generic.NullObject()}),
    generic.DictionaryObject({pdf_name('/Certs'): generic.NullObject()}),
    generic.DictionaryObject({pdf_name('/VRI'): generic.NullObject()}),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/Bleh'): generic.NullObject()
        })
    }),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/' + 'A' * 40): generic.NullObject()
        })
    }),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/' + 'A' * 40): generic.DictionaryObject({
                pdf_name('/Bleh'): generic.NullObject()
            })
        })
    }),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/' + 'A' * 40): generic.DictionaryObject({
                pdf_name('/OCSP'): generic.NullObject()
            })
        })
    }),
]


@freeze_time('2020-11-01')
@pytest.mark.parametrize('bogus_dss', BOGUS_DSS_VALUES)
def test_pades_dss_object_typing_tamper(requests_mock, bogus_dss):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    out = signers.sign_pdf(
        w, meta1, signer=FROM_CA, timestamper=DUMMY_TS
    )
    out.seek(0)
    original_out = out.read()

    # write some bogus reference into the DSS
    w = IncrementalPdfFileWriter(BytesIO(original_out))

    w.root['/DSS'] = w.add_object(bogus_dss)
    w.update_root()
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
def test_form_field_structure_modification():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    meta =signers.PdfSignatureMetadata(field_name='Sig1')

    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    field_arr = w.root['/AcroForm']['/Fields']
    # shallow copy the text field
    tf = generic.DictionaryObject(field_arr[1].get_object())
    tf['/T'] = generic.pdf_string('OtherField')
    field_arr.append(w.add_object(tf))
    w.update_container(field_arr)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
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
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig2'
    val_trusted_but_modified(s)


@pytest.mark.parametrize('policy, skip_diff',
                         [(None, False),
                          (NoChangesDiffPolicy(), False),
                          (None, True)])
def test_tamper_sig_obj(policy, skip_diff):
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
    status = validate_pdf_signature(
        emb, diff_policy=policy, skip_diff=skip_diff
    )
    if skip_diff:
        assert emb.diff_result is None
        assert status.modification_level is None
    else:
        assert isinstance(emb.diff_result, SuspiciousModification)
        assert status.modification_level == ModificationLevel.OTHER


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
    fields.append_signature_field(w, sp)
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
    assert isinstance(emb.diff_result, SuspiciousModification)


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
