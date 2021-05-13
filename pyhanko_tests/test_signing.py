import hashlib
from datetime import datetime

import pytest
from io import BytesIO

import pytz
from asn1crypto import ocsp, tsp
from asn1crypto.algos import (
    SignedDigestAlgorithm, RSASSAPSSParams,
    MaskGenAlgorithm, DigestAlgorithm, DigestInfo,
)
import tzlocal
from asn1crypto import cms
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import CertLabel, KeyLabel

import pyhanko.pdf_utils.content
from pyhanko_certvalidator.errors import PathValidationError

import pyhanko.sign.fields
from pyhanko_certvalidator import ValidationContext, CertificateValidator

from pyhanko import stamp
from pyhanko.sign.ades.api import CAdESSignedAttrSpec, GenericCommitment
from pyhanko.sign.ades.cades_asn1 import (
    SignaturePolicyIdentifier, SignaturePolicyId
)
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.misc import PdfWriteError, PdfReadError
from pyhanko.pdf_utils.writer import PdfFileWriter, copy_into_new_writer
from pyhanko.sign import timestamps, fields, signers
from pyhanko.sign.general import (
    SigningError, SignatureValidationError, validate_sig_integrity,
    load_cert_from_pemder, find_cms_attribute, WeakHashAlgorithmError,
    SimpleCertificateStore, load_certs_from_pemder
)
from pyhanko.sign.signers import PdfTimeStamper
from pyhanko.sign.validation import (
    validate_pdf_signature, read_certification_data, DocumentSecurityStore,
    EmbeddedPdfSignature, apply_adobe_revocation_info,
    validate_pdf_ltv_signature, RevocationInfoValidationType,
    SignatureCoverageLevel, validate_pdf_timestamp, add_validation_info
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

ROOT_CERT = TESTING_CA.get_cert(CertLabel('root'))
ECC_ROOT_CERT = TESTING_CA_ECDSA.get_cert(CertLabel('root'))
INTERM_CERT = TESTING_CA.get_cert(CertLabel('interm'))
ECC_INTERM_CERT = TESTING_CA_ECDSA.get_cert(CertLabel('interm'))
OCSP_CERT = TESTING_CA.get_cert(CertLabel('interm-ocsp'))
REVOKED_CERT = TESTING_CA.get_cert(CertLabel('signer2'))
TSA_CERT = TESTING_CA.get_cert(CertLabel('tsa'))
TSA2_CERT = TESTING_CA.get_cert(CertLabel('tsa2'))

FROM_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs([ROOT_CERT, INTERM_CERT])
)

FROM_ECC_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA_ECDSA.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA_ECDSA.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs(
        [ECC_ROOT_CERT, ECC_INTERM_CERT]
    )
)


REVOKED_SIGNER = signers.SimpleSigner(
    signing_cert=TESTING_CA.get_cert(CertLabel('signer2')),
    signing_key=TESTING_CA.key_set.get_private_key(KeyLabel('signer2')),
    cert_registry=SimpleCertificateStore.from_certs([ROOT_CERT, INTERM_CERT])
)

TRUST_ROOTS = [TESTING_CA.get_cert(CertLabel('root'))]

FROM_CA_PKCS12 = signers.SimpleSigner.load_pkcs12(
    TESTING_CA_DIR + '/interm/signer1.pfx', passphrase=None
)

NOTRUST_V_CONTEXT = lambda: ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = lambda: ValidationContext(trust_roots=[ROOT_CERT])
SIMPLE_ECC_V_CONTEXT = lambda: ValidationContext(trust_roots=[ECC_ROOT_CERT])

OCSP_KEY = TESTING_CA.key_set.get_private_key('interm-ocsp')
DUMMY_TS = timestamps.DummyTimeStamper(
    tsa_cert=TSA_CERT,
    tsa_key=TESTING_CA.key_set.get_private_key('tsa'),
    certs_to_embed=FROM_CA.cert_registry
)

DUMMY_TS2 = timestamps.DummyTimeStamper(
    tsa_cert=TSA2_CERT,
    tsa_key=TESTING_CA.key_set.get_private_key('tsa2'),
    certs_to_embed=FROM_CA.cert_registry
)

DUMMY_HTTP_TS = timestamps.HTTPTimeStamper(
    'http://pyhanko.test/testing-ca/tsa/tsa', https=False
)

# with the testing CA setup update, this OCSP response is totally
#  unrelated to the keys being used, so it should fail any sort of real
#  validation
FIXED_OCSP = ocsp.OCSPResponse.load(
    read_all(CRYPTO_DATA_DIR + '/ocsp.resp.der')
)


DUMMY_POLICY_ID = SignaturePolicyId({
    'sig_policy_id': '2.999',
    'sig_policy_hash': DigestInfo({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
        'digest': hashlib.sha256().digest()
    })
})


# TODO rewrite tests using new in-place signing mechanism

def dummy_ocsp_vc():
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS, crls=[], ocsps=[FIXED_OCSP],
        other_certs=list(FROM_CA.cert_registry), allow_fetching=False,
        weak_hash_algos=set()
    )
    return vc


def live_testing_vc(requests_mock):
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS, allow_fetching=True,
        other_certs=[]
    )
    Illusionist(TESTING_CA).register(requests_mock)
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


def test_der_detect(tmp_path):
    from pathlib import Path
    tmp: Path = tmp_path / "test.der"
    orig_bytes = SELF_SIGN.signing_cert.dump()
    tmp.write_bytes(orig_bytes)
    result = load_cert_from_pemder(str(tmp))

    # make sure the resulting object gets parsed fully, for good measure
    # noinspection PyStatementEffect
    result.native
    assert result.dump() == orig_bytes


def test_enforce_one_cert(tmp_path):

    fname = CRYPTO_DATA_DIR + '/some-chain.cert.pem'

    assert len(list(load_certs_from_pemder([fname]))) == 2
    with pytest.raises(ValueError):
        load_cert_from_pemder(fname)


def test_simple_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)


def test_simple_sign_tamper():
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


def test_simple_sign_fresh_doc():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = copy_into_new_writer(r)
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)


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


def test_no_diff_summary():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    # just do an incremental DSS update
    DocumentSecurityStore.add_dss(
        out, sig_contents=None, certs=(SELF_SIGN.signing_cert,)
    )

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    status = validate_pdf_signature(emb, skip_diff=True)
    assert emb.diff_result is None
    assert status.modification_level is None
    assert not status.docmdp_ok
    assert status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
    assert 'EXTENDED' in status.summary()


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


def test_verify_sig_without_signed_attrs():
    # pyHanko never produces signatures of this type, but we should be able
    # to validate them (this file was created using a modified version of
    # pyHanko's signing code, which will never see the light of day)

    with open(PDF_DATA_DIR + '/sig-no-signed-attrs.pdf', 'rb') as f:
        r = PdfFileReader(f)
        s = r.embedded_signatures[0]
        assert s.field_name == 'Sig1'
        val_untrusted(s)


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
    signer = signers.SimpleSigner(
        signing_cert=TESTING_CA_ECDSA.get_cert(CertLabel('signer1')),
        signing_key=TESTING_CA_ECDSA.key_set.get_private_key(
            KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [ECC_ROOT_CERT, ECC_INTERM_CERT]
        ),
        signature_mechanism=SignedDigestAlgorithm({'algorithm': 'ecdsa'})
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


@freeze_time('2020-12-05')
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
    with freeze_time('2020-12-05'):

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

    w = IncrementalPdfFileWriter(out)

    # shouldn't work now since all fields are taken
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA,
            existing_fields_only=True
        )


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
def test_sign_with_indir_annots():
    with open(PDF_DATA_DIR + '/minimal-one-field-indir-annots.pdf', 'rb') as f:
        w = IncrementalPdfFileWriter(f)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA
        )
        r = PdfFileReader(out)
        e = r.embedded_signatures[0]
        assert e.field_name == 'SigNew'
        val_trusted(e)

        annots_ref = r.root['/Pages']['/Kids'][0].raw_get('/Annots')
        assert isinstance(annots_ref, generic.IndirectObject)
        assert len(annots_ref.get_object()) == 2



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


def test_append_sigfield_second_page():
    buf = BytesIO(MINIMAL_TWO_PAGES)
    w = IncrementalPdfFileWriter(buf)
    fields.append_signature_field(w, fields.SigFieldSpec('Sig1', on_page=1))
    w.write_in_place()

    r = PdfFileReader(buf)

    pg1 = r.root['/Pages']['/Kids'][0]
    assert '/Annots' not in pg1

    pg2 = r.root['/Pages']['/Kids'][1]
    assert '/Annots' in pg2
    assert len(pg2['/Annots']) == 1
    assert pg2['/Annots'][0]['/T'] == 'Sig1'


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
    assert len(refs) == 1
    ref = refs[0]
    assert ref['/TransformMethod'] == '/FieldMDP'
    assert ref['/TransformParams']['/Fields'] == generic.ArrayObject(['blah'])
    assert ref.raw_get('/Data').reference == r.root_ref
    assert '/Perms' not in r.root
    if include_docmdp:
        # test if the Acrobat-compatibility hack was included
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
    assert len(s.sig_object.get_object()['/Reference']) == 1

    val_trusted(s)


@freeze_time('2020-11-01')
def test_skip_diff_scenario_1():
    # Test if skip_diff behaves as expected
    # scenario 1: sign a locked file

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='SigFirst', certify=True,
            docmdp_permissions=fields.MDPPerm.NO_CHANGES
        ), signer=FROM_CA,
    )
    w = IncrementalPdfFileWriter(out)

    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='SigNew'),
        signer=FROM_CA
    )

    # dummy out certification enforcer
    pdf_signer._enforce_certification_constraints = lambda _: None

    out = pdf_signer.sign_pdf(w)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # should be OK with skip_diff
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT(), skip_diff=True)
    assert status.docmdp_ok is None
    assert status.bottom_line
    assert 'skipped' in status.pretty_print_details()

    # ... but not otherwise
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT())
    assert status.docmdp_ok is False
    assert not status.bottom_line
    assert 'incompatible with the current document modification' \
           in status.pretty_print_details()


@freeze_time('2020-11-01')
def test_skip_diff_scenario_2():
    # Test if skip_diff behaves as expected
    # scenario 2: do something blatantly illegal in the second revision

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigFirst'),
        signer=FROM_CA,
    )

    from pyhanko.pdf_utils.content import RawContent
    w = IncrementalPdfFileWriter(out)
    w.add_content_to_page(
        0, RawContent(b'q BT /F1 18 Tf 0 50 Td (Sneaky text!) Tj ET Q')
    )
    w.write_in_place()

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # should be OK with skip_diff
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT(), skip_diff=True)
    assert status.docmdp_ok is None
    assert status.bottom_line
    assert 'skipped' in status.pretty_print_details()

    # ... but not otherwise
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT())
    assert status.docmdp_ok is False
    assert not status.bottom_line
    report = status.pretty_print_details()
    assert 'illegitimate' in report
    assert 'incompatible with the current document modification' in report


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
    w.encrypt_pubkey(PUBKEY_SELFSIGNED_DECRYPTER)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_SELFSIGNED_DECRYPTER)
    s = r.embedded_signatures[0]
    val_trusted(s)


@freeze_time('2020-11-01')
def test_sign_crypt_pubkey_rc4():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_PUBKEY_ONE_FIELD_RC4))
    w.encrypt_pubkey(PUBKEY_SELFSIGNED_DECRYPTER)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_SELFSIGNED_DECRYPTER)
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

    # since this test didn't detect a regression because I made
    # sha256 the default MD (instead of sha512), I made the test use
    # SHA1, since that's definitely NEVER going to be a default.
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            md_algorithm='sha1'
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
    assert EmbeddedPdfSignature(r, sig_field, field_name).md_algorithm == 'sha1'


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
            subfilter=PADES, embed_validation_info=True, use_pades_lta=True
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )
    r = PdfFileReader(out)
    rivt_pades_lta = RevocationInfoValidationType.PADES_LTA
    # check if updates work
    out = PdfTimeStamper(DUMMY_TS).update_archival_timestamp_chain(r, vc)
    r = PdfFileReader(out)
    emb_sig = r.embedded_signatures[0]
    status = validate_pdf_ltv_signature(
        emb_sig, rivt_pades_lta, {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert len(r.embedded_signatures) == 3
    assert len(r.embedded_regular_signatures) == 1
    assert len(r.embedded_timestamp_signatures) == 2
    assert emb_sig is r.embedded_regular_signatures[0]


def test_update_no_timestamps():
    r = PdfFileReader(BytesIO(MINIMAL))
    output = PdfTimeStamper(DUMMY_TS).update_archival_timestamp_chain(
        r, dummy_ocsp_vc(), in_place=False
    )
    r = PdfFileReader(output)
    status = validate_pdf_timestamp(
        r.embedded_signatures[0], validation_context=SIMPLE_V_CONTEXT()
    )
    assert status.valid and status.trusted


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


def test_pades_revinfo_live_lta_direct_flush_newfile(requests_mock, tmp_path):
    # test transparent handling of non-readable/seekable output buffers
    from pathlib import Path
    in_file: Path = tmp_path / "test.pdf"
    in_file.write_bytes(MINIMAL_ONE_FIELD)
    out_file: Path = tmp_path / "test-out.pdf"
    with in_file.open('rb') as inf:
        with out_file.open('wb') as out:
            w = IncrementalPdfFileWriter(inf)
            _test_pades_revinfo_live_lta_sign(w, requests_mock, output=out)
        with out_file.open('rb') as out:
            _test_pades_revinfo_live_lta_validate(
                out, requests_mock, no_write=True
            )


def _test_pades_revinfo_live_lta_sign(w, requests_mock, **kwargs):
    with freeze_time('2020-11-01'):
        vc = live_testing_vc(requests_mock)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=vc,
                subfilter=PADES, embed_validation_info=True,
                use_pades_lta=True
            ), signer=FROM_CA, timestamper=DUMMY_TS, **kwargs
        )
    return out


def _test_pades_revinfo_live_lta_validate(out, requests_mock, no_write=False,
                                          has_more_sigs=False):
    if has_more_sigs:
        expected_modlevel = ModificationLevel.FORM_FILLING
    else:
        expected_modlevel = ModificationLevel.LTA_UPDATES

    with freeze_time('2020-11-01'):
        r = PdfFileReader(out)
        dss = DocumentSecurityStore.read_dss(handler=r)
        vc = dss.as_validation_context({'trust_roots': TRUST_ROOTS})
        assert dss is not None
        if not has_more_sigs:
            assert len(dss.vri_entries) == 2
            assert len(dss.certs) == 5
            assert len(dss.ocsps) == len(vc.ocsps) == 1
            assert len(dss.crls) == len(vc.crls) == 1
        rivt_pades = RevocationInfoValidationType.PADES_LT
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and status.trusted
        assert status.modification_level == expected_modlevel

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
            assert status.modification_level == expected_modlevel

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

    if no_write:
        return
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
        assert status.modification_level == expected_modlevel

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


def _test_pades_revinfo_live_lta(w, requests_mock, **kwargs):
    out = _test_pades_revinfo_live_lta_sign(w, requests_mock, **kwargs)
    _test_pades_revinfo_live_lta_validate(out, requests_mock)


def test_pades_lta_dss_indirect_arrs(requests_mock):
    testfile = PDF_DATA_DIR + '/pades-lta-dss-indirect-arrs-test.pdf'
    live_testing_vc(requests_mock)
    with open(testfile, 'rb') as f:
        r = PdfFileReader(f)
        validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            validation_type=RevocationInfoValidationType.PADES_LTA,
            # the cert embedded into this file uses a mock URL
            # that doesn't work in the current testing architecture
            validation_context_kwargs={
                'trust_roots': TRUST_ROOTS, 'allow_fetching': False,
                'revocation_mode': 'soft-fail'
            }
        )


def test_pades_lta_sign_twice(requests_mock):
    stream = BytesIO(MINIMAL_TWO_FIELDS)
    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-10-01'):
        vc = live_testing_vc(requests_mock)
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=vc,
                subfilter=PADES, embed_validation_info=True,
                use_pades_lta=True
            ), signer=FROM_CA, timestamper=DUMMY_TS, in_place=True
        )

    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-11-01'):
        vc = live_testing_vc(requests_mock)
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig2', validation_context=vc,
                subfilter=PADES, embed_validation_info=True,
                use_pades_lta=True
            ), signer=FROM_CA, timestamper=DUMMY_TS, in_place=True
        )

    # test if the first sig still validates
    _test_pades_revinfo_live_lta_validate(
        stream, requests_mock, no_write=True, has_more_sigs=True
    )

    # and the second one (i.e. 3rd in the embedded_signatures list),
    # just because we can:
    with freeze_time('2025-12-01'):
        validate_pdf_ltv_signature(
            PdfFileReader(stream).embedded_signatures[2],
            validation_type=RevocationInfoValidationType.PADES_LTA,
            validation_context_kwargs={'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock)
        )


def test_pades_lta_sign_twice_post_expiry(requests_mock):
    stream = BytesIO(MINIMAL_TWO_FIELDS)
    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-10-01'):
        vc = live_testing_vc(requests_mock)
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=vc,
                subfilter=PADES, embed_validation_info=True,
                use_pades_lta=True
            ), signer=FROM_CA, timestamper=DUMMY_TS, in_place=True
        )

    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-10-10'):
        # intentionally load a VC in which the original TS does
        # not validate
        vc = SIMPLE_ECC_V_CONTEXT()
        with pytest.raises(SigningError, match=".*most recent timestamp.*"):
            signers.sign_pdf(
                w, signers.PdfSignatureMetadata(
                    field_name='Sig2', validation_context=vc,
                    subfilter=PADES, embed_validation_info=True,
                    use_pades_lta=True
                ), signer=FROM_ECC_CA, timestamper=DUMMY_TS, in_place=True
            )


@freeze_time('2020-11-01')
def test_standalone_document_timestamp(requests_mock):
    pdf_ts = signers.PdfTimeStamper(timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = pdf_ts.timestamp_pdf(w, md_algorithm='sha256', validation_context=vc)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    with pytest.raises(SignatureValidationError, match='.*must be /Sig.*'):
        val_trusted(s, vc=vc)

    status = validate_pdf_timestamp(embedded_sig=s, validation_context=vc)
    assert status.valid and status.trusted
    assert status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
    assert status.modification_level == ModificationLevel.LTA_UPDATES

    # tamper with the file
    out.seek(0x9d)
    out.write(b'4')
    out.seek(0)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    tampered = validate_pdf_timestamp(embedded_sig=s, validation_context=vc)
    assert not tampered.intact and not tampered.valid


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
        CRYPTO_DATA_DIR + '/selfsigned.key.pem',
        CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
        ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
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
    val_untrusted(s)

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

    # add some stuff to the DSS for kicks
    DocumentSecurityStore.add_dss(
        output, sig_contents, certs=FROM_CA.cert_registry, ocsps=(FIXED_OCSP,)
    )
    r = PdfFileReader(input_buf)
    dss = DocumentSecurityStore.read_dss(handler=r)
    val_trusted(r.embedded_signatures[0], extd=True)
    assert dss is not None
    assert len(dss.certs) == 3
    assert len(dss.ocsps) == 1


def test_bytes_reserved_even():
    with pytest.raises(ValueError):
        signers.PdfByteRangeDigest(bytes_reserved=1)


def test_name_location():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', name='Bleh', location='Bluh'
    )
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)

    assert emb.sig_object['/Name'] == 'Bleh'
    assert emb.sig_object['/Location'] == 'Bluh'


def test_no_email():

    # just sign with any cert, don't care about validation etc.
    # This is simply to test the name generation logic if no email address
    # is available
    signer = signers.SimpleSigner.load(
        CRYPTO_DATA_DIR + '/keys-rsa/tsa.key.pem',
        CRYPTO_DATA_DIR + '/tsa.cert.pem',
        ca_chain_files=(),
        key_passphrase=b'secret'
    )

    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
    )
    pdf_signer = signers.PdfSigner(
        meta, signer=signer, stamp_style=stamp.TextStampStyle(
            stamp_text='%(signer)s\n%(ts)s',
        ),
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = pdf_signer.sign_pdf(w, )

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)

    ap_data = emb.sig_field['/AP']['/N'].data
    cn = signer.signing_cert.subject.native['common_name'].encode('ascii')
    assert cn in ap_data


def _tamper_with_signed_attrs(attr_name, *, duplicate=False, delete=False,
                              replace_with=None, resign=False):
    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)
    md_algorithm = 'sha256'

    cms_writer = signers.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    cms_writer.send(signers.SigObjSetup(sig_placeholder=sig_obj))

    document_hash = cms_writer.send(
        signers.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    signer: signers.SimpleSigner = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pkcs1v15'
        })
    )
    cms_obj = signer.sign(
        data_digest=document_hash, digest_algorithm=md_algorithm,
    )
    sd = cms_obj['content']
    si, = sd['signer_infos']
    signed_attrs = si['signed_attrs']
    ix = next(
        ix for ix, attr in enumerate(signed_attrs)
        if attr['type'].native == attr_name
    )

    # mess with the attribute in the requested way
    if delete:
        del signed_attrs[ix]
    elif duplicate:
        vals = signed_attrs[ix]['values']
        vals.append(vals[0])
    else:
        vals = signed_attrs[ix]['values']
        vals[0] = replace_with

    # ... and replace the signature if requested
    if resign:
        si['signature'] = \
            signer.sign_raw(si['signed_attrs'].untag().dump(), md_algorithm)
    return cms_writer.send(cms_obj)[0]


@pytest.mark.parametrize('replacement_value', [
    cms.CMSAlgorithmProtection({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha1'}),
        'signature_algorithm': SignedDigestAlgorithm(
            {'algorithm': 'rsassa_pkcs1v15'}
        )
    }),
    cms.CMSAlgorithmProtection({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
        'signature_algorithm': SignedDigestAlgorithm(
            {'algorithm': 'sha512_rsa'}
        )
    }),
    cms.CMSAlgorithmProtection({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
    }),
    None
])
def test_cms_algorithm_protection(replacement_value):
    output = _tamper_with_signed_attrs(
        'cms_algorithm_protection', duplicate=replacement_value is None,
        replace_with=replacement_value, resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()
    with pytest.raises(SignatureValidationError, match='.*CMS.*'):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_signed_attrs_tampering():
    # delete the (signed) CMSAlgorithmProtection attribute
    # this should invalidate the signature

    output = _tamper_with_signed_attrs('cms_algorithm_protection', delete=True)

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    intact, valid = validate_sig_integrity(
        emb.signer_info, emb.signer_cert, 'data', digest
    )
    # "intact" refers to the messageDigest attribute, which we didn't touch
    assert intact and not valid


def test_no_message_digest():
    output = _tamper_with_signed_attrs(
        'message_digest', delete=True, resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_duplicate_content_type():
    output = _tamper_with_signed_attrs(
        'content_type', duplicate=True, resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_no_content_type():
    output = _tamper_with_signed_attrs('content_type', delete=True, resign=True)

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_wrong_content_type():
    # delete the (signed) CMSAlgorithmProtection attribute
    # this should invalidate the signature

    output = _tamper_with_signed_attrs(
        'content_type', replace_with='enveloped_data', resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def _tamper_with_sig_obj(tamper_fun):
    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)
    md_algorithm = 'sha256'

    cms_writer = signers.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    cms_writer.send(signers.SigObjSetup(sig_placeholder=sig_obj))

    tamper_fun(w, sig_obj)

    document_hash = cms_writer.send(
        signers.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    signer: signers.SimpleSigner = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pkcs1v15'
        })
    )
    cms_obj = signer.sign(
        data_digest=document_hash, digest_algorithm=md_algorithm,
    )
    return cms_writer.send(cms_obj)[0]


@freeze_time('2020-11-01')
def test_sig_delete_type():
    # test whether deleting /Type defaults to /Sig
    def tamper(writer, sig_obj):
        del sig_obj['/Type']
    out = _tamper_with_sig_obj(tamper)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted(emb)

    # ... but the doctimestamp validator shouldn't let that slide
    # (yes, obviously this also isn't a valid timestamp token, hence the
    #  match=... rule here)
    with pytest.raises(SignatureValidationError,
                       match='.*must be /DocTimeStamp.*'):
        validate_pdf_timestamp(emb, validation_context=SIMPLE_V_CONTEXT())


def test_timestamp_wrong_type():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    # Again:
    # (yes, obviously this also isn't a valid timestamp token, hence the
    #  match=... rule here)
    with pytest.raises(SignatureValidationError,
                       match='.*must be /DocTimeStamp.*'):
        validate_pdf_timestamp(emb, validation_context=SIMPLE_V_CONTEXT())


@pytest.mark.parametrize('wrong_subfilter', [
    pdf_name('/abcde'), pdf_name("/ETSI.RFC3161"), None,
    generic.NullObject()
])
@freeze_time('2020-11-01')
def test_sig_wrong_subfilter(wrong_subfilter):
    def tamper(writer, sig_obj):
        if wrong_subfilter:
            sig_obj['/SubFilter'] = wrong_subfilter
        else:
            del sig_obj['/SubFilter']
    out = _tamper_with_sig_obj(tamper)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    with pytest.raises(SignatureValidationError):
        val_trusted(emb)


@freeze_time('2020-11-01')
def test_sig_no_contents():
    def tamper(writer, sig_obj):
        # the placeholder object needs to be written to, to make the
        # run its course
        sig_obj['/FakeContents'] = sig_obj['/Contents']
        del sig_obj['/Contents']
    out = _tamper_with_sig_obj(tamper)

    r = PdfFileReader(out)
    with pytest.raises(PdfReadError, match='.*not correctly formatted.*'):
        # noinspection PyStatementEffect
        r.embedded_signatures[0]


@freeze_time('2020-11-01')
def test_sig_null_contents():
    def tamper(writer, sig_obj):
        sig_obj['/FakeContents'] = sig_obj['/Contents']
        sig_obj['/Contents'] = generic.NullObject()
    out = _tamper_with_sig_obj(tamper)

    r = PdfFileReader(out)
    with pytest.raises(PdfReadError, match='.*string-like.*'):
        # noinspection PyStatementEffect
        r.embedded_signatures[0]


@freeze_time('2020-11-01')
def test_sig_indirect_contents():
    def tamper(writer, sig_obj):
        sig_obj['/Contents'] = writer.add_object(sig_obj['/Contents'])
    out = _tamper_with_sig_obj(tamper)

    r = PdfFileReader(out)
    with pytest.raises(PdfReadError, match='.*be direct.*'):
        # noinspection PyStatementEffect
        r.embedded_signatures[0]


@freeze_time('2020-11-01')
def test_timestamp_with_different_digest():
    ts = timestamps.DummyTimeStamper(
        tsa_cert=TSA_CERT, tsa_key=TESTING_CA.key_set.get_private_key('tsa'),
        certs_to_embed=FROM_CA.cert_registry,
        override_md='sha512'
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(md_algorithm='sha256'),
        signer=FROM_CA, timestamper=ts,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


def test_simple_sign_with_separate_annot():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer = signers.PdfSigner(
        signature_meta=meta, signer=SELF_SIGN,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig1', combine_annotation=False,
            box=(20, 20, 80, 40)
        )
    )
    out = signer.sign_pdf(w)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert '/AP' not in emb.sig_field
    assert '/AP' in emb.sig_field['/Kids'][0]
    val_untrusted(emb)


@freeze_time('2020-11-01')
def test_double_sign_with_separate_annot():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer = signers.PdfSigner(
        signature_meta=meta, signer=FROM_CA,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig1', combine_annotation=False,
            box=(20, 20, 80, 40)
        )
    )
    out = signer.sign_pdf(w, in_place=True)
    w = IncrementalPdfFileWriter(out)
    meta = signers.PdfSignatureMetadata(field_name='Sig2')
    signer = signers.PdfSigner(
        signature_meta=meta, signer=FROM_CA,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig2', combine_annotation=False,
            box=(20, 120, 80, 140)
        )
    )
    signer.sign_pdf(w, in_place=True)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert '/AP' not in emb.sig_field
    assert '/AP' in emb.sig_field['/Kids'][0]
    val_trusted(emb, extd=True)

    emb = r.embedded_signatures[1]
    assert emb.field_name == 'Sig2'
    assert '/AP' not in emb.sig_field
    assert '/AP' in emb.sig_field['/Kids'][0]
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_validate_separate_annot_with_indir_kids():
    with open(PDF_DATA_DIR + '/separate-annots-kids-indir.pdf', 'rb') as f:
        r = PdfFileReader(f)
        emb = r.embedded_signatures[0]
        assert emb.field_name == 'Sig1'
        assert '/AP' not in emb.sig_field
        assert '/AP' in emb.sig_field['/Kids'][0]
        val_trusted(emb, extd=True)

        emb = r.embedded_signatures[1]
        assert emb.field_name == 'Sig2'
        assert '/AP' not in emb.sig_field
        assert '/AP' in emb.sig_field['/Kids'][0]
        val_trusted(emb)


def test_sign_with_empty_kids():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(
        w, fields.SigFieldSpec(
            sig_field_name='Sig1', combine_annotation=False,
            box=(20, 20, 80, 40)
        )
    )
    w.root['/AcroForm']['/Fields'][0]['/Kids'] = generic.ArrayObject()
    meta = signers.PdfSignatureMetadata(field_name='Sig1')

    with pytest.raises(SigningError, match="Failed to access.*annot.*"):
        signers.sign_pdf(w, meta, signer=FROM_CA)


@freeze_time('2020-11-01')
def test_sign_without_annot():
    with open(PDF_DATA_DIR + '/minimal-annotless.pdf', 'rb') as f:
        w = IncrementalPdfFileWriter(f)
        meta = signers.PdfSignatureMetadata(field_name='Sig1')
        out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert '/AP' not in emb.sig_field
    assert '/Rect' not in emb.sig_field
    assert '/Kids' not in emb.sig_field
    assert '/Type' not in emb.sig_field
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_sign_and_update_with_orphaned_obj():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    w = IncrementalPdfFileWriter(out)
    w.add_object(generic.pdf_string("Hello there"))
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, extd=True)


@freeze_time('2020-11-01')
def test_sign_and_update_with_orphaned_obj_and_other_upd():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    w = IncrementalPdfFileWriter(out)
    w.add_object(generic.pdf_string("Hello there"))
    w.root['/Blah'] = w.add_object(
        generic.pdf_string("Hello there too")
    )
    w.update_root()
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted_but_modified(emb)


@freeze_time('2020-11-01')
def test_indir_ref_in_sigref_dict(requests_mock):
    fname = PDF_DATA_DIR + '/certified-with-indirect-refs-in-dir.pdf'
    with open(fname, 'rb') as f:
        content = f.read()

    # first, try validating without additions
    r = PdfFileReader(BytesIO(content))
    emb = r.embedded_signatures[0]
    val_trusted(emb)

    w = IncrementalPdfFileWriter(BytesIO(content))

    out = PdfTimeStamper(timestamper=DUMMY_TS).timestamp_pdf(
        w, md_algorithm='sha256',
        validation_context=live_testing_vc(requests_mock)
    )
    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted(emb, extd=True)


@pytest.mark.parametrize('with_vri', [True, False])
def test_add_revinfo_later(requests_mock, with_vri):
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)

    # create signature without revocation info
    with freeze_time('2020-11-01'):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA, timestamper=DUMMY_TS, in_place=True
        )

    # fast forward 1 month
    with freeze_time('2020-12-01'):
        vc = live_testing_vc(requests_mock)
        r = PdfFileReader(buf)
        emb_sig = r.embedded_signatures[0]
        add_validation_info(emb_sig, vc, in_place=True, add_vri_entry=with_vri)

        r = PdfFileReader(buf)
        emb_sig = r.embedded_signatures[0]

        # without retroactive revinfo, the validation should fail
        status = validate_pdf_ltv_signature(
            emb_sig, RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and not status.trusted

        # with retroactive revinfo, it should be OK
        status = validate_pdf_ltv_signature(
            emb_sig, RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True}
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES


@pytest.mark.parametrize('with_vri', [True, False])
def test_add_revinfo_timestamp_separate_no_dss(requests_mock, with_vri):
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)

    # create signature & timestamp without revocation info
    with freeze_time('2020-11-01'):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA, in_place=True
        )
        signers.PdfTimeStamper(timestamper=DUMMY_TS).timestamp_pdf(
            IncrementalPdfFileWriter(buf), 'sha256', in_place=True
        )

    # fast forward 1 month
    with freeze_time('2020-12-01'):
        vc = live_testing_vc(requests_mock)
        r = PdfFileReader(buf)
        emb_sig = r.embedded_signatures[0]
        add_validation_info(emb_sig, vc, in_place=True, add_vri_entry=with_vri)

        r = PdfFileReader(buf)
        emb_sig = r.embedded_signatures[0]

        # without retroactive revinfo, the validation should fail
        status = validate_pdf_ltv_signature(
            emb_sig, RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and not status.trusted

        # with retroactive revinfo, it should be OK
        status = validate_pdf_ltv_signature(
            emb_sig, RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True}
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES

def test_add_revinfo_without_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    # create signature without revocation info
    with freeze_time('2020-11-01'):
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA, in_place=True
        )

    # fast forward 1 month
    with freeze_time('2020-12-01'):
        vc = live_testing_vc(requests_mock)
        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]
        out = add_validation_info(emb_sig, vc)

        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]

        # even with revinfo, this should fail for lack of a timestamp
        with pytest.raises(SignatureValidationError,
                           match='.*trusted timestamp.*'):
            validate_pdf_ltv_signature(
                emb_sig, RevocationInfoValidationType.PADES_LT,
                {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True}
            )

        # ... and certainly for LTA
        with pytest.raises(SignatureValidationError,
                           match='Purported.*LTA.*'):
            validate_pdf_ltv_signature(
                emb_sig, RevocationInfoValidationType.PADES_LTA,
                {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True}
            )


def test_add_revinfo_and_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    # create signature without revocation info
    with freeze_time('2020-11-01'):
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA, in_place=True
        )

    # fast forward 1 month
    with freeze_time('2020-12-01'):
        vc = live_testing_vc(requests_mock)
        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]
        out = add_validation_info(emb_sig, vc)

        timestamper = signers.PdfTimeStamper(timestamper=DUMMY_TS)
        timestamper.timestamp_pdf(
            IncrementalPdfFileWriter(out), 'sha256', vc, in_place=True
        )

        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]

        # This should suffice for PAdES-LT, even without retroactive_revinfo
        # (since the new timestamp is now effectively the only trusted record
        #  of the signing time anyway)
        status = validate_pdf_ltv_signature(
            emb_sig, RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and status.trusted
        assert status.signer_reported_dt == datetime.now(tz=pytz.utc)

        # ... but PAdES-LTA should fail
        with pytest.raises(SignatureValidationError,
                           match='.*requires separate timestamps.*'):
            validate_pdf_ltv_signature(
                emb_sig, RevocationInfoValidationType.PADES_LTA,
                {'trust_roots': TRUST_ROOTS}
            )


def test_add_revinfo_and_lta_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    # create signature without revocation info
    with freeze_time('2020-11-01'):
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA, in_place=True
        )

    # fast forward 1 month
    with freeze_time('2020-12-01'):
        vc = live_testing_vc(requests_mock)
        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]
        out = add_validation_info(emb_sig, vc)

        timestamper = signers.PdfTimeStamper(timestamper=DUMMY_TS)
        timestamper.timestamp_pdf(
            IncrementalPdfFileWriter(out), 'sha256', vc, in_place=True
        )
        timestamper.update_archival_timestamp_chain(PdfFileReader(out), vc)

        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]

        status = validate_pdf_ltv_signature(
            emb_sig, RevocationInfoValidationType.PADES_LTA,
            {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and status.trusted
        assert status.signer_reported_dt == datetime.now(tz=pytz.utc)

    # test post-expiration, but before timestamp expires
    with freeze_time('2025-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], RevocationInfoValidationType.PADES_LTA,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock)
        )
        assert status.valid and status.trusted


@freeze_time('2020-11-01')
def test_sign_with_commitment():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', subfilter=fields.SigSeedSubFilter.PADES,
        cades_signed_attr_spec=CAdESSignedAttrSpec(
            commitment_type=GenericCommitment.PROOF_OF_ORIGIN.asn1
        )
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)

    indic = find_cms_attribute(
        emb.signer_info['signed_attrs'], 'commitment_type'
    )[0]
    assert indic['commitment_type_id'].native == 'proof_of_origin'


@freeze_time('2020-11-01')
def test_sign_with_content_sig():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', subfilter=fields.SigSeedSubFilter.PADES,
        cades_signed_attr_spec=CAdESSignedAttrSpec(timestamp_content=True),
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)

    content_ts = find_cms_attribute(
        emb.signer_info['signed_attrs'], 'content_time_stamp'
    )[0]
    eci = content_ts['content']['encap_content_info']
    assert eci['content_type'].native == 'tst_info'


@freeze_time('2020-11-01')
def test_sign_with_policy():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', subfilter=fields.SigSeedSubFilter.PADES,
        cades_signed_attr_spec=CAdESSignedAttrSpec(
            signature_policy_identifier=SignaturePolicyIdentifier({
                'signature_policy_id': DUMMY_POLICY_ID
            })
        ),
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)

    sp_id = find_cms_attribute(
        emb.signer_info['signed_attrs'], 'signature_policy_identifier'
    )[0]
    assert sp_id.chosen['sig_policy_id'].native == '2.999'


@freeze_time('2020-11-01')
def test_sign_weak_digest():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1', md_algorithm='md5')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    with pytest.raises(WeakHashAlgorithmError):
        val_trusted(emb)

    lenient_vc = ValidationContext(
        trust_roots=[ROOT_CERT], weak_hash_algos=set()
    )
    val_trusted(emb, vc=lenient_vc)


@freeze_time('2020-11-01')
def test_sign_weak_digest_prevention():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='md5',
        validation_context=SIMPLE_V_CONTEXT()
    )
    with pytest.raises(SigningError, match='.*weak.*'):
        signers.sign_pdf(w, meta, signer=FROM_CA)


@freeze_time('2020-11-01')
def test_sign_weak_sig_digest():
    # We have to jump through some hoops to put together a signature
    # where the signing method's digest is not the same as the "external"
    # digest. This is intentional, since it's bad practice.

    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)

    cms_writer = signers.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)

    timestamp = datetime.now(tz=tzlocal.get_localzone())
    sig_obj = signers.SignatureObject(timestamp=timestamp, bytes_reserved=8192)

    external_md_algorithm = 'sha256'
    cms_writer.send(signers.SigObjSetup(sig_placeholder=sig_obj))

    document_hash = cms_writer.send(
        signers.SigIOSetup(md_algorithm=external_md_algorithm, in_place=True)
    )
    signer = signers.SimpleSigner(
        signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
        signing_key=TESTING_CA.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs([ROOT_CERT, INTERM_CERT])
    )
    cms_obj = signer.sign(
        data_digest=document_hash, digest_algorithm=external_md_algorithm,
        timestamp=timestamp
    )
    si_obj: cms.SignerInfo = cms_obj['content']['signer_infos'][0]
    bad_algo = SignedDigestAlgorithm({'algorithm': 'md5_rsa'})
    si_obj['signature_algorithm'] = signer.signature_mechanism = bad_algo
    attrs = si_obj['signed_attrs']
    cms_prot = find_cms_attribute(attrs, 'cms_algorithm_protection')[0]
    cms_prot['signature_algorithm'] = bad_algo
    # recompute the signature
    si_obj['signature'] = signer.sign_raw(attrs.untag().dump(), 'md5')
    output, sig_contents = cms_writer.send(cms_obj)

    # we requested in-place output
    assert output is input_buf

    r = PdfFileReader(input_buf)
    emb = r.embedded_signatures[0]
    with pytest.raises(WeakHashAlgorithmError):
        val_trusted(emb)

    lenient_vc = ValidationContext(
        trust_roots=[ROOT_CERT], weak_hash_algos=set()
    )
    val_trusted(emb, vc=lenient_vc)
