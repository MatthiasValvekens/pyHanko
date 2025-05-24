import asyncio
import hashlib
import os
from datetime import datetime
from io import BytesIO

import pyhanko.pdf_utils.content
import pyhanko.sign.fields
import pytest
from asn1crypto.algos import SignedDigestAlgorithm
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import CertLabel, KeyLabel
from freezegun import freeze_time
from pyhanko import stamp
from pyhanko.keys import load_cert_from_pemder, load_certs_from_pemder
from pyhanko.pdf_utils import embed, generic, layout
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.diff_analysis import (
    NO_CHANGES_DIFF_POLICY,
    DiffResult,
    ModificationLevel,
)
from pyhanko.sign.general import SigningError, get_pyca_cryptography_hash
from pyhanko.sign.signers import cms_embedder
from pyhanko.sign.signers.pdf_byterange import BuildProps
from pyhanko.sign.signers.pdf_cms import (
    ExternalSigner,
    PdfCMSSignedAttributes,
    asyncify_signer,
)
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    RevocationInfoValidationType,
    SignatureCoverageLevel,
    add_validation_info,
    apply_adobe_revocation_info,
    async_validate_detached_cms,
    read_certification_data,
    validate_pdf_ltv_signature,
    validate_pdf_signature,
    validate_pdf_timestamp,
)
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.stamp import QRStampStyle

from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathValidationError
from pyhanko_certvalidator.registry import SimpleCertificateStore

from .samples import *
from .signing_commons import (
    DUMMY_HTTP_TS,
    DUMMY_TS,
    FIXED_OCSP,
    FROM_CA,
    FROM_CA_PKCS12,
    FROM_ECC_CA,
    FROM_ED448_CA,
    FROM_ED25519_CA,
    REVOKED_SIGNER,
    SELF_SIGN,
    SIMPLE_ED448_V_CONTEXT,
    SIMPLE_ED25519_V_CONTEXT,
    SIMPLE_V_CONTEXT,
    TRUST_ROOTS,
    TSA_CERT,
    async_val_trusted,
    dummy_ocsp_vc,
    live_testing_vc,
    val_trusted,
    val_untrusted,
)

DUMMY_TS_NO_NONCE = timestamps.DummyTimeStamper(
    tsa_cert=TSA_CERT,
    tsa_key=TESTING_CA.key_set.get_private_key('tsa'),
    certs_to_embed=FROM_CA.cert_registry,
    include_nonce=False,
)


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


def test_enforce_one_cert():
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
    out.seek(0x9D)
    # this just changes the size of the media box, so the file should remain
    # a valid PDF.
    out.write(b'4')
    out.seek(0)
    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    tampered = validate_pdf_signature(emb, SIMPLE_V_CONTEXT())
    assert not tampered.intact
    assert tampered.valid
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


def test_simple_sign_120mb_file():
    # put this in a function to avoid putting multiple copies
    #  of a huge buffer in locals
    def _gen_signed():
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
        w.root['/YugeObject'] = w.add_object(
            generic.StreamObject(stream_data=bytes(120 * 1024 * 1024))
        )
        w.update_root()

        meta = signers.PdfSignatureMetadata(field_name='Sig1')
        return signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(_gen_signed())
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)


def test_append_sigfield_tu_on_signing():
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)
    spec = fields.SigFieldSpec(
        sig_field_name='Sig1',
        empty_field_appearance=True,
        readable_field_name="Test test",
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.PdfSigner(
        meta, signer=SELF_SIGN, new_field_spec=spec
    ).sign_pdf(w)

    r = PdfFileReader(out)

    assert r.root['/AcroForm']['/Fields'][0]['/TU'] == "Test test"


@pytest.mark.parametrize(
    'policy, skip_diff',
    [(None, False), (NO_CHANGES_DIFF_POLICY, False), (None, True)],
)
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


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sign_with_trust_async():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/AP' not in s.sig_field
    await async_val_trusted(s)


@freeze_time('2020-12-05')
def test_sign_with_revoked(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=REVOKED_SIGNER,
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
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1', validation_context=vc
            ),
            signer=REVOKED_SIGNER,
        )


def test_sign_with_later_revoked_nots(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with freeze_time('2020-01-20'):
        out = signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=REVOKED_SIGNER,
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
        w,
        signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA_PKCS12,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_untrusted(s)
    assert not status.trusted

    val_trusted(s)


sign_test_files = (MINIMAL, MINIMAL_ONE_FIELD)


def test_enumerate_empty():
    with pytest.raises(StopIteration):
        next(fields.enumerate_sig_fields(PdfFileReader(BytesIO(MINIMAL))))


def test_certify_blank():
    r = PdfFileReader(BytesIO(MINIMAL))
    assert read_certification_data(r) is None


@freeze_time('2020-11-01')
def test_certify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            certify=True,
            docmdp_permissions=pyhanko.sign.fields.MDPPerm.NO_CHANGES,
        ),
        signer=FROM_CA,
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
def test_no_certify_after_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
        ),
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s)

    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(SigningError, match='must be the first'):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig2',
                certify=True,
                docmdp_permissions=pyhanko.sign.fields.MDPPerm.FILL_FORMS,
            ),
            signer=FROM_CA,
        )


@freeze_time('2020-11-01')
def test_approval_sig():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            certify=True,
        ),
        signer=FROM_CA,
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


@freeze_time('2020-11-01')
def test_ocsp_embed():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=dummy_ocsp_vc(),
            embed_validation_info=True,
        ),
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_untrusted(s)
    assert not status.trusted

    val_trusted(s)

    vc = apply_adobe_revocation_info(s.signer_info)
    assert len(vc.ocsps) == 1


@freeze_time('2020-11-01')
def test_ocsp_without_nextupdate_embed(requests_mock):
    ca = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-ocsp-no-nextupdate'))
    vc = ValidationContext(
        trust_roots=[ca.get_cert(CertLabel('root'))],
        allow_fetching=True,
        other_certs=[],
    )

    signer = signers.SimpleSigner(
        signing_cert=ca.get_cert(CertLabel('signer-special')),
        signing_key=ca.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [ca.get_cert(CertLabel('root')), ca.get_cert(CertLabel('interm'))]
        ),
    )
    Illusionist(ca).register(requests_mock)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            embed_validation_info=True,
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    vc = apply_adobe_revocation_info(s.signer_info)
    assert len(vc.ocsps) == 1
    assert len(vc.crls) == 1

    simple_response = vc.ocsps[0]['response_bytes']['response']
    rdata = simple_response.parsed['tbs_response_data']
    assert rdata['responses'][0]['next_update'].native is None


@freeze_time('2020-11-01')
def test_adobe_revinfo_live(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    r = PdfFileReader(out)
    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    status = validate_pdf_ltv_signature(
        r.embedded_signatures[0], rivt_adobe, {'trust_roots': TRUST_ROOTS}
    )
    assert status.valid and status.trusted


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_meta_tsa_verify():
    # check if my testing setup works
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS,
        allow_fetching=False,
        crls=[],
        ocsps=[FIXED_OCSP],
        revocation_mode='hard-fail',
    )
    with pytest.raises(PathValidationError):
        cv = CertificateValidator(TSA_CERT, validation_context=vc)
        await cv.async_validate_usage({'time_stamping'})


@freeze_time('2020-11-01')
def test_adobe_revinfo_live_nofullchain():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=dummy_ocsp_vc(),
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    r = PdfFileReader(out)
    rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
    # same as for the pades test above
    with pytest.raises(SignatureValidationError):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            rivt_adobe,
            {
                'trust_roots': TRUST_ROOTS,
                'allow_fetching': False,
                'ocsps': [FIXED_OCSP],
            },
        )
    from requests_mock import Mocker

    with Mocker() as m:
        live_testing_vc(m)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            rivt_adobe,
            {'trust_roots': TRUST_ROOTS, 'allow_fetching': True},
        )
        assert status.valid and not status.trusted, status.summary()


@freeze_time('2020-11-01')
def test_simple_qr_sign():
    style = QRStampStyle(stamp_text="Hi, it's\n%(ts)s")
    signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='Sig1'),
        FROM_CA,
        stamp_style=style,
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signer.sign_pdf(
        w,
        existing_fields_only=True,
        appearance_text_params={'url': 'https://example.com'},
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
        signers.PdfSignatureMetadata(field_name='Sig1'),
        FROM_CA,
        stamp_style=style,
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    with pytest.raises(layout.LayoutError):
        signer.sign_pdf(
            w, existing_fields_only=True, appearance_text_params=params_value
        )


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
        key_passphrase=b'secret',
    )

    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
    )
    pdf_signer = signers.PdfSigner(
        meta,
        signer=signer,
        stamp_style=stamp.TextStampStyle(
            stamp_text='%(signer)s\n%(ts)s',
        ),
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = pdf_signer.sign_pdf(
        w,
    )

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)

    ap_data = emb.sig_field['/AP']['/N'].data
    cn = signer.signing_cert.subject.native['common_name'].encode('ascii')
    assert cn in ap_data


def _tamper_with_sig_obj(tamper_fun):
    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)
    md_algorithm = 'sha256'

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    cms_writer.send(cms_embedder.SigObjSetup(sig_placeholder=sig_obj))

    tamper_fun(w, sig_obj)

    prep_document_hash, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    signer: signers.SimpleSigner = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        signature_mechanism=SignedDigestAlgorithm(
            {'algorithm': 'rsassa_pkcs1v15'}
        ),
    )
    with pytest.deprecated_call():
        # noinspection PyDeprecation
        cms_obj = signer.sign(
            data_digest=prep_document_hash.document_digest,
            digest_algorithm=md_algorithm,
        )
    cms_writer.send(cms_obj)
    return output


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
    with pytest.raises(
        SignatureValidationError, match='.*must be /DocTimeStamp.*'
    ):
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
    with pytest.raises(
        SignatureValidationError, match='.*must be /DocTimeStamp.*'
    ):
        validate_pdf_timestamp(emb, validation_context=SIMPLE_V_CONTEXT())


@pytest.mark.parametrize(
    'wrong_subfilter',
    [pdf_name('/abcde'), pdf_name("/ETSI.RFC3161"), None, generic.NullObject()],
)
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
    with pytest.raises(PdfReadError, match='.*Could not read /Contents.*'):
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
    with pytest.raises(PdfReadError, match='.*be string-like.*'):
        # noinspection PyStatementEffect
        r.embedded_signatures[0]


@freeze_time('2020-11-01')
def test_timestamp_with_different_digest():
    ts = timestamps.DummyTimeStamper(
        tsa_cert=TSA_CERT,
        tsa_key=TESTING_CA.key_set.get_private_key('tsa'),
        certs_to_embed=FROM_CA.cert_registry,
        override_md='sha512',
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(md_algorithm='sha256'),
        signer=FROM_CA,
        timestamper=ts,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


def test_sign_with_empty_kids():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(
        w,
        fields.SigFieldSpec(
            sig_field_name='Sig1',
            combine_annotation=False,
            box=(20, 20, 80, 40),
        ),
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


@pytest.mark.parametrize('in_place', [True, False])
@freeze_time('2020-11-01')
def test_no_revinfo_to_be_added(requests_mock, in_place):
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)

    vc = live_testing_vc(requests_mock)
    signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            embed_validation_info=True,
            validation_context=vc,
            subfilter=fields.SigSeedSubFilter.PADES,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
        in_place=True,
    )

    orig_file_length = buf.seek(0, os.SEEK_END)
    r = PdfFileReader(buf)
    emb_sig = r.embedded_signatures[0]
    orig_dss = DocumentSecurityStore.read_dss(r)
    assert len(orig_dss.ocsps) == 1
    assert len(orig_dss.crls) == 1
    # test with same vc, this shouldn't change anything
    # Turn off VRI updates, since those always trigger a write.
    output = add_validation_info(
        emb_sig, vc, in_place=in_place, add_vri_entry=False
    )
    if in_place:
        assert output is r.stream

    new_file_length = output.seek(0, os.SEEK_END)
    assert orig_file_length == new_file_length
    new_dss = DocumentSecurityStore.read_dss(PdfFileReader(output))
    assert len(new_dss.ocsps) == 1
    assert len(new_dss.crls) == 1


@pytest.mark.parametrize('with_vri', [True, False])
def test_add_revinfo_timestamp_separate_no_dss(requests_mock, with_vri):
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)

    # create signature & timestamp without revocation info
    with freeze_time('2020-11-01'):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA,
            in_place=True,
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
            emb_sig,
            RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS},
        )
        assert status.valid and not status.trusted

        # with retroactive revinfo, it should be OK
        status = validate_pdf_ltv_signature(
            emb_sig,
            RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True},
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES


def test_add_revinfo_without_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    # create signature without revocation info
    with freeze_time('2020-11-01'):
        out = signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA,
            in_place=True,
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
        with pytest.raises(
            SignatureValidationError, match='.*trusted timestamp.*'
        ):
            validate_pdf_ltv_signature(
                emb_sig,
                RevocationInfoValidationType.PADES_LT,
                {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True},
            )

        # ... and certainly for LTA
        with pytest.raises(SignatureValidationError, match='Purported.*LTA.*'):
            validate_pdf_ltv_signature(
                emb_sig,
                RevocationInfoValidationType.PADES_LTA,
                {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True},
            )


@pytest.mark.asyncio
async def test_embed_signed_attachment():
    dt = datetime.fromisoformat('2020-11-01T05:00:00+00:00')
    signature = await FROM_CA.async_sign_general_data(
        VECTOR_IMAGE_PDF, 'sha256', PdfCMSSignedAttributes(signing_time=dt)
    )

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    signers.embed_payload_with_cms(
        w,
        file_spec_string='attachment.pdf',
        payload=embed.EmbeddedFileObject.from_file_data(
            w,
            data=VECTOR_IMAGE_PDF,
            mime_type='application/pdf',
            params=embed.EmbeddedFileParams(
                creation_date=dt, modification_date=dt
            ),
        ),
        cms_obj=signature,
        file_name='添付ファイル.pdf',
        file_spec_kwargs={'description': "Signed attachment test"},
    )
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    emb_lst = r.root['/Names']['/EmbeddedFiles']['/Names']
    assert len(emb_lst) == 4
    assert emb_lst[0] == 'attachment.pdf'
    spec_obj = emb_lst[1]
    assert spec_obj['/UF'] == '添付ファイル.pdf'
    stream = spec_obj['/EF']['/F']
    assert stream.data == VECTOR_IMAGE_PDF
    assert spec_obj['/RF']['/F'][0] == 'attachment.sig'
    assert spec_obj['/RF']['/UF'][0] == '添付ファイル.sig'
    rel_file_ref = spec_obj['/RF']['/F'].raw_get(1).reference

    assert emb_lst[2] == 'attachment.sig'
    spec_obj = emb_lst[3]
    assert spec_obj['/UF'] == '添付ファイル.sig'
    stream = spec_obj['/EF']['/F']
    assert stream.data == signature.dump()
    assert stream.container_ref == rel_file_ref


@freeze_time('2020-11-01')
def test_simple_interrupted_signature():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA
    )
    with pytest.deprecated_call():
        # noinspection PyDeprecation
        prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(w)
    md_algorithm = tbs_document.md_algorithm
    assert tbs_document.post_sign_instructions is None

    # copy the output to a new buffer, just to make a point
    new_output = BytesIO()
    assert isinstance(output, BytesIO)
    buf = output.getbuffer()
    new_output.write(buf)
    buf.release()

    with pytest.deprecated_call():
        # noinspection PyDeprecation
        PdfTBSDocument.finish_signing(
            new_output,
            prep_digest,
            FROM_CA.sign(
                prep_digest.document_digest,
                digest_algorithm=md_algorithm,
            ),
        )

    r = PdfFileReader(new_output)
    val_trusted(r.embedded_signatures[0])


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_interrupted_with_delayed_signing_cert_mech():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='SigNew'),
        signer=ExternalSigner(
            signing_cert=None,
            cert_registry=None,
            signature_value=256,
            signature_mechanism=SignedDigestAlgorithm(
                {'algorithm': 'sha256_rsa'}
            ),
        ),
    )
    (
        prep_digest,
        tbs_document,
        output,
    ) = await pdf_signer.async_digest_doc_for_signing(w, bytes_reserved=8192)
    md_algorithm = tbs_document.md_algorithm
    assert tbs_document.post_sign_instructions is None

    # copy the output to a new buffer, just to make a point
    new_output = BytesIO()
    assert isinstance(output, BytesIO)
    buf = output.getbuffer()
    new_output.write(buf)
    buf.release()

    await PdfTBSDocument.async_finish_signing(
        new_output,
        prep_digest,
        await FROM_CA.async_sign(
            prep_digest.document_digest,
            digest_algorithm=md_algorithm,
        ),
    )

    r = PdfFileReader(new_output)
    await async_val_trusted(r.embedded_signatures[0])


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_interrupted_with_delayed_signing_cert_directly_specify_md():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='SigNew', md_algorithm='sha256'
        ),
        signer=ExternalSigner(
            signing_cert=None,
            cert_registry=None,
            signature_value=256,
        ),
    )
    (
        prep_digest,
        tbs_document,
        output,
    ) = await pdf_signer.async_digest_doc_for_signing(w, bytes_reserved=8192)
    md_algorithm = tbs_document.md_algorithm
    assert tbs_document.post_sign_instructions is None

    await PdfTBSDocument.async_finish_signing(
        output,
        prep_digest,
        await FROM_CA.async_sign(
            prep_digest.document_digest,
            digest_algorithm=md_algorithm,
        ),
    )

    r = PdfFileReader(output)
    await async_val_trusted(r.embedded_signatures[0])


@pytest.mark.asyncio
async def test_interrupted_could_not_determine_digest_algo():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='SigNew'),
        signer=ExternalSigner(
            signing_cert=None, cert_registry=None, signature_value=256
        ),
    )

    with pytest.raises(
        SigningError, match="Could not select.*digest algorithm"
    ):
        await pdf_signer.async_digest_doc_for_signing(w)


@pytest.mark.asyncio
async def test_interrupted_no_estimation():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='SigNew'),
        signer=ExternalSigner(
            signing_cert=None,
            cert_registry=None,
            signature_value=bytes(256),
            signature_mechanism=SignedDigestAlgorithm(
                {'algorithm': 'sha256_rsa'}
            ),
        ),
    )

    with pytest.raises(SigningError, match="estimation.*bytes_reserved"):
        await pdf_signer.async_digest_doc_for_signing(w)


@pytest.mark.asyncio
async def test_interrupted_with_delayed_signing_no_prevalidation():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='SigNew',
            embed_validation_info=True,
            validation_context=SIMPLE_V_CONTEXT(),
        ),
        signer=ExternalSigner(
            signing_cert=None,
            cert_registry=None,
            signature_value=256,
            signature_mechanism=SignedDigestAlgorithm(
                {'algorithm': 'sha256_rsa'}
            ),
        ),
    )
    with pytest.raises(SigningError, match='certificate must be provided'):
        await pdf_signer.async_digest_doc_for_signing(w, bytes_reserved=8192)


def test_determine_mechanism_no_signing_cert():
    signer = ExternalSigner(
        signing_cert=None, cert_registry=None, signature_value=bytes(256)
    )

    with pytest.raises(SigningError, match="Could not set up.*mechanism"):
        signer.get_signature_mechanism_for_digest('sha256')


@pytest.mark.asyncio
async def test_signer_info_no_signing_cert():
    signer = ExternalSigner(
        signing_cert=None,
        cert_registry=None,
        signature_value=256,
        signature_mechanism=SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
    )

    with pytest.raises(
        SigningError, match="certificate must be available.*SignerInfo"
    ):
        await signer.async_sign_general_data(
            b"Hello world",
            digest_algorithm="sha256",
        )


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sign_prescribed_attrs(requests_mock):
    vc = live_testing_vc(requests_mock)
    message = b'Hello world!'
    digest = hashlib.sha256(message).digest()
    signed_attrs = await FROM_CA.signed_attrs(digest, 'sha256')
    sig_cms = await FROM_CA.async_sign_prescribed_attributes(
        'sha256', signed_attrs=signed_attrs, timestamper=DUMMY_HTTP_TS
    )
    status = await async_validate_detached_cms(
        b'Hello world!', sig_cms['content'], signer_validation_context=vc
    )
    assert status.valid and status.intact and status.trusted
    ts_status = status.timestamp_validity
    assert ts_status.valid and ts_status.intact and ts_status.trusted


# noinspection PyDeprecation
@freeze_time('2020-11-01')
def test_sign_prescribed_attrs_legacy(requests_mock):
    vc = live_testing_vc(requests_mock)
    message = b'Hello world!'
    digest = hashlib.sha256(message).digest()
    signed_attrs = asyncio.run(FROM_CA.signed_attrs(digest, 'sha256'))
    with pytest.deprecated_call():
        sig_cms = FROM_CA.sign_prescribed_attributes(
            'sha256', signed_attrs=signed_attrs, timestamper=DUMMY_HTTP_TS
        )

    from pyhanko.sign.validation import validate_detached_cms

    with pytest.deprecated_call():
        status = validate_detached_cms(
            b'Hello world!', sig_cms['content'], signer_validation_context=vc
        )
    assert status.valid and status.intact and status.trusted
    ts_status = status.timestamp_validity
    assert ts_status.valid and ts_status.intact and ts_status.trusted


@freeze_time('2020-11-01')
def test_sign_tight_container():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', tight_size_estimates=True
    )
    out = signers.sign_pdf(w, meta, signer=SELF_SIGN)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)

    contents_str = emb.pkcs7_content
    ci = cms.ContentInfo(
        {'content_type': 'signed_data', 'content': emb.signed_data}
    )
    assert ci.dump() == contents_str


@freeze_time('2020-11-01')
def test_sign_tight_container_with_ts():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', tight_size_estimates=True, md_algorithm='sha256'
    )
    out = signers.sign_pdf(
        w, meta, signer=SELF_SIGN, timestamper=DUMMY_TS_NO_NONCE
    )

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)

    contents_str = emb.pkcs7_content
    ci = cms.ContentInfo(
        {'content_type': 'signed_data', 'content': emb.signed_data}
    )
    assert ci.dump() == contents_str


@freeze_time('2020-11-01')
def test_sign_tight_container_with_lta(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        tight_size_estimates=True,
        subfilter=fields.SigSeedSubFilter.PADES,
        use_pades_lta=True,
        embed_validation_info=True,
        validation_context=live_testing_vc(requests_mock),
    )
    out = signers.sign_pdf(
        w,
        meta,
        signer=FROM_CA,
        timestamper=DUMMY_TS_NO_NONCE,
    )

    r = PdfFileReader(out)

    def _check(emb):
        contents_str = emb.pkcs7_content
        ci = cms.ContentInfo(
            {'content_type': 'signed_data', 'content': emb.signed_data}
        )
        assert ci.dump() == contents_str

    _check(r.embedded_regular_signatures[0])
    _check(r.embedded_timestamp_signatures[0])


# noinspection PyAbstractClass
@asyncify_signer
class LegacyRSASigner(signers.Signer):
    def __init__(
        self,
        signing_cert,
        signing_key,
        cert_registry,
        signature_mechanism: SignedDigestAlgorithm = None,
        prefer_pss=False,
    ):
        self.signing_key = signing_key
        super().__init__(
            prefer_pss=prefer_pss,
            signing_cert=signing_cert,
            cert_registry=cert_registry,
            signature_mechanism=signature_mechanism,
        )

    # noinspection PyUnusedLocal
    def sign_raw(
        self, data: bytes, digest_algorithm: str, dry_run=False
    ) -> bytes:
        from cryptography.hazmat.primitives import serialization

        priv_key = serialization.load_der_private_key(
            self.signing_key.dump(), password=None
        )

        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

        padding = PKCS1v15()
        hash_algo = get_pyca_cryptography_hash(digest_algorithm)
        return priv_key.sign(data, padding, hash_algo)


def test_simple_sign_legacy_signer_upgrade():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    legacy_signer = LegacyRSASigner(
        signing_cert=SELF_SIGN.signing_cert,
        signing_key=SELF_SIGN.signing_key,
        cert_registry=SELF_SIGN.cert_registry,
    )
    out = signers.sign_pdf(w, meta, signer=legacy_signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_untrusted(emb)


def test_disallow_hybrid_sign():
    fname = 'minimal-hybrid-xref.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        meta = signers.PdfSignatureMetadata(field_name='Sig1')
        with pytest.raises(SigningError, match='hybrid xrefs are disabled'):
            signers.sign_pdf(w, meta, signer=SELF_SIGN)


def test_allow_hybrid_sign():
    fname = 'minimal-hybrid-xref.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        w = IncrementalPdfFileWriter(inf, strict=False)
        meta = signers.PdfSignatureMetadata(field_name='Sig1')
        signers.PdfSigner(signature_meta=meta, signer=SELF_SIGN).sign_pdf(w)


@freeze_time('2020-11-01')
def test_allow_hybrid_sign_validate_fail():
    fname = 'minimal-hybrid-xref.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        w = IncrementalPdfFileWriter(inf, strict=False)
        meta = signers.PdfSignatureMetadata(field_name='Sig1')
        out = signers.PdfSigner(signature_meta=meta, signer=FROM_CA).sign_pdf(w)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    with pytest.raises(SignatureValidationError, match="do not permit.*hybrid"):
        val_trusted(s)


@freeze_time('2020-11-01')
def test_allow_hybrid_sign_validate_allow():
    fname = 'minimal-hybrid-xref.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        w = IncrementalPdfFileWriter(inf, strict=False)
        meta = signers.PdfSignatureMetadata(field_name='Sig1')
        out = signers.PdfSigner(signature_meta=meta, signer=FROM_CA).sign_pdf(w)

    r = PdfFileReader(out, strict=False)
    s = r.embedded_signatures[0]

    vc = SIMPLE_V_CONTEXT()
    val_status = validate_pdf_signature(s, vc)
    assert val_status.bottom_line


@freeze_time('2020-11-01')
def test_ed25519():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_ED25519_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = val_untrusted(s)
    assert status.md_algorithm == 'sha512'

    (extn,) = r.root['/Extensions']['/ISO_']
    assert extn['/ExtensionLevel'] == 32002


@freeze_time('2020-11-01')
def test_ed25519_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_ED25519_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s, vc=SIMPLE_ED25519_V_CONTEXT())


@freeze_time('2020-11-01')
def test_ed448():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_ED448_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = val_untrusted(s)
    assert status.md_algorithm == 'shake256_len'

    assert len(s.external_digest) == 64

    extn1, extn2 = r.root['/Extensions']['/ISO_']
    assert {extn1['/ExtensionLevel'], extn2['/ExtensionLevel']} == {
        32001,
        32002,
    }


@freeze_time('2020-11-01')
def test_ed448_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_ED448_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s, vc=SIMPLE_ED448_V_CONTEXT())


@freeze_time('2020-11-01')
def test_ed448_invalid_hash_algo():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with pytest.raises(SigningError, match='specifies.*shake256'):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1', md_algorithm='sha256'
            ),
            signer=FROM_ED448_CA,
        )


@freeze_time('2020-11-01')
def test_ecdsa_with_sha256():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1', md_algorithm='sha256'),
        signer=FROM_ECC_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = val_untrusted(s)
    assert status.md_algorithm == 'sha256'

    (extn,) = r.root['/Extensions']['/ISO_']
    assert extn['/ExtensionLevel'] == 32002


@freeze_time('2020-11-01')
def test_ecdsa_with_sha3():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1', md_algorithm='sha3_256'
        ),
        signer=FROM_ECC_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = val_untrusted(s)
    assert status.md_algorithm == 'sha3_256'

    extn1, extn2 = r.root['/Extensions']['/ISO_']
    assert {extn1['/ExtensionLevel'], extn2['/ExtensionLevel']} == {
        32001,
        32002,
    }


@freeze_time('2020-11-01')
def test_rsa_with_sha3():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        # need the generic mechanism because asn1crypto (==1.5.1)
        # doesn't have the OIDs for RSA-with-SHA3 family
        # hash functions.
        signature_mechanism=SignedDigestAlgorithm(
            {'algorithm': 'rsassa_pkcs1v15'}
        ),
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            md_algorithm='sha3_256',
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = val_untrusted(s)
    assert status.md_algorithm == 'sha3_256'

    (extn,) = r.root['/Extensions']['/ISO_']
    assert extn['/ExtensionLevel'] == 32001


@freeze_time('2020-11-01')
def test_rsa_with_sha384():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        # need the generic mechanism because asn1crypto (==1.5.1)
        # doesn't have the OIDs for RSA-with-SHA3 family
        # hash functions.
        signature_mechanism=SignedDigestAlgorithm(
            {'algorithm': 'rsassa_pkcs1v15'}
        ),
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            md_algorithm='sha384',
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = val_untrusted(s)
    assert status.md_algorithm == 'sha384'

    assert r.input_version == (1, 7)
    assert '/Extensions' not in r.root


@freeze_time('2020-11-01')
def test_sign_with_build_props_app_name():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', app_build_props=BuildProps(name='Test Application')
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s)
    build_prop_dict = s.sig_object['/Prop_Build']['/App']
    assert build_prop_dict['/Name'] == '/Test Application'
    assert '/REx' not in build_prop_dict


@freeze_time('2020-11-01')
def test_sign_with_build_props_versioned_app_name():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        app_build_props=BuildProps(name='Test Application', revision='1.2.3'),
    )

    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s)
    build_prop_dict = s.sig_object['/Prop_Build']['/App']
    assert build_prop_dict['/Name'] == '/Test Application'
    assert build_prop_dict['/REx'] == '1.2.3'


@freeze_time('2020-11-01')
def test_signature_dict_with_prop_auth_time():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1', prop_auth_time=512)

    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s)
    assert s.sig_object['/Prop_AuthTime'] == 512


@freeze_time('2020-11-01')
def test_signature_dict_with_contact_info():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    contact_info = '+55 99 99999-9999'
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', contact_info=contact_info
    )

    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s)
    assert s.sig_object['/ContactInfo'] == contact_info


@freeze_time('2020-11-01')
def test_signature_dict_with_prop_auth_type():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    auth_type = fields.SigAuthType.PASSWORD
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        prop_auth_type=auth_type,
    )

    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s)
    assert s.sig_object['/Prop_AuthType'] == 'Password'


def test_sign_reject_econtent_if_detached():
    fname = os.path.join(PDF_DATA_DIR, 'pdf-sig-with-econtent.pdf')
    with open(fname, 'rb') as inf:
        r = PdfFileReader(inf)
        emb = r.embedded_signatures[0]

        with pytest.raises(
            SignatureValidationError, match='detached.*encapsulated'
        ):
            val_untrusted(emb)
