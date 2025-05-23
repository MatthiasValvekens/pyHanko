import asyncio
from datetime import datetime, timezone
from io import BytesIO
from typing import Iterable

import pytest
from asn1crypto import cms, core, tsp
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import ArchLabel, CertLabel, KeyLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import PdfTimeStamper, fields, signers, timestamps
from pyhanko.sign.ades.api import (
    CAdESSignedAttrSpec,
    GenericCommitment,
    SignerAttrSpec,
)
from pyhanko.sign.ades.cades_asn1 import (
    CertifiedAttributeChoices,
    CommitmentTypeIndication,
    SignaturePolicyIdentifier,
    SignedAssertion,
    SignerAttributesV2,
)
from pyhanko.sign.attributes import (
    CMSAttributeProvider,
    SignedAttributeProviderSpec,
    TSTProvider,
)
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.general import SigningError, find_cms_attribute
from pyhanko.sign.signers.pdf_signer import (
    DSSContentSettings,
    PdfTBSDocument,
    PostSignInstructions,
    SigDSSPlacementPreference,
    TimestampDSSContentSettings,
)
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    PdfSignatureStatus,
    RevocationInfoValidationType,
    SignatureCoverageLevel,
    add_validation_info,
    async_validate_pdf_ltv_signature,
    async_validate_pdf_signature,
    validate_pdf_ltv_signature,
    validate_pdf_timestamp,
)
from pyhanko.sign.validation.errors import (
    SignatureValidationError,
    ValidationInfoReadingError,
)

from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.registry import SimpleCertificateStore

from .samples import (
    CERTOMANCER,
    MINIMAL,
    MINIMAL_ONE_FIELD,
    MINIMAL_SLIGHTLY_BROKEN,
    MINIMAL_TWO_FIELDS,
    PDF_DATA_DIR,
    SAMPLE_GROUP_ATTR,
    TESTING_CA,
    UNRELATED_TSA,
)
from .signing_commons import (
    DUMMY_HTTP_TS,
    DUMMY_HTTP_TS_VARIANT,
    DUMMY_POLICY_ID,
    DUMMY_TS,
    DUMMY_TS2,
    FIXED_OCSP,
    FROM_CA,
    FROM_ECC_CA,
    INTERM_CERT,
    ROOT_CERT,
    SIMPLE_ECC_V_CONTEXT,
    SIMPLE_V_CONTEXT,
    TRUST_ROOTS,
    async_val_trusted,
    dummy_ocsp_vc,
    live_ac_vcs,
    live_testing_vc,
    val_trusted,
)


def ts_response_callback(request, _context):
    req = tsp.TimeStampReq.load(request.body)
    return DUMMY_TS.request_tsa_response(req=req).dump()


PADES = fields.SigSeedSubFilter.PADES


def test_pades_flag():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'
    # the original file is a PDF 1.7 file
    assert '/ESIC' in r.root['/Extensions']
    assert r.input_version == (1, 7)


def test_pades_pdf2():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    w.ensure_output_version(version=(2, 0))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    field_name, sig_obj, sig_field = next(fields.enumerate_sig_fields(r))
    assert field_name == 'Sig1'
    assert sig_obj.get_object()['/SubFilter'] == '/ETSI.CAdES.detached'
    assert '/Extensions' not in r.root
    assert r.input_version == (2, 0)


@freeze_time('2020-11-01')
def test_pades_revinfo_dummydata():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=dummy_ocsp_vc(),
            subfilter=PADES,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
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
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=None,
                subfilter=PADES,
                embed_validation_info=True,
            ),
            signer=FROM_CA,
        )


@freeze_time('2020-11-01')
def test_pades_revinfo_ts_dummydata():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=dummy_ocsp_vc(),
            subfilter=PADES,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
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
        DUMMY_HTTP_TS.url,
        content=ts_response_callback,
        headers={'Content-Type': 'application/timestamp-reply'},
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=dummy_ocsp_vc(),
            subfilter=PADES,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_HTTP_TS,
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
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=PADES,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
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
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=PADES,
                embed_validation_info=True,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
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
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES

        rivt_adobe = RevocationInfoValidationType.ADOBE_STYLE
        with pytest.raises(
            ValidationInfoReadingError, match='No revocation info'
        ):
            validate_pdf_ltv_signature(
                r.embedded_signatures[0],
                rivt_adobe,
                {'trust_roots': TRUST_ROOTS},
            )

    # test post-expiration, but before timestamp expires
    with freeze_time('2025-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0], rivt_pades, {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and status.trusted

    # test after timestamp expires: this is beyond the scope of the "basic" LTV
    #  mechanism, but failing to validate seems to be the conservative thing
    #  to do.
    with freeze_time('2040-11-01'):
        r = PdfFileReader(out)
        with pytest.raises(SignatureValidationError):
            validate_pdf_ltv_signature(
                r.embedded_signatures[0],
                rivt_pades,
                {'trust_roots': TRUST_ROOTS},
            )


@freeze_time('2020-11-01')
def test_pades_revinfo_live_update(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=PADES,
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
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


@freeze_time('2020-11-01')
def test_update_no_timestamps():
    r = PdfFileReader(BytesIO(MINIMAL))
    output = PdfTimeStamper(DUMMY_TS).update_archival_timestamp_chain(
        r, dummy_ocsp_vc(), in_place=False
    )
    r = PdfFileReader(output)
    status = validate_pdf_timestamp(
        r.embedded_signatures[0],
        validation_context=ValidationContext(trust_roots=TRUST_ROOTS),
    )
    assert status.valid and status.trusted
    assert r.embedded_timestamp_signatures[0].sig_field['/TU'] == "Timestamp"


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_pades_revinfo_live_update_to_disk(requests_mock, tmp_path):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=PADES,
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    r = PdfFileReader(out)
    rivt_pades_lta = RevocationInfoValidationType.PADES_LTA
    from pathlib import Path

    out_path: Path = tmp_path / "out.pdf"
    with out_path.open('wb') as outf:
        pdf_ts = PdfTimeStamper(DUMMY_TS)
        await pdf_ts.async_update_archival_timestamp_chain(
            r, vc, in_place=False, output=outf
        )
    with out_path.open('rb') as inf:
        r = PdfFileReader(inf)
        emb_sig = r.embedded_signatures[0]
        status = await async_validate_pdf_ltv_signature(
            emb_sig, rivt_pades_lta, {'trust_roots': TRUST_ROOTS}
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES
        assert len(r.embedded_signatures) == 3
        assert len(r.embedded_regular_signatures) == 1
        assert len(r.embedded_timestamp_signatures) == 2
        assert emb_sig is r.embedded_regular_signatures[0]


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
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=PADES,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
            **kwargs,
        )
    return out


def _test_pades_revinfo_live_lta_validate(
    out, requests_mock, no_write=False, has_more_sigs=False
):
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
                r.embedded_signatures[0],
                rivt_pades_lta,
                {'trust_roots': TRUST_ROOTS},
                bootstrap_validation_context=bootstrap_vc,
            )
            assert status.valid and status.trusted
            assert status.modification_level == expected_modlevel

    # test post-expiration, but before timestamp expires
    with freeze_time('2025-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            rivt_pades_lta,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock),
        )
        assert status.valid and status.trusted

    # test after timestamp expires: this should fail when doing LTA testing
    with freeze_time('2035-11-01'):
        r = PdfFileReader(out)
        with pytest.raises(SignatureValidationError):
            validate_pdf_ltv_signature(
                r.embedded_signatures[0],
                rivt_pades_lta,
                {'trust_roots': TRUST_ROOTS},
                bootstrap_validation_context=live_testing_vc(requests_mock),
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
            r.embedded_signatures[0],
            rivt_pades_lta,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=vc,
        )
        assert status.valid and status.trusted
        assert status.modification_level == expected_modlevel

    # the test that previously failed should now work
    with freeze_time('2035-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            rivt_pades_lta,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock),
        )
        assert status.valid and status.trusted

    # test after timestamp expires: this should fail when doing LTA testing
    with freeze_time('2040-11-01'):
        r = PdfFileReader(out)
        with pytest.raises(SignatureValidationError):
            validate_pdf_ltv_signature(
                r.embedded_signatures[0],
                rivt_pades_lta,
                {'trust_roots': TRUST_ROOTS},
                bootstrap_validation_context=live_testing_vc(requests_mock),
            )


def _test_pades_revinfo_live_lta(w, requests_mock, **kwargs):
    out = _test_pades_revinfo_live_lta_sign(w, requests_mock, **kwargs)
    _test_pades_revinfo_live_lta_validate(out, requests_mock)


@freeze_time('2020-11-01')
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
                'trust_roots': TRUST_ROOTS,
                'allow_fetching': False,
                'revocation_mode': 'soft-fail',
            },
        )


def test_pades_lta_sign_twice(requests_mock):
    stream = BytesIO(MINIMAL_TWO_FIELDS)
    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-10-01'):
        vc = live_testing_vc(requests_mock)
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=PADES,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
            in_place=True,
        )

    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-11-01'):
        vc = live_testing_vc(requests_mock)
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig2',
                validation_context=vc,
                subfilter=PADES,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
            in_place=True,
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
            bootstrap_validation_context=live_testing_vc(requests_mock),
        )


def test_pades_lta_sign_twice_post_expiry(requests_mock):
    stream = BytesIO(MINIMAL_TWO_FIELDS)
    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-10-01'):
        vc = live_testing_vc(requests_mock)
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=PADES,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
            in_place=True,
        )

    w = IncrementalPdfFileWriter(stream)
    with freeze_time('2020-10-10'):
        # intentionally load a VC in which the original TS does
        # not validate
        vc = SIMPLE_ECC_V_CONTEXT()
        with pytest.raises(SigningError, match=".*most recent timestamp.*"):
            signers.sign_pdf(
                w,
                signers.PdfSignatureMetadata(
                    field_name='Sig2',
                    validation_context=vc,
                    subfilter=PADES,
                    embed_validation_info=True,
                    use_pades_lta=True,
                ),
                signer=FROM_ECC_CA,
                timestamper=DUMMY_TS,
                in_place=True,
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
    out.seek(0x9D)
    out.write(b'4')
    out.seek(0)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    tampered = validate_pdf_timestamp(embedded_sig=s, validation_context=vc)
    assert not tampered.intact and tampered.valid


@pytest.mark.parametrize('with_vri', [True, False])
def test_add_revinfo_later(requests_mock, with_vri):
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)

    # create signature without revocation info
    with freeze_time('2020-11-01'):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
            in_place=True,
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


@pytest.mark.parametrize('with_vri', [True, False])
def test_fix_incomplete_revinfo_later(requests_mock, with_vri):
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)

    # create signature with incomplete revinfo
    with freeze_time('2020-11-01'):
        # trust the intermediate cert and the TSA cert absolutely
        incomplete_vc = ValidationContext(
            trust_roots=[INTERM_CERT, DUMMY_TS.tsa_cert],
            allow_fetching=True,
            other_certs=[],
        )
        Illusionist(TESTING_CA).register(requests_mock)
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=incomplete_vc,
                embed_validation_info=True,
                subfilter=PADES,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
            in_place=True,
        )

    # fast forward 1 month
    with freeze_time('2020-12-01'):
        vc = live_testing_vc(requests_mock)
        r = PdfFileReader(buf)
        emb_sig = r.embedded_signatures[0]
        add_validation_info(emb_sig, vc, in_place=True, add_vri_entry=with_vri)

        r = PdfFileReader(buf)
        emb_sig = r.embedded_signatures[0]

        status = validate_pdf_ltv_signature(
            emb_sig,
            RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS, 'retroactive_revinfo': True},
        )
        assert status.valid and status.trusted
        assert status.modification_level == ModificationLevel.LTA_UPDATES


def test_add_revinfo_and_timestamp(requests_mock):
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
            emb_sig,
            RevocationInfoValidationType.PADES_LT,
            {'trust_roots': TRUST_ROOTS},
        )
        assert status.valid and status.trusted
        assert status.signer_reported_dt == datetime.now(tz=timezone.utc)

        # ... but PAdES-LTA should fail
        with pytest.raises(
            SignatureValidationError, match='.*requires separate timestamps.*'
        ):
            validate_pdf_ltv_signature(
                emb_sig,
                RevocationInfoValidationType.PADES_LTA,
                {'trust_roots': TRUST_ROOTS},
            )


def test_add_revinfo_and_lta_timestamp(requests_mock):
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

        timestamper = signers.PdfTimeStamper(timestamper=DUMMY_TS)
        timestamper.timestamp_pdf(
            IncrementalPdfFileWriter(out), 'sha256', vc, in_place=True
        )
        timestamper.update_archival_timestamp_chain(PdfFileReader(out), vc)

        r = PdfFileReader(out)
        emb_sig = r.embedded_signatures[0]

        status = validate_pdf_ltv_signature(
            emb_sig,
            RevocationInfoValidationType.PADES_LTA,
            {'trust_roots': TRUST_ROOTS},
        )
        assert status.valid and status.trusted
        assert status.signer_reported_dt == datetime.now(tz=timezone.utc)

    # test post-expiration, but before timestamp expires
    with freeze_time('2025-11-01'):
        r = PdfFileReader(out)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            RevocationInfoValidationType.PADES_LTA,
            {'trust_roots': TRUST_ROOTS},
            bootstrap_validation_context=live_testing_vc(requests_mock),
        )
        assert status.valid and status.trusted


@freeze_time('2020-11-01')
def test_sign_with_commitment():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        subfilter=fields.SigSeedSubFilter.PADES,
        cades_signed_attr_spec=CAdESSignedAttrSpec(
            commitment_type=GenericCommitment.PROOF_OF_ORIGIN.asn1
        ),
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
        field_name='Sig1',
        subfilter=fields.SigSeedSubFilter.PADES,
        cades_signed_attr_spec=CAdESSignedAttrSpec(timestamp_content=True),
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    status = val_trusted(emb)
    assert isinstance(status, PdfSignatureStatus)
    assert status.content_timestamp_validity.intact
    assert status.content_timestamp_validity.valid
    assert status.content_timestamp_validity.trusted

    content_ts = find_cms_attribute(
        emb.signer_info['signed_attrs'], 'content_time_stamp'
    )[0]
    eci = content_ts['content']['encap_content_info']
    assert eci['content_type'].native == 'tst_info'


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sign_with_wrong_content_sig():
    class Spec(SignedAttributeProviderSpec):
        def signed_attr_providers(
            self, data_digest: bytes, digest_algorithm: str
        ) -> Iterable[CMSAttributeProvider]:
            yield TSTProvider(
                digest_algorithm='sha256',
                data_to_ts=b'\xde\xad\xbe\xef',
                timestamper=DUMMY_TS,
                attr_type='content_time_stamp',
            )

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        subfilter=fields.SigSeedSubFilter.PADES,
    )
    signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
    )
    signer.signed_attr_prov_spec = Spec()
    out = await signers.async_sign_pdf(
        w, meta, signer=signer, timestamper=DUMMY_TS
    )

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    status = await async_validate_pdf_signature(
        embedded_sig=emb, signer_validation_context=SIMPLE_V_CONTEXT()
    )
    assert not status.bottom_line
    assert status.valid
    assert status.intact
    assert status.trusted
    assert not status.content_timestamp_validity.intact
    assert status.content_timestamp_validity.valid
    assert not status.content_timestamp_validity.trusted
    assert status.timestamp_validity.intact
    assert status.timestamp_validity.valid
    assert status.timestamp_validity.trusted


@freeze_time('2020-11-01')
@pytest.mark.parametrize('different_tsa', [True, False])
def test_interrupted_pades_lta_signature(requests_mock, different_tsa):
    # simulate a PAdES-LTA workflow with remote signing
    # (our hypothetical remote signer just signs digests, not full CMS objects)
    requests_mock.post(
        DUMMY_HTTP_TS.url,
        content=ts_response_callback,
        headers={'Content-Type': 'application/timestamp-reply'},
    )

    def instantiate_external_signer(sig_value: bytes):
        return signers.ExternalSigner(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            signature_value=sig_value,
            cert_registry=SimpleCertificateStore.from_certs(
                [ROOT_CERT, INTERM_CERT]
            ),
        )

    async def prep_doc():
        # 2048-bit RSA sig is 256 bytes long -> placeholder
        ext_signer = instantiate_external_signer(sig_value=bytes(256))
        vc = live_testing_vc(requests_mock)
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
        pdf_signer = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                field_name='SigNew',
                embed_validation_info=True,
                use_pades_lta=True,
                subfilter=PADES,
                validation_context=vc,
                md_algorithm='sha256',
                dss_settings=DSSContentSettings(include_vri=False),
            ),
            signer=ext_signer,
            timestamper=DUMMY_HTTP_TS,
        )
        # This function may perform async network I/O
        (
            prep_digest,
            tbs_document,
            output,
        ) = await pdf_signer.async_digest_doc_for_signing(w)
        psi = tbs_document.post_sign_instructions

        # prepare signed attributes
        # Note: signed attribute construction may involve
        # expensive I/O (e.g. when content timestamp tokens
        # need to be obtained). Hence why the API is asynchronous.
        signed_attrs = await ext_signer.signed_attrs(
            prep_digest.document_digest, 'sha256', use_pades=True
        )
        return prep_digest, signed_attrs, psi, output

    async def sim_sign_remote(data_tbs: bytes):
        # pretend that everything below happens on a remote server
        # (we declare the function as async to add to the illusion)
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

        priv_key = serialization.load_der_private_key(
            TESTING_CA.key_set.get_private_key(KeyLabel('signer1')).dump(),
            password=None,
        )
        padding = PKCS1v15()
        hash_algo = hashes.SHA256()
        return priv_key.sign(data_tbs, padding, hash_algo)

    async def proceed_with_signing(
        prep_digest, signed_attrs, sig_value, psi, output_handle
    ):
        # use ExternalSigner to format the CMS given the signed value
        # we obtained from the remote signing service
        ext_signer = instantiate_external_signer(sig_value)

        # again, even though we already produced the signature, we need to
        # perform an async call here, because setting up the unsigned attributes
        # potentially requires async I/O in the general case
        sig_cms = await ext_signer.async_sign_prescribed_attributes(
            'sha256', signed_attrs=signed_attrs, timestamper=DUMMY_HTTP_TS
        )

        # fresh VC
        validation_context = live_testing_vc(
            requests_mock, with_extra_tsa=different_tsa
        )
        await PdfTBSDocument.async_finish_signing(
            output_handle,
            prepared_digest=prep_digest,
            signature_cms=sig_cms,
            post_sign_instr=psi,
            validation_context=validation_context,
        )

    async def full_procedure():
        # prepare document and signed attributes to sign
        prep_digest, signed_attrs, psi, output = await prep_doc()

        # copy the output to a new buffer, just to drive home the point that
        # we no longer care about the original output stream
        new_output = BytesIO()
        assert isinstance(output, BytesIO)
        buf = output.getbuffer()
        new_output.write(buf)
        buf.release()

        # contact our 'remote' signing service
        sig_value = await sim_sign_remote(signed_attrs.dump())
        # let's pretend that we no longer have access to the non-serialisable
        # parts of tbs_document and psi (e.g. because this part happens on a
        # different machine)
        if different_tsa:
            # use another TSA for the document timestamp
            docts_tsa = DUMMY_HTTP_TS_VARIANT
        else:
            docts_tsa = DUMMY_HTTP_TS

        new_psi = PostSignInstructions(
            validation_info=psi.validation_info,
            timestamp_md_algorithm=psi.timestamp_md_algorithm,
            timestamper=docts_tsa,
            timestamp_field_name=psi.timestamp_field_name,
            dss_settings=psi.dss_settings,
        )
        # finish signing
        await proceed_with_signing(
            prep_digest, signed_attrs, sig_value, new_psi, new_output
        )
        return new_output

    r = PdfFileReader(asyncio.run(full_procedure()))
    # check cardinality of DSS content
    dss = DocumentSecurityStore.read_dss(handler=r)
    assert dss is not None
    if different_tsa:
        assert len(dss.certs) == 7
        assert len(dss.ocsps) == 1
        assert len(dss.crls) == 2
        trust_roots = TRUST_ROOTS + [UNRELATED_TSA.get_cert(CertLabel('root'))]
        # extra update was needed to append revinfo for second TSA
        assert r.xrefs.total_revisions == 4
    else:
        assert len(dss.certs) == 5
        assert len(dss.ocsps) == 1
        assert len(dss.crls) == 1
        assert r.xrefs.total_revisions == 3
        trust_roots = TRUST_ROOTS

    emb_sig = r.embedded_signatures[0]
    # perform LTA validation
    status = validate_pdf_ltv_signature(
        emb_sig,
        RevocationInfoValidationType.PADES_LTA,
        {'trust_roots': trust_roots},
    )
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert len(r.embedded_signatures) == 2
    assert len(r.embedded_regular_signatures) == 1
    assert len(r.embedded_timestamp_signatures) == 1
    assert emb_sig is r.embedded_regular_signatures[0]


def test_dss_setting_validation():
    bad_ts_sett = TimestampDSSContentSettings(
        include_vri=True, update_before_ts=True
    )
    with pytest.raises(SigningError):
        bad_ts_sett.assert_viable()

    with pytest.raises(SigningError):
        DSSContentSettings(
            include_vri=True,
            placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
        ).assert_viable()

    DSSContentSettings(
        include_vri=True,
        placement=SigDSSPlacementPreference.TOGETHER_WITH_NEXT_TS,
    ).assert_viable()
    DSSContentSettings(
        include_vri=False,
        placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
    ).assert_viable()
    with pytest.raises(SigningError):
        DSSContentSettings(
            include_vri=False,
            placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
            next_ts_settings=bad_ts_sett,
        ).assert_viable()


@freeze_time('2020-11-01')
def test_pades_one_revision(requests_mock):
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            dss_settings=DSSContentSettings(
                include_vri=False,
                placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
            ),
            validation_context=live_testing_vc(requests_mock),
            embed_validation_info=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    assert r.total_revisions == 1
    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LT,
        validation_context_kwargs={
            'trust_roots': TRUST_ROOTS,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


NOOP_POLICY = CertRevTrustPolicy(
    revocation_checking_policy=RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
        intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
    )
)


def _lazy_pades_signature(requests_mock):
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    # set up a signer that doesn't embed anything
    #  (but still goes through the motions)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            validation_context=live_testing_vc(
                requests_mock, revinfo_policy=NOOP_POLICY
            ),
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    return out


@freeze_time('2020-11-01')
def test_pades_ltv_legacy_policy_sufficient(requests_mock):
    out = _lazy_pades_signature(requests_mock)
    r = PdfFileReader(out)
    # soft fail should not apply to the internal timestamp, so we expect
    # validation to fail
    with pytest.raises(SignatureValidationError, match='time of signing'):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            validation_type=RevocationInfoValidationType.PADES_LTA,
            validation_context_kwargs={
                'trust_roots': TRUST_ROOTS,
                'allow_fetching': False,
                'revocation_mode': 'hard-fail',
            },
            # allow bootstrapping with soft-fail
            bootstrap_validation_context=ValidationContext(
                trust_roots=TRUST_ROOTS,
                allow_fetching=False,
                revocation_mode='soft-fail',
            ),
        )


@freeze_time('2020-11-01')
def test_pades_ltv_upgrade_soft_fail(requests_mock):
    out = _lazy_pades_signature(requests_mock)
    r = PdfFileReader(out)
    # soft fail should not apply to the internal timestamp, so we expect
    # validation to fail
    with pytest.raises(SignatureValidationError, match='time of signing'):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            validation_type=RevocationInfoValidationType.PADES_LTA,
            validation_context_kwargs={
                'trust_roots': TRUST_ROOTS,
                'allow_fetching': False,
                'revocation_mode': 'soft-fail',
            },
        )


@freeze_time('2020-11-01')
def test_pades_ltv_upgrade_lax_policy(requests_mock):
    out = _lazy_pades_signature(requests_mock)
    r = PdfFileReader(out)
    # as in the soft_fail case, we expect this to fail
    with pytest.raises(SignatureValidationError, match='time of signing'):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            validation_type=RevocationInfoValidationType.PADES_LTA,
            validation_context_kwargs={
                'trust_roots': TRUST_ROOTS,
                'allow_fetching': False,
                'revinfo_policy': NOOP_POLICY,
            },
        )


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'dss_settings',
    [
        DSSContentSettings(
            placement=SigDSSPlacementPreference.SEPARATE_REVISION,
        ),
        DSSContentSettings(
            placement=SigDSSPlacementPreference.TOGETHER_WITH_NEXT_TS,
        ),
        DSSContentSettings(),
    ],
)
def test_pades_two_revisions(requests_mock, dss_settings):
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            dss_settings=dss_settings,
            validation_context=live_testing_vc(requests_mock),
            embed_validation_info=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    assert r.total_revisions == 2
    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LT,
        validation_context_kwargs={
            'trust_roots': TRUST_ROOTS,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'dss_settings',
    [
        DSSContentSettings(
            placement=SigDSSPlacementPreference.TOGETHER_WITH_NEXT_TS,
            next_ts_settings=TimestampDSSContentSettings(
                update_before_ts=True, include_vri=False
            ),
        ),
        DSSContentSettings(
            placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
            include_vri=False,
            next_ts_settings=TimestampDSSContentSettings(
                update_before_ts=True, include_vri=False
            ),
        ),
        DSSContentSettings(
            placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
            include_vri=False,
        ),
        DSSContentSettings(
            placement=SigDSSPlacementPreference.TOGETHER_WITH_NEXT_TS,
            include_vri=False,
        ),
    ],
)
def test_pades_lta_two_revisions(requests_mock, dss_settings):
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            dss_settings=dss_settings,
            validation_context=live_testing_vc(requests_mock),
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    assert r.total_revisions == 2
    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LTA,
        validation_context_kwargs={
            'trust_roots': TRUST_ROOTS,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


@freeze_time('2020-11-01')
def test_pades_lta_noskip(requests_mock):
    dss_settings = DSSContentSettings(
        placement=SigDSSPlacementPreference.SEPARATE_REVISION,
        include_vri=False,
        skip_if_unneeded=False,
    )
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            dss_settings=dss_settings,
            validation_context=live_testing_vc(requests_mock),
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    assert r.total_revisions == 4
    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LTA,
        validation_context_kwargs={
            'trust_roots': TRUST_ROOTS,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


@freeze_time('2020-11-01')
def test_pades_post_ts_autosuppress(requests_mock):
    # test if the post-timestamp DSS update is automatically suppressed
    # if we sign with the exact same TSA for both the sig & the document TS
    # (keeping the VC constant as well)
    dss_settings = DSSContentSettings(
        placement=SigDSSPlacementPreference.TOGETHER_WITH_NEXT_TS,
        include_vri=False,
    )
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            dss_settings=dss_settings,
            validation_context=live_testing_vc(requests_mock),
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    assert r.total_revisions == 2
    # assert that the DSS was updated in the timestamped revision
    dss_ref = r.root.get_value_as_reference('/DSS')
    changed_in = r.xrefs.get_last_change(dss_ref)
    assert changed_in == 1

    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LTA,
        validation_context_kwargs={
            'trust_roots': TRUST_ROOTS,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


@freeze_time('2020-11-01')
def test_pades_max_autosuppress(requests_mock):
    # test if all timestamp-related DSS updates are suppressed
    # if we sign with the exact same TSA for both the sig & the document TS
    # (keeping the VC constant as well) and all relevant DSS updates were
    # performed pre-signing
    dss_settings = DSSContentSettings(
        placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
        include_vri=False,
    )
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            dss_settings=dss_settings,
            validation_context=live_testing_vc(requests_mock),
            embed_validation_info=True,
            use_pades_lta=True,
        ),
        timestamper=DUMMY_TS,
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    assert r.total_revisions == 2
    # assert that the DSS was not updated in the timestamped revision
    dss_ref = r.root.get_value_as_reference('/DSS')
    changed_in = r.xrefs.get_last_change(dss_ref)
    assert changed_in == 0

    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LTA,
        validation_context_kwargs={
            'trust_roots': TRUST_ROOTS,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


@freeze_time('2020-11-01')
def test_pades_independent_tsa(requests_mock):
    # test signing/validation behaviour with an independent TSA

    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL_ONE_FIELD)))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            validation_context=live_testing_vc(
                requests_mock, with_extra_tsa=True
            ),
            embed_validation_info=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_HTTP_TS_VARIANT,
    )
    r = PdfFileReader(out)

    # DSS cardinalities
    dss_dict = r.root['/DSS']
    assert len(dss_dict['/CRLs']) == 2
    assert len(dss_dict['/OCSPs']) == 1
    assert len(dss_dict['/Certs']) == 6

    assert r.xrefs.total_revisions == 2

    trust_roots = TRUST_ROOTS + [UNRELATED_TSA.get_cert(CertLabel('root'))]
    validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LT,
        validation_context_kwargs={
            'trust_roots': trust_roots,
            'allow_fetching': False,
            'revocation_mode': 'soft-fail',
        },
    )


@freeze_time('2020-11-01')
def test_sign_with_policy():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        subfilter=fields.SigSeedSubFilter.PADES,
        cades_signed_attr_spec=CAdESSignedAttrSpec(
            signature_policy_identifier=SignaturePolicyIdentifier(
                {'signature_policy_id': DUMMY_POLICY_ID}
            )
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
def test_pades_revinfo_live_nofullchain():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=dummy_ocsp_vc(),
            subfilter=PADES,
            embed_validation_info=True,
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    r = PdfFileReader(out)
    rivt_pades = RevocationInfoValidationType.PADES_LT

    # with the same dumb settings, the timestamp doesn't validate at all,
    # which causes LTV validation to fail to bootstrap
    with pytest.raises(SignatureValidationError):
        validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            rivt_pades,
            {
                'trust_roots': TRUST_ROOTS,
                'ocsps': [FIXED_OCSP],
                'allow_fetching': False,
            },
        )

    # now set up live testing
    from requests_mock import Mocker

    with Mocker() as m:
        live_testing_vc(m)
        status = validate_pdf_ltv_signature(
            r.embedded_signatures[0],
            rivt_pades,
            {'trust_roots': TRUST_ROOTS, 'allow_fetching': True},
        )
        # .. which should still fail because the chain of trust is broken, but
        # at least the timestamp should initially validate
        assert status.valid and not status.trusted, status.summary()


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_pades_lta_no_embed_root(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    cr = SimpleCertificateStore()
    cr.register_multiple(FROM_CA.cert_registry)
    vc = live_testing_vc(requests_mock)
    no_embed_root_signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=cr,
        embed_roots=False,
    )
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            embed_validation_info=True,
            use_pades_lta=True,
            validation_context=vc,
        ),
        signer=no_embed_root_signer,
        timestamper=DUMMY_HTTP_TS,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/AP' not in s.sig_field
    # signer, intermediate, but not TSA (that one is supposed to be in the
    # TST) and of course no root
    assert len(s.signed_data['certificates']) == 2
    # signer, intermediate, TSA and OCSP responder
    assert len(r.root['/DSS']['/Certs']) == 4
    await async_validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        validation_type=RevocationInfoValidationType.PADES_LTA,
        validation_context_kwargs={'trust_roots': TRUST_ROOTS},
    )


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_pades_live_ac_presign_validation(requests_mock):
    # integration test for heavy-duty autofetching logic with ACs
    # NOTE: certificate autofetching is not tested due to lack of availability
    # in Illusionist (at the time of writing)

    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    authorities = [
        pki_arch.get_cert('root'),
        pki_arch.get_cert('interm'),
        pki_arch.get_cert('root-aa'),
        pki_arch.get_cert('interm-aa'),
        pki_arch.get_cert('leaf-aa'),
    ]
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(authorities),
        attribute_certs=[
            pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
        ],
    )
    dummy_ts = timestamps.DummyTimeStamper(
        tsa_cert=pki_arch.get_cert(CertLabel('tsa')),
        tsa_key=pki_arch.key_set.get_private_key(KeyLabel('tsa')),
        certs_to_embed=SimpleCertificateStore.from_certs(
            [pki_arch.get_cert('root')]
        ),
    )

    fetchers = RequestsFetcherBackend().get_fetchers()
    vc = ValidationContext(
        trust_roots=[pki_arch.get_cert('root')],
        allow_fetching=True,
        other_certs=authorities,
        fetchers=fetchers,
        revocation_mode='require',
    )
    ac_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert('root-aa')],
        allow_fetching=True,
        other_certs=authorities,
        fetchers=fetchers,
        revocation_mode='require',
    )
    Illusionist(pki_arch).register(requests_mock)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            validation_context=vc,
            ac_validation_context=ac_vc,
            subfilter=PADES,
            embed_validation_info=True,
            dss_settings=DSSContentSettings(
                include_vri=False,
                placement=SigDSSPlacementPreference.TOGETHER_WITH_SIGNATURE,
            ),
        ),
        signer=signer,
        timestamper=dummy_ts,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # 4 CA certs, 1 AA certs, 1 AC, 1 signer cert, 1 TSA cert,
    # 1 OCSP responder cert -> 9 certs total
    # 7 (4 CA + 1 AA + 1 AC + 1 signer) are in the CMS payload
    assert len(s.other_embedded_certs) == 5
    assert len(s.embedded_attr_certs) == 1
    dss = r.root['/DSS']
    assert len(dss['/Certs']) == 8  # no ACs here, but OCSP and TSA are present
    assert len(dss['/OCSPs']) == 2  # signer + AC (leaf-aa has OCSP)
    assert len(dss['/CRLs']) == 3  # root, interm-aa, root-aa
    status = await async_validate_pdf_ltv_signature(
        s,
        validation_type=RevocationInfoValidationType.PADES_LT,
        validation_context_kwargs={
            'trust_roots': [pki_arch.get_cert('root')],
            'revocation_mode': 'require',
        },
        ac_validation_context_kwargs={
            'trust_roots': [pki_arch.get_cert('root-aa')],
            'revocation_mode': 'require',
        },
    )
    assert status.bottom_line
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert len(status.ac_attrs) == 1
    assert role['role_name'].native == 'bigboss@example.com'


@pytest.mark.parametrize('with_force_revinfo', [True, False])
@pytest.mark.asyncio
async def test_pades_lta_live_ac_presign_validation(
    requests_mock, with_force_revinfo
):
    # Same as the above, but with LTA instead (+some time manipulation)

    with freeze_time('2020-11-01'):
        pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
        authorities = [
            pki_arch.get_cert('root'),
            pki_arch.get_cert('interm'),
            pki_arch.get_cert('root-aa'),
            pki_arch.get_cert('interm-aa'),
            pki_arch.get_cert('leaf-aa'),
        ]
        signer = signers.SimpleSigner(
            signing_cert=pki_arch.get_cert(CertLabel('signer1')),
            signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
            cert_registry=SimpleCertificateStore.from_certs(authorities),
            attribute_certs=[
                pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
            ],
        )
        dummy_ts = timestamps.DummyTimeStamper(
            tsa_cert=pki_arch.get_cert(CertLabel('tsa')),
            tsa_key=pki_arch.key_set.get_private_key(KeyLabel('tsa')),
            certs_to_embed=SimpleCertificateStore.from_certs(
                [pki_arch.get_cert('root')]
            ),
        )

        fetchers = RequestsFetcherBackend().get_fetchers()
        vc = ValidationContext(
            trust_roots=[pki_arch.get_cert('root')],
            allow_fetching=True,
            other_certs=authorities,
            fetchers=fetchers,
            revocation_mode='require',
        )
        ac_vc = ValidationContext(
            trust_roots=[pki_arch.get_cert('root-aa')],
            allow_fetching=True,
            other_certs=authorities,
            fetchers=fetchers,
            revocation_mode='require',
        )
        Illusionist(pki_arch).register(requests_mock)

        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                validation_context=vc,
                ac_validation_context=ac_vc,
                subfilter=PADES,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=signer,
            timestamper=dummy_ts,
            existing_fields_only=True,
        )

    revo_policy = CertRevTrustPolicy(
        RevocationCheckingPolicy(
            RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
            RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
        )
    )

    with freeze_time('2028-02-01'):
        r = PdfFileReader(out)
        s = r.embedded_signatures[0]
        vc_kwargs = {
            'trust_roots': [pki_arch.get_cert('root')],
        }
        ac_vc_kwargs = {
            'trust_roots': [pki_arch.get_cert('root-aa')],
        }
        if not with_force_revinfo:
            # supply parameters the usual way
            vc_kwargs['revinfo_policy'] = revo_policy
            ac_vc_kwargs['revinfo_policy'] = revo_policy
        status = await async_validate_pdf_ltv_signature(
            s,
            validation_type=RevocationInfoValidationType.PADES_LTA,
            validation_context_kwargs=vc_kwargs,
            ac_validation_context_kwargs=ac_vc_kwargs,
            force_revinfo=with_force_revinfo,
        )
        assert status.bottom_line
        roles = list(status.ac_attrs['role'].attr_values)
        role = roles[0]
        assert isinstance(role, cms.RoleSyntax)
        assert len(status.ac_attrs) == 1
        assert role['role_name'].native == 'bigboss@example.com'


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cades_signer_attrs_autofill_dss(requests_mock):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore(),  # no certs here on purpose
    )
    main_vc, ac_vc = live_ac_vcs(requests_mock, with_authorities=True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            embed_validation_info=True,
            validation_context=main_vc,
            ac_validation_context=ac_vc,
            cades_signed_attr_spec=CAdESSignedAttrSpec(
                commitment_type=CommitmentTypeIndication(
                    {
                        'commitment_type_id': 'proof_of_approval',
                    }
                ),
                signer_attributes=SignerAttrSpec(
                    claimed_attrs=[SAMPLE_GROUP_ATTR],
                    certified_attrs=[
                        pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
                    ],
                ),
            ),
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    # 4 CA certs, 1 AA certs, 1 signer cert, 1 OCSP responder cert -> 7 certs
    dss = r.root['/DSS']
    assert len(dss['/Certs']) == 7


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cades_signer_attrs_validate_acs(requests_mock):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [
                pki_arch.get_cert('root'),
                pki_arch.get_cert('interm'),
                pki_arch.get_cert('root-aa'),
                pki_arch.get_cert('interm-aa'),
                pki_arch.get_cert('leaf-aa'),
            ]
        ),
    )
    main_vc, ac_vc = live_ac_vcs(requests_mock, with_authorities=True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            embed_validation_info=True,
            validation_context=main_vc,
            ac_validation_context=ac_vc,
            cades_signed_attr_spec=CAdESSignedAttrSpec(
                commitment_type=CommitmentTypeIndication(
                    {
                        'commitment_type_id': 'proof_of_approval',
                    }
                ),
                signer_attributes=SignerAttrSpec(
                    claimed_attrs=[SAMPLE_GROUP_ATTR],
                    certified_attrs=[
                        pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
                    ],
                ),
            ),
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, ac_vc = live_ac_vcs(requests_mock)
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=ac_vc
    )
    assert status.bottom_line
    # this one was only 'claimed'
    assert 'group' not in status.ac_attrs
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'

    # also perform checks for the CAdES signer attrs info
    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert len(cades_signer_attrs.certified_attrs) == 1

    # claimed attrs
    assert 'role' not in cades_signer_attrs.claimed_attrs
    (all_values,) = iter(cades_signer_attrs.claimed_attrs)
    assert all_values == cades_signer_attrs.claimed_attrs['group']
    (groups_ietf_attr,) = iter(all_values.attr_values)
    assert isinstance(groups_ietf_attr, cms.IetfAttrSyntax)
    groups = groups_ietf_attr['values']
    assert set(groups.native) == {'Executives', 'Employees'}

    # certified attrs
    assert 'group' not in cades_signer_attrs.certified_attrs
    roles = list(cades_signer_attrs.certified_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'


@freeze_time('2020-11-01')
@pytest.mark.parametrize('pass_ac_vc', [True, False])
@pytest.mark.asyncio
async def test_cades_signer_attrs_claimed_only(requests_mock, pass_ac_vc):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            cades_signed_attr_spec=CAdESSignedAttrSpec(
                commitment_type=CommitmentTypeIndication(
                    {
                        'commitment_type_id': 'proof_of_approval',
                    }
                ),
                signer_attributes=SignerAttrSpec(
                    claimed_attrs=[SAMPLE_GROUP_ATTR], certified_attrs=()
                ),
            ),
        ),
        signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc = live_testing_vc(requests_mock)
    status = await async_validate_pdf_signature(
        s,
        signer_validation_context=main_vc,
        # what the VC contains shouldn't matter, since there are no ACs to
        # validate
        ac_validation_context=(main_vc if pass_ac_vc else None),
    )
    assert status.bottom_line
    assert not status.ac_attrs
    if not pass_ac_vc:
        assert status.ac_attrs is None

    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert not cades_signer_attrs.certified_attrs
    if not pass_ac_vc:
        assert cades_signer_attrs.certified_attrs is None

    # claimed attrs
    (groups_ietf_attr,) = iter(
        cades_signer_attrs.claimed_attrs['group'].attr_values
    )
    assert isinstance(groups_ietf_attr, cms.IetfAttrSyntax)
    groups = groups_ietf_attr['values']
    assert set(groups.native) == {'Executives', 'Employees'}


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cades_signer_attrs_validate_acs_no_claimed(requests_mock):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [
                pki_arch.get_cert('root'),
                pki_arch.get_cert('interm'),
                pki_arch.get_cert('root-aa'),
                pki_arch.get_cert('interm-aa'),
                pki_arch.get_cert('leaf-aa'),
            ]
        ),
    )
    main_vc, ac_vc = live_ac_vcs(requests_mock, with_authorities=True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            embed_validation_info=True,
            validation_context=main_vc,
            ac_validation_context=ac_vc,
            cades_signed_attr_spec=CAdESSignedAttrSpec(
                signer_attributes=SignerAttrSpec(
                    claimed_attrs=(),
                    certified_attrs=[
                        pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
                    ],
                )
            ),
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, ac_vc = live_ac_vcs(requests_mock)
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=ac_vc
    )
    assert status.bottom_line
    assert 'CERTIFIED_SIGNER_ATTRS_INVALID' not in status.summary()
    # this one was only 'claimed'
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'

    # also perform checks for the CAdES signer attrs info
    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert not cades_signer_attrs.claimed_attrs
    assert len(cades_signer_attrs.certified_attrs) == 1

    roles = list(cades_signer_attrs.certified_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'
    assert not cades_signer_attrs.unknown_attrs_present


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cades_signer_attrs_validate_acs_wrong_vc(requests_mock):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [
                pki_arch.get_cert('root'),
                pki_arch.get_cert('interm'),
                pki_arch.get_cert('root-aa'),
                pki_arch.get_cert('interm-aa'),
                pki_arch.get_cert('leaf-aa'),
            ]
        ),
    )
    main_vc, ac_vc = live_ac_vcs(requests_mock, with_authorities=True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            embed_validation_info=True,
            validation_context=main_vc,
            ac_validation_context=ac_vc,
            cades_signed_attr_spec=CAdESSignedAttrSpec(
                commitment_type=CommitmentTypeIndication(
                    {
                        'commitment_type_id': 'proof_of_approval',
                    }
                ),
                signer_attributes=SignerAttrSpec(
                    claimed_attrs=[SAMPLE_GROUP_ATTR],
                    certified_attrs=[
                        pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
                    ],
                ),
            ),
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, ac_vc = live_ac_vcs(requests_mock)

    # validate with the wrong AC VC
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=main_vc
    )

    assert not status.cades_signer_attrs.valid
    assert 'CERTIFIED_SIGNER_ATTRS_INVALID' in status.summary()

    assert len(status.ac_attrs) == 0

    # also perform checks for the CAdES signer attrs info
    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert len(cades_signer_attrs.certified_attrs) == 0
    assert len(status.ac_validation_errs) == 1
    assert len(cades_signer_attrs.ac_validation_errs) == 1
    assert not cades_signer_attrs.unknown_attrs_present


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cades_signer_attrs_validate_acs_missing_vc(requests_mock):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [
                pki_arch.get_cert('root'),
                pki_arch.get_cert('interm'),
                pki_arch.get_cert('root-aa'),
                pki_arch.get_cert('interm-aa'),
                pki_arch.get_cert('leaf-aa'),
            ]
        ),
    )
    main_vc, ac_vc = live_ac_vcs(requests_mock, with_authorities=True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
            embed_validation_info=True,
            validation_context=main_vc,
            ac_validation_context=ac_vc,
            cades_signed_attr_spec=CAdESSignedAttrSpec(
                commitment_type=CommitmentTypeIndication(
                    {
                        'commitment_type_id': 'proof_of_approval',
                    }
                ),
                signer_attributes=SignerAttrSpec(
                    claimed_attrs=[SAMPLE_GROUP_ATTR],
                    certified_attrs=[
                        pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
                    ],
                ),
            ),
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, _ = live_ac_vcs(requests_mock)

    # validate with the wrong AC VC
    status = await async_validate_pdf_signature(
        s,
        signer_validation_context=main_vc,
    )

    # this should _not_ fail validation, since we've indicated that we don't
    # care about ACs
    assert status.bottom_line
    assert 'CERTIFIED_SIGNER_ATTRS_INVALID' not in status.summary()
    assert status.ac_attrs is None

    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert cades_signer_attrs.certified_attrs is None
    assert status.ac_validation_errs is None
    assert cades_signer_attrs.ac_validation_errs is None


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'as_signed_assertions,pass_ac_vc',
    [(True, True), (True, False), (False, True), (False, False)],
)
@pytest.mark.asyncio
async def test_cades_signer_attrs_unknown_attrs(
    requests_mock, as_signed_assertions, pass_ac_vc
):
    class CustomAttrProvider(CMSAttributeProvider):
        attribute_type = 'signer_attributes_v2'

        async def build_attr_value(self, dry_run=False):
            signer_attrs = {
                'claimed_attributes': [SAMPLE_GROUP_ATTR],
            }
            value = core.OctetString(b'\xde\xad\xbe\xef')
            if as_signed_assertions:
                signer_attrs['signed_assertions'] = [
                    SignedAssertion(
                        {
                            'signed_assertion_id': '2.999',
                            'signed_assertion': value,
                        }
                    )
                ]
            else:
                signer_attrs['certified_attributes_v2'] = [
                    CertifiedAttributeChoices(
                        name='other_attr_cert',
                        value={
                            'other_attr_cert_id': '2.999',
                            'other_attr_cert': value,
                        },
                    )
                ]
            return SignerAttributesV2(signer_attrs)

    class CustomSigner(signers.SimpleSigner):
        def _signed_attr_providers(self, *args, **kwargs):
            yield from super()._signed_attr_providers(*args, **kwargs)
            yield CustomAttrProvider()

    signer = CustomSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc = live_testing_vc(requests_mock)
    status = await async_validate_pdf_signature(
        s,
        signer_validation_context=main_vc,
        # what the VC contains shouldn't matter, since there are no ACs to
        # validate
        ac_validation_context=(main_vc if pass_ac_vc else None),
    )
    # bottom line is unaffected
    assert status.bottom_line
    assert not status.ac_attrs
    if not pass_ac_vc:
        assert status.ac_attrs is None

    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    # check for unknown_attrs_present
    assert cades_signer_attrs.unknown_attrs_present
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert not cades_signer_attrs.certified_attrs
    if not pass_ac_vc:
        assert cades_signer_attrs.certified_attrs is None

    # claimed attrs should still be OK
    (groups_ietf_attr,) = iter(
        cades_signer_attrs.claimed_attrs['group'].attr_values
    )
    assert isinstance(groups_ietf_attr, cms.IetfAttrSyntax)
    groups = groups_ietf_attr['values']
    assert set(groups.native) == {'Executives', 'Employees'}


@freeze_time('2020-11-01')
@pytest.mark.parametrize('pass_ac_vc', [True, False])
@pytest.mark.asyncio
async def test_cades_signer_attrs_multivalued(requests_mock, pass_ac_vc):
    class CustomSigner(signers.SimpleSigner):
        async def signed_attrs(self, *args, **kwargs):
            signed_attrs = await super().signed_attrs(*args, **kwargs)
            signer_attrs = {
                'claimed_attributes': [SAMPLE_GROUP_ATTR],
            }
            attr = SignerAttributesV2(signer_attrs)
            signed_attrs.append(
                cms.CMSAttribute(
                    {'type': 'signer_attributes_v2', 'values': [attr, attr]}
                )
            )
            return signed_attrs

    signer = CustomSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            subfilter=PADES,
        ),
        signer=signer,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc = live_testing_vc(requests_mock)
    with pytest.raises(SignatureValidationError, match='Expected single'):
        await async_validate_pdf_signature(
            s,
            signer_validation_context=main_vc,
            # what the VC contains shouldn't matter, since there are no ACs to
            # validate
            ac_validation_context=(main_vc if pass_ac_vc else None),
        )


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_interrupted_nonstrict_with_psi():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_SLIGHTLY_BROKEN), strict=False)
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='SigNew',
            subfilter=PADES,
            embed_validation_info=True,
            validation_context=SIMPLE_V_CONTEXT(),
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    prep_digest, tbs_document, output = (
        await pdf_signer.async_digest_doc_for_signing(w)
    )
    md_algorithm = tbs_document.md_algorithm
    assert tbs_document.post_sign_instructions is not None

    await PdfTBSDocument.async_finish_signing(
        output,
        prep_digest,
        await FROM_CA.async_sign(
            prep_digest.document_digest,
            digest_algorithm=md_algorithm,
        ),
        post_sign_instr=tbs_document.post_sign_instructions,
    )

    r = PdfFileReader(output, strict=False)
    await async_val_trusted(r.embedded_signatures[0], extd=True)
