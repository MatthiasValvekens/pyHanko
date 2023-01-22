import datetime
from io import BytesIO

import pytest
from asn1crypto import cms
from freezegun import freeze_time
from pyhanko_certvalidator import policy_decl as certv_policy_decl
from pyhanko_certvalidator.authority import CertTrustAnchor
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import FreshnessReqType
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_certvalidator.validate import async_validate_path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfTimeStamper, signers
from pyhanko.sign.ades.api import CAdESSignedAttrSpec
from pyhanko.sign.ades.report import AdESFailure, AdESIndeterminate, AdESPassed
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
from pyhanko.sign.validation import ades
from pyhanko.sign.validation.policy_decl import SignatureValidationSpec
from pyhanko_tests.samples import MINIMAL_ONE_FIELD
from pyhanko_tests.signing_commons import (
    DUMMY_TS,
    DUMMY_TS2,
    FROM_CA,
    INTERM_CERT,
    REVOKED_SIGNER,
    TRUST_ROOTS,
    live_testing_vc,
)
from pyhanko_tests.test_pades import PADES


async def _generate_pades_test_doc(requests_mock, **kwargs):
    kwargs.setdefault('use_pades_lta', True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)
    return await signers.async_sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', validation_context=vc,
            subfilter=PADES, embed_validation_info=True,
            **kwargs,
        ), signer=FROM_CA, timestamper=DUMMY_TS
    )


async def _update_pades_test_doc(requests_mock, out):
    r = PdfFileReader(out)

    vc = live_testing_vc(requests_mock)
    await PdfTimeStamper(DUMMY_TS2).async_update_archival_timestamp_chain(r, vc)


DEFAULT_VALIDATION_SPEC = SignatureValidationSpec(
    cert_validation_policy=CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
        revinfo_policy=certv_policy_decl.CertRevTrustPolicy(
            revocation_checking_policy=certv_policy_decl.REQUIRE_REVINFO,
            freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION
        )
    )
)


@pytest.mark.asyncio
async def test_pades_basic_happy_path(requests_mock):
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1',
                subfilter=PADES
            ), signer=FROM_CA, timestamper=DUMMY_TS
        )

    with freeze_time('2020-11-25'):
        r = PdfFileReader(out)
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            r.embedded_signatures[0].signed_data,
            validation_spec=DEFAULT_VALIDATION_SPEC,
            raw_digest=r.embedded_signatures[0].compute_digest()
        )
        assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
async def test_embedded_cades_happy_path(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await FROM_CA.async_sign_general_data(
            b'Hello world!', 'sha256', detached=False,
            use_cades=True
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-11-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            signature['content'],
            validation_spec=DEFAULT_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
async def test_embedded_cades_with_time_happy_path(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await FROM_CA.async_sign_general_data(
            b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
            use_cades=True
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-11-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_with_time_validation(
            signature['content'],
            validation_spec=DEFAULT_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 1, tzinfo=datetime.timezone.utc
        )


@pytest.mark.asyncio
async def test_embedded_cades_provably_revoked(requests_mock):
    with freeze_time('2020-12-10'):
        signature = await REVOKED_SIGNER.async_sign_general_data(
            b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
            use_cades=True, signed_attr_settings=PdfCMSSignedAttributes(
                cades_signed_attrs=CAdESSignedAttrSpec(timestamp_content=True)
            )
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-12-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            signature['content'],
            validation_spec=DEFAULT_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESFailure.REVOKED


@pytest.mark.asyncio
async def test_embedded_cades_revoked_no_poe(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await REVOKED_SIGNER.async_sign_general_data(
            b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
            use_cades=True, signed_attr_settings=PdfCMSSignedAttributes(
                cades_signed_attrs=CAdESSignedAttrSpec(timestamp_content=False)
            )
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-12-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            signature['content'],
            validation_spec=DEFAULT_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESIndeterminate.REVOKED_NO_POE


@pytest.mark.asyncio
async def test_embedded_cades_pre_revoke_with_poe(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await REVOKED_SIGNER.async_sign_general_data(
            b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
            use_cades=True,
        )
        signature = cms.ContentInfo.load(signature.dump())
        vc = live_testing_vc(requests_mock)

        await async_validate_path(
            vc, ValidationPath(
                trust_anchor=CertTrustAnchor(TRUST_ROOTS[0]),
                interm=[INTERM_CERT],
                leaf=REVOKED_SIGNER.signing_cert,
            )
        )

    with freeze_time('2020-12-25'):
        result = await ades.ades_with_time_validation(
            signature['content'],
            validation_spec=DEFAULT_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 1, tzinfo=datetime.timezone.utc
        )


@pytest.mark.asyncio
@freeze_time('2020-11-20')
async def test_pades_lta_happy_path_current_time(requests_mock):
    out = await _generate_pades_test_doc(requests_mock)
    r = PdfFileReader(out)
    result = await ades.ades_lta_validation(
        r.embedded_signatures[0], validation_spec=DEFAULT_VALIDATION_SPEC
    )
    assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
async def test_pades_lta_happy_path_past_time(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(requests_mock)

    with freeze_time('2021-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0], validation_spec=DEFAULT_VALIDATION_SPEC
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 20, tzinfo=datetime.timezone.utc
        )


@pytest.mark.asyncio
@pytest.mark.parametrize('with_dts', [True, False])
async def test_pades_lta_expired_timestamp(requests_mock, with_dts):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(requests_mock, use_pades_lta=with_dts)

    with freeze_time('2080-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0], validation_spec=DEFAULT_VALIDATION_SPEC
        )
        assert result.ades_subindic == AdESIndeterminate.NO_POE


@pytest.mark.asyncio
async def test_pades_lta_happy_path_past_time_with_chain(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(requests_mock)

    with freeze_time('2028-11-20'):
        await _update_pades_test_doc(requests_mock, out)

    with freeze_time('2035-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0], validation_spec=DEFAULT_VALIDATION_SPEC
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 20, tzinfo=datetime.timezone.utc
        )
