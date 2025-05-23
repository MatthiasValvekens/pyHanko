import datetime
from io import BytesIO
from typing import Optional

import pytest
import tzlocal
from asn1crypto import algos, cms, keys, ocsp
from asn1crypto.pdf import RevocationInfoArchival
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    EntityLabel,
    KeyLabel,
    ServiceLabel,
)
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfTimeStamper, signers, timestamps
from pyhanko.sign.ades.api import CAdESSignedAttrSpec
from pyhanko.sign.ades.report import (
    AdESFailure,
    AdESIndeterminate,
    AdESPassed,
    AdESStatus,
)
from pyhanko.sign.signers.pdf_cms import (
    GenericPdfSignedAttributeProviderSpec,
    PdfCMSSignedAttributes,
    SimpleSigner,
)
from pyhanko.sign.validation import SignatureCoverageLevel, ades
from pyhanko.sign.validation.policy_decl import (
    LocalKnowledge,
    PdfSignatureValidationSpec,
    SignatureValidationSpec,
)

from pyhanko_certvalidator import policy_decl as certv_policy_decl
from pyhanko_certvalidator.authority import CertTrustAnchor
from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
    ValidationContext,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)
from pyhanko_certvalidator.ltv.poe import (
    KnownPOE,
    POEType,
    ValidationObject,
    ValidationObjectType,
    digest_for_poe,
)
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    AlgorithmUsageConstraint,
    AlgorithmUsagePolicy,
    FreshnessReqType,
)
from pyhanko_certvalidator.registry import (
    SimpleCertificateStore,
    SimpleTrustManager,
)
from pyhanko_certvalidator.validate import async_validate_path

from .samples import (
    CERTOMANCER,
    MINIMAL_ONE_FIELD,
    TESTING_CA,
    UNRELATED_TSA,
)
from .signing_commons import (
    DUMMY_HTTP_TS_VARIANT,
    DUMMY_TS,
    DUMMY_TS2,
    FROM_CA,
    INTERM_CERT,
    REVOKED_SIGNER,
    TRUST_ROOTS,
    TSA_CERT,
    live_testing_vc,
)
from .test_pades import PADES


async def _generate_pades_test_doc(requests_mock, signer=FROM_CA, **kwargs):
    kwargs.setdefault('use_pades_lta', True)
    kwargs.setdefault('embed_validation_info', True)
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock)

    timestamper = timestamps.DummyTimeStamper(
        tsa_cert=TSA_CERT,
        tsa_key=TESTING_CA.key_set.get_private_key('tsa'),
        certs_to_embed=FROM_CA.cert_registry,
        override_md='sha256',
    )
    return await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=PADES,
            **kwargs,
        ),
        signer=signer,
        timestamper=timestamper,
    )


async def _update_pades_test_doc(requests_mock, out):
    r = PdfFileReader(out)

    vc = live_testing_vc(requests_mock)
    await PdfTimeStamper(DUMMY_TS2).async_update_archival_timestamp_chain(r, vc)


DEFAULT_REVINFO_POLICY = certv_policy_decl.CertRevTrustPolicy(
    revocation_checking_policy=certv_policy_decl.REQUIRE_REVINFO,
    freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
)
DEFAULT_SIG_VALIDATION_SPEC = SignatureValidationSpec(
    cert_validation_policy=CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
        revinfo_policy=DEFAULT_REVINFO_POLICY,
    )
)
DEFAULT_PDF_VALIDATION_SPEC = PdfSignatureValidationSpec(
    signature_validation_spec=DEFAULT_SIG_VALIDATION_SPEC
)


@pytest.mark.asyncio
async def test_pades_basic_happy_path(requests_mock):
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )

    with freeze_time('2020-11-25'):
        r = PdfFileReader(out)
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            r.embedded_signatures[0].signed_data,
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
            raw_digest=r.embedded_signatures[0].compute_digest(),
        )
        assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
async def test_embedded_cades_happy_path(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await FROM_CA.async_sign_general_data(
            b'Hello world!', 'sha256', detached=False, use_cades=True
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-11-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            signature['content'],
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
async def test_embedded_cades_with_time_happy_path(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await FROM_CA.async_sign_general_data(
            b'Hello world!',
            'sha256',
            detached=False,
            timestamper=DUMMY_TS,
            use_cades=True,
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-11-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_with_time_validation(
            signature['content'],
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 1, tzinfo=datetime.timezone.utc
        )


@pytest.mark.asyncio
async def test_embedded_cades_provably_revoked(requests_mock):
    with freeze_time('2020-12-10'):
        signature = await REVOKED_SIGNER.async_sign_general_data(
            b'Hello world!',
            'sha256',
            detached=False,
            timestamper=DUMMY_TS,
            use_cades=True,
            signed_attr_settings=PdfCMSSignedAttributes(
                cades_signed_attrs=CAdESSignedAttrSpec(timestamp_content=True)
            ),
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-12-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            signature['content'],
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESFailure.REVOKED


@pytest.mark.asyncio
async def test_embedded_cades_revoked_no_poe(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await REVOKED_SIGNER.async_sign_general_data(
            b'Hello world!',
            'sha256',
            detached=False,
            timestamper=DUMMY_TS,
            use_cades=True,
            signed_attr_settings=PdfCMSSignedAttributes(
                cades_signed_attrs=CAdESSignedAttrSpec(timestamp_content=False)
            ),
        )
        signature = cms.ContentInfo.load(signature.dump())

    with freeze_time('2020-12-25'):
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            signature['content'],
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESIndeterminate.REVOKED_NO_POE


@pytest.mark.asyncio
async def test_embedded_cades_pre_revoke_with_poe(requests_mock):
    with freeze_time('2020-11-01'):
        signature = await REVOKED_SIGNER.async_sign_general_data(
            b'Hello world!',
            'sha256',
            detached=False,
            timestamper=DUMMY_TS,
            use_cades=True,
        )
        signature = cms.ContentInfo.load(signature.dump())
        vc = live_testing_vc(requests_mock)

        await async_validate_path(
            vc,
            ValidationPath(
                trust_anchor=CertTrustAnchor(TRUST_ROOTS[0]),
                interm=[INTERM_CERT],
                leaf=REVOKED_SIGNER.signing_cert,
            ),
        )

    with freeze_time('2020-12-25'):
        result = await ades.ades_with_time_validation(
            signature['content'],
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
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
        r.embedded_signatures[0],
        pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
    )
    assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
async def test_pades_lta_happy_path_past_time(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(requests_mock)

    with freeze_time('2021-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 20, tzinfo=datetime.timezone.utc
        )


@pytest.mark.asyncio
@pytest.mark.parametrize('with_lta', [True, False])
@freeze_time('2020-11-20')
async def test_simulate_future_lta_happy_path(requests_mock, with_lta):
    # it shouldn't matter for the purposes of this function whether the initial
    # signature is followed by a DTS or not, so we test both
    out = await _generate_pades_test_doc(requests_mock, use_pades_lta=with_lta)

    r = PdfFileReader(out)
    result = await ades.simulate_future_ades_lta_validation(
        r.embedded_signatures[0],
        pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
        future_validation_time=datetime.datetime(
            2030, 11, 20, tzinfo=datetime.timezone.utc
        ),
    )
    assert result.ades_subindic == AdESPassed.OK
    assert result.best_signature_time == datetime.datetime(
        2020, 11, 20, tzinfo=datetime.timezone.utc
    )


@pytest.mark.asyncio
async def test_simulate_future_lta_happy_path_with_ts_chain(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(requests_mock)

    with freeze_time('2028-11-20'):
        await _update_pades_test_doc(requests_mock, out)

        r = PdfFileReader(out)
        result = await ades.simulate_future_ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
            future_validation_time=datetime.datetime(
                2050, 11, 20, tzinfo=datetime.timezone.utc
            ),
        )
    assert result.ades_subindic == AdESPassed.OK
    assert result.best_signature_time == datetime.datetime(
        2020, 11, 20, tzinfo=datetime.timezone.utc
    )


@pytest.mark.asyncio
@freeze_time('2020-11-20')
async def test_simulate_future_lta_no_revinfo_fail(requests_mock):
    out = await _generate_pades_test_doc(
        requests_mock, embed_validation_info=False
    )
    r = PdfFileReader(out)
    result = await ades.simulate_future_ades_lta_validation(
        r.embedded_signatures[0],
        pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
        future_validation_time=datetime.datetime(
            2030, 11, 20, tzinfo=datetime.timezone.utc
        ),
    )
    assert result.ades_subindic.status == AdESStatus.INDETERMINATE


@pytest.mark.asyncio
async def test_simulate_future_lta_with_broken_ts_chain(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(requests_mock)

    # gap too large
    with freeze_time('2031-11-20'):
        w = IncrementalPdfFileWriter(out)
        vc = live_testing_vc(requests_mock)
        await PdfTimeStamper(DUMMY_TS2).async_timestamp_pdf(
            w, md_algorithm='sha256', validation_context=vc, in_place=True
        )

        r = PdfFileReader(out)
        result = await ades.simulate_future_ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
            future_validation_time=datetime.datetime(
                2050, 11, 20, tzinfo=datetime.timezone.utc
            ),
        )
    assert result.ades_subindic == AdESIndeterminate.OUT_OF_BOUNDS_NO_POE


@pytest.mark.asyncio
@pytest.mark.parametrize('with_dts', [True, False])
async def test_pades_lta_expired_timestamp(requests_mock, with_dts):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(
            requests_mock, use_pades_lta=with_dts
        )

    with freeze_time('2080-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
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
            r.embedded_signatures[0],
            pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 20, tzinfo=datetime.timezone.utc
        )


class NoSha512AfterSomeTime(AlgorithmUsagePolicy):
    # Algo policy for tests

    def __init__(self, year):
        self.cutoff = datetime.datetime(
            year, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc
        )

    def signature_algorithm_allowed(
        self,
        algo: algos.SignedDigestAlgorithm,
        moment: Optional[datetime.datetime],
        public_key: Optional[keys.PublicKeyInfo],
    ) -> AlgorithmUsageConstraint:
        try:
            h = algo.hash_algo
        except ValueError:
            h = None

        if h == 'sha512':
            if moment is None or moment > self.cutoff:
                return AlgorithmUsageConstraint(
                    allowed=False,
                    not_allowed_after=self.cutoff,
                    failure_reason='just because',
                )
        return AlgorithmUsageConstraint(allowed=True)

    def digest_algorithm_allowed(
        self, algo: algos.DigestAlgorithm, moment: Optional[datetime.datetime]
    ) -> AlgorithmUsageConstraint:
        if algo['algorithm'].native == 'sha512':
            if moment is None or moment > self.cutoff:
                return AlgorithmUsageConstraint(
                    allowed=False,
                    not_allowed_after=self.cutoff,
                    failure_reason='just because',
                )
        return AlgorithmUsageConstraint(allowed=True)


class BanAllTheThings(AlgorithmUsagePolicy):
    def signature_algorithm_allowed(
        self,
        algo: algos.SignedDigestAlgorithm,
        moment: Optional[datetime.datetime],
        public_key: Optional[keys.PublicKeyInfo],
    ) -> AlgorithmUsageConstraint:
        return AlgorithmUsageConstraint(allowed=False)

    def digest_algorithm_allowed(
        self, algo: algos.DigestAlgorithm, moment: Optional[datetime.datetime]
    ) -> AlgorithmUsageConstraint:
        return AlgorithmUsageConstraint(allowed=False)


def _assert_certs_known(certs):
    return [
        KnownPOE(
            digest=digest_for_poe(cert.dump()),
            poe_time=cert.not_valid_before,
            poe_type=POEType.PROVIDED,
            validation_object=ValidationObject(
                object_type=ValidationObjectType.CERTIFICATE,
                value=cert,
            ),
        )
        for cert in certs
    ]


@pytest.mark.parametrize('place', ['in_sig', 'in_cert', 'both'])
@pytest.mark.asyncio
async def test_pades_hash_algorithm_banned_but_poe_ok(requests_mock, place):
    md_algorithm = 'sha256'
    signer = FROM_CA
    if place == 'in_sig' or place == 'both':
        md_algorithm = 'sha512'
    if place == 'in_cert' or place == 'both':
        store = SimpleCertificateStore().from_certs(FROM_CA.cert_registry)
        signer = SimpleSigner(
            signing_cert=TESTING_CA.get_cert('signer1-sha512'),
            signing_key=FROM_CA.signing_key,
            cert_registry=store,
        )
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(
            requests_mock, md_algorithm=md_algorithm, signer=signer
        )

    with freeze_time('2029-11-20'):
        revinfo_policy = (
            DEFAULT_SIG_VALIDATION_SPEC.cert_validation_policy.revinfo_policy
        )
        spec = SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
                algorithm_usage_policy=NoSha512AfterSomeTime(2025),
                revinfo_policy=revinfo_policy,
            ),
            local_knowledge=LocalKnowledge(
                known_poes=_assert_certs_known(FROM_CA.cert_registry)
            ),
        )
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=PdfSignatureValidationSpec(spec),
        )
        assert result.ades_subindic == AdESPassed.OK


@pytest.mark.parametrize(
    'place',
    ['in_sig', 'in_cert', 'both'],
)
@pytest.mark.asyncio
async def test_pades_lta_hash_algorithm_banned_and_no_poe(requests_mock, place):
    md_algorithm = 'sha256'
    signer = FROM_CA
    if place == 'in_sig' or place == 'both':
        md_algorithm = 'sha512'
    if place == 'in_cert' or place == 'both':
        # disable docts so we don't have PoE for the certs
        store = SimpleCertificateStore().from_certs(FROM_CA.cert_registry)
        signer = SimpleSigner(
            signing_cert=TESTING_CA.get_cert('signer1-sha512'),
            signing_key=FROM_CA.signing_key,
            cert_registry=store,
        )
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(
            requests_mock, md_algorithm=md_algorithm, signer=signer
        )

    with freeze_time('2029-11-20'):
        revinfo_policy = (
            DEFAULT_SIG_VALIDATION_SPEC.cert_validation_policy.revinfo_policy
        )
        spec = SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
                algorithm_usage_policy=NoSha512AfterSomeTime(2019),
                revinfo_policy=revinfo_policy,
            ),
            local_knowledge=LocalKnowledge(
                known_poes=_assert_certs_known(FROM_CA.cert_registry)
            ),
        )
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=PdfSignatureValidationSpec(spec),
        )
        assert (
            result.ades_subindic
            == AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE_NO_POE
        )


@pytest.mark.asyncio
async def test_pades_lta_algo_permaban(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _generate_pades_test_doc(
            requests_mock, md_algorithm='sha512'
        )

    with freeze_time('2029-11-20'):
        revinfo_policy = (
            DEFAULT_SIG_VALIDATION_SPEC.cert_validation_policy.revinfo_policy
        )
        spec = SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
                algorithm_usage_policy=BanAllTheThings(),
                revinfo_policy=revinfo_policy,
            )
        )
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=PdfSignatureValidationSpec(spec),
        )
        assert (
            result.ades_subindic == AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE
        )


@pytest.mark.asyncio
async def test_pades_lta_live_ac_validation(requests_mock):
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

    revinfo_policy = certv_policy_decl.CertRevTrustPolicy(
        revocation_checking_policy=certv_policy_decl.REQUIRE_REVINFO,
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    sig_validation_spec = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build([pki_arch.get_cert('root')]),
            revinfo_policy=revinfo_policy,
        ),
        ac_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(
                [pki_arch.get_cert('root-aa')]
            ),
            revinfo_policy=revinfo_policy,
        ),
    )
    with freeze_time('2028-02-01'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=PdfSignatureValidationSpec(sig_validation_spec),
        )
        assert result.ades_subindic == AdESPassed.OK

        roles = list(result.api_status.ac_attrs['role'].attr_values)
        role = roles[0]
        assert isinstance(role, cms.RoleSyntax)
        assert len(result.api_status.ac_attrs) == 1
        assert role['role_name'].native == 'bigboss@example.com'


async def _nontraditional_hybrid_lta_doc(requests_mock):
    # this document reproduces the situation of #228:
    #  - No DSS or DTSes
    #  - declared PAdES (/ETSI.CAdES.detached)
    #  - short-lived leaf cert (=> expired by validation time)
    #  - Leaf cert OCSP response in Adobe revinfo archival
    #  - Revinfo for intermediate cert must be fetched
    #  - Different TS root.
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    vc = live_testing_vc(requests_mock, with_extra_tsa=True)

    custom_signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
    )
    cert_id = ocsp.CertId(
        {
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'issuer_name_hash': TESTING_CA.entities.get_name_hash(
                EntityLabel('interm'), 'sha256'
            ),
            'issuer_key_hash': INTERM_CERT.public_key.sha256,
            'serial_number': FROM_CA.signing_cert.serial_number,
        }
    )
    responder = TESTING_CA.service_registry.summon_responder(
        ServiceLabel('interm'),
        at_time=datetime.datetime.now(tz=tzlocal.get_localzone()),
    )
    ocsp_response = responder.assemble_simple_ocsp_responses(
        [responder.format_single_ocsp_response(cert_id, INTERM_CERT)]
    )
    custom_signer.signed_attr_prov_spec = GenericPdfSignedAttributeProviderSpec(
        attr_settings=PdfCMSSignedAttributes(
            adobe_revinfo_attr=RevocationInfoArchival({'ocsp': [ocsp_response]})
        ),
        signing_cert=custom_signer.signing_cert,
        signature_mechanism=custom_signer.signature_mechanism,
        timestamper=None,
    )

    timestamper = DUMMY_HTTP_TS_VARIANT
    out = await signers.async_sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=PADES,
            embed_validation_info=False,  # done manually
        ),
        signer=custom_signer,
        timestamper=timestamper,
    )
    r = PdfFileReader(out)
    assert len(r.embedded_signatures) == 1
    assert '/DSS' not in r.root
    return out


@pytest.mark.asyncio
async def test_nontraditional_hybrid_lta(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _nontraditional_hybrid_lta_doc(requests_mock)

    modified_policy = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(
                TRUST_ROOTS + [UNRELATED_TSA.get_cert('root')]
            ),
            revinfo_policy=DEFAULT_REVINFO_POLICY,
        )
    )
    with freeze_time('2022-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=PdfSignatureValidationSpec(modified_policy),
        )
        assert result.ades_subindic == AdESPassed.OK
        assert result.api_status.bottom_line
        assert result.api_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert result.best_signature_time == datetime.datetime(
            2020, 11, 20, tzinfo=datetime.timezone.utc
        )


@pytest.mark.asyncio
async def test_nontraditional_hybrid_lta_with_failed_timestamp(requests_mock):
    with freeze_time('2020-11-20'):
        out = await _nontraditional_hybrid_lta_doc(requests_mock)

    with freeze_time('2022-11-20'):
        r = PdfFileReader(out)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
        )
        # since we assert that time stamp tokens must be valid, the
        # spec requires us to return the TS validation result
        assert (
            result.ades_subindic == AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND
        )
        assert not result.api_status.bottom_line
        assert result.api_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert result.best_signature_time == datetime.datetime(
            2022, 11, 20, tzinfo=datetime.timezone.utc
        )
