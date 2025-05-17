from io import BytesIO

import pytest
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import ArchLabel, CertLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.ades.api import CAdESSignedAttrSpec, SignerAttrSpec
from pyhanko.sign.ades.cades_asn1 import (
    CommitmentTypeIndication,
    SignaturePolicyIdentifier,
)
from pyhanko.sign.validation import ades
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    SignatureValidationSpec,
)

from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.registry import (
    SimpleCertificateStore,
    SimpleTrustManager,
)

from .samples import CERTOMANCER, MINIMAL_ONE_FIELD, SAMPLE_GROUP_ATTR
from .signing_commons import (
    DUMMY_POLICY_ID,
    DUMMY_TS,
    FROM_CA,
    FROM_ECC_CA,
    live_testing_vc,
)
from .test_ades_validation import DEFAULT_SIG_VALIDATION_SPEC
from .test_pades import PADES


async def _generate_basic_report(requests_mock, out):
    with freeze_time('2020-11-25'):
        r = PdfFileReader(out)
        live_testing_vc(requests_mock)
        result = await ades.ades_basic_validation(
            r.embedded_signatures[0].signed_data,
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
            raw_digest=r.embedded_signatures[0].compute_digest(),
        )
        from pyhanko.sign.validation.report.tools import generate_report

        return generate_report(r.embedded_signatures[0], result)


@pytest.mark.asyncio
async def test_pades_basic_report_smoke_test(requests_mock):
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )
    report = await _generate_basic_report(requests_mock, out)
    assert 'urn:etsi:019102:mainindication:total-passed' in report


@pytest.mark.asyncio
async def test_pades_basic_failing_report_smoke_test(requests_mock):
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )
        out.seek(10)
        out.write(b'@')

    report = await _generate_basic_report(requests_mock, out)
    assert 'urn:etsi:019102:mainindication:total-failed' in report


@pytest.mark.asyncio
async def test_pades_basic_indeteriminate_report_smoke_test(requests_mock):
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Sig1', subfilter=PADES),
            signer=FROM_ECC_CA,
            timestamper=DUMMY_TS,
        )

    report = await _generate_basic_report(requests_mock, out)
    assert 'urn:etsi:019102:mainindication:indeterminate' in report


async def _generate_lta_report(
    requests_mock, out, policy=DEFAULT_SIG_VALIDATION_SPEC
):
    with freeze_time('2028-11-25'):
        r = PdfFileReader(out)
        live_testing_vc(requests_mock)
        result = await ades.ades_lta_validation(
            r.embedded_signatures[0],
            pdf_validation_spec=PdfSignatureValidationSpec(
                signature_validation_spec=policy
            ),
        )
        from pyhanko.sign.validation.report.tools import generate_report

        return generate_report(r.embedded_signatures[0], result)


@pytest.mark.asyncio
async def test_pades_lta_report_smoke_test(requests_mock):
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                subfilter=PADES,
                use_pades_lta=True,
                validation_context=live_testing_vc(requests_mock),
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )
    report = await _generate_lta_report(requests_mock, out)
    assert 'urn:etsi:019102:mainindication:total-passed' in report
    assert 'urn:etsi:019102:validationprocess:LTA' in report


@pytest.mark.asyncio
async def test_pades_with_attributes_report_smoke_test(requests_mock):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))

    authorities = [
        pki_arch.get_cert('root'),
        pki_arch.get_cert('interm'),
        pki_arch.get_cert('root-aa'),
        pki_arch.get_cert('interm-aa'),
        pki_arch.get_cert('leaf-aa'),
    ]
    sig_validation_spec = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build([pki_arch.get_cert('root')]),
            revinfo_policy=(
                DEFAULT_SIG_VALIDATION_SPEC.cert_validation_policy.revinfo_policy
            ),
        ),
        ac_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(
                [pki_arch.get_cert('root-aa')]
            ),
            revinfo_policy=(
                DEFAULT_SIG_VALIDATION_SPEC.cert_validation_policy.revinfo_policy
            ),
        ),
    )
    signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=SimpleCertificateStore.from_certs(authorities),
    )
    Illusionist(pki_arch).register(requests_mock)
    with freeze_time('2020-11-20'):
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                subfilter=PADES,
                use_pades_lta=True,
                validation_context=live_testing_vc(requests_mock),
                cades_signed_attr_spec=CAdESSignedAttrSpec(
                    commitment_type=CommitmentTypeIndication(
                        {'commitment_type_id': 'proof_of_creation'}
                    ),
                    timestamp_content=True,
                    signature_policy_identifier=SignaturePolicyIdentifier(
                        {'signature_policy_id': DUMMY_POLICY_ID}
                    ),
                    signer_attributes=SignerAttrSpec(
                        claimed_attrs=[SAMPLE_GROUP_ATTR],
                        certified_attrs=[
                            pki_arch.get_attr_cert(
                                CertLabel('alice-role-with-rev')
                            )
                        ],
                    ),
                ),
            ),
            signer=signer,
            timestamper=DUMMY_TS,
        )
    report = await _generate_lta_report(
        requests_mock, out, policy=sig_validation_spec
    )
    assert 'urn:etsi:019102:mainindication:total-passed' in report
    assert 'claimed' in report
    assert 'certified' in report
    assert 'urn:etsi:019102:validationprocess:LTA' in report
