from io import BytesIO

import pytest
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.ades.report import (
    AdESPassed,
)
from pyhanko.sign.validation import ades
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    RevocationInfoGatheringSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)
from pyhanko_certvalidator.registry import (
    SimpleTrustManager,
)
from pyhanko_testing_commons.test_data.samples import (
    MINIMAL_ONE_FIELD,
)
from pyhanko_testing_commons.test_utils.signing_commons import (
    DUMMY_TS,
    FROM_CA,
    TRUST_ROOTS,
    live_testing_vc,
)

from .test_ades_validation import (
    DEFAULT_REVINFO_POLICY,
    _generate_pades_test_doc,
)
from .test_pades import PADES

DEFAULT_SIG_VALIDATION_SPEC = SignatureValidationSpec(
    cert_validation_policy=CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(TRUST_ROOTS),
        revinfo_policy=DEFAULT_REVINFO_POLICY,
    ),
    revinfo_gathering_policy=RevocationInfoGatheringSpec(
        fetcher_backend=RequestsFetcherBackend()
    ),
)
DEFAULT_PDF_VALIDATION_SPEC = PdfSignatureValidationSpec(
    signature_validation_spec=DEFAULT_SIG_VALIDATION_SPEC
)


@pytest.mark.asyncio
async def test_pades_basic_happy_path_requests(pki_services):
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
        live_testing_vc(pki_services)
        result = await ades.ades_basic_validation(
            r.embedded_signatures[0].signed_data,
            validation_spec=DEFAULT_SIG_VALIDATION_SPEC,
            raw_digest=r.embedded_signatures[0].compute_digest(),
        )
        assert result.ades_subindic == AdESPassed.OK


@pytest.mark.asyncio
@freeze_time('2020-11-20')
async def test_pades_lta_happy_path_current_time_requests(pki_services):
    out = await _generate_pades_test_doc(pki_services)
    r = PdfFileReader(out)
    result = await ades.ades_lta_validation(
        r.embedded_signatures[0],
        pdf_validation_spec=DEFAULT_PDF_VALIDATION_SPEC,
    )
    assert result.ades_subindic == AdESPassed.OK
