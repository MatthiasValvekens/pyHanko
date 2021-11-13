import asyncio
import logging
import os

import pytest

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_tests.csc_utils.csc_dummy_client import CSCDummy
from pyhanko_tests.signing_commons import async_val_trusted

logger = logging.getLogger(__name__)


SKIP_LIVE = False
CSC_SCAL2_HOST_URL = os.environ.get('LIVE_CSC_SCAL2_HOST_URL', None)
if not CSC_SCAL2_HOST_URL:
    logger.warning("Skipping live tests -- no CSC dummy host")
    SKIP_LIVE = True

CERTOMANCER_HOST_URL = os.environ.get('LIVE_CERTOMANCER_HOST_URL', None)
if not CERTOMANCER_HOST_URL:
    logger.warning("Skipping live tests -- no Certomancer host")
    SKIP_LIVE = True

TIMEOUT = 10

run_if_live = pytest.mark.skipif(
    SKIP_LIVE, reason="no CSC/Certomancer instance available"
)


@run_if_live
async def test_simple_sign_with_dummy():
    from io import BytesIO

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import PdfSignatureMetadata, async_sign_pdf
    from pyhanko_tests.samples import MINIMAL_ONE_FIELD

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    async with CSCDummy(endpoint_url=CSC_SCAL2_HOST_URL,
                        credential_id='testing-ca/signer1-long',
                        timeout=TIMEOUT) as signer:
        out = await async_sign_pdf(
            w, signature_meta=PdfSignatureMetadata(),
            existing_fields_only=True, signer=signer, in_place=True
        )

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    await async_val_trusted(emb)


@run_if_live
@pytest.mark.parametrize(
    'num_results,batch_size,expected_auth_count,waste_time', [
        (3, 3, 1, 0),
        (6, 3, 2, 0),
        (6, 3, 2, 1)
    ]
)
async def test_implicit_batch_sign_with_dummy(num_results, batch_size,
                                              expected_auth_count, waste_time):
    from io import BytesIO

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import PdfSignatureMetadata, async_sign_pdf
    from pyhanko_tests.samples import MINIMAL_ONE_FIELD

    async with CSCDummy(endpoint_url=CSC_SCAL2_HOST_URL,
                        credential_id='testing-ca/signer1-long',
                        waste_time=waste_time,
                        timeout=TIMEOUT, batch_size=batch_size) as signer:

        async def do_sign(num):
            w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
            return await async_sign_pdf(
                w, signature_meta=PdfSignatureMetadata(
                    reason=f"I'm number #{num}!"
                ),
                existing_fields_only=True, signer=signer, in_place=True,
            )
        results = await asyncio.gather(
            *(do_sign(i) for i in range(1, num_results + 1))
        )
        assert signer.auth_manager.authorizations_requested \
               == expected_auth_count

    for ix, out in enumerate(results):
        r = PdfFileReader(out)
        emb = r.embedded_signatures[0]
        assert emb.sig_object['/Reason'].endswith(f"#{ix + 1}!")
        await async_val_trusted(emb)
