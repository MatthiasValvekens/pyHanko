import hashlib
from io import BytesIO

import pytest
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.timestamps import HTTPTimeStamper, TimestampRequestError
from pyhanko.sign.timestamps.requests_client import RequestsHTTPTimeStamper
from pyhanko_testing_commons.test_data.samples import MINIMAL_ONE_FIELD
from pyhanko_testing_commons.test_utils.signing_commons import (
    DUMMY_HTTP_TS,
    FROM_CA,
    val_trusted,
)

from .test_pades import ts_response_callback

FETCH_TIMEOUT = 30
MESSAGE = b'Hello world!'
MESSAGE_DIGEST = hashlib.sha256(MESSAGE).digest()


@pytest.mark.asyncio
async def test_ts_fetch_supplied_session_error_requests():
    with pytest.raises(TimestampRequestError):
        ts = RequestsHTTPTimeStamper(
            "http://example.invalid",
            timeout=FETCH_TIMEOUT,
        )
        await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.asyncio
async def test_ts_fetch_error_requests():
    with pytest.raises(TimestampRequestError):
        ts = HTTPTimeStamper("http://example.invalid", timeout=FETCH_TIMEOUT)
        await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@freeze_time('2020-11-01')
def test_http_timestamp_bad_content_type_requests(pki_services):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    # bad content-type
    pki_services.post(DUMMY_HTTP_TS.url, content=ts_response_callback)
    from pyhanko.sign.timestamps import TimestampRequestError

    requests_http_ts = RequestsHTTPTimeStamper(DUMMY_HTTP_TS.url, https=False)

    with pytest.raises(TimestampRequestError):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(),
            signer=FROM_CA,
            timestamper=requests_http_ts,
            existing_fields_only=True,
        )


@freeze_time('2020-11-01')
def test_http_timestamp_requests(pki_services):
    requests_http_ts = RequestsHTTPTimeStamper(DUMMY_HTTP_TS.url, https=False)
    pki_services.post(
        DUMMY_HTTP_TS.url,
        content=ts_response_callback,
        content_type='application/timestamp-reply',
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(),
        signer=FROM_CA,
        timestamper=requests_http_ts,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted
