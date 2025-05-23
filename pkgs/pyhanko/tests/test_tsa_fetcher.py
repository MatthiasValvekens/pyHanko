import hashlib
from io import BytesIO

import aiohttp
import pytest
from asn1crypto import tsp
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.ades.report import AdESIndeterminate
from pyhanko.sign.timestamps import HTTPTimeStamper, TimestampRequestError
from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
from pyhanko.sign.timestamps.common_utils import handle_tsp_response

from pyhanko_certvalidator import ValidationContext

from .samples import *
from .signing_commons import (
    DUMMY_HTTP_TS,
    DUMMY_TS,
    FROM_CA,
    val_trusted,
)
from .test_pades import ts_response_callback

# Run some tests against a real TSA
EXTERNAL_TSA_URL = 'http://timestamp.entrust.net/TSS/RFC3161sha2TS'
FETCH_TIMEOUT = 30
MESSAGE = b'Hello world!'
MESSAGE_DIGEST = hashlib.sha256(MESSAGE).digest()


@pytest.mark.asyncio
async def test_ts_fetch_aiohttp():
    async with aiohttp.ClientSession() as session:
        ts = AIOHttpTimeStamper(
            EXTERNAL_TSA_URL, session, timeout=FETCH_TIMEOUT
        )
        ts_result = await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')
        from pyhanko.sign.validation.generic_cms import validate_tst_signed_data

        result = await validate_tst_signed_data(
            ts_result['content'],
            ValidationContext(trust_roots=[]),
            expected_tst_imprint=MESSAGE_DIGEST,
        )
        assert result['valid'] and result['intact']
        # empty trust root list
        assert (
            result['trust_problem_indic']
            == AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND
        )


@pytest.mark.asyncio
async def test_ts_fetch_aiohttp_error():
    with pytest.raises(TimestampRequestError):
        async with aiohttp.ClientSession() as session:
            ts = AIOHttpTimeStamper(
                "http://example.invalid", session, timeout=FETCH_TIMEOUT
            )
            await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.asyncio
async def test_ts_fetch_requests():
    ts = HTTPTimeStamper(EXTERNAL_TSA_URL, timeout=FETCH_TIMEOUT)
    ts_result = await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')
    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data

    result = await validate_tst_signed_data(
        ts_result['content'],
        ValidationContext(trust_roots=[]),
        expected_tst_imprint=MESSAGE_DIGEST,
    )
    assert result['valid'] and result['intact']
    # empty trust root list
    assert (
        result['trust_problem_indic']
        == AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND
    )


@pytest.mark.asyncio
async def test_ts_fetch_requests_error():
    with pytest.raises(TimestampRequestError):
        ts = HTTPTimeStamper("http://example.invalid", timeout=FETCH_TIMEOUT)
        await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.parametrize(
    'status_string,fail_info,err_resp,',
    [
        (
            'clock is down',
            'time_not_available',
            tsp.TimeStampResp(
                {
                    'status': {
                        'status': 'waiting',
                        'status_string': ['clock is down'],
                        'fail_info': tsp.PKIFailureInfo({'time_not_available'}),
                    },
                    # this is nonsense, but the parser will accept it, so good enough
                    'time_stamp_token': cms.ContentInfo(
                        {'content_type': 'data'}
                    ),
                }
            ),
        ),
        (
            'clock is down',
            '',
            tsp.TimeStampResp(
                {
                    'status': {
                        'status': 'waiting',
                        'status_string': ['clock is down'],
                    },
                    'time_stamp_token': cms.ContentInfo(
                        {'content_type': 'data'}
                    ),
                }
            ),
        ),
        (
            '',
            'time_not_available',
            tsp.TimeStampResp(
                {
                    'status': {
                        'status': 'waiting',
                        'fail_info': tsp.PKIFailureInfo({'time_not_available'}),
                    },
                    'time_stamp_token': cms.ContentInfo(
                        {'content_type': 'data'}
                    ),
                }
            ),
        ),
    ],
)
def test_handle_error_response(status_string, fail_info, err_resp):
    err_match = (
        f'refused.*statusString "{status_string}", failInfo "{fail_info}"'
    )
    with pytest.raises(TimestampRequestError, match=err_match):
        handle_tsp_response(err_resp, b'0000')


def test_handle_bad_nonce():
    from .signing_commons import DUMMY_TS

    message = b'Hello world!'
    nonce, req = DUMMY_TS.request_cms(
        hashlib.sha256(message).digest(), 'sha256'
    )
    response = DUMMY_TS.request_tsa_response(req)
    with pytest.raises(TimestampRequestError, match='bad nonce'):
        handle_tsp_response(response, b'0000')


@freeze_time('2020-11-01')
def test_dummy_timestamp():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted


@freeze_time('2020-11-01')
def test_http_timestamp(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    # bad content-type
    requests_mock.post(DUMMY_HTTP_TS.url, content=ts_response_callback)
    from pyhanko.sign.timestamps import TimestampRequestError

    with pytest.raises(TimestampRequestError):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(),
            signer=FROM_CA,
            timestamper=DUMMY_HTTP_TS,
            existing_fields_only=True,
        )

    requests_mock.post(
        DUMMY_HTTP_TS.url,
        content=ts_response_callback,
        headers={'Content-Type': 'application/timestamp-reply'},
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(),
        signer=FROM_CA,
        timestamper=DUMMY_HTTP_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted
