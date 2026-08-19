import hashlib
from io import BytesIO

import aiohttp
import pytest
from asn1crypto import cms, tsp
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.timestamps import HTTPTimeStamper, TimestampRequestError
from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
from pyhanko.sign.timestamps.common_utils import handle_tsp_response
from pyhanko_testing_commons.test_data.samples import MINIMAL_ONE_FIELD
from pyhanko_testing_commons.test_utils.signing_commons import (
    DUMMY_HTTP_TS,
    DUMMY_TS,
    FROM_CA,
    val_trusted,
)

from .test_pades import ts_response_callback

FETCH_TIMEOUT = 30
MESSAGE = b'Hello world!'
MESSAGE_DIGEST = hashlib.sha256(MESSAGE).digest()


@pytest.mark.asyncio
async def test_ts_fetch_supplied_session_error():
    with pytest.raises(TimestampRequestError):
        async with aiohttp.ClientSession() as session:
            ts = HTTPTimeStamper(
                "http://example.invalid",
                timeout=FETCH_TIMEOUT,
                session=session,
            )
            await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.asyncio
async def test_ts_fetch_error():
    with pytest.raises(TimestampRequestError):
        ts = HTTPTimeStamper("http://example.invalid", timeout=FETCH_TIMEOUT)
        await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.asyncio
async def test_deprecated_aiohttp_timestamper_forwards():
    async with aiohttp.ClientSession() as session:
        with pytest.warns(DeprecationWarning):
            ts = AIOHttpTimeStamper(
                "http://example.invalid", session, timeout=FETCH_TIMEOUT
            )
        assert ts._session is session
        with pytest.raises(TimestampRequestError):
            await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.parametrize(
    'auth,expected',
    [
        (None, None),
        (('user', 'pass'), aiohttp.BasicAuth('user', 'pass')),
        (aiohttp.BasicAuth('user', 'pass'), aiohttp.BasicAuth('user', 'pass')),
    ],
)
def test_auth_coercion(auth, expected):
    ts = HTTPTimeStamper("http://example.invalid", auth=auth)
    assert ts.auth == expected


def test_auth_coercion_rejects_nonsense():
    with pytest.raises(TypeError, match='BasicAuth'):
        HTTPTimeStamper("http://example.invalid", auth=object())


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
    from pyhanko_testing_commons.test_utils.signing_commons import DUMMY_TS

    message = b'Hello world!'
    _nonce, req = DUMMY_TS.request_cms(
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
def test_http_timestamp_bad_content_type(pki_services):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    # bad content-type
    pki_services.post(DUMMY_HTTP_TS.url, content=ts_response_callback)
    from pyhanko.sign.timestamps import TimestampRequestError

    with pytest.raises(TimestampRequestError):
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(),
            signer=FROM_CA,
            timestamper=DUMMY_HTTP_TS,
            existing_fields_only=True,
        )


@freeze_time('2020-11-01')
def test_http_timestamp(pki_services):
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
        timestamper=DUMMY_HTTP_TS,
        existing_fields_only=True,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    validity = val_trusted(s)
    assert validity.timestamp_validity is not None
    assert validity.timestamp_validity.trusted
