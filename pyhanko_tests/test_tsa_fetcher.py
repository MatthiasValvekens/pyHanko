import hashlib

import aiohttp
import pytest
from asn1crypto import cms, tsp
from pyhanko_certvalidator import ValidationContext

from pyhanko.sign.timestamps import HTTPTimeStamper, TimestampRequestError
from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
from pyhanko.sign.timestamps.common_utils import handle_tsp_response

# Test against a real TSA
EXTERNAL_TSA_URL = 'http://timestamp.entrust.net/TSS/RFC3161sha2TS'
FETCH_TIMEOUT = 30
MESSAGE = b'Hello world!'
MESSAGE_DIGEST = hashlib.sha256(MESSAGE).digest()


async def test_ts_fetch_aiohttp():
    async with aiohttp.ClientSession() as session:
        ts = AIOHttpTimeStamper(
            EXTERNAL_TSA_URL, session, timeout=FETCH_TIMEOUT
        )
        ts_result = await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')
        from pyhanko.sign.validation import _validate_timestamp
        result = await _validate_timestamp(
            ts_result['content'], ValidationContext(trust_roots=[]),
            expected_tst_imprint=MESSAGE_DIGEST
        )
        assert result['valid'] and result['intact']
        # empty trust root list
        assert not result['trusted']


async def test_ts_fetch_aiohttp_error():
    with pytest.raises(TimestampRequestError):
        async with aiohttp.ClientSession() as session:
            ts = AIOHttpTimeStamper(
                "http://nasdlfkqowiuqoeljasd.yyq", session,
                timeout=FETCH_TIMEOUT
            )
            await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


async def test_ts_fetch_requests():
    ts = HTTPTimeStamper(
        EXTERNAL_TSA_URL, timeout=FETCH_TIMEOUT
    )
    ts_result = await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')
    from pyhanko.sign.validation import _validate_timestamp
    result = await _validate_timestamp(
        ts_result['content'], ValidationContext(trust_roots=[]),
        expected_tst_imprint=MESSAGE_DIGEST
    )
    assert result['valid'] and result['intact']
    # empty trust root list
    assert not result['trusted']


async def test_ts_fetch_requests_error():
    with pytest.raises(TimestampRequestError):
        ts = HTTPTimeStamper(
            "http://nasdlfkqowiuqoeljasd.yyq", timeout=FETCH_TIMEOUT
        )
        await ts.async_timestamp(MESSAGE_DIGEST, 'sha256')


@pytest.mark.parametrize('status_string,fail_info,err_resp,', [
    (
        'clock is down',
        'time_not_available',
        tsp.TimeStampResp({
            'status': {
                'status': 'waiting',
                'status_string': ['clock is down'],
                'fail_info': tsp.PKIFailureInfo({'time_not_available'}),
            },
            # this is nonsense, but the parser will accept it, so good enough
            'time_stamp_token': cms.ContentInfo({'content_type': 'data'})
        })
    ),
    (
        'clock is down',
        '',
        tsp.TimeStampResp({
            'status': {
                'status': 'waiting',
                'status_string': ['clock is down'],
            },
            'time_stamp_token': cms.ContentInfo({'content_type': 'data'})
        })
    ),
    (
        '',
        'time_not_available',
        tsp.TimeStampResp({
            'status': {
                'status': 'waiting',
                'fail_info': tsp.PKIFailureInfo({'time_not_available'}),
            },
            'time_stamp_token': cms.ContentInfo({'content_type': 'data'})
        })
    ),
])
def test_handle_error_response(status_string, fail_info, err_resp):
    err_match = (
        f'refused.*statusString "{status_string}", failInfo "{fail_info}"'
    )
    with pytest.raises(TimestampRequestError, match=err_match):
        handle_tsp_response(err_resp, b'0000')


def test_handle_bad_nonce():
    from .test_signing import DUMMY_TS
    message = b'Hello world!'
    nonce, req = DUMMY_TS.request_cms(
        hashlib.sha256(message).digest(), 'sha256'
    )
    response = DUMMY_TS.request_tsa_response(req)
    with pytest.raises(TimestampRequestError, match='bad nonce'):
        handle_tsp_response(response, b'0000')
