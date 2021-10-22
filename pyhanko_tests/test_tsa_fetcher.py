import hashlib

import aiohttp
import pytest
from pyhanko_certvalidator import ValidationContext

from pyhanko.sign.timestamps import HTTPTimeStamper, TimestampRequestError
from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper

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
