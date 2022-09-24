# coding: utf-8

import pytest

from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.fetchers import aiohttp_fetchers, requests_fetchers
from pyhanko_certvalidator.revinfo.validate_crl import verify_crl

from .common import load_cert_object
from .constants import TEST_REQUEST_TIMEOUT


async def _test_with_fetchers(fetchers):
    intermediate = load_cert_object('digicert-g5-ecc-sha384-2021-ca1.crt')
    root = load_cert_object('digicert-root-g5.crt')

    crls = await fetchers.crl_fetcher.fetch(intermediate)
    context = ValidationContext(
        trust_roots=[root], crls=crls, fetchers=fetchers
    )
    paths = await context.path_builder.async_build_paths(intermediate)
    path = paths[0]

    await verify_crl(intermediate, path, context)


@pytest.mark.asyncio
async def test_fetch_crl_aiohttp():
    fb = aiohttp_fetchers.AIOHttpFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    async with fb as fetchers:
        await _test_with_fetchers(fetchers)


@pytest.mark.asyncio
async def test_fetch_requests():
    fetchers = requests_fetchers.RequestsFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    ).get_fetchers()
    await _test_with_fetchers(fetchers)
