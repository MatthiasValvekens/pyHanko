# coding: utf-8

import os
import unittest

from asn1crypto import pem, x509

from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.fetchers import aiohttp_fetchers, requests_fetchers
from pyhanko_certvalidator.revinfo.validate_crl import verify_crl

from .constants import TEST_REQUEST_TIMEOUT

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def _read(fname):
    cert_file = os.path.join(fixtures_dir, fname)
    with open(cert_file, 'rb') as f:
        file_bytes = f.read()
        if pem.detect(file_bytes):
            _, _, file_bytes = pem.unarmor(file_bytes)
        return x509.Certificate.load(file_bytes)


class CRLClientTests(unittest.IsolatedAsyncioTestCase):
    async def _test_with_fetchers(self, fetchers):
        intermediate = _read('digicert-g5-ecc-sha384-2021-ca1.crt')
        root = _read('digicert-root-g5.crt')

        crls = await fetchers.crl_fetcher.fetch(intermediate)
        context = ValidationContext(
            trust_roots=[root], crls=crls, fetchers=fetchers
        )
        paths = await context.path_builder.async_build_paths(intermediate)
        path = paths[0]

        await verify_crl(intermediate, path, context)

    async def test_fetch_crl_aiohttp(self):
        fb = aiohttp_fetchers.AIOHttpFetcherBackend(
            per_request_timeout=TEST_REQUEST_TIMEOUT
        )
        async with fb as fetchers:
            await self._test_with_fetchers(fetchers)

    async def test_fetch_requests(self):
        fetchers = requests_fetchers.RequestsFetcherBackend(
            per_request_timeout=TEST_REQUEST_TIMEOUT
        ).get_fetchers()
        await self._test_with_fetchers(fetchers)
