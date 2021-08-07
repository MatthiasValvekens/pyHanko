# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

from asn1crypto import x509, pem
from pyhanko_certvalidator.fetchers import aiohttp_fetchers, requests_fetchers
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.validate import verify_crl


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CRLClientTests(unittest.IsolatedAsyncioTestCase):

    async def _test_with_fetchers(self, fetchers):
        cert_file = os.path.join(
            fixtures_dir, 'digicert-sha2-secure-server-ca.crt'
        )
        with open(cert_file, 'rb') as f:
            file_bytes = f.read()
            if pem.detect(file_bytes):
                _, _, file_bytes = pem.unarmor(file_bytes)
            intermediate = x509.Certificate.load(file_bytes)

        crls = await fetchers.crl_fetcher.fetch(intermediate)
        context = ValidationContext(crls=crls, fetchers=fetchers)
        registry = context.certificate_registry
        paths = await registry.async_build_paths(intermediate)
        path = paths[0]

        await verify_crl(intermediate, path, context)

    async def test_fetch_crl_aiohttp(self):
        fb = aiohttp_fetchers.AIOHttpFetcherBackend(per_request_timeout=3)
        async with fb as fetchers:
            await self._test_with_fetchers(fetchers)

    async def test_fetch_requests(self):
        fetchers = requests_fetchers.RequestsFetcherBackend(
            per_request_timeout=3
        ).get_fetchers()
        await self._test_with_fetchers(fetchers)
