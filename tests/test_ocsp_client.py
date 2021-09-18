# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

from asn1crypto import pem, x509
from pyhanko_certvalidator.fetchers import aiohttp_fetchers, requests_fetchers
from pyhanko_certvalidator.registry import CertificateRegistry
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.validate import verify_ocsp_response
from.constants import TEST_REQUEST_TIMEOUT

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPClientTests(unittest.IsolatedAsyncioTestCase):

    async def _test_with_fetchers(self, fetchers):
        cert_file = os.path.join(
            fixtures_dir, 'digicert-sha2-secure-server-ca.crt'
        )
        with open(cert_file, 'rb') as f:
            file_bytes = f.read()
            if pem.detect(file_bytes):
                _, _, file_bytes = pem.unarmor(file_bytes)
            intermediate = x509.Certificate.load(file_bytes)

        registry = CertificateRegistry(cert_fetcher=fetchers.cert_fetcher)
        paths = await registry.async_build_paths(intermediate)
        path = paths[0]
        issuer = path.find_issuer(intermediate)

        ocsp_response = await fetchers.ocsp_fetcher.fetch(intermediate, issuer)
        context = ValidationContext(ocsps=[ocsp_response], fetchers=fetchers)
        await verify_ocsp_response(intermediate, path, context)

    async def test_fetch_ocsp_aiohttp(self):
        fb = aiohttp_fetchers.AIOHttpFetcherBackend(
            per_request_timeout=TEST_REQUEST_TIMEOUT
        )
        async with fb as fetchers:
            await self._test_with_fetchers(fetchers)

    async def test_fetch_ocsp_requests(self):
        fb = requests_fetchers.RequestsFetcherBackend(
            per_request_timeout=TEST_REQUEST_TIMEOUT
        )
        fetchers = fb.get_fetchers()
        await self._test_with_fetchers(fetchers)
