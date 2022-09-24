# coding: utf-8

import os

import pytest
from asn1crypto import pem, x509

from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.errors import OCSPFetchError
from pyhanko_certvalidator.fetchers import aiohttp_fetchers, requests_fetchers
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    PathBuilder,
    SimpleTrustManager,
)
from pyhanko_certvalidator.revinfo.validate_ocsp import verify_ocsp_response

from .common import load_cert_object
from .constants import TEST_REQUEST_TIMEOUT


@pytest.mark.asyncio
async def _test_with_fetchers(fetchers):
    intermediate = load_cert_object('digicert-g5-ecc-sha384-2021-ca1.crt')

    trust_roots = [load_cert_object(os.path.join('digicert-root-g5.crt'))]
    path_builder = PathBuilder(
        registry=CertificateRegistry.build(cert_fetcher=fetchers.cert_fetcher),
        trust_manager=SimpleTrustManager.build(trust_roots=trust_roots),
    )
    paths = await path_builder.async_build_paths(intermediate)
    path = paths[0]
    authority = path.find_issuing_authority(intermediate)

    ocsp_response = await fetchers.ocsp_fetcher.fetch(intermediate, authority)
    context = ValidationContext(
        trust_roots=trust_roots, ocsps=[ocsp_response], fetchers=fetchers
    )
    await verify_ocsp_response(intermediate, path, context)


async def _test_fetch_error(fetchers):
    # a cert that doesn't have any OCSP URLs will always throw an error
    cert_file = os.path.join('testing-ca-pss', 'interm.cert.pem')
    intermediate = load_cert_object(cert_file)

    root_file = os.path.join('testing-ca-pss', 'root.cert.pem')
    root = load_cert_object(root_file)

    path_builder = PathBuilder(
        registry=CertificateRegistry.build(cert_fetcher=fetchers.cert_fetcher),
        trust_manager=SimpleTrustManager.build(trust_roots=[root]),
    )
    paths = await path_builder.async_build_paths(intermediate)
    path = paths[0]
    authority = path.find_issuing_authority(intermediate)

    async def fetch_err():
        with pytest.raises(OCSPFetchError):
            await fetchers.ocsp_fetcher.fetch(intermediate, authority)

    # trigger this twice, to make sure we get an error for both jobs
    await fetch_err()
    await fetch_err()


@pytest.mark.asyncio
async def test_fetch_ocsp_aiohttp():
    fb = aiohttp_fetchers.AIOHttpFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    async with fb as fetchers:
        await _test_with_fetchers(fetchers)


@pytest.mark.asyncio
async def test_fetch_ocsp_err_aiohttp():
    fb = aiohttp_fetchers.AIOHttpFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    async with fb as fetchers:
        await _test_fetch_error(fetchers)


@pytest.mark.asyncio
async def test_fetch_ocsp_requests():
    fb = requests_fetchers.RequestsFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    fetchers = fb.get_fetchers()
    await _test_with_fetchers(fetchers)


@pytest.mark.asyncio
async def test_fetch_ocsp_err_requests():
    fb = requests_fetchers.RequestsFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    fetchers = fb.get_fetchers()
    await _test_fetch_error(fetchers)
