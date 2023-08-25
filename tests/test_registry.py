# coding: utf-8

import pytest

from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsCertificateFetcher,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    PathBuilder,
    SimpleTrustManager,
)

from .common import load_cert_object


def test_build_paths_custom_ca_certs():
    cert = load_cert_object('mozilla.org.crt')
    other_certs = [load_cert_object('digicert-sha2-secure-server-ca.crt')]

    builder = PathBuilder(
        trust_manager=SimpleTrustManager.build(trust_roots=other_certs),
        registry=CertificateRegistry.build(certs=other_certs),
    )
    paths = builder.build_paths(cert)
    assert 1 == len(paths)

    path = paths[0]
    assert 2 == len(path)
    assert [item.subject.sha1 for item in path] == [
        b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
        b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81',
    ]


@pytest.mark.parametrize(
    'domain',
    [
        "google.com",
        "www.cnn.com",
        "microsoft.com",
        "southwest.com",
        "xuite.net",
        "icpedu.rnp.br",
    ],
)
@pytest.mark.asyncio
async def test_basic_certificate_validator_tls_aia(domain):
    # google.com    -> application/pkix-cert
    # www.cnn.com   -> application/x-x509-ca-cert
    # microsoft.com -> application/octet-stream (DER)
    # southwest.com -> application/pkcs7-mime
    # xuite.net     -> application/x-pkcs7-certificates
    # icpedu.rnp.br -> binary/octet-stream (PEM, PKCS#7)

    icpedu_root = load_cert_object('testing-aia', 'root-icpedu.rnp.br')
    trust_manager = SimpleTrustManager.build(
        extra_trust_roots=[icpedu_root],
    )
    cert = load_cert_object('testing-aia', domain)
    registry = CertificateRegistry.build(
        certs=(cert,),
        cert_fetcher=RequestsCertificateFetcher(per_request_timeout=30),
    )
    builder = PathBuilder(trust_manager=trust_manager, registry=registry)
    paths = await builder.async_build_paths(end_entity_cert=cert)
    assert len(paths) >= 1
