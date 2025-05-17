import pytest

from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsCertificateFetcher,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    PathBuilder,
    SimpleTrustManager,
)

from ..common import load_cert_object


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
