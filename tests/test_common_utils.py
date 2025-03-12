import os

from certomancer.crypto_utils import load_cert_from_pemder

from pyhanko_certvalidator.fetchers.common_utils import (
    enumerate_delivery_point_urls,
    unpack_cert_content,
)

TESTS_ROOT = os.path.dirname(__file__)
FIXTURES_DIR = os.path.join(TESTS_ROOT, 'fixtures')


def test_unpack_cert_content_pkcs7_with_binary_octet_stream_alias():
    with open(
        os.path.join(FIXTURES_DIR, 'certs_to_unpack/acserprorfbv5.p7b'), 'rb'
    ) as f:
        pkcs7_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pkcs7_bytes,
        content_type="binary/octet-stream",
        permit_pem=True,
        url="http://repositorio.serpro.gov.br/cadeias/acserprorfbv5.p7b",
    )
    assert len(list(certs_returned)) == 3


def test_crl_distribution_point_enumeration_skip_ldap():
    cert = load_cert_from_pemder(
        os.path.join(FIXTURES_DIR, 'PostaSrbijeCA1.pem')
    )
    (dist_point,) = cert.crl_distribution_points_value
    (url,) = enumerate_delivery_point_urls(dist_point)
    assert url.startswith('http://')
