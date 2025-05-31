import os

import pytest
from asn1crypto import core, x509

from pyhanko_certvalidator.fetchers.common_utils import (
    ACCEPTABLE_CERT_DER_ALIASES,
    ACCEPTABLE_PKCS7_DER_ALIASES,
    enumerate_delivery_point_urls,
    unpack_cert_content,
)

TESTS_ROOT = os.path.dirname(__file__)
FIXTURES_DIR = os.path.join(TESTS_ROOT, 'fixtures')


@pytest.mark.parametrize("content_type", (None, *ACCEPTABLE_CERT_DER_ALIASES))
def test_unpack_cert_content_der(content_type):
    with open(os.path.join(FIXTURES_DIR, 'PostaSrbijeCA1.der'), 'rb') as f:
        der_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=der_bytes,
        content_type=content_type,
        permit_pem=False,
        url="http://example.com",
    )
    assert len(list(certs_returned)) == 1


def test_unpack_content_unknown_der():
    with pytest.raises(ValueError, match="Failed to heuristically"):
        next(
            unpack_cert_content(
                response_data=core.SequenceOf([]).dump(),
                content_type=None,
                permit_pem=False,
                url="http://example.com",
            )
        )


def test_unpack_cert_content_pem():
    with open(
        os.path.join(FIXTURES_DIR, 'digicert-g5-ecc-sha384-2021-ca1.crt'), 'rb'
    ) as f:
        pem_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pem_bytes,
        content_type="anything/goes",
        permit_pem=True,
        url="http://example.com",
    )
    assert len(list(certs_returned)) == 1


def test_unpack_cert_content_pem_multiple():
    with open(
        os.path.join(FIXTURES_DIR, 'certs_to_unpack/many-certs.pem'), 'rb'
    ) as f:
        pem_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pem_bytes,
        content_type="any",
        permit_pem=True,
        url="http://example.com",
    )
    assert len(list(certs_returned)) == 2


def test_unpack_cert_content_forbid_pem():
    with open(
        os.path.join(FIXTURES_DIR, 'digicert-g5-ecc-sha384-2021-ca1.crt'), 'rb'
    ) as f:
        pem_bytes = f.read()

    with pytest.raises(ValueError, match="Failed to extract"):
        next(
            unpack_cert_content(
                response_data=pem_bytes,
                content_type="anything/goes",
                permit_pem=False,
                url="http://example.com",
            )
        )


@pytest.mark.parametrize("content_type", (None, *ACCEPTABLE_PKCS7_DER_ALIASES))
def test_unpack_cert_content_pkcs7(content_type):
    with open(
        os.path.join(FIXTURES_DIR, 'certs_to_unpack/acserprorfbv5.p7b'), 'rb'
    ) as f:
        pkcs7_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pkcs7_bytes,
        content_type=content_type,
        permit_pem=True,
        url="http://repositorio.serpro.gov.br/cadeias/acserprorfbv5.p7b",
    )
    assert len(list(certs_returned)) == 3


def test_unpack_cert_content_pkcs7_pem():
    with open(
        os.path.join(FIXTURES_DIR, 'certs_to_unpack/acserprorfbv5.p7.pem'), 'rb'
    ) as f:
        pkcs7_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pkcs7_bytes,
        content_type="any",
        permit_pem=True,
        url="http://repositorio.serpro.gov.br/cadeias/acserprorfbv5.p7b",
    )
    assert len(list(certs_returned)) == 3


def test_crl_distribution_point_enumeration_skip_ldap():
    with open(os.path.join(FIXTURES_DIR, 'PostaSrbijeCA1.der'), 'rb') as f:
        cert = x509.Certificate.load(f.read())
    (dist_point,) = cert.crl_distribution_points_value
    (url,) = enumerate_delivery_point_urls(dist_point)
    assert url.startswith('http://')
