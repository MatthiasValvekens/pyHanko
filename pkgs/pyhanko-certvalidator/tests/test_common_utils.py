import os

import pytest
from asn1crypto import cms, core, x509
from pyhanko_certvalidator.fetchers.common_utils import (
    ACCEPTABLE_CERT_DER_ALIASES,
    ACCEPTABLE_PKCS7_DER_ALIASES,
    enumerate_delivery_point_urls,
    gather_aia_issuer_urls,
    unpack_cert_content,
)

TESTS_ROOT = os.path.dirname(__file__)
FIXTURES_DIR = os.path.join(TESTS_ROOT, 'fixtures')

ac_path = os.path.join(
    FIXTURES_DIR,
    'attribute-certs',
    'basic-aa',
    'aa',
    'alice-role-with-rev.attr.crt',
)
with open(ac_path, 'rb') as inf:
    ATTRIBUTE_CERT = cms.AttributeCertificateV2.load(inf.read())

with open(os.path.join(FIXTURES_DIR, 'PostaSrbijeCA1.der'), 'rb') as f:
    POSTA_SRBIJE_CERT = x509.Certificate.load(f.read())


@pytest.mark.parametrize("content_type", (None, *ACCEPTABLE_CERT_DER_ALIASES))
def test_unpack_cert_content_der(content_type):
    certs_returned = unpack_cert_content(
        response_data=POSTA_SRBIJE_CERT.dump(),
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


def test_unpack_content_bad_pkcs7():
    with pytest.raises(ValueError, match="Expected CMS SignedData"):
        next(
            unpack_cert_content(
                response_data=cms.ContentInfo(
                    {'content_type': 'data', 'content': core.OctetString(b"")}
                ).dump(),
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
    (dist_point,) = POSTA_SRBIJE_CERT.crl_distribution_points_value
    (url,) = enumerate_delivery_point_urls(dist_point)
    assert url.startswith('http://')


def test_crl_distribution_point_enumeration_skip_relative():
    result = enumerate_delivery_point_urls(
        x509.DistributionPoint(
            {
                'distribution_point': x509.DistributionPointName(
                    name='name_relative_to_crl_issuer',
                    value=POSTA_SRBIJE_CERT.issuer.chosen[0],
                )
            }
        )
    )
    assert len(list(result)) == 0


def test_crl_distribution_point_enumeration_skip_non_uri():
    result = enumerate_delivery_point_urls(
        x509.DistributionPoint(
            {
                'distribution_point': x509.DistributionPointName(
                    name='full_name',
                    value=[
                        x509.GeneralName(
                            name='directory_name',
                            value=POSTA_SRBIJE_CERT.issuer,
                        )
                    ],
                )
            }
        )
    )
    assert len(list(result)) == 0


def test_gather_issuer_urls_cert():
    urls = gather_aia_issuer_urls(POSTA_SRBIJE_CERT)
    assert list(urls) == [
        'http://repository.ca.posta.rs/ca-sertifikati/PostaSrbijeCARoot.der'
    ]


def test_gather_issuer_urls_ac():
    urls = gather_aia_issuer_urls(ATTRIBUTE_CERT)
    assert list(urls) == ['http://localhost:9000/basic-aa/certs/interm/ca.crt']


def test_gather_issuer_urls_ac_no_aia():
    ac_norev_path = os.path.join(
        FIXTURES_DIR,
        'attribute-certs',
        'basic-aa',
        'aa',
        'alice-role-norev.attr.crt',
    )
    with open(ac_norev_path, 'rb') as inf:
        ac = cms.AttributeCertificateV2.load(inf.read())
    urls = gather_aia_issuer_urls(ac)
    assert list(urls) == []


@pytest.mark.parametrize(
    'pkcs7_data',
    [
        {
            'version': 'v1',
            'digest_algorithms': [],
            'encap_content_info': {
                'content_type': 'data',
            },
            'signer_infos': [],
        },
        {
            'version': 'v1',
            'digest_algorithms': [],
            'encap_content_info': {
                'content_type': 'data',
            },
            'signer_infos': [],
            'certificates': [],
        },
        {
            'version': 'v1',
            'digest_algorithms': [],
            'encap_content_info': {
                'content_type': 'data',
            },
            'signer_infos': [],
            'certificates': [
                cms.CertificateChoices(
                    name='v2_attr_cert', value=ATTRIBUTE_CERT
                )
            ],
        },
    ],
)
def test_unpack_content_empty_pkcs7(pkcs7_data):
    certs_returned = unpack_cert_content(
        response_data=cms.ContentInfo(
            {
                'content_type': 'signed_data',
                'content': cms.SignedData(pkcs7_data),
            }
        ).dump(),
        content_type=None,
        permit_pem=False,
        url="http://example.com",
    )

    assert len(list(certs_returned)) == 0
