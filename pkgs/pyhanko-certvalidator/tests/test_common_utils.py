import asyncio
import os

import pytest
from asn1crypto import cms, core, x509
from pyhanko_certvalidator.fetchers.common_utils import (
    ACCEPTABLE_CERT_DER_ALIASES,
    ACCEPTABLE_PKCS7_DER_ALIASES,
    enumerate_delivery_point_urls,
    gather_aia_issuer_urls,
    queue_fetch_task,
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

with open(
    os.path.join(FIXTURES_DIR, 'testing-aia', 'with-ldap-urls.der'), 'rb'
) as f:
    WITH_LDAP_URLS = x509.Certificate.load(f.read())


@pytest.mark.parametrize("content_type", (None, *ACCEPTABLE_CERT_DER_ALIASES))
def test_unpack_cert_content_der(content_type):
    certs_returned = unpack_cert_content(
        response_data=WITH_LDAP_URLS.dump(),
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
        os.path.join(FIXTURES_DIR, 'testing-ca-ed25519', 'interm.cert.pem'),
        'rb',
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
        os.path.join(FIXTURES_DIR, 'testing-ca-ed25519', 'interm.cert.pem'),
        'rb',
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
        os.path.join(FIXTURES_DIR, 'certs_to_unpack/test.p7b'), 'rb'
    ) as f:
        pkcs7_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pkcs7_bytes,
        content_type=content_type,
        permit_pem=True,
        url="http://example.com",
    )
    assert len(list(certs_returned)) == 2


def test_unpack_cert_content_pkcs7_pem():
    with open(
        os.path.join(FIXTURES_DIR, 'certs_to_unpack/test.p7b.pem'), 'rb'
    ) as f:
        pkcs7_bytes = f.read()

    certs_returned = unpack_cert_content(
        response_data=pkcs7_bytes,
        content_type="any",
        permit_pem=True,
        url="http://example.com",
    )
    assert len(list(certs_returned)) == 2


def test_crl_distribution_point_enumeration_skip_ldap():
    (dist_point,) = WITH_LDAP_URLS.crl_distribution_points_value
    (url,) = enumerate_delivery_point_urls(dist_point)
    assert url.startswith('http://')


def test_crl_distribution_point_enumeration_skip_relative():
    result = enumerate_delivery_point_urls(
        x509.DistributionPoint(
            {
                'distribution_point': x509.DistributionPointName(
                    name='name_relative_to_crl_issuer',
                    value=WITH_LDAP_URLS.issuer.chosen[0],
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
                            value=WITH_LDAP_URLS.issuer,
                        )
                    ],
                )
            }
        )
    )
    assert len(list(result)) == 0


def test_gather_issuer_urls_cert():
    urls = gather_aia_issuer_urls(WITH_LDAP_URLS)
    assert list(urls) == ['http://repo.ca.example.com']


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


@pytest.mark.asyncio
async def test_waiter_takes_over_cancelled_fetch_job():
    results, running = {}, {}
    started = asyncio.Event()

    async def never():
        started.set()
        await asyncio.Event().wait()

    async def ok():
        return 'ok'

    owner = asyncio.create_task(queue_fetch_task(results, running, 't', never))
    await started.wait()
    waiter = asyncio.create_task(queue_fetch_task(results, running, 't', ok))
    await asyncio.sleep(0)
    owner.cancel()
    assert await asyncio.wait_for(waiter, 1) == 'ok'
    assert running == {}
    assert results == {'t': 'ok'}
