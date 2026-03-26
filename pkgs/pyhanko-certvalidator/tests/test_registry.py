# coding: utf-8
from datetime import datetime, timedelta, timezone

import pytest
from asn1crypto import core, x509
from pyhanko_certvalidator import PathBuildingError
from pyhanko_certvalidator.authority import (
    Authority,
    CertTrustAnchor,
    TrustedServiceType,
    TrustQualifiers,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    LayeredCertificateStore,
    PathBuilder,
    SimpleTrustManager,
    TrustManager,
)

from .common import load_cert_object


def test_build_paths_custom_ca_certs():
    cert = load_cert_object('testing-ca-ed25519', 'signer.cert.pem')
    other_certs = [load_cert_object('testing-ca-ed25519', 'interm.cert.pem')]

    builder = PathBuilder(
        trust_manager=SimpleTrustManager.build(trust_roots=other_certs),
        registry=CertificateRegistry.build(certs=other_certs),
    )
    paths = builder.build_paths(cert)
    assert 1 == len(paths)

    path = paths[0]
    assert 2 == len(path)
    assert [item.subject.sha1 for item in path] == [
        b'Xm\xb3f\xac[T\x13\xbaP$\x13\xfb\x93L\xf0\x9ex\x83V',
        b'\x8d\x19\xc0\xcdx\x84[\x7f\xe3/$\x86B\xfc\x83\xd9Kzm\x97',
    ]


def test_build_paths_qualified_root_with_wrong_type():
    cert = load_cert_object('testing-ca-ed25519', 'signer.cert.pem')
    ca = load_cert_object('testing-ca-ed25519', 'interm.cert.pem')
    other_certs = [ca]

    builder = PathBuilder(
        trust_manager=SimpleTrustManager.build(
            trust_roots=[
                CertTrustAnchor(
                    ca,
                    TrustQualifiers(
                        trusted_service_type=TrustedServiceType.UNSUPPORTED
                    ),
                )
            ]
        ),
        registry=CertificateRegistry.build(certs=other_certs),
    )
    with pytest.raises(PathBuildingError):
        builder.build_paths(cert)


def _gen_issuer_candidate_cert(key_identifier, common_name, coords):
    dt = datetime(2019, 9, 10, tzinfo=timezone.utc)
    cert_in = load_cert_object('testing-ca-ed25519', 'interm.cert.pem')
    pubkey = cert_in.public_key
    extensions = [
        x509.Extension(
            {
                'extn_id': 'key_usage',
                'critical': False,
                'extn_value': x509.KeyUsage(
                    {'key_cert_sign', 'digital_signature'}
                ),
            }
        )
    ]
    if key_identifier:
        extensions.append(
            x509.Extension(
                {
                    'extn_id': 'key_identifier',
                    'critical': False,
                    'extn_value': core.OctetString(key_identifier),
                }
            )
        )
    tbs = x509.TbsCertificate(
        {
            'version': 'v3',
            'serial_number': coords[1],
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': x509.Name.build({'common_name': coords[0]}),
            'validity': {
                'not_before': x509.Time({'utc_time': dt}),
                'not_after': x509.Time({'utc_time': dt + timedelta(days=3650)}),
            },
            'subject': x509.Name.build({'common_name': common_name}),
            'subject_public_key_info': pubkey,
            'extensions': extensions,
        }
    )

    cert = x509.Certificate(
        {
            'tbs_certificate': tbs,
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature_value': core.OctetBitString(b""),
        }
    )
    return cert


def _gen_subject_candidate_cert(aki, iss_common_name, iss_coords, ski=None):
    iss_name = x509.Name.build({'common_name': iss_common_name})
    dt = datetime(2019, 9, 10, tzinfo=timezone.utc)
    cert_in = load_cert_object('testing-ca-ed25519', 'signer.cert.pem')
    pubkey = cert_in.public_key
    extensions = [
        x509.Extension(
            {
                'extn_id': 'key_usage',
                'critical': False,
                'extn_value': x509.KeyUsage({'digital_signature'}),
            }
        ),
        x509.Extension(
            {
                'extn_id': 'key_identifier',
                'critical': False,
                'extn_value': x509.OctetString(ski or pubkey.sha1),
            }
        ),
    ]
    if aki or iss_coords:
        vals = {}
        if aki:
            vals['key_identifier'] = aki
        if iss_coords:
            vals['authority_cert_issuer'] = x509.GeneralNames(
                [
                    x509.GeneralName(
                        name='directory_name',
                        value=x509.Name.build({'common_name': iss_coords[0]}),
                    )
                ]
            )
            vals['authority_cert_serial_number'] = iss_coords[1]
        extensions.append(
            x509.Extension(
                {
                    'extn_id': 'authority_key_identifier',
                    'critical': False,
                    'extn_value': x509.AuthorityKeyIdentifier(vals),
                }
            )
        )
    tbs = x509.TbsCertificate(
        {
            'version': 'v3',
            'serial_number': 1,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': iss_name,
            'validity': {
                'not_before': x509.Time({'utc_time': dt}),
                'not_after': x509.Time({'utc_time': dt + timedelta(days=3650)}),
            },
            'subject': x509.Name.build({'common_name': 'subject'}),
            'subject_public_key_info': pubkey,
            'extensions': extensions,
        }
    )

    cert = x509.Certificate(
        {
            'tbs_certificate': tbs,
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature_value': core.OctetBitString(b""),
        }
    )
    return cert


class DummyTrustManager(TrustManager):
    def find_potential_issuers(self, cert: x509.Certificate):
        return iter(())

    def as_trust_anchor(self, authority: Authority):
        return None


@pytest.mark.parametrize(
    "key_identifier,authority_cert_coords",
    [
        # by key identifier
        (b"foo", None),
        # by auth cert coordinates
        (None, ("root", 0)),
        # both
        (b"foo", ("root", 0)),
    ],
)
def test_disambiguate_issuer_by_authority_info(
    key_identifier, authority_cert_coords
):
    subject = _gen_subject_candidate_cert(
        key_identifier, "issuer", authority_cert_coords
    )
    issuer1 = _gen_issuer_candidate_cert(b"foo", "issuer", ("root", 0))
    issuer2 = _gen_issuer_candidate_cert(b"bar", "issuer", ("root", 1))

    registry = CertificateRegistry.build([issuer1, issuer2])
    found = list(registry.find_potential_issuers(subject, DummyTrustManager()))
    assert len(found) == 1
    assert found[0].dump() == issuer1.dump()


def test_partial_match_handling_aki_filter():
    # corner case handling, not realistic in a sane PKI

    subject = _gen_subject_candidate_cert(b"foo", "issuer", ("root", 0))
    issuer1 = _gen_issuer_candidate_cert(b"foo", "issuer", ("root", 0))
    issuer2 = _gen_issuer_candidate_cert(b"bar", "issuer", ("root", 0))
    issuer3 = _gen_issuer_candidate_cert(b"foo", "issuer", ("root", 1))

    registry = CertificateRegistry.build([issuer1, issuer2, issuer3])
    found = list(registry.find_potential_issuers(subject, DummyTrustManager()))
    assert len(found) == 1
    assert found[0].dump() == issuer1.dump()


def test_distinguish_ski_and_key_hash():
    subject = _gen_subject_candidate_cert(b"foo", "issuer", ("root", 0), b"bar")
    issuer = _gen_issuer_candidate_cert(b"foo", "issuer", ("root", 0))
    data1 = subject.dump()
    data2 = issuer.dump()

    registry = CertificateRegistry.build([subject, issuer])
    assert (
        registry.retrieve_by_key_hash(subject.public_key.sha1).dump() == data1
    )
    assert registry.retrieve_by_key_hash(issuer.public_key.sha1).dump() == data2
    assert registry.retrieve_by_key_identifier(b"bar").dump() == data1
    assert registry.retrieve_by_key_identifier(subject.public_key.sha1) is None


def test_layered_prefer_first():
    subject1 = _gen_subject_candidate_cert(b"foo", "issuer", ("root", 0))
    subject2 = _gen_subject_candidate_cert(b"quux", "issuer", ("root", 0))

    store1 = CertificateRegistry.build([subject1])
    store2 = CertificateRegistry.build([subject2])
    layered = LayeredCertificateStore([store1, store2])

    expected = subject1.dump()

    assert subject1.issuer_serial == subject2.issuer_serial
    assert (
        layered.retrieve_by_key_hash(subject1.public_key.sha1).dump()
        == expected
    )
    assert (
        layered.retrieve_by_key_identifier(subject1.public_key.sha1).dump()
        == expected
    )
    assert (
        layered.retrieve_by_issuer_serial(subject1.issuer_serial).dump()
        == expected
    )


def test_layered_fallthrough():
    subject1 = _gen_subject_candidate_cert(b"foo", "issuer", ("root", 0))

    store1 = CertificateRegistry.build([])
    store2 = CertificateRegistry.build([subject1])
    layered = LayeredCertificateStore([store1, store2])

    expected = subject1.dump()

    assert (
        layered.retrieve_by_key_hash(subject1.public_key.sha1).dump()
        == expected
    )
    assert (
        layered.retrieve_by_key_identifier(subject1.public_key.sha1).dump()
        == expected
    )
    assert (
        layered.retrieve_by_issuer_serial(subject1.issuer_serial).dump()
        == expected
    )
