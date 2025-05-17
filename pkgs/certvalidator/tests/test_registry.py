# coding: utf-8

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
