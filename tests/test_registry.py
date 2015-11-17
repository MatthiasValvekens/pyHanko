# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

from asn1crypto import pem, x509
from certvalidator.registry import CertificateRegistry


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class RegistryTests(unittest.TestCase):

    def test_build_paths(self):
        with open(os.path.join(fixtures_dir, 'codex.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'GeoTrust_EV_SSL_CA_-_G4.crt'), 'rb') as f:
            other_certs = [f.read()]

        repo = CertificateRegistry(other_certs=other_certs)
        paths = repo.build_paths(cert)
        self.assertEqual(1, len(paths))

        path = paths[0]
        self.assertEqual(3, len(path))
        self.assertEqual(
            [
                b'z\x10xI\xe1u\x1a@\x0e\r\xdb\xac0\xc8\xaaK\x12u\xd1\xac',
                b'\xaa+\x03\x14\xafd.\x13\x0e\xd6\x92%\xe3\xff*\xba\xd7=b0',
                b"\xfcq\x7f\x98='\xcc\xb3D\xfbK\x85\xf0\x81\x8f\xab\xcb\xf0\x9b\x14"
            ],
            [item.subject.sha1 for item in path]
        )

    def test_build_paths_custom_ca_certs(self):
        with open(os.path.join(fixtures_dir, 'codex.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'GeoTrust_EV_SSL_CA_-_G4.crt'), 'rb') as f:
            other_certs = [f.read()]

        repo = CertificateRegistry(trust_roots=other_certs)
        paths = repo.build_paths(cert)
        self.assertEqual(1, len(paths))

        path = paths[0]
        self.assertEqual(2, len(path))
        self.assertEqual(
            [
                b'\xaa+\x03\x14\xafd.\x13\x0e\xd6\x92%\xe3\xff*\xba\xd7=b0',
                b"\xfcq\x7f\x98='\xcc\xb3D\xfbK\x85\xf0\x81\x8f\xab\xcb\xf0\x9b\x14"
            ],
            [item.subject.sha1 for item in path]
        )
