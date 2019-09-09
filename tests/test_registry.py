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
        with open(os.path.join(fixtures_dir, 'mozilla.org.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            other_certs = [f.read()]

        repo = CertificateRegistry(other_certs=other_certs)
        paths = repo.build_paths(cert)
        self.assertEqual(1, len(paths))

        path = paths[0]
        self.assertEqual(3, len(path))
        self.assertEqual(
            [
                b'\x80Q\x06\x012\xad\x9a\xc2}Q\x87\xa0\xe8\x87\xfb\x01b\x01U\xee',
                b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
                b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81'
            ],
            [item.subject.sha1 for item in path]
        )

    def test_build_paths_custom_ca_certs(self):
        with open(os.path.join(fixtures_dir, 'mozilla.org.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            other_certs = [f.read()]

        repo = CertificateRegistry(trust_roots=other_certs)
        paths = repo.build_paths(cert)
        self.assertEqual(1, len(paths))

        path = paths[0]
        self.assertEqual(2, len(path))
        self.assertEqual(
            [
                b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
                b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81'
            ],
            [item.subject.sha1 for item in path]
        )
