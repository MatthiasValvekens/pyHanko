# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

from asn1crypto import pem, x509
from certvalidator import ocsp_client
from certvalidator.registry import CertificateRegistry
from certvalidator.context import ValidationContext
from certvalidator.validate import verify_ocsp_response


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPClientTests(unittest.TestCase):

    def test_fetch_ocsp(self):
        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            intermediate = x509.Certificate.load(cert_bytes)

        registry = CertificateRegistry()
        path = registry.build_paths(intermediate)[0]
        issuer = path.find_issuer(intermediate)

        ocsp_response = ocsp_client.fetch(intermediate, issuer, timeout=3)
        context = ValidationContext(ocsps=[ocsp_response])
        verify_ocsp_response(intermediate, path, context)
