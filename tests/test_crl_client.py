# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

from asn1crypto import x509, pem
from certvalidator import crl_client
from certvalidator.context import ValidationContext
from certvalidator.validate import verify_crl


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CRLClientTests(unittest.TestCase):

    def test_fetch_crl(self):
        with open(os.path.join(fixtures_dir, 'GeoTrust_EV_SSL_CA_-_G4.crt'), 'rb') as f:
            file_bytes = f.read()
            if pem.detect(file_bytes):
                _, _, file_bytes = pem.unarmor(file_bytes)
            intermediate = x509.Certificate.load(file_bytes)

        crls = crl_client.fetch(intermediate, timeout=3)
        context = ValidationContext(crls=crls)
        registry = context.certificate_registry
        path = registry.build_paths(intermediate)[0]

        verify_crl(intermediate, path, context)
