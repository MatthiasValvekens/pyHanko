# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CertificateValidatorTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def test_basic_certificate_validator_tls(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        path = validator.validate_tls('www.mozilla.org')
        self.assertEqual(3, len(path))

    def test_basic_certificate_validator_tls_expired(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegexp(PathValidationError, 'expired'):
            validator.validate_tls('www.mozilla.org')

    def test_basic_certificate_validator_tls_invalid_hostname(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegexp(PathValidationError, 'not valid'):
            validator.validate_tls('google.com')

    def test_basic_certificate_validator_tls_invalid_key_usage(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegexp(PathValidationError, 'for the purpose'):
            validator.validate_usage(set(['crl_sign']))

    def test_basic_certificate_validator_tls_whitelist(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(
            whitelisted_certs=[cert.sha1_fingerprint],
            moment=moment
        )
        validator = CertificateValidator(cert, other_certs, context)

        # If whitelist does not work, this will raise exception for expiration
        validator.validate_tls('www.mozilla.org')

        # If whitelist does not work, this will raise exception for hostname
        validator.validate_tls('google.com')

        # If whitelist does not work, this will raise exception for key usage
        validator.validate_usage(set(['crl_sign']))
