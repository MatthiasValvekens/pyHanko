# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from pyhanko_certvalidator import CertificateValidator, ValidationContext, \
    PKIXValidationParams
from pyhanko_certvalidator.errors import PathValidationError

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

        validator.validate_tls('www.mozilla.org')

    def test_basic_certificate_validator_tls_expired(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'expired'):
            validator.validate_tls('www.mozilla.org')

    def test_basic_certificate_validator_tls_invalid_hostname(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'not valid'):
            validator.validate_tls('google.com')

    def test_basic_certificate_validator_tls_invalid_key_usage(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'for the purpose'):
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

    def test_certvalidator_with_params(self):

        cert = self._load_nist_cert('ValidPolicyMappingTest12EE.crt')
        ca_certs = [self._load_nist_cert('TrustAnchorRootCertificate.crt')]
        other_certs = [self._load_nist_cert('P12Mapping1to3CACert.crt')]

        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            revocation_mode="soft-fail",
            weak_hash_algos={'md2', 'md5'}
        )

        validator = CertificateValidator(
            cert, validation_context=context,
            pkix_params=PKIXValidationParams(
                user_initial_policy_set=frozenset(['2.16.840.1.101.3.2.1.48.1'])
            )
        )
        path = validator.validate_usage(key_usage={'digital_signature'})

        # check if we got the right policy processing
        # (i.e. if our params got through)
        qps = path.qualified_policies()

        qp, = qps
        self.assertEqual(1, len(qp.qualifiers))
        qual_obj, = qp.qualifiers
        self.assertEqual(qual_obj['policy_qualifier_id'].native, 'user_notice')
        self.assertEqual(
            qual_obj['qualifier']['explicit_text'].native,
            'q7:  This is the user notice from qualifier 7 associated with '
            'NIST-test-policy-3.  This user notice should be displayed '
            'when  NIST-test-policy-1 is in the user-constrained-policy-set'
        )
