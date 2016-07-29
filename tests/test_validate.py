# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import base64
import unittest
import os
import sys

from asn1crypto import crl, ocsp, pem, x509
from asn1crypto.util import timezone
from certvalidator import crl_client, ocsp_client
from certvalidator.context import ValidationContext
from certvalidator.path import ValidationPath
from certvalidator.validate import validate_path
from certvalidator.errors import PathValidationError, RevokedError

from ._unittest_compat import patch
from .unittest_data import data_decorator, data

if sys.version_info < (3,):
    from urllib2 import URLError
else:
    from urllib.error import URLError

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@data_decorator
class ValidateTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def _load_nist_crl(self, filename):
        with open(os.path.join(fixtures_dir, 'nist_pkits', 'crls', filename), 'rb') as f:
            return crl.CertificateList.load(f.read())

    def _load_openssl_ors(self, filename):
        with open(os.path.join(fixtures_dir, 'openssl-ocsp', filename), 'rb') as f:
            return ocsp.OCSPResponse.load(base64.b64decode(f.read()))

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def test_revocation_mode_soft(self):
        cert = self._load_cert_object('revoked.grc.com.crt')
        ca_certs = [self._load_cert_object('globalsign_root.crt')]
        other_certs = [
            self._load_cert_object('globalsign_dv_g2.crt'),
        ]

        try:
            # Mock the crl and ocsp clients to fail
            orig_crl_fetch = crl_client.fetch
            orig_ocsp_fetch = ocsp_client.fetch

            def crl_fetch(cert, use_deltas=True, user_agent=None, timeout=10):
                raise URLError('Connection timed out')
            crl_client.fetch = crl_fetch

            def ocsp_fetch(cert, issuer, hash_algo='sha1', nonce=True, user_agent=None, timeout=10):
                raise URLError('Connection timed out')
            ocsp_client.fetch = ocsp_fetch

            context = ValidationContext(
                trust_roots=ca_certs,
                other_certs=other_certs,
                allow_fetching=True
            )
            paths = context.certificate_registry.build_paths(cert)
            self.assertEqual(1, len(paths))
            path = paths[0]
            self.assertEqual(3, len(path))

            validate_path(context, path)
        finally:
            crl_client.fetch = orig_crl_fetch
            ocsp_client.fetch = orig_ocsp_fetch


    def test_revocation_mode_hard(self):
        cert = self._load_cert_object('revoked.grc.com.crt')
        ca_certs = [self._load_cert_object('globalsign_root.crt')]
        other_certs = [
            self._load_cert_object('globalsign_dv_g2.crt'),
        ]

        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            allow_fetching=True,
            crl_fetch_params={'timeout': 30},
            ocsp_fetch_params={'timeout': 30},
            revocation_mode='hard-fail'
        )
        paths = context.certificate_registry.build_paths(cert)
        self.assertEqual(1, len(paths))
        path = paths[0]
        self.assertEqual(3, len(path))

        expected = (
            '(CRL|OCSP response) indicates the end-entity certificate was '
            'revoked at 15:44:10 on 2014-04-23, due to an unspecified reason'
        )
        with self.assertRaisesRegexp(RevokedError, expected):
            validate_path(context, path)

    @data('ocsp_info', True)
    def openssl_ocsp(self, ca_file, other_files, cert_file, ocsp_files, path_len, moment, excp_class, excp_msg):
        ca_certs = [self._load_cert_object('openssl-ocsp', ca_file)]
        other_certs = [self._load_cert_object('openssl-ocsp', filename) for filename in other_files]
        cert = self._load_cert_object('openssl-ocsp', cert_file)
        ocsp_responses = [self._load_openssl_ors(filename) for filename in ocsp_files]

        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            moment=moment,
            ocsps=ocsp_responses
        )
        paths = context.certificate_registry.build_paths(cert)
        self.assertEqual(1, len(paths))
        path = paths[0]
        self.assertEqual(path_len, len(path))

        if excp_class:
            with self.assertRaisesRegexp(excp_class, excp_msg):
                validate_path(context, path)
        else:
            validate_path(context, path)

    @staticmethod
    def ocsp_info():
        return (
            (
                'direct_with_intermediate_success',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'ND1.ors',
                    'ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                None,
                None,
            ),
            (
                'direct_success',
                'ND3_Issuer_Root.pem',
                [],
                'ND3_Cert_EE.pem',
                [
                    'ND3.ors',
                ],
                2,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                None,
                None,
            ),
            (
                'delegated_with_intermediate_success',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'D1.ors',
                ],
                3,
                datetime(2012, 10, 23, 11, 0, 0, tzinfo=timezone.utc),
                None,
                None,
            ),
            (
                'delegated_success',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'D3.ors',
                ],
                2,
                datetime(2012, 10, 23, 11, 0, 0, tzinfo=timezone.utc),
                None,
                None,
            ),
            (
                'direct_with_intermediate_invalid_response_signature_ee',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'ISOP_ND1.ors',
                    'ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response signature'
                ),
            ),
            (
                'direct_with_intermediate_invalid_response_signature_intermediate',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'ND1.ors',
                    'ISOP_ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the intermediate '
                    'certificate 1 revocation checks failed: Unable to verify '
                    'OCSP response signature'
                ),
            ),
            (
                'direct_invalid_response_signature',
                'ND3_Issuer_Root.pem',
                [],
                'ND3_Cert_EE.pem',
                [
                    'ISOP_ND3.ors',
                ],
                2,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response signature'
                ),
            ),
            (
                'delegated_with_intermediate_invalid_response_signature',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'ISOP_D1.ors',
                ],
                3,
                datetime(2012, 10, 10, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response signature'
                ),
            ),
            (
                'delegated_invalid_response_signature',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'ISOP_D3.ors',
                ],
                2,
                datetime(2012, 10, 10, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response signature'
                ),
            ),
            (
                'direct_with_intermediate_invalid_wrong_responder_id_ee',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'WRID_ND1.ors',
                    'ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be located'
                ),
            ),
            (
                'direct_with_intermediate_invalid_wrong_responder_id_intermediate',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'ND1.ors',
                    'WRID_ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the intermediate '
                    'certificate 1 revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be located'
                ),
            ),
            (
                'direct_invalid_wrong_responder_id',
                'ND3_Issuer_Root.pem',
                [],
                'ND3_Cert_EE.pem',
                [
                    'WRID_ND3.ors',
                ],
                2,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be located'
                ),
            ),
            (
                'delegated_with_intermediate_invalid_wrong_responder_id',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'WRID_D1.ors',
                ],
                3,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be located'
                ),
            ),
            (
                'delegated_invalid_wrong_responder_id',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'WRID_D3.ors',
                ],
                2,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be located'
                ),
            ),
            (
                'direct_with_intermediate_invalid_wrong_issuer_name_hash_ee',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'WINH_ND1.ors',
                    'ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer name hash does not match'
                ),
            ),
            (
                'direct_with_intermediate_invalid_wrong_issuer_name_hash_intermediate',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'ND1.ors',
                    'WINH_ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the intermediate '
                    'certificate 1 revocation checks failed: OCSP response '
                    'issuer name hash does not match'
                ),
            ),
            (
                'direct_invalid_wrong_issuer_name_hash',
                'ND3_Issuer_Root.pem',
                [],
                'ND3_Cert_EE.pem',
                [
                    'WINH_ND3.ors',
                ],
                2,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer name hash does not match'
                ),
            ),
            (
                'delegated_with_intermediate_invalid_wrong_issuer_name_hash',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'WINH_D1.ors',
                ],
                3,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer name hash does not match'
                ),
            ),
            (
                'delegated_invalid_wrong_issuer_name_hash',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'WINH_D3.ors',
                ],
                2,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer name hash does not match'
                ),
            ),
            (
                'direct_with_intermediate_invalid_wrong_issuer_key_hash_ee',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'WIKH_ND1.ors',
                    'ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer key hash does not match'
                ),
            ),
            (
                'direct_with_intermediate_invalid_wrong_issuer_key_hash_intermediate',
                'ND2_Issuer_Root.pem',
                [
                    'ND1_Issuer_ICA.pem',
                ],
                'ND1_Cert_EE.pem',
                [
                    'ND1.ors',
                    'WIKH_ND2.ors',
                ],
                3,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the intermediate '
                    'certificate 1 revocation checks failed: OCSP response '
                    'issuer key hash does not match'
                ),
            ),
            (
                'direct_invalid_wrong_issuer_key_hash',
                'ND3_Issuer_Root.pem',
                [],
                'ND3_Cert_EE.pem',
                [
                    'WIKH_ND3.ors',
                ],
                2,
                datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer key hash does not match'
                ),
            ),
            (
                'delegated_with_intermediate_invalid_wrong_issuer_key_hash',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'WIKH_D1.ors',
                ],
                3,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer key hash does not match'
                ),
            ),
            (
                'delegated_invalid_wrong_issuer_key_hash',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'WIKH_D3.ors',
                ],
                2,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: OCSP response '
                    'issuer key hash does not match'
                ),
            ),
            (
                'delegated_with_intermediate_invalid_wrong_key_in_signing_cert',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'WKDOSC_D1.ors',
                ],
                3,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be validated'
                ),
            ),
            (
                'delegated_invalid_wrong_key_in_signing_cert',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'WKDOSC_D3.ors',
                ],
                2,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be validated'
                ),
            ),
            (
                'delegated_with_intermediate_invalid_signature_on_signing_cert',
                'R2.pem',
                [
                    'D1_Issuer_ICA.pem',
                ],
                'D1_Cert_EE.pem',
                [
                    'ISDOSC_D1.ors',
                ],
                3,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be validated'
                ),
            ),
            (
                'delegated_invalid_signature_on_signing_cert',
                'D3_Issuer_Root.pem',
                [],
                'D3_Cert_EE.pem',
                [
                    'ISDOSC_D3.ors',
                ],
                2,
                datetime(2012, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: Unable to verify '
                    'OCSP response since response signing certificate could '
                    'not be validated'
                ),
            ),
        )

    def test_nist_40301_invalid_name_chaining_ee_test1(self):
        cert = self._load_cert_object('nist_pkits', 'certs', 'InvalidNameChainingTest1EE.crt')
        ca_certs = [self._load_nist_cert('TrustAnchorRootCertificate.crt')]
        other_certs = [
            self._load_nist_cert('GoodCACert.crt'),
        ]
        crls = [
            self._load_nist_crl('GoodCACRL.crl'),
            self._load_nist_crl('TrustAnchorRootCRL.crl'),
        ]

        # Hand build the path since we are testing an issuer mismatch that
        # will result in a path building error
        path = ValidationPath(cert)
        path.prepend(other_certs[0])
        path.prepend(ca_certs[0])

        self.assertEqual(3, len(path))

        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            crls=crls
        )

        expected = (
            'The path could not be validated because the end-entity certificate '
            'issuer name could not be matched'
        )
        with self.assertRaisesRegexp(PathValidationError, expected):
            validate_path(context, path)

    def test_nist_40302_invalid_name_chaining_order_test2(self):
        cert = self._load_cert_object('nist_pkits', 'certs', 'InvalidNameChainingOrderTest2EE.crt')
        ca_certs = [self._load_nist_cert('TrustAnchorRootCertificate.crt')]
        other_certs = [
            self._load_nist_cert('NameOrderingCACert.crt'),
        ]
        crls = [
            self._load_nist_crl('NameOrderCACRL.crl'),
            self._load_nist_crl('TrustAnchorRootCRL.crl'),
        ]

        # Hand build the path since we are testing an issuer mismatch that
        # will result in a path building error
        path = ValidationPath(cert)
        path.prepend(other_certs[0])
        path.prepend(ca_certs[0])

        self.assertEqual(3, len(path))

        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            crls=crls
        )

        expected = (
            'The path could not be validated because the end-entity certificate '
            'issuer name could not be matched'
        )
        with self.assertRaisesRegexp(PathValidationError, expected):
            validate_path(context, path)

    @data('nist_info', True)
    def nist(self, cert_filename, other_cert_files, crl_files, path_len, require_rev, excp_class, excp_msg):
        cert = self._load_nist_cert(cert_filename)
        ca_certs = [self._load_nist_cert('TrustAnchorRootCertificate.crt')]
        other_certs = [self._load_nist_cert(filename) for filename in other_cert_files]
        crls = [self._load_nist_crl(filename) for filename in crl_files]
        crls.append(self._load_nist_crl('TrustAnchorRootCRL.crl'))

        revocation_mode = "require" if require_rev else "hard-fail"

        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            crls=crls,
            revocation_mode=revocation_mode
        )

        paths = context.certificate_registry.build_paths(cert)
        self.assertEqual(1, len(paths))
        path = paths[0]
        self.assertEqual(path_len, len(path))

        if excp_class:
            with self.assertRaisesRegexp(excp_class, excp_msg):
                validate_path(context, path)
        else:
            validate_path(context, path)

    @staticmethod
    def nist_info():
        return (
            (
                '40101_valid_signatures_test1',
                'ValidCertificatePathTest1EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None
            ),
            (
                '40102_invalid_ca_signature_test2',
                'InvalidCASignatureTest2EE.crt',
                [
                    'BadSignedCACert.crt',
                ],
                [
                    'BadSignedCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because the signature of '
                    'intermediate certificate 1 could not be verified'
                ),
            ),
            (
                '40103_invalid_ee_signature_test3',
                'InvalidEESignatureTest3EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because the signature of '
                    'the end-entity certificate could not be verified'
                ),
            ),
            (
                '40104_valid_dsa_signatures_test4',
                'ValidDSASignaturesTest4EE.crt',
                [
                    'DSACACert.crt',
                ],
                [
                    'DSACACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40105_valid_dsa_parameter_inheritance_test5',
                'ValidDSAParameterInheritanceTest5EE.crt',
                [
                    'DSACACert.crt',
                    'DSAParametersInheritedCACert.crt',
                ],
                [
                    'DSAParametersInheritedCACRL.crl',
                    'DSACACRL.crl',
                ],
                4,
                False,
                None,
                None,
            ),
            (
                '40106_invalid_dsa_signature_test6',
                'InvalidDSASignatureTest6EE.crt',
                [
                    'DSACACert.crt',
                ],
                [
                    'DSACACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because the signature of '
                    'the end-entity certificate could not be verified'
                ),
            ),
            (
                '40201_invalid_ca_notbefore_date_test1',
                'InvalidCAnotBeforeDateTest1EE.crt',
                [
                    'BadnotBeforeDateCACert.crt',
                ],
                [
                    'BadnotBeforeDateCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate 1 '
                    'is not valid until 2047-01-01 12:01:00Z'
                )
            ),
            (
                '40202_invalid_ee_notbefore_date_test2',
                'InvalidEEnotBeforeDateTest2EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity certificate '
                    'is not valid until 2047-01-01 12:01:00Z'
                )
            ),
            (
                '40203_valid_pre2000_utc_notbefore_date_test3',
                'Validpre2000UTCnotBeforeDateTest3EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40204_valid_generalizedtime_notbefore_date_test4',
                'ValidGeneralizedTimenotBeforeDateTest4EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40205_invalid_ca_notafter_date_test5',
                'InvalidCAnotAfterDateTest5EE.crt',
                [
                    'BadnotAfterDateCACert.crt',
                ],
                [
                    'BadnotAfterDateCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate 1 '
                    'expired 2011-01-01 08:30:00Z'
                )
            ),
            (
                '40206_invalid_ee_notafter_date_test6',
                'InvalidEEnotAfterDateTest6EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity certificate '
                    'expired 2011-01-01 08:30:00Z'
                )
            ),
            (
                '40207_invalid_pre2000_utc_ee_notafter_date_test7',
                'Invalidpre2000UTCEEnotAfterDateTest7EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity certificate '
                    'expired 1999-01-01 12:01:00Z'
                )
            ),
            (
                '40208_valid_generalizedtime_notbefore_date_test8',
                'ValidGeneralizedTimenotAfterDateTest8EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40303_valid_name_chaining_whitespace_test3',
                'ValidNameChainingWhitespaceTest3EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40304_valid_name_chaining_whitespace_test4',
                'ValidNameChainingWhitespaceTest4EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40305_valid_name_chaining_capitalization_test5',
                'ValidNameChainingCapitalizationTest5EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40306_valid_name_chaining_uids_test6',
                'ValidNameUIDsTest6EE.crt',
                [
                    'UIDCACert.crt',
                ],
                [
                    'UIDCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40307_valid_rfc3280_mandatory_attribute_types_test7',
                'ValidRFC3280MandatoryAttributeTypesTest7EE.crt',
                [
                    'RFC3280MandatoryAttributeTypesCACert.crt',
                ],
                [
                    'RFC3280MandatoryAttributeTypesCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40308_valid_rfc3280_optional_attribute_types_test8',
                'ValidRFC3280OptionalAttributeTypesTest8EE.crt',
                [
                    'RFC3280OptionalAttributeTypesCACert.crt',
                ],
                [
                    'RFC3280OptionalAttributeTypesCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40309_valid_utf8string_encoded_names_test9',
                'ValidUTF8StringEncodedNamesTest9EE.crt',
                [
                    'UTF8StringEncodedNamesCACert.crt',
                ],
                [
                    'UTF8StringEncodedNamesCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40310_valid_rollover_from_printablestring_to_utf8string_test10',
                'ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt',
                [
                    'RolloverfromPrintableStringtoUTF8StringCACert.crt',
                ],
                [
                    'RolloverfromPrintableStringtoUTF8StringCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40311_valid_utf8string_case_insensitive_match_test11',
                'ValidUTF8StringCaseInsensitiveMatchTest11EE.crt',
                [
                    'UTF8StringCaseInsensitiveMatchCACert.crt',
                ],
                [
                    'UTF8StringCaseInsensitiveMatchCACRL.crl',
                ],
                3,
                False,
                None,
                None,
            ),
            (
                '40401_missing_crl_test1',
                'InvalidMissingCRLTest1EE.crt',
                [
                    'NoCRLCACert.crt',
                ],
                [
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                )
            ),
            (
                '40402_invalid_revoked_ca_test2',
                'InvalidRevokedCATest2EE.crt',
                [
                    'RevokedsubCACert.crt',
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                    'RevokedsubCACRL.crl',
                ],
                4,
                True,
                RevokedError,
                (
                    'CRL indicates intermediate certificate 2 was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40403_invalid_revoked_ee_test3',
                'InvalidRevokedEETest3EE.crt',
                [
                    'GoodCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:01 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40404_invalid_bad_crl_signature_test4',
                'InvalidBadCRLSignatureTest4EE.crt',
                [
                    'BadCRLSignatureCACert.crt',
                ],
                [
                    'BadCRLSignatureCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL signature could not '
                    'be verified'
                )
            ),
            (
                '40405_invalid_bad_crl_issuer_name_test5',
                'InvalidBadCRLIssuerNameTest5EE.crt',
                [
                    'BadCRLIssuerNameCACert.crt',
                ],
                [
                    'BadCRLIssuerNameCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                )
            ),
            (
                '40406_invalid_wrong_crl_test6',
                'InvalidWrongCRLTest6EE.crt',
                [
                    'WrongCRLCACert.crt',
                ],
                [
                    'WrongCRLCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                )
            ),
            (
                '40407_valid_two_crls_test7',
                'ValidTwoCRLsTest7EE.crt',
                [
                    'TwoCRLsCACert.crt',
                ],
                [
                    'TwoCRLsCAGoodCRL.crl',
                    'TwoCRLsCABadCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40408_invalid_unknown_crl_entry_extension_test8',
                'InvalidUnknownCRLEntryExtensionTest8EE.crt',
                [
                    'UnknownCRLEntryExtensionCACert.crt',
                ],
                [
                    'UnknownCRLEntryExtensionCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: One or more critical '
                    'extensions are present in the CRL entry for the certificate'
                )
            ),
            (
                '40409_invalid_unknown_crl_extension_test9',
                'InvalidUnknownCRLExtensionTest9EE.crt',
                [
                    'UnknownCRLExtensionCACert.crt',
                ],
                [
                    'UnknownCRLExtensionCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: One or more unrecognized '
                    'critical extensions are present in the CRL'
                )
            ),
            (
                '40410_invalid_unknown_crl_extension_test10',
                'InvalidUnknownCRLExtensionTest10EE.crt',
                [
                    'UnknownCRLExtensionCACert.crt',
                ],
                [
                    'UnknownCRLExtensionCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: One or more unrecognized '
                    'critical extensions are present in the CRL'
                )
            ),
            (
                '40411_invalid_old_crl_nextupdate_test11',
                'InvalidOldCRLnextUpdateTest11EE.crt',
                [
                    'OldCRLnextUpdateCACert.crt',
                ],
                [
                    'OldCRLnextUpdateCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL should have been '
                    'regenerated by the validation time'
                )
            ),
            (
                '40412_invalid_pre2000_crl_nextupdate_test12',
                'Invalidpre2000CRLnextUpdateTest12EE.crt',
                [
                    'pre2000CRLnextUpdateCACert.crt',
                ],
                [
                    'pre2000CRLnextUpdateCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL should have been '
                    'regenerated by the validation time'
                )
            ),
            (
                '40413_valid_generalizedtime_crl_nextupdate_test13',
                'ValidGeneralizedTimeCRLnextUpdateTest13EE.crt',
                [
                    'GeneralizedTimeCRLnextUpdateCACert.crt',
                ],
                [
                    'GeneralizedTimeCRLnextUpdateCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40414_valid_negative_serial_number_test14',
                'ValidNegativeSerialNumberTest14EE.crt',
                [
                    'NegativeSerialNumberCACert.crt',
                ],
                [
                    'NegativeSerialNumberCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40415_invalid_negative_serial_number_test15',
                'InvalidNegativeSerialNumberTest15EE.crt',
                [
                    'NegativeSerialNumberCACert.crt',
                ],
                [
                    'NegativeSerialNumberCACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40416_valid_long_serial_number_test16',
                'ValidLongSerialNumberTest16EE.crt',
                [
                    'LongSerialNumberCACert.crt',
                ],
                [
                    'LongSerialNumberCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40417_valid_long_serial_number_test17',
                'ValidLongSerialNumberTest17EE.crt',
                [
                    'LongSerialNumberCACert.crt',
                ],
                [
                    'LongSerialNumberCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40418_invalid_long_serial_number_test18',
                'InvalidLongSerialNumberTest18EE.crt',
                [
                    'LongSerialNumberCACert.crt',
                ],
                [
                    'LongSerialNumberCACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40419_valid_separate_certificate_and_crl_keys_test19',
                'ValidSeparateCertificateandCRLKeysTest19EE.crt',
                [
                    'SeparateCertificateandCRLKeysCertificateSigningCACert.crt',
                    'SeparateCertificateandCRLKeysCRLSigningCert.crt',
                ],
                [
                    'SeparateCertificateandCRLKeysCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40420_invalid_separate_certificate_and_crl_keys_test20',
                'InvalidSeparateCertificateandCRLKeysTest20EE.crt',
                [
                    'SeparateCertificateandCRLKeysCertificateSigningCACert.crt',
                    'SeparateCertificateandCRLKeysCRLSigningCert.crt',
                ],
                [
                    'SeparateCertificateandCRLKeysCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40421_invalid_separate_certificate_and_crl_keys_test21',
                'InvalidSeparateCertificateandCRLKeysTest21EE.crt',
                [
                    'SeparateCertificateandCRLKeysCA2CertificateSigningCACert.crt',
                    'SeparateCertificateandCRLKeysCA2CRLSigningCert.crt',
                ],
                [
                    'SeparateCertificateandCRLKeysCA2CRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the intermediate certificate 1 CRL issuer was '
                    'revoked at 08:30:00 on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40501_valid_basic_self_issued_old_with_new_test1',
                'ValidBasicSelfIssuedOldWithNewTest1EE.crt',
                [
                    'BasicSelfIssuedNewKeyOldWithNewCACert.crt',
                    'BasicSelfIssuedNewKeyCACert.crt',
                ],
                [
                    'BasicSelfIssuedNewKeyCACRL.crl',
                ],
                4,
                True,
                None,
                None,
            ),
            (
                '40502_invalid_basic_self_issued_old_with_new_test2',
                'InvalidBasicSelfIssuedOldWithNewTest2EE.crt',
                [
                    'BasicSelfIssuedNewKeyOldWithNewCACert.crt',
                    'BasicSelfIssuedNewKeyCACert.crt',
                ],
                [
                    'BasicSelfIssuedNewKeyCACRL.crl',
                ],
                4,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40503_valid_basic_self_issued_new_with_old_test3',
                'ValidBasicSelfIssuedNewWithOldTest3EE.crt',
                [
                    'BasicSelfIssuedOldKeyCACert.crt',
                    'BasicSelfIssuedOldKeyNewWithOldCACert.crt',
                ],
                [
                    'BasicSelfIssuedOldKeySelfIssuedCertCRL.crl',
                    'BasicSelfIssuedOldKeyCACRL.crl',
                ],
                4,
                True,
                None,
                None,
            ),
            (
                '40504_valid_basic_self_issued_new_with_old_test4',
                'ValidBasicSelfIssuedNewWithOldTest4EE.crt',
                [
                    'BasicSelfIssuedOldKeyCACert.crt',
                    'BasicSelfIssuedOldKeyNewWithOldCACert.crt',
                ],
                [
                    'BasicSelfIssuedOldKeySelfIssuedCertCRL.crl',
                    'BasicSelfIssuedOldKeyCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40505_invalid_basic_self_issued_new_with_old_test5',
                'InvalidBasicSelfIssuedNewWithOldTest5EE.crt',
                [
                    'BasicSelfIssuedOldKeyCACert.crt',
                    'BasicSelfIssuedOldKeyNewWithOldCACert.crt',
                ],
                [
                    'BasicSelfIssuedOldKeySelfIssuedCertCRL.crl',
                    'BasicSelfIssuedOldKeyCACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40506_valid_basic_self_issued_crl_signing_key_test6',
                'ValidBasicSelfIssuedCRLSigningKeyTest6EE.crt',
                [
                    'BasicSelfIssuedCRLSigningKeyCACert.crt',
                    'BasicSelfIssuedCRLSigningKeyCRLCert.crt',
                ],
                [
                    'BasicSelfIssuedCRLSigningKeyCRLCertCRL.crl',
                    'BasicSelfIssuedCRLSigningKeyCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40507_invalid_basic_self_issued_crl_signing_key_test7',
                'InvalidBasicSelfIssuedCRLSigningKeyTest7EE.crt',
                [
                    'BasicSelfIssuedCRLSigningKeyCACert.crt',
                    'BasicSelfIssuedCRLSigningKeyCRLCert.crt',
                ],
                [
                    'BasicSelfIssuedCRLSigningKeyCRLCertCRL.crl',
                    'BasicSelfIssuedCRLSigningKeyCACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                )
            ),
            (
                '40508_invalid_basic_self_issued_crl_signing_key_test8',
                'InvalidBasicSelfIssuedCRLSigningKeyTest8EE.crt',
                [
                    'BasicSelfIssuedCRLSigningKeyCACert.crt',
                    'BasicSelfIssuedCRLSigningKeyCRLCert.crt',
                ],
                [
                    'BasicSelfIssuedCRLSigningKeyCRLCertCRL.crl',
                    'BasicSelfIssuedCRLSigningKeyCACRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate '
                    '2 is not a CA'
                )
            ),
            (
                '40601_invalid_missing_basicconstraints_test1',
                'InvalidMissingbasicConstraintsTest1EE.crt',
                [
                    'MissingbasicConstraintsCACert.crt',
                ],
                [
                    'MissingbasicConstraintsCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate '
                    '1 is not a CA'
                )
            ),
            (
                '40602_invalid_ca_false_test2',
                'InvalidcAFalseTest2EE.crt',
                [
                    'basicConstraintsCriticalcAFalseCACert.crt',
                ],
                [
                    'basicConstraintsCriticalcAFalseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate '
                    '1 is not a CA'
                )
            ),
            (
                '40603_invalid_ca_false_test3',
                'InvalidcAFalseTest3EE.crt',
                [
                    'basicConstraintsNotCriticalcAFalseCACert.crt',
                ],
                [
                    'basicConstraintsNotCriticalcAFalseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate '
                    '1 is not a CA'
                )
            ),
            (
                '40604_valid_basicconstraints_not_critical_test4',
                'ValidbasicConstraintsNotCriticalTest4EE.crt',
                [
                    'basicConstraintsNotCriticalCACert.crt',
                ],
                [
                    'basicConstraintsNotCriticalCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40605_invalid_pathlenconstraint_test5',
                'InvalidpathLenConstraintTest5EE.crt',
                [
                    'pathLenConstraint0CACert.crt',
                    'pathLenConstraint0subCACert.crt',
                ],
                [
                    'pathLenConstraint0CACRL.crl',
                    'pathLenConstraint0subCACRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40606_invalid_pathlenconstraint_test6',
                'InvalidpathLenConstraintTest6EE.crt',
                [
                    'pathLenConstraint0CACert.crt',
                    'pathLenConstraint0subCACert.crt',
                ],
                [
                    'pathLenConstraint0CACRL.crl',
                    'pathLenConstraint0subCACRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40607_valid_pathlenconstraint_test7',
                'ValidpathLenConstraintTest7EE.crt',
                [
                    'pathLenConstraint0CACert.crt',
                ],
                [
                    'pathLenConstraint0CACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40608_valid_pathlenconstraint_test8',
                'ValidpathLenConstraintTest8EE.crt',
                [
                    'pathLenConstraint0CACert.crt',
                ],
                [
                    'pathLenConstraint0CACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40609_invalid_pathlenconstraint_test9',
                'InvalidpathLenConstraintTest9EE.crt',
                [
                    'pathLenConstraint6CACert.crt',
                    'pathLenConstraint6subCA0Cert.crt',
                    'pathLenConstraint6subsubCA00Cert.crt',
                ],
                [
                    'pathLenConstraint6CACRL.crl',
                    'pathLenConstraint6subCA0CRL.crl',
                    'pathLenConstraint6subsubCA00CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40610_invalid_pathlenconstraint_test10',
                'InvalidpathLenConstraintTest10EE.crt',
                [
                    'pathLenConstraint6CACert.crt',
                    'pathLenConstraint6subCA0Cert.crt',
                    'pathLenConstraint6subsubCA00Cert.crt',
                ],
                [
                    'pathLenConstraint6CACRL.crl',
                    'pathLenConstraint6subCA0CRL.crl',
                    'pathLenConstraint6subsubCA00CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40611_invalid_pathlenconstraint_test11',
                'InvalidpathLenConstraintTest11EE.crt',
                [
                    'pathLenConstraint6CACert.crt',
                    'pathLenConstraint6subCA1Cert.crt',
                    'pathLenConstraint6subsubCA11Cert.crt',
                    'pathLenConstraint6subsubsubCA11XCert.crt',
                ],
                [
                    'pathLenConstraint6CACRL.crl',
                    'pathLenConstraint6subCA1CRL.crl',
                    'pathLenConstraint6subsubCA11CRL.crl',
                    'pathLenConstraint6subsubsubCA11XCRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40612_invalid_pathlenconstraint_test12',
                'InvalidpathLenConstraintTest12EE.crt',
                [
                    'pathLenConstraint6CACert.crt',
                    'pathLenConstraint6subCA1Cert.crt',
                    'pathLenConstraint6subsubCA11Cert.crt',
                    'pathLenConstraint6subsubsubCA11XCert.crt',
                ],
                [
                    'pathLenConstraint6CACRL.crl',
                    'pathLenConstraint6subCA1CRL.crl',
                    'pathLenConstraint6subsubCA11CRL.crl',
                    'pathLenConstraint6subsubsubCA11XCRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40613_valid_pathlenconstraint_test13',
                'ValidpathLenConstraintTest13EE.crt',
                [
                    'pathLenConstraint6CACert.crt',
                    'pathLenConstraint6subCA4Cert.crt',
                    'pathLenConstraint6subsubCA41Cert.crt',
                    'pathLenConstraint6subsubsubCA41XCert.crt',
                ],
                [
                    'pathLenConstraint6CACRL.crl',
                    'pathLenConstraint6subCA4CRL.crl',
                    'pathLenConstraint6subsubCA41CRL.crl',
                    'pathLenConstraint6subsubsubCA41XCRL.crl',
                ],
                6,
                True,
                None,
                None,
            ),
            (
                '40614_valid_pathlenconstraint_test14',
                'ValidpathLenConstraintTest14EE.crt',
                [
                    'pathLenConstraint6CACert.crt',
                    'pathLenConstraint6subCA4Cert.crt',
                    'pathLenConstraint6subsubCA41Cert.crt',
                    'pathLenConstraint6subsubsubCA41XCert.crt',
                ],
                [
                    'pathLenConstraint6CACRL.crl',
                    'pathLenConstraint6subCA4CRL.crl',
                    'pathLenConstraint6subsubCA41CRL.crl',
                    'pathLenConstraint6subsubsubCA41XCRL.crl',
                ],
                6,
                True,
                None,
                None,
            ),
            (
                '40615_valid_self_issued_pathlenconstraint_test15',
                'ValidSelfIssuedpathLenConstraintTest15EE.crt',
                [
                    'pathLenConstraint0CACert.crt',
                    'pathLenConstraint0SelfIssuedCACert.crt',
                ],
                [
                    'pathLenConstraint0CACRL.crl',
                ],
                4,
                True,
                None,
                None,
            ),
            (
                '40616_invalid_self_issued_pathlenconstraint_test16',
                'InvalidSelfIssuedpathLenConstraintTest16EE.crt',
                [
                    'pathLenConstraint0CACert.crt',
                    'pathLenConstraint0SelfIssuedCACert.crt',
                    'pathLenConstraint0subCA2Cert.crt',
                ],
                [
                    'pathLenConstraint0CACRL.crl',
                    'pathLenConstraint0subCA2CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because it exceeds the maximum '
                    'path length'
                )
            ),
            (
                '40617_valid_self_issued_pathlenconstraint_test17',
                'ValidSelfIssuedpathLenConstraintTest17EE.crt',
                [
                    'pathLenConstraint1CACert.crt',
                    'pathLenConstraint1SelfIssuedCACert.crt',
                    'pathLenConstraint1subCACert.crt',
                    'pathLenConstraint1SelfIssuedsubCACert.crt',
                ],
                [
                    'pathLenConstraint1CACRL.crl',
                    'pathLenConstraint1subCACRL.crl',
                ],
                6,
                True,
                None,
                None,
            ),
            (
                '40701_invalid_keyusage_critical_keycertsign_false_test1',
                'InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt',
                [
                    'keyUsageCriticalkeyCertSignFalseCACert.crt',
                ],
                [
                    'keyUsageCriticalkeyCertSignFalseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate '
                    '1 is not allowed to sign certificates'
                )
            ),
            (
                '40702_invalid_keyusage_not_critical_keycertsign_false_test2',
                'InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt',
                [
                    'keyUsageNotCriticalkeyCertSignFalseCACert.crt',
                ],
                [
                    'keyUsageNotCriticalkeyCertSignFalseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate certificate '
                    '1 is not allowed to sign certificates'
                )
            ),
            (
                '40703_valid_keyusage_not_critical_test3',
                'ValidkeyUsageNotCriticalTest3EE.crt',
                [
                    'keyUsageNotCriticalCACert.crt',
                ],
                [
                    'keyUsageNotCriticalCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '40704_invalid_keyusage_critical_crlsign_false_test4',
                'InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt',
                [
                    'keyUsageCriticalcRLSignFalseCACert.crt',
                ],
                [
                    'keyUsageCriticalcRLSignFalseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: The CRL issuer is not '
                    'authorized to sign CRLs'
                )
            ),
            (
                '40705_invalid_keyusage_not_critical_crlsign_false_test5',
                'InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt',
                [
                    'keyUsageNotCriticalcRLSignFalseCACert.crt',
                ],
                [
                    'keyUsageNotCriticalcRLSignFalseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: The CRL issuer is not '
                    'authorized to sign CRLs'
                )
            ),
            (
                '40802_all_certificates_no_policies_test2',
                'AllCertificatesNoPoliciesTest2EE.crt',
                [
                    'NoPoliciesCACert.crt',
                ],
                [
                    'NoPoliciesCACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '40803_different_policies_test3',
                'DifferentPoliciesTest3EE.crt',
                [
                    'GoodCACert.crt',
                    'PoliciesP2subCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                    'PoliciesP2subCACRL.crl',
                ],
                4,
                True,
                None,
                None
            ),
            (
                '40804_different_policies_test4',
                'DifferentPoliciesTest4EE.crt',
                [
                    'GoodCACert.crt',
                    'GoodsubCACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                    'GoodsubCACRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40805_different_policies_test5',
                'DifferentPoliciesTest5EE.crt',
                [
                    'GoodCACert.crt',
                    'PoliciesP2subCA2Cert.crt',
                ],
                [
                    'GoodCACRL.crl',
                    'PoliciesP2subCA2CRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40806_overlapping_policies_test3',
                'OverlappingPoliciesTest6EE.crt',
                [
                    'PoliciesP1234CACert.crt',
                    'PoliciesP1234subCAP123Cert.crt',
                    'PoliciesP1234subsubCAP123P12Cert.crt',
                ],
                [
                    'PoliciesP1234CACRL.crl',
                    'PoliciesP1234subCAP123CRL.crl',
                    'PoliciesP1234subsubCAP123P12CRL.crl',
                ],
                5,
                True,
                None,
                None
            ),
            (
                '40807_different_policies_test7',
                'DifferentPoliciesTest7EE.crt',
                [
                    'PoliciesP123CACert.crt',
                    'PoliciesP123subCAP12Cert.crt',
                    'PoliciesP123subsubCAP12P1Cert.crt',
                ],
                [
                    'PoliciesP123CACRL.crl',
                    'PoliciesP123subCAP12CRL.crl',
                    'PoliciesP123subsubCAP12P1CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40808_different_policies_test8',
                'DifferentPoliciesTest8EE.crt',
                [
                    'PoliciesP12CACert.crt',
                    'PoliciesP12subCAP1Cert.crt',
                    'PoliciesP12subsubCAP1P2Cert.crt',
                ],
                [
                    'PoliciesP12CACRL.crl',
                    'PoliciesP12subCAP1CRL.crl',
                    'PoliciesP12subsubCAP1P2CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for intermediate certificate 3'
                )
            ),
            (
                '40809_different_policies_test9',
                'DifferentPoliciesTest9EE.crt',
                [
                    'PoliciesP123CACert.crt',
                    'PoliciesP123subCAP12Cert.crt',
                    'PoliciesP123subsubCAP12P2Cert.crt',
                    'PoliciesP123subsubsubCAP12P2P1Cert.crt',
                ],
                [
                    'PoliciesP123CACRL.crl',
                    'PoliciesP123subCAP12CRL.crl',
                    'PoliciesP123subsubCAP2P2CRL.crl',
                    'PoliciesP123subsubsubCAP12P2P1CRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for intermediate certificate 4'
                )
            ),
            (
                '40810_all_certificates_same_policies_test10',
                'AllCertificatesSamePoliciesTest10EE.crt',
                [
                    'PoliciesP12CACert.crt',
                ],
                [
                    'PoliciesP12CACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '40811_all_certificates_any_policy_test10',
                'AllCertificatesanyPolicyTest11EE.crt',
                [
                    'anyPolicyCACert.crt',
                ],
                [
                    'anyPolicyCACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '40812_different_policies_test12',
                'DifferentPoliciesTest12EE.crt',
                [
                    'PoliciesP3CACert.crt',
                ],
                [
                    'PoliciesP3CACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40813_all_certificates_same_policies_test13',
                'AllCertificatesSamePoliciesTest13EE.crt',
                [
                    'PoliciesP123CACert.crt',
                ],
                [
                    'PoliciesP123CACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '40814_any_policy_test14',
                'AnyPolicyTest14EE.crt',
                [
                    'anyPolicyCACert.crt',
                ],
                [
                    'anyPolicyCACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '40901_valid_require_explicit_policy_test1',
                'ValidrequireExplicitPolicyTest1EE.crt',
                [
                    'requireExplicitPolicy10CACert.crt',
                    'requireExplicitPolicy10subCACert.crt',
                    'requireExplicitPolicy10subsubCACert.crt',
                    'requireExplicitPolicy10subsubsubCACert.crt',
                ],
                [
                    'requireExplicitPolicy10CACRL.crl',
                    'requireExplicitPolicy10subCACRL.crl',
                    'requireExplicitPolicy10subsubCACRL.crl',
                    'requireExplicitPolicy10subsubsubCACRL.crl',
                ],
                6,
                True,
                None,
                None
            ),
            (
                '40902_valid_require_explicit_policy_test2',
                'ValidrequireExplicitPolicyTest2EE.crt',
                [
                    'requireExplicitPolicy5CACert.crt',
                    'requireExplicitPolicy5subCACert.crt',
                    'requireExplicitPolicy5subsubCACert.crt',
                    'requireExplicitPolicy5subsubsubCACert.crt',
                ],
                [
                    'requireExplicitPolicy5CACRL.crl',
                    'requireExplicitPolicy5subCACRL.crl',
                    'requireExplicitPolicy5subsubCACRL.crl',
                    'requireExplicitPolicy5subsubsubCACRL.crl',
                ],
                6,
                True,
                None,
                None
            ),
            (
                '40903_invalid_require_explicit_policy_test3',
                'InvalidrequireExplicitPolicyTest3EE.crt',
                [
                    'requireExplicitPolicy4CACert.crt',
                    'requireExplicitPolicy4subCACert.crt',
                    'requireExplicitPolicy4subsubCACert.crt',
                    'requireExplicitPolicy4subsubsubCACert.crt',
                ],
                [
                    'requireExplicitPolicy4CACRL.crl',
                    'requireExplicitPolicy4subCACRL.crl',
                    'requireExplicitPolicy4subsubCACRL.crl',
                    'requireExplicitPolicy4subsubsubCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40904_valid_require_explicit_policy_test4',
                'ValidrequireExplicitPolicyTest4EE.crt',
                [
                    'requireExplicitPolicy0CACert.crt',
                    'requireExplicitPolicy0subCACert.crt',
                    'requireExplicitPolicy0subsubCACert.crt',
                    'requireExplicitPolicy0subsubsubCACert.crt',
                ],
                [
                    'requireExplicitPolicy0CACRL.crl',
                    'requireExplicitPolicy0subCACRL.crl',
                    'requireExplicitPolicy0subsubCACRL.crl',
                    'requireExplicitPolicy0subsubsubCACRL.crl',
                ],
                6,
                True,
                None,
                None
            ),
            (
                '40905_invalid_require_explicit_policy_test5',
                'InvalidrequireExplicitPolicyTest5EE.crt',
                [
                    'requireExplicitPolicy7CACert.crt',
                    'requireExplicitPolicy7subCARE2Cert.crt',
                    'requireExplicitPolicy7subsubCARE2RE4Cert.crt',
                    'requireExplicitPolicy7subsubsubCARE2RE4Cert.crt',
                ],
                [
                    'requireExplicitPolicy7CACRL.crl',
                    'requireExplicitPolicy7subCARE2CRL.crl',
                    'requireExplicitPolicy7subsubCARE2RE4CRL.crl',
                    'requireExplicitPolicy7subsubsubCARE2RE4CRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40906_valid_self_issued_require_explicit_policy_test6',
                'ValidSelfIssuedrequireExplicitPolicyTest6EE.crt',
                [
                    'requireExplicitPolicy2CACert.crt',
                    'requireExplicitPolicy2SelfIssuedCACert.crt',
                ],
                [
                    'requireExplicitPolicy2CACRL.crl',
                ],
                4,
                True,
                None,
                None
            ),
            (
                '40907_invalid_self_issued_require_explicit_policy_test7',
                'InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt',
                [
                    'requireExplicitPolicy2CACert.crt',
                    'requireExplicitPolicy2SelfIssuedCACert.crt',
                    'requireExplicitPolicy2subCACert.crt',
                ],
                [
                    'requireExplicitPolicy2CACRL.crl',
                    'requireExplicitPolicy2subCACRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '40908_invalid_self_issued_require_explicit_policy_test8',
                'InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt',
                [
                    'requireExplicitPolicy2CACert.crt',
                    'requireExplicitPolicy2SelfIssuedCACert.crt',
                    'requireExplicitPolicy2subCACert.crt',
                    'requireExplicitPolicy2SelfIssuedsubCACert.crt',
                ],
                [
                    'requireExplicitPolicy2CACRL.crl',
                    'requireExplicitPolicy2subCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41002_invalid_policy_mapping_test2',
                'InvalidPolicyMappingTest2EE.crt',
                [
                    'Mapping1to2CACert.crt',
                ],
                [
                    'Mapping1to2CACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41004_invalid_policy_mapping_test4',
                'InvalidPolicyMappingTest4EE.crt',
                [
                    'P12Mapping1to3CACert.crt',
                    'P12Mapping1to3subCACert.crt',
                    'P12Mapping1to3subsubCACert.crt',
                ],
                [
                    'P12Mapping1to3CACRL.crl',
                    'P12Mapping1to3subCACRL.crl',
                    'P12Mapping1to3subsubCACRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41007_invalid_mapping_from_any_policy_test7',
                'InvalidMappingFromanyPolicyTest7EE.crt',
                [
                    'MappingFromanyPolicyCACert.crt',
                ],
                [
                    'MappingFromanyPolicyCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate '
                    'certificate 1 contains a policy mapping for the '
                    '"any policy"'
                )
            ),
            (
                '41008_invalid_mapping_to_any_policy_test8',
                'InvalidMappingToanyPolicyTest8EE.crt',
                [
                    'MappingToanyPolicyCACert.crt',
                ],
                [
                    'MappingToanyPolicyCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because intermediate '
                    'certificate 1 contains a policy mapping for the '
                    '"any policy"'
                )
            ),
            (
                '41009_valid_policy_mapping_test9',
                'ValidPolicyMappingTest9EE.crt',
                [
                    'PanyPolicyMapping1to2CACert.crt',
                ],
                [
                    'PanyPolicyMapping1to2CACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '41010_invalid_policy_mapping_test10',
                'InvalidPolicyMappingTest10EE.crt',
                [
                    'GoodCACert.crt',
                    'GoodsubCAPanyPolicyMapping1to2CACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                    'GoodsubCAPanyPolicyMapping1to2CACRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41011_valid_policy_mapping_test11',
                'ValidPolicyMappingTest11EE.crt',
                [
                    'GoodCACert.crt',
                    'GoodsubCAPanyPolicyMapping1to2CACert.crt',
                ],
                [
                    'GoodCACRL.crl',
                    'GoodsubCAPanyPolicyMapping1to2CACRL.crl'
                ],
                4,
                True,
                None,
                None
            ),
            (
                '41013_valid_policy_mapping_test13',
                'ValidPolicyMappingTest13EE.crt',
                [
                    'P1anyPolicyMapping1to2CACert.crt',
                ],
                [
                    'P1anyPolicyMapping1to2CACRL.crl'
                ],
                3,
                True,
                None,
                None
            ),
            (
                '41014_valid_policy_mapping_test14',
                'ValidPolicyMappingTest14EE.crt',
                [
                    'P1anyPolicyMapping1to2CACert.crt',
                ],
                [
                    'P1anyPolicyMapping1to2CACRL.crl'
                ],
                3,
                True,
                None,
                None
            ),
            (
                '41101_invalid_inhibit_policy_mapping_test1',
                'InvalidinhibitPolicyMappingTest1EE.crt',
                [
                    'inhibitPolicyMapping0CACert.crt',
                    'inhibitPolicyMapping0subCACert.crt',
                ],
                [
                    'inhibitPolicyMapping0CACRL.crl',
                    'inhibitPolicyMapping0subCACRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41102_valid_inhibit_policy_mapping_test2',
                'ValidinhibitPolicyMappingTest2EE.crt',
                [
                    'inhibitPolicyMapping1P12CACert.crt',
                    'inhibitPolicyMapping1P12subCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P12CACRL.crl',
                    'inhibitPolicyMapping1P12subCACRL.crl',
                ],
                4,
                True,
                None,
                None
            ),
            (
                '41103_invalid_inhibit_policy_mapping_test3',
                'InvalidinhibitPolicyMappingTest3EE.crt',
                [
                    'inhibitPolicyMapping1P12CACert.crt',
                    'inhibitPolicyMapping1P12subCACert.crt',
                    'inhibitPolicyMapping1P12subsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P12CACRL.crl',
                    'inhibitPolicyMapping1P12subCACRL.crl',
                    'inhibitPolicyMapping1P12subsubCACRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41104_valid_inhibit_policy_mapping_test4',
                'ValidinhibitPolicyMappingTest4EE.crt',
                [
                    'inhibitPolicyMapping1P12CACert.crt',
                    'inhibitPolicyMapping1P12subCACert.crt',
                    'inhibitPolicyMapping1P12subsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P12CACRL.crl',
                    'inhibitPolicyMapping1P12subCACRL.crl',
                    'inhibitPolicyMapping1P12subsubCACRL.crl',
                ],
                5,
                True,
                None,
                None
            ),
            (
                '41105_invalid_inhibit_policy_mapping_test5',
                'InvalidinhibitPolicyMappingTest5EE.crt',
                [
                    'inhibitPolicyMapping5CACert.crt',
                    'inhibitPolicyMapping5subCACert.crt',
                    'inhibitPolicyMapping5subsubCACert.crt',
                    'inhibitPolicyMapping5subsubsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping5CACRL.crl',
                    'inhibitPolicyMapping5subCACRL.crl',
                    'inhibitPolicyMapping5subsubCACRL.crl',
                    'inhibitPolicyMapping5subsubsubCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41106_invalid_inhibit_policy_mapping_test6',
                'InvalidinhibitPolicyMappingTest6EE.crt',
                [
                    'inhibitPolicyMapping1P12CACert.crt',
                    'inhibitPolicyMapping1P12subCAIPM5Cert.crt',
                    'inhibitPolicyMapping1P12subsubCAIPM5Cert.crt',
                ],
                [
                    'inhibitPolicyMapping1P12CACRL.crl',
                    'inhibitPolicyMapping1P12subCAIPM5CRL.crl',
                    'inhibitPolicyMapping1P12subsubCAIPM5CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41107_valid_self_issued_inhibit_policy_mapping_test7',
                'ValidSelfIssuedinhibitPolicyMappingTest7EE.crt',
                [
                    'inhibitPolicyMapping1P1CACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedCACert.crt',
                    'inhibitPolicyMapping1P1subCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P1CACRL.crl',
                    'inhibitPolicyMapping1P1subCACRL.crl',
                ],
                5,
                True,
                None,
                None
            ),
            (
                '41108_invalid_self_issued_inhibit_policy_mapping_test8',
                'InvalidSelfIssuedinhibitPolicyMappingTest8EE.crt',
                [
                    'inhibitPolicyMapping1P1CACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedCACert.crt',
                    'inhibitPolicyMapping1P1subCACert.crt',
                    'inhibitPolicyMapping1P1subsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P1CACRL.crl',
                    'inhibitPolicyMapping1P1subCACRL.crl',
                    'inhibitPolicyMapping1P1subsubCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41109_invalid_self_issued_inhibit_policy_mapping_test9',
                'InvalidSelfIssuedinhibitPolicyMappingTest9EE.crt',
                [
                    'inhibitPolicyMapping1P1CACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedCACert.crt',
                    'inhibitPolicyMapping1P1subCACert.crt',
                    'inhibitPolicyMapping1P1subsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P1CACRL.crl',
                    'inhibitPolicyMapping1P1subCACRL.crl',
                    'inhibitPolicyMapping1P1subsubCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41110_invalid_self_issued_inhibit_policy_mapping_test10',
                'InvalidSelfIssuedinhibitPolicyMappingTest10EE.crt',
                [
                    'inhibitPolicyMapping1P1CACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedCACert.crt',
                    'inhibitPolicyMapping1P1subCACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P1CACRL.crl',
                    'inhibitPolicyMapping1P1subCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41111_invalid_self_issued_inhibit_policy_mapping_test11',
                'InvalidSelfIssuedinhibitPolicyMappingTest11EE.crt',
                [
                    'inhibitPolicyMapping1P1CACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedCACert.crt',
                    'inhibitPolicyMapping1P1subCACert.crt',
                    'inhibitPolicyMapping1P1SelfIssuedsubCACert.crt',
                ],
                [
                    'inhibitPolicyMapping1P1CACRL.crl',
                    'inhibitPolicyMapping1P1subCACRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41201_invalid_inhibit_any_policy_test1',
                'InvalidinhibitAnyPolicyTest1EE.crt',
                [
                    'inhibitAnyPolicy0CACert.crt',
                ],
                [
                    'inhibitAnyPolicy0CACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41202_valid_inhibit_any_policy_test2',
                'ValidinhibitAnyPolicyTest2EE.crt',
                [
                    'inhibitAnyPolicy0CACert.crt',
                ],
                [
                    'inhibitAnyPolicy0CACRL.crl',
                ],
                3,
                True,
                None,
                None
            ),
            (
                '41203_inhibit_any_policy_test3',
                'inhibitAnyPolicyTest3EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1subCA1Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCA1CRL.crl',
                ],
                4,
                True,
                None,
                None
            ),
            (
                '41204_invalid_inhibit_any_policy_test4',
                'InvalidinhibitAnyPolicyTest4EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1subCA1Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCA1CRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41205_invalid_inhibit_any_policy_test5',
                'InvalidinhibitAnyPolicyTest5EE.crt',
                [
                    'inhibitAnyPolicy5CACert.crt',
                    'inhibitAnyPolicy5subCACert.crt',
                    'inhibitAnyPolicy5subsubCACert.crt',
                ],
                [
                    'inhibitAnyPolicy5CACRL.crl',
                    'inhibitAnyPolicy5subCACRL.crl',
                    'inhibitAnyPolicy5subsubCACRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41206_invalid_inhibit_any_policy_test6',
                'InvalidinhibitAnyPolicyTest6EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1subCAIAP5Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCAIAP5CRL.crl',
                ],
                4,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41207_valid_self_issued_inhibit_any_policy_test7',
                'ValidSelfIssuedinhibitAnyPolicyTest7EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1SelfIssuedCACert.crt',
                    'inhibitAnyPolicy1subCA2Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCA2CRL.crl',
                ],
                5,
                True,
                None,
                None
            ),
            (
                '41208_invalid_self_issued_inhibit_any_policy_test8',
                'InvalidSelfIssuedinhibitAnyPolicyTest8EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1SelfIssuedCACert.crt',
                    'inhibitAnyPolicy1subCA2Cert.crt',
                    'inhibitAnyPolicy1subsubCA2Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCA2CRL.crl',
                    'inhibitAnyPolicy1subsubCA2CRL.crl',
                ],
                6,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for intermediate certificate 4'
                )
            ),
            (
                '41209_valid_self_issued_inhibit_any_policy_test9',
                'ValidSelfIssuedinhibitAnyPolicyTest9EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1SelfIssuedCACert.crt',
                    'inhibitAnyPolicy1subCA2Cert.crt',
                    'inhibitAnyPolicy1SelfIssuedsubCA2Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCA2CRL.crl',
                ],
                6,
                True,
                None,
                None
            ),
            (
                '41210_invalid_self_issued_inhibit_any_policy_test10',
                'InvalidSelfIssuedinhibitAnyPolicyTest10EE.crt',
                [
                    'inhibitAnyPolicy1CACert.crt',
                    'inhibitAnyPolicy1SelfIssuedCACert.crt',
                    'inhibitAnyPolicy1subCA2Cert.crt',
                ],
                [
                    'inhibitAnyPolicy1CACRL.crl',
                    'inhibitAnyPolicy1subCA2CRL.crl',
                ],
                5,
                True,
                PathValidationError,
                (
                    'The path could not be validated because there is no valid '
                    'set of policies for the end-entity certificate'
                )
            ),
            (
                '41401_valid_distributionpoint_test1',
                'ValiddistributionPointTest1EE.crt',
                [
                    'distributionPoint1CACert.crt',
                ],
                [
                    'distributionPoint1CACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41402_invalid_distributionpoint_test2',
                'InvaliddistributionPointTest2EE.crt',
                [
                    'distributionPoint1CACert.crt',
                ],
                [
                    'distributionPoint1CACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41403_invalid_distributionpoint_test3',
                'InvaliddistributionPointTest3EE.crt',
                [
                    'distributionPoint1CACert.crt',
                ],
                [
                    'distributionPoint1CACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41404_valid_distributionpoint_test4',
                'ValiddistributionPointTest4EE.crt',
                [
                    'distributionPoint1CACert.crt',
                ],
                [
                    'distributionPoint1CACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41405_valid_distributionpoint_test5',
                'ValiddistributionPointTest5EE.crt',
                [
                    'distributionPoint2CACert.crt',
                ],
                [
                    'distributionPoint2CACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41406_invalid_distributionpoint_test6',
                'InvaliddistributionPointTest6EE.crt',
                [
                    'distributionPoint2CACert.crt',
                ],
                [
                    'distributionPoint2CACRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41407_valid_distributionpoint_test7',
                'ValiddistributionPointTest7EE.crt',
                [
                    'distributionPoint2CACert.crt',
                ],
                [
                    'distributionPoint2CACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41408_invalid_distributionpoint_test8',
                'InvaliddistributionPointTest8EE.crt',
                [
                    'distributionPoint2CACert.crt',
                ],
                [
                    'distributionPoint2CACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41409_invalid_distributionpoint_test9',
                'InvaliddistributionPointTest9EE.crt',
                [
                    'distributionPoint2CACert.crt',
                ],
                [
                    'distributionPoint2CACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41410_valid_no_issuingdistributionpoint_test10',
                'ValidNoissuingDistributionPointTest10EE.crt',
                [
                    'NoissuingDistributionPointCACert.crt',
                ],
                [
                    'NoissuingDistributionPointCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41411_invalid_onlycontainsusercerts_crl_test11',
                'InvalidonlyContainsUserCertsTest11EE.crt',
                [
                    'onlyContainsUserCertsCACert.crt',
                ],
                [
                    'onlyContainsUserCertsCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL only contains '
                    'end-entity certificates and certificate is a CA certificate'
                ),
            ),
            (
                '41412_invalid_onlycontainscacerts_crl_test12',
                'InvalidonlyContainsCACertsTest12EE.crt',
                [
                    'onlyContainsCACertsCACert.crt',
                ],
                [
                    'onlyContainsCACertsCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL only contains '
                    'CA certificates and certificate is an end-entity certificate'
                ),
            ),
            (
                '41413_valid_onlycontainscacerts_crl_test13',
                'ValidonlyContainsCACertsTest13EE.crt',
                [
                    'onlyContainsCACertsCACert.crt',
                ],
                [
                    'onlyContainsCACertsCACRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41414_invalid_onlycontainsattributecerts_crl_test14',
                'InvalidonlyContainsAttributeCertsTest14EE.crt',
                [
                    'onlyContainsAttributeCertsCACert.crt',
                ],
                [
                    'onlyContainsAttributeCertsCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL only contains attribute '
                    'certificates'
                ),
            ),
            (
                '41415_invalid_onlysomereasons_test15',
                'InvalidonlySomeReasonsTest15EE.crt',
                [
                    'onlySomeReasonsCA1Cert.crt',
                ],
                [
                    'onlySomeReasonsCA1compromiseCRL.crl',
                    'onlySomeReasonsCA1otherreasonsCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41416_invalid_onlysomereasons_test16',
                'InvalidonlySomeReasonsTest16EE.crt',
                [
                    'onlySomeReasonsCA1Cert.crt',
                ],
                [
                    'onlySomeReasonsCA1compromiseCRL.crl',
                    'onlySomeReasonsCA1otherreasonsCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a certificate hold'
                ),
            ),
            (
                '41417_invalid_onlysomereasons_test17',
                'InvalidonlySomeReasonsTest17EE.crt',
                [
                    'onlySomeReasonsCA2Cert.crt',
                ],
                [
                    'onlySomeReasonsCA2CRL1.crl',
                    'onlySomeReasonsCA2CRL2.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: The available CRLs do not '
                    'cover all revocation reasons'
                ),
            ),
            (
                '41418_valid_onlysomereasons_test18',
                'ValidonlySomeReasonsTest18EE.crt',
                [
                    'onlySomeReasonsCA3Cert.crt',
                ],
                [
                    'onlySomeReasonsCA3compromiseCRL.crl',
                    'onlySomeReasonsCA3otherreasonsCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41419_valid_onlysomereasons_test19',
                'ValidonlySomeReasonsTest19EE.crt',
                [
                    'onlySomeReasonsCA4Cert.crt',
                ],
                [
                    'onlySomeReasonsCA4compromiseCRL.crl',
                    'onlySomeReasonsCA4otherreasonsCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41420_invalid_onlysomereasons_test20',
                'InvalidonlySomeReasonsTest20EE.crt',
                [
                    'onlySomeReasonsCA4Cert.crt',
                ],
                [
                    'onlySomeReasonsCA4compromiseCRL.crl',
                    'onlySomeReasonsCA4otherreasonsCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41421_invalid_onlysomereasons_test21',
                'InvalidonlySomeReasonsTest21EE.crt',
                [
                    'onlySomeReasonsCA4Cert.crt',
                ],
                [
                    'onlySomeReasonsCA4compromiseCRL.crl',
                    'onlySomeReasonsCA4otherreasonsCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to an affiliation change'
                ),
            ),
            (
                '41422_valid_idp_with_indirectcrl_test22',
                'ValidIDPwithindirectCRLTest22EE.crt',
                [
                    'indirectCRLCA1Cert.crt',
                ],
                [
                    'indirectCRLCA1CRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41423_invalid_idp_with_indirectcrl_test23',
                'InvalidIDPwithindirectCRLTest23EE.crt',
                [
                    'indirectCRLCA1Cert.crt',
                ],
                [
                    'indirectCRLCA1CRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41424_valid_idp_with_indirectcrl_test24',
                'ValidIDPwithindirectCRLTest24EE.crt',
                [
                    'indirectCRLCA1Cert.crt',
                    'indirectCRLCA2Cert.crt',
                ],
                [
                    'indirectCRLCA1CRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41425_valid_idp_with_indirectcrl_test25',
                'ValidIDPwithindirectCRLTest25EE.crt',
                [
                    'indirectCRLCA1Cert.crt',
                    'indirectCRLCA2Cert.crt',
                ],
                [
                    'indirectCRLCA1CRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41426_invalid_idp_with_indirectcrl_test26',
                'InvalidIDPwithindirectCRLTest26EE.crt',
                [
                    'indirectCRLCA1Cert.crt',
                    'indirectCRLCA2Cert.crt',
                ],
                [
                    'indirectCRLCA1CRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41427_invalid_crlissuer_test27',
                'InvalidcRLIssuerTest27EE.crt',
                [
                    'GoodCACert.crt',
                    'indirectCRLCA2Cert.crt',
                ],
                [
                    'GoodCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41428_valid_crlissuer_test28',
                'ValidcRLIssuerTest28EE.crt',
                [
                    'indirectCRLCA3Cert.crt',
                    'indirectCRLCA3cRLIssuerCert.crt',
                ],
                [
                    'indirectCRLCA3CRL.crl',
                    'indirectCRLCA3cRLIssuerCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41429_valid_crlissuer_test29',
                'ValidcRLIssuerTest29EE.crt',
                [
                    'indirectCRLCA3Cert.crt',
                    'indirectCRLCA3cRLIssuerCert.crt',
                ],
                [
                    'indirectCRLCA3CRL.crl',
                    'indirectCRLCA3cRLIssuerCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41430_valid_crlissuer_test30',
                'ValidcRLIssuerTest30EE.crt',
                [
                    'indirectCRLCA4Cert.crt',
                    'indirectCRLCA4cRLIssuerCert.crt',
                ],
                [
                    'indirectCRLCA4cRLIssuerCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41431_invalid_crlissuer_test31',
                'InvalidcRLIssuerTest31EE.crt',
                [
                    'indirectCRLCA5Cert.crt',
                    'indirectCRLCA6Cert.crt',
                ],
                [
                    'indirectCRLCA5CRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41432_invalid_crlissuer_test32',
                'InvalidcRLIssuerTest32EE.crt',
                [
                    'indirectCRLCA5Cert.crt',
                    'indirectCRLCA6Cert.crt',
                ],
                [
                    'indirectCRLCA5CRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41433_valid_crlissuer_test33',
                'ValidcRLIssuerTest33EE.crt',
                [
                    'indirectCRLCA5Cert.crt',
                    'indirectCRLCA6Cert.crt',
                ],
                [
                    'indirectCRLCA5CRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41434_invalid_crlissuer_test34',
                'InvalidcRLIssuerTest34EE.crt',
                [
                    'indirectCRLCA5Cert.crt',
                ],
                [
                    'indirectCRLCA5CRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41435_invalid_crlissuer_test35',
                'InvalidcRLIssuerTest35EE.crt',
                [
                    'indirectCRLCA5Cert.crt',
                ],
                [
                    'indirectCRLCA5CRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41501_invalid_deltacrlindicator_no_base_set_test1',
                'InvaliddeltaCRLIndicatorNoBaseTest1EE.crt',
                [
                    'deltaCRLIndicatorNoBaseCACert.crt',
                ],
                [
                    'deltaCRLIndicatorNoBaseCACRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because no revocation information '
                    'could be found for the end-entity certificate'
                ),
            ),
            (
                '41502_valid_deltacrl_test2',
                'ValiddeltaCRLTest2EE.crt',
                [
                    'deltaCRLCA1Cert.crt',
                ],
                [
                    'deltaCRLCA1CRL.crl',
                    'deltaCRLCA1deltaCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41503_invalid_deltacrl_test3',
                'InvaliddeltaCRLTest3EE.crt',
                [
                    'deltaCRLCA1Cert.crt',
                ],
                [
                    'deltaCRLCA1CRL.crl',
                    'deltaCRLCA1deltaCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41504_invalid_deltacrl_test4',
                'InvaliddeltaCRLTest4EE.crt',
                [
                    'deltaCRLCA1Cert.crt',
                ],
                [
                    'deltaCRLCA1CRL.crl',
                    'deltaCRLCA1deltaCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-06-01, due to a compromised key'
                ),
            ),
            (
                '41505_valid_deltacrl_test5',
                'ValiddeltaCRLTest5EE.crt',
                [
                    'deltaCRLCA1Cert.crt',
                ],
                [
                    'deltaCRLCA1CRL.crl',
                    'deltaCRLCA1deltaCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41506_invalid_deltacrl_test6',
                'InvaliddeltaCRLTest6EE.crt',
                [
                    'deltaCRLCA1Cert.crt',
                ],
                [
                    'deltaCRLCA1CRL.crl',
                    'deltaCRLCA1deltaCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41507_valid_deltacrl_test7',
                'ValiddeltaCRLTest7EE.crt',
                [
                    'deltaCRLCA1Cert.crt',
                ],
                [
                    'deltaCRLCA1CRL.crl',
                    'deltaCRLCA1deltaCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41508_valid_deltacrl_test8',
                'ValiddeltaCRLTest8EE.crt',
                [
                    'deltaCRLCA2Cert.crt',
                ],
                [
                    'deltaCRLCA2CRL.crl',
                    'deltaCRLCA2deltaCRL.crl',
                ],
                3,
                True,
                None,
                None,
            ),
            (
                '41509_invalid_deltacrl_test9',
                'InvaliddeltaCRLTest9EE.crt',
                [
                    'deltaCRLCA2Cert.crt',
                ],
                [
                    'deltaCRLCA2CRL.crl',
                    'deltaCRLCA2deltaCRL.crl',
                ],
                3,
                True,
                RevokedError,
                (
                    'CRL indicates the end-entity certificate was revoked at 08:30:00 '
                    'on 2010-01-01, due to a compromised key'
                ),
            ),
            (
                '41510_invalid_deltacrl_test10',
                'InvaliddeltaCRLTest10EE.crt',
                [
                    'deltaCRLCA3Cert.crt',
                ],
                [
                    'deltaCRLCA3CRL.crl',
                    'deltaCRLCA3deltaCRL.crl',
                ],
                3,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate revocation checks failed: CRL should have been '
                    'regenerated by the validation time'
                ),
            ),
            (
                '41601_valid_unknown_not_critical_certificate_extension_test1',
                'ValidUnknownNotCriticalCertificateExtensionTest1EE.crt',
                [],
                [],
                2,
                True,
                None,
                None
            ),
            (
                '41602_invalid_unknown_critical_certificate_extension_test2',
                'InvalidUnknownCriticalCertificateExtensionTest2EE.crt',
                [],
                [],
                2,
                True,
                PathValidationError,
                (
                    'The path could not be validated because the end-entity '
                    'certificate contains the following unsupported critical '
                    'extension: 2.16.840.1.101.2.1.12.2'
                )
            )
        )
