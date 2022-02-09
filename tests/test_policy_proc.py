import os
import unittest

from asn1crypto import x509, pem

from pyhanko_certvalidator.trust_anchor import CertTrustAnchor

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def nist_test_policy(no):
    return '2.16.840.1.101.3.2.1.48.' + str(int(no))


class TrustQualifierDerivationTests(unittest.TestCase):
    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def test_extract_policy(self):
        # I know this isn't a CA cert, but it's a convenient one to use
        crt = self._load_nist_cert('ValidCertificatePathTest1EE.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        params = anchor.trust_qualifiers.standard_parameters
        self.assertEqual(params.user_initial_policy_set, {nist_test_policy(1)})

    def test_extract_permitted_subtrees(self):
        crt = self._load_nist_cert('nameConstraintsDN1CACert.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        params = anchor.trust_qualifiers.standard_parameters
        from pyhanko_certvalidator.name_trees import GeneralNameType
        dirname_trs = \
            params.initial_permitted_subtrees[GeneralNameType.DIRECTORY_NAME]
        self.assertEqual(len(dirname_trs), 1)
        tree, = dirname_trs
        self.assertIn(
            'Organizational Unit: permittedSubtree1',
            tree.tree_base.value.human_friendly
        )
