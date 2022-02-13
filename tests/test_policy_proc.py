import os
import unittest

from asn1crypto import x509, pem

from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.validate import async_validate_path
from pyhanko_certvalidator.policy_decl import PKIXValidationParams
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.errors import PathValidationError
from pyhanko_certvalidator.name_trees import GeneralNameType, \
    x509_names_to_subtrees
from pyhanko_certvalidator.trust_anchor import CertTrustAnchor, \
    NamedKeyAuthority, TrustQualifiers, TrustAnchor

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def _load_cert_object(*path_components):
    with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
        cert_bytes = f.read()
        if pem.detect(cert_bytes):
            _, _, cert_bytes = pem.unarmor(cert_bytes)
        cert = x509.Certificate.load(cert_bytes)
    return cert


def _load_nist_cert(filename) -> x509.Certificate:
    return _load_cert_object('nist_pkits', 'certs', filename)


def nist_test_policy(no):
    return '2.16.840.1.101.3.2.1.48.' + str(int(no))


class TrustQualifierDerivationTests(unittest.TestCase):

    def test_extract_policy(self):
        # I know this isn't a CA cert, but it's a convenient one to use
        crt = _load_nist_cert('ValidCertificatePathTest1EE.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        params = anchor.trust_qualifiers.standard_parameters
        self.assertEqual(params.user_initial_policy_set, {nist_test_policy(1)})

    def test_extract_permitted_subtrees(self):
        crt = _load_nist_cert('nameConstraintsDN1CACert.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        params = anchor.trust_qualifiers.standard_parameters
        dirname_trs = \
            params.initial_permitted_subtrees[GeneralNameType.DIRECTORY_NAME]
        self.assertEqual(len(dirname_trs), 1)
        tree, = dirname_trs
        expected_name = x509.Name.build({
            'organizational_unit_name': 'permittedSubtree1',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US'
        })
        self.assertEqual(tree.tree_base.value, expected_name)


class ValidationWithTrustQualifiersTest(unittest.IsolatedAsyncioTestCase):
    async def test_validate_with_derived(self):
        crt = _load_nist_cert('nameConstraintsDN1CACert.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        ee = _load_nist_cert('InvalidDNnameConstraintsTest2EE.crt')
        context = ValidationContext(
            trust_roots=[anchor], revocation_mode='soft-fail',
        )
        path, = await context.certificate_registry.async_build_paths(ee)
        self.assertEqual(path.pkix_len, 1)
        with self.assertRaisesRegex(PathValidationError,
                                    'not all names.*permitted'):
            await async_validate_path(context, path)

    async def test_validate_with_merged_permitted_subtrees(self):
        crt = _load_nist_cert('nameConstraintsDN1CACert.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        ee = _load_nist_cert('ValidDNnameConstraintsTest1EE.crt')
        context = ValidationContext(
            trust_roots=[anchor], revocation_mode='soft-fail',
        )
        path, = await context.certificate_registry.async_build_paths(ee)
        self.assertEqual(path.pkix_len, 1)

        # this should be OK
        await async_validate_path(context, path)
        # merge in an extra name constraint
        extra_name = x509.Name.build({
            'organizational_unit_name': 'someNameYouDontHave',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US'
        })
        extra_params = PKIXValidationParams(
            initial_permitted_subtrees=x509_names_to_subtrees([extra_name])
        )
        with self.assertRaisesRegex(PathValidationError,
                                    'not all names.*permitted'):
            await async_validate_path(context, path, parameters=extra_params)

    async def test_validate_with_merged_excluded_subtrees(self):
        crt = _load_nist_cert('nameConstraintsDN3CACert.crt')
        anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
        ee = _load_nist_cert('ValidDNnameConstraintsTest6EE.crt')
        context = ValidationContext(
            trust_roots=[anchor], revocation_mode='soft-fail',
        )
        path, = await context.certificate_registry.async_build_paths(ee)
        self.assertEqual(path.pkix_len, 1)

        # this should be OK
        await async_validate_path(context, path)
        # merge in an extra name constraint
        extra_name = x509.Name.build({
            'organizational_unit_name': 'permittedSubtree1',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US'
        })
        extra_params = PKIXValidationParams(
            initial_excluded_subtrees=x509_names_to_subtrees([extra_name])
        )
        with self.assertRaisesRegex(PathValidationError,
                                    'some names.*excluded'):
            await async_validate_path(context, path, parameters=extra_params)

    async def test_validate_with_certless_root(self):
        crt = _load_nist_cert('nameConstraintsDN1CACert.crt')
        # manually build params
        permitted = x509.Name.build({
            'organizational_unit_name': 'permittedSubtree1',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US'
        })
        extra_params = PKIXValidationParams(
            initial_permitted_subtrees=x509_names_to_subtrees([permitted])
        )
        anchor = TrustAnchor(
            NamedKeyAuthority(crt.subject, crt.public_key),
            quals=TrustQualifiers(standard_parameters=extra_params)
        )
        ee = _load_nist_cert('ValidDNnameConstraintsTest1EE.crt')
        context = ValidationContext(
            trust_roots=[anchor], revocation_mode='soft-fail',
        )
        path, = await context.certificate_registry.async_build_paths(ee)
        self.assertEqual(path.pkix_len, 1)

        self.assertIsInstance(path.first, x509.Certificate)
        self.assertIs(path.trust_anchor, anchor)

        await async_validate_path(context, path, parameters=extra_params)

    async def test_validate_with_certless_root_failure(self):
        crt = _load_nist_cert('nameConstraintsDN1CACert.crt')
        # manually build params
        permitted = x509.Name.build({
            'organizational_unit_name': 'someNameYouDontHave',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US'
        })
        extra_params = PKIXValidationParams(
            initial_permitted_subtrees=x509_names_to_subtrees([permitted])
        )
        anchor = TrustAnchor(
            NamedKeyAuthority(crt.subject, crt.public_key),
            quals=TrustQualifiers(standard_parameters=extra_params)
        )
        ee = _load_nist_cert('ValidDNnameConstraintsTest1EE.crt')
        context = ValidationContext(
            trust_roots=[anchor], revocation_mode='soft-fail',
        )
        path, = await context.certificate_registry.async_build_paths(ee)
        self.assertEqual(path.pkix_len, 1)

        self.assertIsInstance(path.first, x509.Certificate)
        self.assertIs(path.trust_anchor, anchor)
        with self.assertRaisesRegex(PathValidationError,
                                    'not all names.*permitted'):
            await async_validate_path(context, path, parameters=extra_params)

    async def test_validate_empty_path_certless_root(self):
        crt = _load_nist_cert('nameConstraintsDN1CACert.crt')
        anchor = TrustAnchor(
            NamedKeyAuthority(crt.subject, crt.public_key),
        )
        context = ValidationContext(
            trust_roots=[anchor], revocation_mode='soft-fail',
        )

        trivial_path = ValidationPath(trust_anchor=anchor, certs=[])
        await async_validate_path(context, trivial_path)
