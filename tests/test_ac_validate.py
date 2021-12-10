import os
import unittest

from asn1crypto import cms, x509

from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator import validate
from pyhanko_certvalidator.errors import PathValidationError
from .test_validate import MockFetcherBackend, fixtures_dir

attr_cert_dir = os.path.join(fixtures_dir, 'attribute-certs')
basic_aa_dir = os.path.join(attr_cert_dir, 'basic-aa')


def load_cert(fname):
    with open(fname, 'rb') as inf:
        return x509.Certificate.load(inf.read())


def load_attr_cert(fname):
    with open(fname, 'rb') as inf:
        return cms.AttributeCertificateV2.load(inf.read())


# noinspection PyMethodMayBeStatic
class ACValidateTests(unittest.IsolatedAsyncioTestCase):
    async def test_basic_ac_validation_aacontrols_norev(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-role.crt')
        )
        role_aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'role-aa.crt')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
            fetcher_backend=MockFetcherBackend(),
        )

        result = await validate.async_validate_ac(ac, vc)
        assert len(result.aa_path) == 3
        assert 'role' in result.approved_attributes
        assert 'group' not in result.approved_attributes

    async def test_basic_ac_validation_bad_aa_controls(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        # no AA controls on this one
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-unrestricted.crt')
        )
        role_aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'role-aa.crt')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
            fetcher_backend=MockFetcherBackend(),
        )

        msg = 'AA controls extension only present on part '
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)

    async def test_basic_ac_validation_aa_controls_path_too_long(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        # no AA controls on this one
        interm = load_cert(os.path.join(
            basic_aa_dir, 'inbetween', 'interm-pathlen-violation.crt'
        ))
        inbetween = load_cert(os.path.join(
            basic_aa_dir, 'root', 'inbetween-aa.crt'
        ))
        role_aa = load_cert(os.path.join(
            basic_aa_dir, 'interm', 'role-aa.crt'
        ))

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa, inbetween],
            fetcher_backend=MockFetcherBackend(),
        )

        msg = 'exceeds the maximum path length for an AA certificate'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)
