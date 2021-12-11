import datetime
import os
import unittest

from asn1crypto import cms, x509, crl, ocsp

from pyhanko_certvalidator import validate
from pyhanko_certvalidator.context import ValidationContext, ACTargetDescription
from pyhanko_certvalidator.errors import PathValidationError, RevokedError
from pyhanko_certvalidator.path import ValidationPath
from .test_validate import fixtures_dir

attr_cert_dir = os.path.join(fixtures_dir, 'attribute-certs')
basic_aa_dir = os.path.join(attr_cert_dir, 'basic-aa')


def load_cert(fname) -> x509.Certificate:
    with open(fname, 'rb') as inf:
        return x509.Certificate.load(inf.read())


def load_attr_cert(fname) -> cms.AttributeCertificateV2:
    with open(fname, 'rb') as inf:
        return cms.AttributeCertificateV2.load(inf.read())


def load_crl(fname) -> crl.CertificateList:
    with open(fname, 'rb') as inf:
        return crl.CertificateList.load(inf.read())


def load_ocsp_response(fname) -> ocsp.OCSPResponse:
    with open(fname, 'rb') as inf:
        return ocsp.OCSPResponse.load(inf.read())

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
        )

        result = await validate.async_validate_ac(ac, vc)
        assert len(result.aa_path) == 3
        assert 'role' in result.approved_attributes
        assert 'group' not in result.approved_attributes

    async def test_basic_ac_validation_bad_signature(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'badsig.attr.crt')
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
        )
        msg = 'signature could not be verified'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)

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
        )

        msg = 'exceeds the maximum path length for an AA certificate'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)

    def _load_targeted_ac(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-norev-targeted.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-unrestricted.crt')
        )
        aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'aa-unrestricted.crt')
        )
        return root, interm, aa, ac

    async def test_basic_ac_validation_no_targeting(self):
        root, interm, aa, ac = self._load_targeted_ac()

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, aa],
        )

        msg = 'no targeting information'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)

    async def test_basic_ac_validation_bad_targeting_name(self):
        root, interm, aa, ac = self._load_targeted_ac()

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, aa],
            acceptable_ac_targets=ACTargetDescription(
                validator_names=[x509.GeneralName(
                    name='directory_name', value=x509.Name.build({
                        'country_name': 'XX',
                        'organization_name': 'Testing Attribute Authority',
                        'organizational_unit_name': 'Validators',
                        'common_name': 'Not Validator'
                    })
                )]
            )
        )

        msg = 'AC targeting'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)

    async def test_basic_ac_validation_bad_targeting_group(self):
        root, interm, aa, ac = self._load_targeted_ac()

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, aa],
            acceptable_ac_targets=ACTargetDescription(
                group_memberships=[x509.GeneralName(
                    name='directory_name', value=x509.Name.build({
                        'country_name': 'XX',
                        'organization_name': 'Testing Attribute Authority',
                        'organizational_unit_name': 'Not Validators',
                    })
                )]
            )
        )

        msg = 'AC targeting'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc)

    async def test_basic_ac_validation_good_targeting_name(self):
        root, interm, aa, ac = self._load_targeted_ac()

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, aa],
            acceptable_ac_targets=ACTargetDescription(
                validator_names=[x509.GeneralName(
                    name='directory_name', value=x509.Name.build({
                        'country_name': 'XX',
                        'organization_name': 'Testing Attribute Authority',
                        'organizational_unit_name': 'Validators',
                        'common_name': 'Validator'
                    })
                )]
            )
        )

        result = await validate.async_validate_ac(ac, vc)
        assert len(result.aa_path) == 3
        assert 'role' in result.approved_attributes
        assert 'group' in result.approved_attributes

    async def test_basic_ac_validation_good_targeting_group(self):
        root, interm, aa, ac = self._load_targeted_ac()

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, aa],
            acceptable_ac_targets=ACTargetDescription(
                group_memberships=[x509.GeneralName(
                    name='directory_name', value=x509.Name.build({
                        'country_name': 'XX',
                        'organization_name': 'Testing Attribute Authority',
                        'organizational_unit_name': 'Validators',
                    })
                )]
            )
        )

        result = await validate.async_validate_ac(ac, vc)
        assert len(result.aa_path) == 3
        assert 'role' in result.approved_attributes
        assert 'group' in result.approved_attributes

    async def test_match_holder_ac(self):
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

        alice = load_cert(
            os.path.join(basic_aa_dir, 'people-ca', 'alice.crt')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
        )

        await validate.async_validate_ac(ac, vc, holder_cert=alice)

    async def test_match_holder_ac_mismatch(self):
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

        bob = load_cert(os.path.join(basic_aa_dir, 'people-ca', 'bob.crt'))

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
        )

        msg = 'Could not match.*base_certificate_id'
        with self.assertRaisesRegex(PathValidationError, expected_regex=msg):
            await validate.async_validate_ac(ac, vc, holder_cert=bob)


# noinspection PyMethodMayBeStatic
class ACCRLTests(unittest.IsolatedAsyncioTestCase):

    async def test_ac_revoked(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-role.crt')
        )
        role_aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'role-aa.crt')
        )

        role_aa_crl = load_crl(os.path.join(
            basic_aa_dir, 'role-aa-some-revoked.crl'
        ))

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
            crls=[role_aa_crl],
            moment=datetime.datetime(
                year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
            )
        )
        aa_path = ValidationPath()
        aa_path.append(root)
        aa_path.append(interm)
        aa_path.append(role_aa)

        with self.assertRaises(RevokedError):
            await validate.verify_crl(ac, aa_path, vc)

    async def test_ac_unrevoked(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-role.crt')
        )
        role_aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'role-aa.crt')
        )

        role_aa_crl = load_crl(os.path.join(
            basic_aa_dir, 'role-aa-all-good.crl'
        ))

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
            crls=[role_aa_crl],
            moment=datetime.datetime(
                year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
            )
        )
        aa_path = ValidationPath()
        aa_path.append(root)
        aa_path.append(interm)
        aa_path.append(role_aa)

        await validate.verify_crl(ac, aa_path, vc)


# noinspection PyMethodMayBeStatic
class ACOCSPResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_ac_revoked(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-role.crt')
        )
        role_aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'role-aa.crt')
        )

        ocsp_resp = load_ocsp_response(os.path.join(
            basic_aa_dir, 'alice-revoked.ors'
        ))

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
            ocsps=[ocsp_resp],
            moment=datetime.datetime(
                year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
            )
        )
        aa_path = ValidationPath()
        aa_path.append(root)
        aa_path.append(interm)
        aa_path.append(role_aa)

        with self.assertRaises(RevokedError):
            await validate.verify_ocsp_response(ac, aa_path, vc)

    async def test_ac_unrevoked(self):
        ac = load_attr_cert(
            os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
        )

        root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
        interm = load_cert(os.path.join(
            basic_aa_dir, 'root', 'interm-role.crt')
        )
        role_aa = load_cert(
            os.path.join(basic_aa_dir, 'interm', 'role-aa.crt')
        )

        ocsp_resp = load_ocsp_response(os.path.join(
            basic_aa_dir, 'alice-all-good.ors'
        ))

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm, role_aa],
            ocsps=[ocsp_resp],
            moment=datetime.datetime(
                year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
            )
        )
        aa_path = ValidationPath()
        aa_path.append(root)
        aa_path.append(interm)
        aa_path.append(role_aa)

        await validate.verify_ocsp_response(ac, aa_path, vc)
