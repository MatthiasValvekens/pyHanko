import datetime
import os

import pytest
from asn1crypto import cms, crl, ocsp, x509
from freezegun import freeze_time
from pyhanko_certvalidator import PathBuildingError, validate
from pyhanko_certvalidator.authority import CertTrustAnchor
from pyhanko_certvalidator.context import ACTargetDescription, ValidationContext
from pyhanko_certvalidator.errors import (
    CRLValidationIndeterminateError,
    InvalidAttrCertificateError,
    InvalidCertificateError,
    PathValidationError,
    RevokedError,
)
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.revinfo.validate_crl import verify_crl
from pyhanko_certvalidator.revinfo.validate_ocsp import verify_ocsp_response

from .test_validate import FIXTURES_DIR

attr_cert_dir = os.path.join(FIXTURES_DIR, 'attribute-certs')
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


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_aacontrols_norev():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )

    result = await validate.async_validate_ac(ac, vc)
    assert len(result.aa_path) == 3
    assert 'role' in result.approved_attributes
    assert 'group' not in result.approved_attributes


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_bad_signature():
    ac = load_attr_cert(os.path.join(basic_aa_dir, 'aa', 'badsig.attr.crt'))

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )
    msg = 'signature could not be verified'
    with pytest.raises(InvalidCertificateError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_validation_expired():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        moment=datetime.datetime(3000, 1, 1, tzinfo=datetime.timezone.utc),
    )
    msg = 'intermediate certificate 1 expired'
    with pytest.raises(PathValidationError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_sig_algo_mismatch():
    ac = load_attr_cert(os.path.join(basic_aa_dir, 'aa', 'badsig.attr.crt'))
    # manipulate the signature algorithm
    ac = cms.AttributeCertificateV2(
        {
            'ac_info': ac['ac_info'],
            'signature_algorithm': {'algorithm': 'md5_rsa'},
            'signature': ac['signature'],
        }
    )
    ac.dump()

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )
    msg = 'algorithm declaration.*does not match'
    with pytest.raises(InvalidCertificateError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_bad_aa_controls():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    # no AA controls on this one
    interm = load_cert(
        os.path.join(basic_aa_dir, 'root', 'interm-unrestricted.crt')
    )
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )

    msg = 'AA controls extension only present on part '
    with pytest.raises(PathValidationError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_aa_controls_path_too_long():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    # no AA controls on this one
    interm = load_cert(
        os.path.join(basic_aa_dir, 'inbetween', 'interm-pathlen-violation.crt')
    )
    inbetween = load_cert(
        os.path.join(basic_aa_dir, 'root', 'inbetween-aa.crt')
    )
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa, inbetween],
    )

    msg = 'exceeds the maximum path length for an AA certificate'
    with pytest.raises(PathValidationError, match=msg):
        await validate.async_validate_ac(ac, vc)


def _load_targeted_ac():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-norev-targeted.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(
        os.path.join(basic_aa_dir, 'root', 'interm-unrestricted.crt')
    )
    aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'aa-unrestricted.crt'))
    return root, interm, aa, ac


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_no_targeting():
    root, interm, aa, ac = _load_targeted_ac()

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, aa],
    )

    msg = 'no targeting information'
    with pytest.raises(InvalidCertificateError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_bad_targeting_name():
    root, interm, aa, ac = _load_targeted_ac()

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, aa],
        acceptable_ac_targets=ACTargetDescription(
            validator_names=[
                x509.GeneralName(
                    name='directory_name',
                    value=x509.Name.build(
                        {
                            'country_name': 'XX',
                            'organization_name': 'Testing Attribute Authority',
                            'organizational_unit_name': 'Validators',
                            'common_name': 'Not Validator',
                        }
                    ),
                )
            ]
        ),
    )

    msg = 'AC targeting'
    with pytest.raises(InvalidCertificateError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_bad_targeting_group():
    root, interm, aa, ac = _load_targeted_ac()

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, aa],
        acceptable_ac_targets=ACTargetDescription(
            group_memberships=[
                x509.GeneralName(
                    name='directory_name',
                    value=x509.Name.build(
                        {
                            'country_name': 'XX',
                            'organization_name': 'Testing Attribute Authority',
                            'organizational_unit_name': 'Not Validators',
                        }
                    ),
                )
            ]
        ),
    )

    msg = 'AC targeting'
    with pytest.raises(InvalidCertificateError, match=msg):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_good_targeting_name():
    root, interm, aa, ac = _load_targeted_ac()

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, aa],
        acceptable_ac_targets=ACTargetDescription(
            validator_names=[
                x509.GeneralName(
                    name='directory_name',
                    value=x509.Name.build(
                        {
                            'country_name': 'XX',
                            'organization_name': 'Testing Attribute Authority',
                            'organizational_unit_name': 'Validators',
                            'common_name': 'Validator',
                        }
                    ),
                )
            ]
        ),
    )

    result = await validate.async_validate_ac(ac, vc)
    assert len(result.aa_path) == 3
    assert 'role' in result.approved_attributes
    assert 'group' in result.approved_attributes


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_basic_ac_validation_good_targeting_group():
    root, interm, aa, ac = _load_targeted_ac()

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, aa],
        acceptable_ac_targets=ACTargetDescription(
            group_memberships=[
                x509.GeneralName(
                    name='directory_name',
                    value=x509.Name.build(
                        {
                            'country_name': 'XX',
                            'organization_name': 'Testing Attribute Authority',
                            'organizational_unit_name': 'Validators',
                        }
                    ),
                )
            ]
        ),
    )

    result = await validate.async_validate_ac(ac, vc)
    assert len(result.aa_path) == 3
    assert 'role' in result.approved_attributes
    assert 'group' in result.approved_attributes


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_match_holder_ac():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    alice = load_cert(os.path.join(basic_aa_dir, 'people-ca', 'alice.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )

    await validate.async_validate_ac(ac, vc, holder_cert=alice)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'name',
    [
        'alice-aki-with-issuer-id.attr.crt',
        'alice-v1form-issuer.attr.crt',
        'alice-v2form-only-base-cert-id.attr.crt',
        'alice-v2form-with-base-certificate-id.attr.crt',
        'alice-no-aki-with-base-certificate-id.attr.crt',
        'alice-aki-with-issuer-id-and-base-certificate-id.attr.crt',
    ],
)
async def test_ac_issuer_search_nonstandard_forms(name):
    ac = load_attr_cert(os.path.join(attr_cert_dir, 'oneoff', name))

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    alice = load_cert(os.path.join(basic_aa_dir, 'people-ca', 'alice.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )

    await validate.async_validate_ac(ac, vc, holder_cert=alice)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'name,err_type,err_str',
    [
        (
            'alice-v2form-issuer-aki-misaligned.attr.crt',
            InvalidAttrCertificateError,
            'conflicting',
        ),
        ('alice-misleading-aki.attr.crt', PathBuildingError, 'suitable AA'),
        (
            'alice-v2form-wrong-serial.attr.crt',
            PathBuildingError,
            'suitable AA',
        ),
    ],
)
async def test_ac_issuer_search_nonstandard_forms_failures(
    name, err_type, err_str
):
    ac = load_attr_cert(os.path.join(attr_cert_dir, 'oneoff', name))

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    alice = load_cert(os.path.join(basic_aa_dir, 'people-ca', 'alice.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )

    with pytest.raises(err_type, match=err_str):
        await validate.async_validate_ac(ac, vc, holder_cert=alice)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_match_holder_ac_mismatch():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-norev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    bob = load_cert(os.path.join(basic_aa_dir, 'people-ca', 'bob.crt'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
    )

    msg = 'Could not match.*base_certificate_id'
    with pytest.raises(InvalidCertificateError, match=msg):
        await validate.async_validate_ac(ac, vc, holder_cert=bob)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_revoked_crl():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))
    root_crl = load_crl(
        os.path.join(basic_aa_dir, 'root', 'root-some-revoked.crl')
    )
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-some-revoked.crl')
    )

    role_aa_crl = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-some-revoked.crl')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        crls=[root_crl, interm_crl, role_aa_crl],
        moment=datetime.datetime(
            year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    ac_path = ValidationPath(CertTrustAnchor(root), [interm, role_aa], ac)

    with pytest.raises(RevokedError):
        await verify_crl(ac, ac_path, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_unrevoked_crl():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(os.path.join(basic_aa_dir, 'root', 'root-all-good.crl'))
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-all-good.crl')
    )
    role_aa_crl = load_crl(os.path.join(basic_aa_dir, 'role-aa-all-good.crl'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        crls=[root_crl, interm_crl, role_aa_crl],
        moment=datetime.datetime(
            year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    ac_path = ValidationPath(CertTrustAnchor(root), [interm, role_aa], ac)

    await verify_crl(ac, ac_path, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_revoked_full_path_validation_crl():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    root_crl = load_crl(
        os.path.join(basic_aa_dir, 'root', 'root-some-revoked.crl')
    )
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-some-revoked.crl')
    )
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    role_aa_crl = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-some-revoked.crl')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        crls=[root_crl, interm_crl, role_aa_crl],
        moment=datetime.datetime(
            year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )

    with pytest.raises(RevokedError):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_revoked_complex_crls_full_path_validation():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-complex-crls.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    crl_issuer = load_cert(
        os.path.join(basic_aa_dir, 'interm', 'role-aa-crl-issuer.crt')
    )
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(
        os.path.join(basic_aa_dir, 'root', 'root-some-revoked.crl')
    )
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-some-revoked.crl')
    )
    role_aa_aa_compromised = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-aa-compromise-some-revoked.crl')
    )
    role_aa_other_reasons = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-other-reasons-some-revoked.crl')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa, crl_issuer],
        crls=[
            root_crl,
            interm_crl,
            role_aa_aa_compromised,
            role_aa_other_reasons,
        ],
        moment=datetime.datetime(
            year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )

    with pytest.raises(RevokedError):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_unrevoked_full_path_validation_crl():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(os.path.join(basic_aa_dir, 'root', 'root-all-good.crl'))
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-all-good.crl')
    )
    role_aa_crl = load_crl(os.path.join(basic_aa_dir, 'role-aa-all-good.crl'))

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        crls=[root_crl, interm_crl, role_aa_crl],
        moment=datetime.datetime(
            year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_crls_out_of_scope():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-complex-crls.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    crl_issuer = load_cert(
        os.path.join(basic_aa_dir, 'interm', 'role-aa-crl-issuer.crt')
    )
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(os.path.join(basic_aa_dir, 'root', 'root-all-good.crl'))
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-all-good.crl')
    )
    role_aa_nonaligned_name = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-nonaligned-name.crl')
    )
    role_aa_nonsensically_scoped = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-nonsensically-scoped.crl')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa, crl_issuer],
        crls=[
            root_crl,
            interm_crl,
            role_aa_nonaligned_name,
            role_aa_nonsensically_scoped,
        ],
        moment=datetime.datetime(
            year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    ac_path = ValidationPath(CertTrustAnchor(root), [interm, role_aa], ac)
    with pytest.raises(
        CRLValidationIndeterminateError,
        match="insufficient information from known CRLs",
    ):
        await verify_crl(ac, ac_path, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_unrevoked_complex_crls_full_path_validation():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-complex-crls.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    crl_issuer = load_cert(
        os.path.join(basic_aa_dir, 'interm', 'role-aa-crl-issuer.crt')
    )
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(os.path.join(basic_aa_dir, 'root', 'root-all-good.crl'))
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-all-good.crl')
    )
    role_aa_aa_compromised = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-aa-compromise-all-good.crl')
    )
    role_aa_other_reasons = load_crl(
        os.path.join(basic_aa_dir, 'role-aa-other-reasons-all-good.crl')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa, crl_issuer],
        crls=[
            root_crl,
            interm_crl,
            role_aa_aa_compromised,
            role_aa_other_reasons,
        ],
        moment=datetime.datetime(
            year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_revoked_ocsp():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    ocsp_resp = load_ocsp_response(
        os.path.join(basic_aa_dir, 'alice-revoked.ors')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        ocsps=[ocsp_resp],
        moment=datetime.datetime(
            year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    ac_path = ValidationPath(CertTrustAnchor(root), [interm, role_aa], ac)

    with pytest.raises(RevokedError):
        await verify_ocsp_response(ac, ac_path, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_unrevoked_oscp():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    ocsp_resp = load_ocsp_response(
        os.path.join(basic_aa_dir, 'alice-all-good.ors')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        ocsps=[ocsp_resp],
        moment=datetime.datetime(
            year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )
    ac_path = ValidationPath(CertTrustAnchor(root), [interm, role_aa], ac)
    await verify_ocsp_response(ac, ac_path, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_revoked_full_path_validation():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(
        os.path.join(basic_aa_dir, 'root', 'root-some-revoked.crl')
    )
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-some-revoked.crl')
    )
    ocsp_resp = load_ocsp_response(
        os.path.join(basic_aa_dir, 'alice-revoked.ors')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        ocsps=[ocsp_resp],
        crls=[root_crl, interm_crl],
        moment=datetime.datetime(
            year=2021, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )

    with pytest.raises(RevokedError):
        await validate.async_validate_ac(ac, vc)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_ac_unrevoked_full_path_validation_ocsp():
    ac = load_attr_cert(
        os.path.join(basic_aa_dir, 'aa', 'alice-role-with-rev.attr.crt')
    )

    root = load_cert(os.path.join(basic_aa_dir, 'root', 'root.crt'))
    interm = load_cert(os.path.join(basic_aa_dir, 'root', 'interm-role.crt'))
    role_aa = load_cert(os.path.join(basic_aa_dir, 'interm', 'role-aa.crt'))

    root_crl = load_crl(os.path.join(basic_aa_dir, 'root', 'root-all-good.crl'))
    interm_crl = load_crl(
        os.path.join(basic_aa_dir, 'interm', 'interm-all-good.crl')
    )
    ocsp_resp = load_ocsp_response(
        os.path.join(basic_aa_dir, 'alice-all-good.ors')
    )

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm, role_aa],
        ocsps=[ocsp_resp],
        crls=[root_crl, interm_crl],
        moment=datetime.datetime(
            year=2019, month=12, day=12, tzinfo=datetime.timezone.utc
        ),
        revocation_mode='require',
    )

    await validate.async_validate_ac(ac, vc)
