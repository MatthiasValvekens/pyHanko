import pytest
from asn1crypto import x509
from freezegun import freeze_time

from pyhanko_certvalidator.authority import (
    CertTrustAnchor,
    NamedKeyAuthority,
    TrustAnchor,
    TrustQualifiers,
)
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.errors import PathValidationError
from pyhanko_certvalidator.name_trees import (
    GeneralNameType,
    x509_names_to_subtrees,
)
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import PKIXValidationParams
from pyhanko_certvalidator.validate import async_validate_path

from .common import load_nist_cert


def test_extract_policy():
    # I know this isn't a CA cert, but it's a convenient one to use
    crt = load_nist_cert('ValidCertificatePathTest1EE.crt')
    anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
    params = anchor.trust_qualifiers.standard_parameters
    nist_test_policy = '2.16.840.1.101.3.2.1.48.1'
    assert params.user_initial_policy_set == {nist_test_policy}


def test_extract_permitted_subtrees():
    crt = load_nist_cert('nameConstraintsDN1CACert.crt')
    anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
    params = anchor.trust_qualifiers.standard_parameters
    dirname_trs = params.initial_permitted_subtrees[
        GeneralNameType.DIRECTORY_NAME
    ]
    assert len(dirname_trs) == 1
    (tree,) = dirname_trs
    expected_name = x509.Name.build(
        {
            'organizational_unit_name': 'permittedSubtree1',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US',
        }
    )
    assert tree.tree_base.value == expected_name


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_validate_with_derived():
    crt = load_nist_cert('nameConstraintsDN1CACert.crt')
    anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
    ee = load_nist_cert('InvalidDNnameConstraintsTest2EE.crt')
    context = ValidationContext(
        trust_roots=[anchor],
        revocation_mode='soft-fail',
    )
    (path,) = await context.path_builder.async_build_paths(ee)
    assert path.pkix_len == 1
    with pytest.raises(PathValidationError, match='not all names.*permitted'):
        await async_validate_path(context, path)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_validate_with_merged_permitted_subtrees():
    crt = load_nist_cert('nameConstraintsDN1CACert.crt')
    anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
    ee = load_nist_cert('ValidDNnameConstraintsTest1EE.crt')
    context = ValidationContext(
        trust_roots=[anchor],
        revocation_mode='soft-fail',
    )
    (path,) = await context.path_builder.async_build_paths(ee)
    assert path.pkix_len == 1

    # this should be OK
    await async_validate_path(context, path)
    # merge in an extra name constraint
    extra_name = x509.Name.build(
        {
            'organizational_unit_name': 'someNameYouDontHave',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US',
        }
    )
    extra_params = PKIXValidationParams(
        initial_permitted_subtrees=x509_names_to_subtrees([extra_name])
    )
    with pytest.raises(PathValidationError, match='not all names.*permitted'):
        await async_validate_path(context, path, parameters=extra_params)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_validate_with_merged_excluded_subtrees():
    crt = load_nist_cert('nameConstraintsDN3CACert.crt')
    anchor = CertTrustAnchor(crt, derive_default_quals_from_cert=True)
    ee = load_nist_cert('ValidDNnameConstraintsTest6EE.crt')
    context = ValidationContext(
        trust_roots=[anchor],
        revocation_mode='soft-fail',
    )
    (path,) = await context.path_builder.async_build_paths(ee)
    assert path.pkix_len == 1

    # this should be OK
    await async_validate_path(context, path)
    # merge in an extra name constraint
    extra_name = x509.Name.build(
        {
            'organizational_unit_name': 'permittedSubtree1',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US',
        }
    )
    extra_params = PKIXValidationParams(
        initial_excluded_subtrees=x509_names_to_subtrees([extra_name])
    )
    with pytest.raises(PathValidationError, match='some names.*excluded'):
        await async_validate_path(context, path, parameters=extra_params)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_validate_with_certless_root():
    crt = load_nist_cert('nameConstraintsDN1CACert.crt')
    # manually build params
    permitted = x509.Name.build(
        {
            'organizational_unit_name': 'permittedSubtree1',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US',
        }
    )
    extra_params = PKIXValidationParams(
        initial_permitted_subtrees=x509_names_to_subtrees([permitted])
    )
    anchor = TrustAnchor(
        NamedKeyAuthority(crt.subject, crt.public_key),
        quals=TrustQualifiers(standard_parameters=extra_params),
    )
    ee = load_nist_cert('ValidDNnameConstraintsTest1EE.crt')
    context = ValidationContext(
        trust_roots=[anchor],
        revocation_mode='soft-fail',
    )
    (path,) = await context.path_builder.async_build_paths(ee)
    assert path.pkix_len == 1

    assert isinstance(path.first, x509.Certificate)
    assert path.trust_anchor is anchor

    await async_validate_path(context, path, parameters=extra_params)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_validate_with_certless_root_failure():
    crt = load_nist_cert('nameConstraintsDN1CACert.crt')
    # manually build params
    permitted = x509.Name.build(
        {
            'organizational_unit_name': 'someNameYouDontHave',
            'organization_name': 'Test Certificates 2011',
            'country_name': 'US',
        }
    )
    extra_params = PKIXValidationParams(
        initial_permitted_subtrees=x509_names_to_subtrees([permitted])
    )
    anchor = TrustAnchor(
        NamedKeyAuthority(crt.subject, crt.public_key),
        quals=TrustQualifiers(standard_parameters=extra_params),
    )
    ee = load_nist_cert('ValidDNnameConstraintsTest1EE.crt')
    context = ValidationContext(
        trust_roots=[anchor],
        revocation_mode='soft-fail',
    )
    (path,) = await context.path_builder.async_build_paths(ee)
    assert path.pkix_len == 1

    assert isinstance(path.first, x509.Certificate)
    assert path.trust_anchor is anchor
    with pytest.raises(PathValidationError, match='not all names.*permitted'):
        await async_validate_path(context, path, parameters=extra_params)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_validate_empty_path_certless_root():
    crt = load_nist_cert('nameConstraintsDN1CACert.crt')
    anchor = TrustAnchor(
        NamedKeyAuthority(crt.subject, crt.public_key),
    )
    context = ValidationContext(
        trust_roots=[anchor],
        revocation_mode='soft-fail',
    )

    trivial_path = ValidationPath(trust_anchor=anchor, interm=[], leaf=None)
    await async_validate_path(context, trivial_path)
