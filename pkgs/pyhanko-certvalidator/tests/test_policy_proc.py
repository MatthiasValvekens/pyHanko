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
    NameSubtree,
    PKIXSubtrees,
    default_excluded_subtrees,
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


def test_trust_anchor_authority_consistency():
    anchor = CertTrustAnchor(load_nist_cert('nameConstraintsDN1CACert.crt'))

    without_cert = NamedKeyAuthority(
        anchor.certificate.subject, anchor.certificate.public_key
    )

    assert anchor.authority == without_cert


def _excluded_subtree(name_type: GeneralNameType, base: str) -> PKIXSubtrees:
    # start from the defaults so that every name type has an entry; the
    # validator looks up each type it encounters in the path
    trees = default_excluded_subtrees()
    trees[name_type] = {NameSubtree.from_name(name_type, base)}
    return trees


async def _nist_ee_path(ca_cert: str, ee_cert: str):
    context = ValidationContext(
        trust_roots=[load_nist_cert('TrustAnchorRootCertificate.crt')],
        other_certs=[load_nist_cert(ca_cert)],
        revocation_mode='soft-fail',
    )
    (path,) = await context.path_builder.async_build_paths(
        load_nist_cert(ee_cert)
    )
    assert path.pkix_len == 2
    return context, path


# Testing certificate from PKITS test suite
#  DNS -> testserver.testcertificates.gov
#  RFC822 -> Test21EE@mailserver.testcertificates.gov
#  URI -> http://testserver.testcertificates.gov/index.html
NC_DNS = (
    'nameConstraintsDNS1CACert.crt',
    'ValidDNSnameConstraintsTest30EE.crt',
)
NC_EMAIL = (
    'nameConstraintsRFC822CA1Cert.crt',
    'ValidRFC822nameConstraintsTest21EE.crt',
)
NC_URI = (
    'nameConstraintsURI1CACert.crt',
    'ValidURInameConstraintsTest34EE.crt',
)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'certs,name_type,base',
    [
        (NC_DNS, GeneralNameType.DNS_NAME, 'TESTSERVER.TESTCERTIFICATES.GOV'),
        (NC_DNS, GeneralNameType.DNS_NAME, 'TestCertificates.GOV'),
        (NC_DNS, GeneralNameType.DNS_NAME, 'testserver.testcertificates.gov.'),
        (NC_DNS, GeneralNameType.DNS_NAME, 'TESTCERTIFICATES.GOV.'),
        (
            NC_EMAIL,
            GeneralNameType.RFC822_NAME,
            'Test21EE@MAILSERVER.TESTCERTIFICATES.GOV',
        ),
        (
            NC_EMAIL,
            GeneralNameType.RFC822_NAME,
            'Test21EE@mailserver.testcertificates.gov.',
        ),
        (NC_EMAIL, GeneralNameType.RFC822_NAME, '.TESTCERTIFICATES.GOV'),
        (
            NC_EMAIL,
            GeneralNameType.RFC822_NAME,
            'MAILSERVER.TESTCERTIFICATES.GOV',
        ),
        (
            NC_URI,
            GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER,
            'TESTSERVER.TESTCERTIFICATES.GOV',
        ),
        (
            NC_URI,
            GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER,
            '.TESTCERTIFICATES.GOV',
        ),
        (
            NC_URI,
            GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER,
            'testserver.testcertificates.gov.',
        ),
    ],
)
async def test_excluded_subtree_catches_differently_cased_name(
    certs, name_type, base
):
    context, path = await _nist_ee_path(*certs)
    # sanity check: the path is fine without the extra constraint
    await async_validate_path(context, path)

    params = PKIXValidationParams(
        initial_excluded_subtrees=_excluded_subtree(name_type, base)
    )
    with pytest.raises(PathValidationError, match='some names.*excluded'):
        await async_validate_path(context, path, parameters=params)


@freeze_time('2022-05-01')
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'certs,name_type,base',
    [
        (NC_DNS, GeneralNameType.DNS_NAME, 'OTHER.TESTCERTIFICATES.GOV'),
        (NC_DNS, GeneralNameType.DNS_NAME, 'ESTCERTIFICATES.GOV'),
        # RFC 5280 s 7.5: the local part stays case-sensitive
        (
            NC_EMAIL,
            GeneralNameType.RFC822_NAME,
            'test21ee@mailserver.testcertificates.gov',
        ),
        (
            NC_URI,
            GeneralNameType.UNIFORM_RESOURCE_IDENTIFIER,
            'OTHER.TESTCERTIFICATES.GOV',
        ),
    ],
)
async def test_excluded_subtree_does_not_overmatch(certs, name_type, base):
    context, path = await _nist_ee_path(*certs)
    params = PKIXValidationParams(
        initial_excluded_subtrees=_excluded_subtree(name_type, base)
    )
    await async_validate_path(context, path, parameters=params)
