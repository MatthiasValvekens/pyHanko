# coding: utf-8

from datetime import datetime

import pytest
from asn1crypto.util import timezone
from freezegun import freeze_time

from pyhanko_certvalidator import (
    CertificateValidator,
    PKIXValidationParams,
    ValidationContext,
)
from pyhanko_certvalidator.errors import (
    InvalidCertificateError,
    PathValidationError,
)

from .common import load_cert_object, load_nist_cert


@pytest.mark.asyncio
async def test_basic_certificate_validator_tls():
    cert = load_cert_object('mozilla.org.crt')
    other_certs = [load_cert_object('digicert-sha2-secure-server-ca.crt')]

    moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    context = ValidationContext(moment=moment)
    validator = CertificateValidator(cert, other_certs, context)

    await validator.async_validate_tls('www.mozilla.org')


@pytest.mark.asyncio
async def test_basic_certificate_validator_tls_expired():
    cert = load_cert_object('mozilla.org.crt')
    other_certs = [load_cert_object('digicert-sha2-secure-server-ca.crt')]

    moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    context = ValidationContext(moment=moment)
    validator = CertificateValidator(cert, other_certs, context)

    with pytest.raises(PathValidationError, match='expired'):
        await validator.async_validate_tls('www.mozilla.org')


@pytest.mark.asyncio
async def test_basic_certificate_validator_tls_invalid_hostname():
    cert = load_cert_object('mozilla.org.crt')
    other_certs = [load_cert_object('digicert-sha2-secure-server-ca.crt')]

    moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    context = ValidationContext(moment=moment)
    validator = CertificateValidator(cert, other_certs, context)

    with pytest.raises(InvalidCertificateError, match='not valid'):
        await validator.async_validate_tls('google.com')


@pytest.mark.asyncio
async def test_basic_certificate_validator_tls_invalid_key_usage():
    cert = load_cert_object('mozilla.org.crt')
    other_certs = [load_cert_object('digicert-sha2-secure-server-ca.crt')]

    moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    context = ValidationContext(moment=moment)
    validator = CertificateValidator(cert, other_certs, context)

    with pytest.raises(InvalidCertificateError, match='for the purpose'):
        await validator.async_validate_usage({'crl_sign'})


@pytest.mark.asyncio
async def test_basic_certificate_validator_tls_whitelist():
    cert = load_cert_object('mozilla.org.crt')
    other_certs = [load_cert_object('digicert-sha2-secure-server-ca.crt')]

    moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    context = ValidationContext(
        whitelisted_certs=[cert.sha1_fingerprint], moment=moment
    )
    validator = CertificateValidator(cert, other_certs, context)

    # If whitelist does not work, this will raise exception for expiration
    await validator.async_validate_tls('www.mozilla.org')

    # If whitelist does not work, this will raise exception for hostname
    await validator.async_validate_tls('google.com')

    # If whitelist does not work, this will raise exception for key usage
    await validator.async_validate_usage({'crl_sign'})


@freeze_time('2022-05-01')
@pytest.mark.asyncio
async def test_certvalidator_with_params():
    cert = load_nist_cert('ValidPolicyMappingTest12EE.crt')
    ca_certs = [load_nist_cert('TrustAnchorRootCertificate.crt')]
    other_certs = [load_nist_cert('P12Mapping1to3CACert.crt')]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        revocation_mode="soft-fail",
        weak_hash_algos={'md2', 'md5'},
    )

    validator = CertificateValidator(
        cert,
        validation_context=context,
        pkix_params=PKIXValidationParams(
            user_initial_policy_set=frozenset(['2.16.840.1.101.3.2.1.48.1'])
        ),
    )
    path = await validator.async_validate_usage(key_usage={'digital_signature'})

    # check if we got the right policy processing
    # (i.e. if our params got through)
    qps = path.qualified_policies()

    (qp,) = qps
    assert 1 == len(qp.qualifiers)
    (qual_obj,) = qp.qualifiers
    assert qual_obj['policy_qualifier_id'].native == 'user_notice'
    assert qual_obj['qualifier']['explicit_text'].native == (
        'q7:  This is the user notice from qualifier 7 associated with '
        'NIST-test-policy-3.  This user notice should be displayed '
        'when  NIST-test-policy-1 is in the user-constrained-policy-set'
    )


@pytest.mark.asyncio
async def test_self_signed_with_policy():
    # tests whether a corner case in the policy validation logic when the
    # path length is zero is handled gracefully
    cert = load_cert_object('self-signed-with-policy.crt')
    context = ValidationContext(trust_roots=[cert], allow_fetching=False)
    validator = CertificateValidator(cert, validation_context=context)
    path = await validator.async_validate_usage({'digital_signature'})
    (qp,) = path.qualified_policies()
    # Note: the cert declares a concrete policy, but for the purposes
    # of PKIX validation, any policy is valid, since we're validating
    # a -signed certificate (so everything breaks down anyway)
    assert qp.user_domain_policy_id == 'any_policy'
    assert qp.issuer_domain_policy_id == 'any_policy'
