import pytest
from freezegun import freeze_time
from pyhanko_certvalidator import (
    CertificateValidator,
    PKIXValidationParams,
    ValidationContext,
)

from .common import load_cert_object, load_nist_cert


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
