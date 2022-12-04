import os
from datetime import datetime, timedelta, timezone

import pytest
from asn1crypto import crl, ocsp, x509

from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.errors import PathValidationError, RevokedError
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    FreshnessReqType,
    RevocationCheckingPolicy,
)
from pyhanko_certvalidator.validate import async_validate_path

from .common import load_cert_object, load_crl, load_ocsp_response

freshness_dir = 'freshness'
certs = os.path.join('freshness', 'certs')


@pytest.mark.asyncio
async def test_cooldown_period_ok():
    req_policy = RevocationCheckingPolicy.from_legacy('require')
    policy = CertRevTrustPolicy(
        revocation_checking_policy=req_policy,
        freshness=timedelta(days=3),
        freshness_req_type=FreshnessReqType.TIME_AFTER_SIGNATURE,
    )
    root = load_cert_object(certs, 'root.crt')
    alice = load_cert_object(certs, 'alice.crt')
    interm = load_cert_object(certs, 'interm.crt')

    alice_ocsp = load_ocsp_response(freshness_dir, 'alice-2020-10-01.ors')
    root_crl = load_crl(freshness_dir, 'root-2020-10-01.crl')

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
        best_signature_time=datetime(2020, 9, 18, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    await async_validate_path(vc, path)


@pytest.mark.asyncio
async def test_cooldown_period_too_early():
    req_policy = RevocationCheckingPolicy.from_legacy('require')
    policy = CertRevTrustPolicy(
        revocation_checking_policy=req_policy,
        freshness=timedelta(days=3),
        freshness_req_type=FreshnessReqType.TIME_AFTER_SIGNATURE,
    )
    root = load_cert_object(certs, 'root.crt')
    alice = load_cert_object(certs, 'alice.crt')
    interm = load_cert_object(certs, 'interm.crt')

    alice_ocsp = load_ocsp_response(freshness_dir, 'alice-2020-10-01.ors')
    root_crl = load_crl(freshness_dir, 'root-2020-10-01.crl')

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
        best_signature_time=datetime(2020, 9, 30, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    with pytest.raises(PathValidationError, match='CRL.*recent enough'):
        await async_validate_path(vc, path)


@pytest.mark.asyncio
async def test_use_delta_ok():
    req_policy = RevocationCheckingPolicy.from_legacy('require')
    policy = CertRevTrustPolicy(
        revocation_checking_policy=req_policy,
        freshness=timedelta(days=9),
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    root = load_cert_object(certs, 'root.crt')
    alice = load_cert_object(certs, 'alice.crt')
    interm = load_cert_object(certs, 'interm.crt')

    alice_ocsp = load_ocsp_response(freshness_dir, 'alice-2020-10-01.ors')
    root_crl = load_crl(freshness_dir, 'root-2020-10-01.crl')

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    await async_validate_path(vc, path)


@pytest.mark.asyncio
async def test_use_delta_stale():
    req_policy = RevocationCheckingPolicy.from_legacy('require')
    policy = CertRevTrustPolicy(
        revocation_checking_policy=req_policy,
        freshness=timedelta(hours=1),
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    root = load_cert_object(certs, 'root.crt')
    alice = load_cert_object(certs, 'alice.crt')
    interm = load_cert_object(certs, 'interm.crt')

    alice_ocsp = load_ocsp_response(freshness_dir, 'alice-2020-10-01.ors')
    root_crl = load_crl(freshness_dir, 'root-2020-10-01.crl')

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    with pytest.raises(PathValidationError, match='CRL.*recent enough'):
        await async_validate_path(vc, path)


@pytest.mark.asyncio
async def test_use_most_recent():
    req_policy = RevocationCheckingPolicy.from_legacy('require')
    policy = CertRevTrustPolicy(
        revocation_checking_policy=req_policy,
        freshness=timedelta(days=20),  # some ridiculous value
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    root = load_cert_object(certs, 'root.crt')
    alice = load_cert_object(certs, 'alice.crt')
    interm = load_cert_object(certs, 'interm.crt')

    alice_ocsp_older = load_ocsp_response(freshness_dir, 'alice-2020-11-29.ors')
    alice_ocsp_recent = load_ocsp_response(
        freshness_dir, 'alice-2020-12-10.ors'
    )
    root_crl = load_crl(freshness_dir, 'root-2020-12-10.crl')

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp_older, alice_ocsp_recent],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 12, 10, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    with pytest.raises(RevokedError):
        await async_validate_path(vc, path)

    # Double-check: the validator should be fooled if we don't include the
    #  second OCSP response because of the very lenient time delta allowed
    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp_older],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 12, 10, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    await async_validate_path(vc, path)


@pytest.mark.asyncio
async def test_discard_post_validation_time():
    req_policy = RevocationCheckingPolicy.from_legacy('require')
    policy = CertRevTrustPolicy(
        revocation_checking_policy=req_policy,
        freshness=timedelta(days=20),  # some ridiculous value
        freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    )
    root = load_cert_object(certs, 'root.crt')
    alice = load_cert_object(certs, 'alice.crt')
    interm = load_cert_object(certs, 'interm.crt')

    alice_ocsp_older = load_ocsp_response(freshness_dir, 'alice-2020-11-29.ors')
    alice_ocsp_recent = load_ocsp_response(
        freshness_dir, 'alice-2020-12-10.ors'
    )
    root_crl = load_crl(freshness_dir, 'root-2020-11-29.crl')

    vc = ValidationContext(
        trust_roots=[root],
        other_certs=[interm],
        ocsps=[alice_ocsp_older, alice_ocsp_recent],
        crls=[root_crl],
        revinfo_policy=policy,
        moment=datetime(2020, 11, 29, tzinfo=timezone.utc),
    )
    (path,) = await vc.path_builder.async_build_paths(alice)
    await async_validate_path(vc, path)
