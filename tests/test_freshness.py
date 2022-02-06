import os
import unittest
from datetime import timedelta, datetime, timezone

from asn1crypto import x509, crl, ocsp

from pyhanko_certvalidator.errors import PathValidationError, RevokedError
from pyhanko_certvalidator.policy_decl import RevocationCheckingPolicy, \
    CertRevTrustPolicy, FreshnessReqType
from pyhanko_certvalidator.validate import async_validate_path
from .test_validate import fixtures_dir
from pyhanko_certvalidator import ValidationContext

freshness_dir = os.path.join(fixtures_dir, 'freshness')
certs = os.path.join(freshness_dir, 'certs')


def load_cert(fname) -> x509.Certificate:
    with open(fname, 'rb') as inf:
        return x509.Certificate.load(inf.read())


def load_crl(fname) -> crl.CertificateList:
    with open(fname, 'rb') as inf:
        return crl.CertificateList.load(inf.read())


def load_ocsp_response(fname) -> ocsp.OCSPResponse:
    with open(fname, 'rb') as inf:
        return ocsp.OCSPResponse.load(inf.read())


class FreshnessTests(unittest.IsolatedAsyncioTestCase):

    async def test_cooldown_period_ok(self):
        req_policy = RevocationCheckingPolicy.from_legacy('require')
        policy = CertRevTrustPolicy(
            revocation_checking_policy=req_policy,
            freshness=timedelta(days=3),
            freshness_req_type=FreshnessReqType.TIME_AFTER_SIGNATURE,
        )
        root = load_cert(os.path.join(certs, 'root.crt'))
        alice = load_cert(os.path.join(certs, 'alice.crt'))
        interm = load_cert(os.path.join(certs, 'interm.crt'))

        alice_ocsp = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-10-01.ors')
        )
        root_crl = load_crl(
            os.path.join(freshness_dir, 'root-2020-10-01.crl')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
            use_poe_time=datetime(2020, 9, 18, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        await async_validate_path(vc, path)

    async def test_cooldown_period_too_early(self):
        req_policy = RevocationCheckingPolicy.from_legacy('require')
        policy = CertRevTrustPolicy(
            revocation_checking_policy=req_policy,
            freshness=timedelta(days=3),
            freshness_req_type=FreshnessReqType.TIME_AFTER_SIGNATURE,
        )
        root = load_cert(os.path.join(certs, 'root.crt'))
        alice = load_cert(os.path.join(certs, 'alice.crt'))
        interm = load_cert(os.path.join(certs, 'interm.crt'))

        alice_ocsp = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-10-01.ors')
        )
        root_crl = load_crl(
            os.path.join(freshness_dir, 'root-2020-10-01.crl')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
            use_poe_time=datetime(2020, 9, 30, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        with self.assertRaisesRegex(PathValidationError, "CRL.*recent enough"):
            await async_validate_path(vc, path)

    async def test_use_delta_ok(self):
        req_policy = RevocationCheckingPolicy.from_legacy('require')
        policy = CertRevTrustPolicy(
            revocation_checking_policy=req_policy,
            freshness=timedelta(days=9),
            freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
        )
        root = load_cert(os.path.join(certs, 'root.crt'))
        alice = load_cert(os.path.join(certs, 'alice.crt'))
        interm = load_cert(os.path.join(certs, 'interm.crt'))

        alice_ocsp = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-10-01.ors')
        )
        root_crl = load_crl(
            os.path.join(freshness_dir, 'root-2020-10-01.crl')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        await async_validate_path(vc, path)

    async def test_use_delta_stale(self):
        req_policy = RevocationCheckingPolicy.from_legacy('require')
        policy = CertRevTrustPolicy(
            revocation_checking_policy=req_policy,
            freshness=timedelta(hours=1),
            freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
        )
        root = load_cert(os.path.join(certs, 'root.crt'))
        alice = load_cert(os.path.join(certs, 'alice.crt'))
        interm = load_cert(os.path.join(certs, 'interm.crt'))

        alice_ocsp = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-10-01.ors')
        )
        root_crl = load_crl(
            os.path.join(freshness_dir, 'root-2020-10-01.crl')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 10, 1, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        with self.assertRaisesRegex(PathValidationError, "CRL.*recent enough"):
            await async_validate_path(vc, path)

    async def test_use_most_recent(self):
        req_policy = RevocationCheckingPolicy.from_legacy('require')
        policy = CertRevTrustPolicy(
            revocation_checking_policy=req_policy,
            freshness=timedelta(days=20),  # some ridiculous value
            freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
        )
        root = load_cert(os.path.join(certs, 'root.crt'))
        alice = load_cert(os.path.join(certs, 'alice.crt'))
        interm = load_cert(os.path.join(certs, 'interm.crt'))

        alice_ocsp_older = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-11-29.ors')
        )
        alice_ocsp_recent = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-12-10.ors')
        )
        root_crl = load_crl(
            os.path.join(freshness_dir, 'root-2020-12-10.crl')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp_older, alice_ocsp_recent], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 12, 10, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        with self.assertRaises(RevokedError):
            await async_validate_path(vc, path)

        # Double-check: the validator should be fooled if we don't include the
        #  second OCSP response because of the very lenient time delta allowed
        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp_older], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 12, 10, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        await async_validate_path(vc, path)

    async def test_discard_post_validation_time(self):
        req_policy = RevocationCheckingPolicy.from_legacy('require')
        policy = CertRevTrustPolicy(
            revocation_checking_policy=req_policy,
            freshness=timedelta(days=20),  # some ridiculous value
            freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
        )
        root = load_cert(os.path.join(certs, 'root.crt'))
        alice = load_cert(os.path.join(certs, 'alice.crt'))
        interm = load_cert(os.path.join(certs, 'interm.crt'))

        alice_ocsp_older = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-11-29.ors')
        )
        alice_ocsp_recent = load_ocsp_response(
            os.path.join(freshness_dir, 'alice-2020-12-10.ors')
        )
        root_crl = load_crl(
            os.path.join(freshness_dir, 'root-2020-11-29.crl')
        )

        vc = ValidationContext(
            trust_roots=[root], other_certs=[interm],
            ocsps=[alice_ocsp_older, alice_ocsp_recent], crls=[root_crl],
            revinfo_policy=policy,
            moment=datetime(2020, 11, 29, tzinfo=timezone.utc),
        )
        path, = await vc.certificate_registry.async_build_paths(alice)
        await async_validate_path(vc, path)
