import datetime
import os

import pytest
from freezegun import freeze_time

from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
    ValidationDataHandlers,
)
from pyhanko_certvalidator.errors import (
    InsufficientPOEError,
    InsufficientRevinfoError,
)
from pyhanko_certvalidator.ltv.ades_past import past_validate
from pyhanko_certvalidator.ltv.errors import TimeSlideFailure
from pyhanko_certvalidator.ltv.poe import POEManager, POEType, digest_for_poe
from pyhanko_certvalidator.ltv.time_slide import time_slide
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    FreshnessReqType,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    SimpleTrustManager,
)
from pyhanko_certvalidator.revinfo.archival import CRLContainer, OCSPContainer
from pyhanko_certvalidator.revinfo.manager import RevinfoManager

from .common import load_cert_object, load_crl, load_ocsp_response, load_path

BASE_DIR = os.path.join('ades', 'time-slide')


def read_test_path(revoked_intermediate_ca=False) -> ValidationPath:
    return load_path(
        os.path.join(BASE_DIR, 'certs'),
        'root.crt',
        'interm-revoked.crt' if revoked_intermediate_ca else 'interm.crt',
        'alice.crt',
    )


def load_cert_registry(revoked_intermediate_ca=False) -> CertificateRegistry:
    cert_files = (
        'root.crt',
        'interm-revoked.crt' if revoked_intermediate_ca else 'interm.crt',
        'interm-ocsp.crt',
        'alice.crt',
    )
    reg = CertificateRegistry()
    for cert_file in cert_files:
        reg.register(load_cert_object(BASE_DIR, 'certs', cert_file))
    return reg


def now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


DEFAULT_REV_CHECK_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
    intermediate_ca_cert_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
)
DEFAULT_TRUST_POLICY = CertRevTrustPolicy(
    revocation_checking_policy=DEFAULT_REV_CHECK_POLICY,
)

DEFAULT_TOLERANCE = datetime.timedelta(minutes=10)


@pytest.mark.asyncio
@freeze_time("2020-11-29T00:05:00+00:00")
async def test_time_slide_not_revoked():
    test_path = read_test_path()
    alice_ocsp = load_ocsp_response(BASE_DIR, 'alice-2020-11-29.ors')
    root_crl = load_crl(BASE_DIR, 'root-2020-11-29.crl')

    revinfo_manager = RevinfoManager(
        certificate_registry=load_cert_registry(),
        poe_manager=POEManager(),
        crls=[CRLContainer(root_crl)],
        ocsps=[OCSPContainer(alice_ocsp)],
    )
    control_time = await time_slide(
        test_path,
        init_control_time=now(),
        revinfo_manager=revinfo_manager,
        rev_trust_policy=DEFAULT_TRUST_POLICY,
        algo_usage_policy=None,
        time_tolerance=DEFAULT_TOLERANCE,
    )
    assert control_time == now()


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_time_slide_revocation_ocsp():
    test_path = read_test_path()
    alice_ocsp = load_ocsp_response(BASE_DIR, 'alice-2020-12-10.ors')
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')

    revinfo_manager = RevinfoManager(
        certificate_registry=load_cert_registry(),
        poe_manager=POEManager(),
        crls=[CRLContainer(root_crl)],
        ocsps=[OCSPContainer(alice_ocsp)],
    )
    control_time = await time_slide(
        test_path,
        init_control_time=now(),
        revinfo_manager=revinfo_manager,
        rev_trust_policy=DEFAULT_TRUST_POLICY,
        algo_usage_policy=None,
        time_tolerance=DEFAULT_TOLERANCE,
    )
    assert control_time == datetime.datetime(
        2020, 12, 1, tzinfo=datetime.timezone.utc
    )


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_time_slide_revocation_crl():
    test_path = read_test_path()
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')
    interm_crl = load_crl(BASE_DIR, 'interm-2020-12-10.crl')

    revinfo_manager = RevinfoManager(
        certificate_registry=load_cert_registry(),
        poe_manager=POEManager(),
        crls=[CRLContainer(root_crl), CRLContainer(interm_crl)],
        ocsps=[],
    )
    control_time = await time_slide(
        test_path,
        init_control_time=now(),
        revinfo_manager=revinfo_manager,
        rev_trust_policy=DEFAULT_TRUST_POLICY,
        algo_usage_policy=None,
        time_tolerance=DEFAULT_TOLERANCE,
    )
    assert control_time == datetime.datetime(
        2020, 12, 1, tzinfo=datetime.timezone.utc
    )


VERY_LENIENT_FRESHNESS = CertRevTrustPolicy(
    revocation_checking_policy=DEFAULT_REV_CHECK_POLICY,
    freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
    freshness=datetime.timedelta(days=100),
)


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_time_slide_revoked_intermediate():
    test_path = read_test_path(revoked_intermediate_ca=True)
    # the intermediate cert is listed as revoked on this CRL
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')
    # this CRL would be valid long enough to serve as non-revocation
    # evidence for the 'alice' cert
    # We set a ridiculous freshness window to ensure it's covered.
    poe_manager = POEManager()
    interm_crl = load_crl(BASE_DIR, 'interm-2020-11-29.crl')
    poe_date = datetime.datetime(2020, 11, 30, tzinfo=datetime.timezone.utc)
    poe_manager.register(test_path.leaf, dt=poe_date, poe_type=POEType.PROVIDED)
    # ...make sure to include some POE prior to the revocation date of the
    # intermediate cert
    poe_manager.register(
        CRLContainer(interm_crl), dt=poe_date, poe_type=POEType.PROVIDED
    )

    revinfo_manager = RevinfoManager(
        certificate_registry=load_cert_registry(revoked_intermediate_ca=True),
        poe_manager=poe_manager,
        crls=[CRLContainer(root_crl), CRLContainer(interm_crl)],
        ocsps=[],
    )
    control_time = await time_slide(
        test_path,
        init_control_time=now(),
        revinfo_manager=revinfo_manager,
        rev_trust_policy=VERY_LENIENT_FRESHNESS,
        algo_usage_policy=None,
        time_tolerance=DEFAULT_TOLERANCE,
    )
    assert control_time == datetime.datetime(
        2020, 12, 1, tzinfo=datetime.timezone.utc
    )


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_time_slide_revoked_intermediate_enforce_cert_poe():
    test_path = read_test_path(revoked_intermediate_ca=True)
    # the intermediate cert is listed as revoked on this CRL
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')
    poe_manager = POEManager()
    # No POE for the leaf cert at the control time
    # at which the intermediate cert was revoked => fail
    interm_crl = load_crl(BASE_DIR, 'interm-2020-11-29.crl')
    poe_date = datetime.datetime(2020, 11, 30, tzinfo=datetime.timezone.utc)
    poe_manager.register(
        CRLContainer(interm_crl), dt=poe_date, poe_type=POEType.PROVIDED
    )

    revinfo_manager = RevinfoManager(
        certificate_registry=load_cert_registry(revoked_intermediate_ca=True),
        poe_manager=poe_manager,
        crls=[CRLContainer(root_crl), CRLContainer(interm_crl)],
        ocsps=[],
    )
    with pytest.raises(InsufficientPOEError, match='for.*Alice'):
        await time_slide(
            test_path,
            init_control_time=now(),
            revinfo_manager=revinfo_manager,
            rev_trust_policy=VERY_LENIENT_FRESHNESS,
            algo_usage_policy=None,
            time_tolerance=DEFAULT_TOLERANCE,
        )


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_time_slide_revoked_intermediate_enforce_revinfo_poe():
    test_path = read_test_path(revoked_intermediate_ca=True)
    # the intermediate cert is listed as revoked on this CRL
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')
    poe_manager = POEManager()
    poe_date = datetime.datetime(2020, 11, 30, tzinfo=datetime.timezone.utc)
    poe_manager.register(test_path.leaf, dt=poe_date, poe_type=POEType.PROVIDED)
    # This CRL issued by the intermediate CA predates its revocation date
    # so without POE, it should be treated as no longer valid
    # => no revinfo for the leaf cert => can't finish
    interm_crl = load_crl(BASE_DIR, 'interm-2020-11-29.crl')

    revinfo_manager = RevinfoManager(
        certificate_registry=load_cert_registry(revoked_intermediate_ca=True),
        poe_manager=poe_manager,
        crls=[CRLContainer(root_crl), CRLContainer(interm_crl)],
        ocsps=[],
    )
    with pytest.raises(InsufficientRevinfoError, match='for.*Alice'):
        await time_slide(
            test_path,
            init_control_time=now(),
            revinfo_manager=revinfo_manager,
            rev_trust_policy=VERY_LENIENT_FRESHNESS,
            algo_usage_policy=None,
            time_tolerance=DEFAULT_TOLERANCE,
        )


VALIDATION_POLICY_SPEC = CertValidationPolicySpec(
    trust_manager=SimpleTrustManager.build(
        trust_roots=[load_cert_object(BASE_DIR, 'certs', 'root.crt')]
    ),
    revinfo_policy=DEFAULT_TRUST_POLICY,
)


@pytest.mark.asyncio
@freeze_time("2020-11-29T00:05:00+00:00")
async def test_point_in_time_validation_not_revoked():
    test_path = read_test_path()
    alice_ocsp = load_ocsp_response(BASE_DIR, 'alice-2020-11-29.ors')
    root_crl = load_crl(BASE_DIR, 'root-2020-11-29.crl')

    cert_registry = load_cert_registry()
    poe_manager = POEManager()
    revinfo_manager = RevinfoManager(
        certificate_registry=cert_registry,
        poe_manager=poe_manager,
        crls=[CRLContainer(root_crl)],
        ocsps=[OCSPContainer(alice_ocsp)],
    )

    last_valid_time = await past_validate(
        test_path,
        validation_policy_spec=VALIDATION_POLICY_SPEC,
        init_control_time=now(),
        validation_data_handlers=ValidationDataHandlers(
            revinfo_manager=revinfo_manager,
            poe_manager=poe_manager,
            cert_registry=cert_registry,
        ),
    )
    assert last_valid_time == now()


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_point_in_time_validation_revoked_intermediate():
    # Same scenario as the time slide test w/ revoked intermediate cert & PoE
    # in this module

    test_path = read_test_path(revoked_intermediate_ca=True)
    # the intermediate cert is listed as revoked on this CRL
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')
    # this CRL would be valid long enough to serve as non-revocation
    # evidence for the 'alice' cert
    # We set a ridiculous freshness window to ensure it's covered.
    poe_date = datetime.datetime(2020, 11, 30, tzinfo=datetime.timezone.utc)
    poe_manager = POEManager()
    poe_manager.register(test_path.leaf, dt=poe_date, poe_type=POEType.PROVIDED)
    interm_crl = load_crl(BASE_DIR, 'interm-2020-11-29.crl')
    # ...make sure to include some POE prior to the revocation date of the
    # intermediate cert
    poe_manager.register(
        CRLContainer(interm_crl), dt=poe_date, poe_type=POEType.PROVIDED
    )

    cert_registry = load_cert_registry(revoked_intermediate_ca=True)
    revinfo_manager = RevinfoManager(
        certificate_registry=cert_registry,
        poe_manager=poe_manager,
        crls=[CRLContainer(root_crl), CRLContainer(interm_crl)],
        ocsps=[],
    )
    last_valid_time = await past_validate(
        test_path,
        validation_policy_spec=VALIDATION_POLICY_SPEC,
        init_control_time=now(),
        validation_data_handlers=ValidationDataHandlers(
            revinfo_manager=revinfo_manager,
            poe_manager=poe_manager,
            cert_registry=cert_registry,
        ),
    )
    assert last_valid_time == datetime.datetime(
        2020, 12, 1, tzinfo=datetime.timezone.utc
    )


@pytest.mark.asyncio
@freeze_time("2020-12-10T00:05:00+00:00")
async def test_point_in_time_validation_revinfo_insufficient_poe():
    test_path = read_test_path(revoked_intermediate_ca=True)
    # the intermediate cert is listed as revoked on this CRL
    root_crl = load_crl(BASE_DIR, 'root-2020-12-10.crl')
    poe_manager = POEManager()

    cert_registry = load_cert_registry(revoked_intermediate_ca=True)
    revinfo_manager = RevinfoManager(
        certificate_registry=cert_registry,
        poe_manager=poe_manager,
        crls=[CRLContainer(root_crl)],
        ocsps=[],
    )
    with pytest.raises(TimeSlideFailure):
        await past_validate(
            test_path,
            validation_policy_spec=VALIDATION_POLICY_SPEC,
            init_control_time=now(),
            validation_data_handlers=ValidationDataHandlers(
                revinfo_manager=revinfo_manager,
                poe_manager=poe_manager,
                cert_registry=cert_registry,
            ),
        )


def test_poe_manager_read_cert():
    manager = POEManager()
    cert = load_cert_object(BASE_DIR, 'certs', 'root.crt')
    with freeze_time('2020-11-11'):
        manager.register(cert, poe_type=POEType.PROVIDED)
    assert manager[cert].date() == datetime.date(2020, 11, 11)


def test_poe_manager_cert_by_digest():
    manager = POEManager()
    cert = load_cert_object(BASE_DIR, 'certs', 'root.crt')
    with freeze_time('2020-11-11'):
        manager.register_by_digest(
            digest_for_poe(cert.dump()), poe_type=POEType.PROVIDED
        )
    assert manager[cert].date() == datetime.date(2020, 11, 11)


def test_poe_manager_read_bytes():
    manager = POEManager()
    msg = b'deadbeef'
    with freeze_time('2020-11-11'):
        manager.register(msg, poe_type=POEType.PROVIDED)
    assert manager[msg].date() == datetime.date(2020, 11, 11)


def test_poe_manager_read_bytes_by_digest():
    manager = POEManager()
    msg = b'deadbeef'
    with freeze_time('2020-11-11'):
        manager.register_by_digest(
            digest_for_poe(msg), poe_type=POEType.PROVIDED
        )
    assert manager[msg].date() == datetime.date(2020, 11, 11)
