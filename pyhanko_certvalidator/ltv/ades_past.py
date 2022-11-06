import dataclasses
from datetime import datetime, timezone
from typing import Optional

from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
    ValidationDataHandlers,
)
from pyhanko_certvalidator.errors import ValidationError
from pyhanko_certvalidator.ltv.errors import (
    PastValidatePrecheckFailure,
    TimeSlideFailure,
)
from pyhanko_certvalidator.ltv.time_slide import time_slide
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.validate import async_validate_path

NO_REVOCATION = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
    intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
)

__all__ = ['past_validate']


async def _past_validate_precheck(
    path: ValidationPath,
    validation_policy_spec: CertValidationPolicySpec,
):
    # The past validation algorithm requires us to run the "regular"
    # validation algorithm without regard for revocation and expiration
    # on a known-good time

    # Shell model: intersect the validity windows of all certs in the path
    certs = list(path.iter_certs(include_root=False))
    lower_bound = max(c.not_valid_before for c in certs)
    upper_bound = min(c.not_valid_after for c in certs)

    if lower_bound >= upper_bound:
        raise PastValidatePrecheckFailure(
            "The intersection of the validity periods of the certificates "
            "in the path is empty or degenerate."
        )

    ref_time = ValidationTimingInfo(
        validation_time=upper_bound,
        use_poe_time=upper_bound,
        point_in_time_validation=True,
    )

    validation_context = dataclasses.replace(
        validation_policy_spec,
        revinfo_policy=CertRevTrustPolicy(
            revocation_checking_policy=NO_REVOCATION
        ),
    ).build_validation_context(timing_info=ref_time, handlers=None)

    try:
        await async_validate_path(
            validation_context,
            path,
            validation_policy_spec.pkix_validation_params,
        )
    except ValidationError as e:
        raise PastValidatePrecheckFailure(
            "Elementary path validation routine failed during pre-check "
            "for past point-in-time validation"
        ) from e


async def past_validate(
    path: ValidationPath,
    validation_policy_spec: CertValidationPolicySpec,
    validation_data_handlers: ValidationDataHandlers,
    init_control_time: Optional[datetime] = None,
    use_poe_time: Optional[datetime] = None,
) -> datetime:

    await _past_validate_precheck(
        path,
        validation_policy_spec,
    )

    try:
        # time slide
        init_control_time = init_control_time or datetime.now(tz=timezone.utc)
        control_time = await time_slide(
            path,
            init_control_time=init_control_time,
            rev_trust_policy=validation_policy_spec.revinfo_policy,
            algo_usage_policy=validation_policy_spec.algorithm_usage_policy,
            time_tolerance=validation_policy_spec.time_tolerance,
            revinfo_manager=validation_data_handlers.revinfo_manager,
        )
    except ValidationError as e:
        raise TimeSlideFailure(
            "Failed to get control time for point-in-time validation."
        ) from e

    ref_time = ValidationTimingInfo(
        validation_time=control_time,
        use_poe_time=use_poe_time or control_time,
        point_in_time_validation=True,
    )

    # -> validate
    validation_context = validation_policy_spec.build_validation_context(
        timing_info=ref_time, handlers=validation_data_handlers
    )

    await async_validate_path(
        validation_context,
        path,
        parameters=validation_policy_spec.pkix_validation_params,
    )

    return control_time
