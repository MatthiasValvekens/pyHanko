import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Set, Tuple

from asn1crypto import algos, x509

from pyhanko_certvalidator._state import ValProcState
from pyhanko_certvalidator.errors import (
    DisallowedAlgorithmError,
    InsufficientRevinfoError,
    RevokedError,
)
from pyhanko_certvalidator.ltv.types import (
    ValidationTimingInfo,
    ValidationTimingParams,
)
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    AlgorithmUsagePolicy,
    CertRevTrustPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.revinfo.archival import (
    RevinfoContainer,
    RevinfoUsabilityRating,
)
from pyhanko_certvalidator.revinfo.manager import RevinfoManager
from pyhanko_certvalidator.revinfo.validate_crl import (
    CRLOfInterest,
    _check_cert_on_crl_and_delta,
    _CRLErrs,
    collect_relevant_crls_with_paths,
)
from pyhanko_certvalidator.revinfo.validate_ocsp import (
    OCSPResponseOfInterest,
    _check_ocsp_status,
    collect_relevant_responses_with_paths,
)
from pyhanko_certvalidator.util import ConsList


async def _ades_gather_lta_revocation(
    path: ValidationPath,
    revinfo_manager: RevinfoManager,
    control_time: datetime,
    revocation_checking_rule: RevocationCheckingRule,
) -> Tuple[List[CRLOfInterest], List[OCSPResponseOfInterest]]:
    cert = path.leaf
    if revocation_checking_rule.ocsp_relevant:
        ocsp_result = await collect_relevant_responses_with_paths(
            cert, path, revinfo_manager, control_time
        )
        ocsps = ocsp_result.responses
    else:
        ocsps = []

    if revocation_checking_rule.crl_relevant:
        crl_result = await collect_relevant_crls_with_paths(
            cert, path, revinfo_manager, control_time
        )
        crls = crl_result.crls
    else:
        crls = []
    return crls, ocsps


def _tails(path: ValidationPath):
    cur_path = path
    yield cur_path, True
    while cur_path.pkix_len > 1:
        cur_path = cur_path.copy_and_drop_leaf()
        yield cur_path, False


def _apply_algo_policy(
    algo_policy: AlgorithmUsagePolicy,
    algo_used: algos.SignedDigestAlgorithm,
    control_time: datetime,
):
    sig_algo = algo_used.signature_algo
    sig_constraint = algo_policy.signature_algorithm_allowed(
        sig_algo, control_time
    )
    hash_algo = algo_used.hash_algo
    digest_constraint = algo_policy.digest_algorithm_allowed(
        hash_algo, control_time
    )
    constraints = ((sig_algo, sig_constraint), (hash_algo, digest_constraint))
    for algo_name, constraint in constraints:
        if not constraint.allowed:
            if constraint.not_allowed_after:
                # rewind the clock up until the point where the algorithm
                # was actually permissible
                control_time = min(control_time, constraint.not_allowed_after)
            else:
                raise DisallowedAlgorithmError(
                    f"Algorithm {algo_name} is banned outright without "
                    f"time constraints",
                    is_ee_cert=False,
                    is_side_validation=True,
                )
    return control_time


def _update_control_time(
    revoked_date: Optional[datetime],
    control_time: datetime,
    revinfo_container: RevinfoContainer,
    rev_trust_policy: CertRevTrustPolicy,
    time_tolerance: timedelta,
    algo_policy: Optional[AlgorithmUsagePolicy],
):
    if revoked_date:
        # this means we have to update control_time
        control_time = min(revoked_date, control_time)
    else:
        # if the cert is not on the list, we need the freshness check
        rating = revinfo_container.usable_at(
            rev_trust_policy,
            ValidationTimingParams(
                timing_info=ValidationTimingInfo(
                    validation_time=control_time,
                    use_poe_time=control_time,
                    point_in_time_validation=True,
                ),
                time_tolerance=time_tolerance,
            ),
        )
        issuance_date = revinfo_container.issuance_date
        if (
            not rating.usable
            and rating != RevinfoUsabilityRating.TOO_NEW
            and issuance_date is not None
        ):
            # set the control time to the issuance date
            # (note: the TOO_NEW check is to prevent problems
            #  with freshness policies involving cooldown periods,
            #  which aren't really supported in the time sliding
            #  algorithm, but hey)
            control_time = min(issuance_date, control_time)

    algo_used = revinfo_container.revinfo_sig_mechanism_used
    if algo_policy is not None and algo_used is not None:
        control_time = _apply_algo_policy(algo_policy, algo_used, control_time)
    return control_time


async def _time_slide(
    path: ValidationPath,
    init_control_time: datetime,
    revinfo_manager: RevinfoManager,
    rev_trust_policy: CertRevTrustPolicy,
    algo_usage_policy: Optional[AlgorithmUsagePolicy],
    # TODO use policy objects
    time_tolerance: timedelta,
    cert_stack: ConsList[bytes],
    path_stack: ConsList[ValidationPath],
) -> datetime:
    control_time = init_control_time
    checking_policy = rev_trust_policy.revocation_checking_policy

    # For zero-length paths, there is nothing to check
    if path.pkix_len == 0:
        return init_control_time

    # The ETSI algorithm requires us to collect revinfo for each
    # cert in the path, starting with the first (after the root).
    # Since our revinfo collection methods require paths instead of individual
    # certs, we instead loop over partial paths
    partial_paths = list(reversed(list(_tails(path))))
    for current_path, is_ee in partial_paths:
        crls, ocsps = await _ades_gather_lta_revocation(
            current_path,
            revinfo_manager=revinfo_manager,
            control_time=control_time,
            revocation_checking_rule=(
                checking_policy.ee_certificate_rule
                if is_ee
                else checking_policy.intermediate_ca_cert_rule
            ),
        )
        cert = current_path.leaf
        new_cert_stack = cert_stack.cons(cert.dump())
        new_path_stack = path_stack.cons(path)
        if not crls and not ocsps:
            if isinstance(cert, x509.Certificate):
                ident = cert.subject.human_friendly
            else:
                ident = "attribute certificate"

            proc_state = ValProcState(cert_path_stack=new_path_stack)

            # don't raise an error for revo-exempt certs (OCSP responders)
            if cert.ocsp_no_check_value is None:
                raise InsufficientRevinfoError.from_state(
                    f"No revocation info from before {control_time.isoformat()}"
                    f" found for certificate {ident}.",
                    proc_state,
                )

        # We always take the chain of trust of a CRL/OCSP response
        # at face value
        poe_manager = revinfo_manager.poe_manager
        for crl_of_interest in crls:
            # skip CRLs that are no longer relevant
            issued = crl_of_interest.crl.issuance_date
            if (
                not issued
                or issued > control_time
                or poe_manager[crl_of_interest.crl.crl_data] > control_time
            ):
                continue
            sub_paths = crl_of_interest.prov_paths

            # recurse into the paths associated with the CRL and adjust
            # the control time accordingly
            # don't bother checking issuers that already appear
            # in the chain of trust that we're currently looking into
            sub_path_skip_list: Set[bytes] = set(new_cert_stack) | set(
                cert.dump() for cert in current_path
            )
            sub_path_control_times = await asyncio.gather(
                *(
                    _time_slide(
                        crl_path.path,
                        control_time,
                        revinfo_manager,
                        rev_trust_policy,
                        algo_usage_policy,
                        time_tolerance,
                        cert_stack=new_cert_stack,
                        path_stack=new_path_stack,
                    )
                    for crl_path in sub_paths
                    if (
                        crl_path.path.leaf
                        and crl_path.path.leaf.dump() not in sub_path_skip_list
                    )
                )
            )
            control_time = min([control_time, *sub_path_control_times])

            for candidate_crl_path in sub_paths:
                revoked_date, revoked_reason = _check_cert_on_crl_and_delta(
                    crl_issuer=candidate_crl_path.path.leaf,
                    cert=cert,
                    certificate_list_cont=crl_of_interest.crl,
                    delta_certificate_list_cont=candidate_crl_path.delta,
                    errs=_CRLErrs(),
                )

                control_time = _update_control_time(
                    revoked_date,
                    control_time,
                    revinfo_container=crl_of_interest.crl,
                    rev_trust_policy=rev_trust_policy,
                    time_tolerance=time_tolerance,
                    algo_policy=algo_usage_policy,
                )
        for ocsp_of_interest in ocsps:

            issued = ocsp_of_interest.ocsp_response.issuance_date
            if (
                not issued
                or issued > control_time
                or poe_manager[
                    ocsp_of_interest.ocsp_response.ocsp_response_data
                ]
                > control_time
            ):
                continue

            control_time = await _time_slide(
                ocsp_of_interest.prov_path,
                control_time,
                revinfo_manager,
                rev_trust_policy,
                algo_usage_policy,
                time_tolerance,
                cert_stack=new_cert_stack,
                path_stack=new_path_stack,
            )
            try:
                _check_ocsp_status(
                    ocsp_response=ocsp_of_interest.ocsp_response,
                    proc_state=ValProcState(cert_path_stack=new_path_stack),
                    control_time=control_time,
                )
                revoked_date = None
            except RevokedError as e:
                revoked_date = e.revocation_dt

            control_time = _update_control_time(
                revoked_date,
                control_time,
                revinfo_container=ocsp_of_interest.ocsp_response,
                rev_trust_policy=rev_trust_policy,
                time_tolerance=time_tolerance,
                algo_policy=algo_usage_policy,
            )
        # check the algorithm constraints for the certificate itself
        if algo_usage_policy is not None:
            control_time = _apply_algo_policy(
                algo_usage_policy, cert['signature_algorithm'], control_time
            )

    return control_time


async def time_slide(
    path: ValidationPath,
    init_control_time: datetime,
    revinfo_manager: RevinfoManager,
    rev_trust_policy: CertRevTrustPolicy,
    algo_usage_policy: Optional[AlgorithmUsagePolicy],
    time_tolerance: timedelta,
) -> datetime:
    """
    Execute the ETSI EN 319 102-1 time slide algorithm against the given path.

    .. warning::
        This is incubating internal API.

    .. note::
        This implementation will also attempt to take into account chains of
        trust of indirect CRLs. This is not a requirement of the specification,
        but also somewhat unlikely to arise in practice in cases where AdES
        compliance actually matters.

    :param path:
        The prospective validation path against which to execute the time slide
        algorithm.
    :param init_control_time:
        The initial control time, typically the current time.
    :param revinfo_manager:
        The revocation info manager.
    :param rev_trust_policy:
        The trust policy for revocation information.
    :param algo_usage_policy:
        The algorithm usage policy.
    :param time_tolerance:
        The tolerance to apply when evaluating time-related constraints.
    :return:
        The resulting control time.
    """
    return await _time_slide(
        path,
        init_control_time,
        revinfo_manager,
        rev_trust_policy,
        algo_usage_policy,
        time_tolerance,
        cert_stack=ConsList.empty(),
        path_stack=ConsList.empty(),
    )
