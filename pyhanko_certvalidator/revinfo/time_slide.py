from datetime import datetime, timedelta
from typing import List, Optional, Tuple

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
    is_ee = True
    while cur_path.pkix_len > 1:
        yield cur_path, is_ee
        is_ee = False
        cur_path = cur_path.copy_and_drop_leaf()


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


async def time_slide(
    path: ValidationPath,
    init_control_time: datetime,
    revinfo_manager: RevinfoManager,
    rev_trust_policy: CertRevTrustPolicy,
    algo_usage_policy: Optional[AlgorithmUsagePolicy],
    # TODO use policy objects
    time_tolerance: timedelta,
) -> datetime:
    control_time = init_control_time
    checking_policy = rev_trust_policy.revocation_checking_policy

    for current_path, is_ee in reversed(list(_tails(path))):
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
        if not crls and not ocsps:
            if isinstance(cert, x509.Certificate):
                ident = cert.subject.human_friendly
            else:
                ident = "attribute certificate"

            proc_state = ValProcState(
                cert_path_stack=ConsList.sing(current_path)
            )

            raise InsufficientRevinfoError.from_state(
                f"No revocation info from before {control_time.isoformat()}"
                f" found for certificate {ident}.",
                proc_state,
            )

        # FIXME: for now, take these on faith until we have
        #  a compliant point-in-time validation routine and we can recursively
        #  apply the time sliding algorithm to our revinfo paths as well
        for crl_of_interest in crls:
            prima_facie_trust = crl_of_interest.prov_paths[0]
            revoked_date, revoked_reason = _check_cert_on_crl_and_delta(
                crl_issuer=prima_facie_trust.path.leaf,
                cert=cert,
                certificate_list_cont=crl_of_interest.crl,
                delta_certificate_list_cont=prima_facie_trust.delta,
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
            try:
                _check_ocsp_status(
                    ocsp_response=ocsp_of_interest.ocsp_response,
                    proc_state=ValProcState(
                        cert_path_stack=ConsList.sing(current_path)
                    ),
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
