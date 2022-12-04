"""
This module contains a number of primitives to handle AdES signature validation
at some point in the future.

It's highly volatile, buggy internal API at this point, and should be considered
very experimental.

.. note::
    The only reason why this is even in the main tree at all is because
    continually rebasing the branch on which it lives became too much of a drag.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, List, Optional, Set, Tuple, TypeVar

from asn1crypto import cms, x509
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.authority import CertTrustAnchor, TrustAnchor
from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
    ValidationDataHandlers,
)
from pyhanko_certvalidator.errors import PathValidationError, ValidationError
from pyhanko_certvalidator.ltv.ades_past import past_validate
from pyhanko_certvalidator.ltv.errors import TimeSlideFailure
from pyhanko_certvalidator.ltv.poe import POEManager, digest_for_poe
from pyhanko_certvalidator.ltv.time_slide import ades_gather_prima_facie_revinfo
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import RevocationCheckingRule
from pyhanko_certvalidator.registry import PathBuilder, TrustManager
from pyhanko_certvalidator.revinfo.validate_crl import CRLOfInterest
from pyhanko_certvalidator.revinfo.validate_ocsp import OCSPResponseOfInterest

from pyhanko.sign.ades.report import (
    AdESFailure,
    AdESIndeterminate,
    AdESPassed,
    AdESSubIndic,
)
from pyhanko.sign.general import CMSExtractionError, extract_certificate_info
from pyhanko.sign.validation import errors, generic_cms
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.status import (
    RevocationDetails,
    SignatureStatus,
    StandardCMSSignatureStatus,
    TimestampSignatureStatus,
)

logger = logging.getLogger(__name__)

StatusType = TypeVar('StatusType', bound=SignatureStatus)


@dataclass(frozen=True)
class AdESBasicValidationResult:
    ades_subindic: AdESSubIndic
    api_status: Optional[StatusType]
    failure_msg: Optional[str]


@dataclass
class _InternalBasicValidationResult:
    ades_subindic: AdESSubIndic
    signature_poe_time: Optional[datetime]
    signature_not_before_time: Optional[datetime]
    status_kwargs: Optional[dict] = None
    trust_subindic_update: Optional[AdESSubIndic] = None

    signature_ts_validity: Optional[TimestampSignatureStatus] = None
    content_ts_validity: Optional[TimestampSignatureStatus] = None

    def update(self, status_cls, with_ts):
        status_kwargs = self.status_kwargs
        if self.trust_subindic_update:
            status_kwargs['trust_problem_indic'] = self.trust_subindic_update

        if with_ts and self.signature_ts_validity:
            status_kwargs['timestamp_validity'] = self.signature_ts_validity
        if with_ts and self.content_ts_validity:
            status_kwargs['content_timestamp_validity'] \
                = self.content_ts_validity
        return status_cls(**status_kwargs)


# ETSI EN 319 102-1 § 5.4

async def ades_timestamp_validation(
        tst_signed_data: cms.SignedData,
        validation_context: ValidationContext,
        expected_tst_imprint: bytes) -> AdESBasicValidationResult:
    status_kwargs = await generic_cms.validate_tst_signed_data(
        tst_signed_data, validation_context=validation_context,
        expected_tst_imprint=expected_tst_imprint
    )
    status = TimestampSignatureStatus(**status_kwargs)
    if not status.intact:
        return AdESBasicValidationResult(
            ades_subindic=AdESFailure.HASH_FAILURE,
            api_status=status,
            failure_msg=None
        )
    elif not status.valid:
        return AdESBasicValidationResult(
            ades_subindic=AdESFailure.SIG_CRYPTO_FAILURE,
            api_status=status,
            failure_msg=None
        )

    interm_result = await _process_basic_validation(
        tst_signed_data, status, validation_context,
        signature_not_before_time=None
    )
    interm_result.status_kwargs = status_kwargs
    return AdESBasicValidationResult(
        ades_subindic=interm_result.ades_subindic,
        api_status=interm_result.update(
            TimestampSignatureStatus, with_ts=False
        ),
        failure_msg=None
    )


async def _ades_process_attached_ts(signer_info, validation_context,
                                    signed: bool) \
        -> AdESBasicValidationResult:
    tst_signed_data = generic_cms.extract_tst_data(signer_info, signed=signed)
    if tst_signed_data is not None:
        return await ades_timestamp_validation(
            tst_signed_data, validation_context,
            generic_cms.compute_signature_tst_digest(signer_info),
        )
    return AdESBasicValidationResult(
        ades_subindic=AdESIndeterminate.GENERIC,
        failure_msg=None, api_status=None
    )


async def _process_basic_validation(
        signed_data: cms.SignedData, temp_status: SignatureStatus,
        ts_validation_context: ValidationContext,
        signature_not_before_time: Optional[datetime]):
    ades_trust_status: Optional[AdESSubIndic] = temp_status.trust_problem_indic
    signer_info = generic_cms.extract_signer_info(signed_data)
    ts_status: Optional[TimestampSignatureStatus] = None
    if ades_trust_status in (AdESIndeterminate.REVOKED_NO_POE,
                             AdESIndeterminate.OUT_OF_BOUNDS_NO_POE):
        # check content timestamp
        # TODO allow selecting one of multiple here
        content_ts_result = await _ades_process_attached_ts(
            signer_info, ts_validation_context, signed=True
        )
        if content_ts_result.ades_subindic == AdESPassed.OK:
            ts_status = content_ts_result.api_status

            if signature_not_before_time is not None:
                signature_not_before_time = max(
                    ts_status.timestamp, signature_not_before_time
                )
            else:
                signature_not_before_time = ts_status.timestamp

            # now we potentially have POE to know for sure that the signer's
            # certificate was in fact revoked/expired.
            # HOWEVER, according to the spec it is _not_ within this functions
            # remit to check the signature timestamp to reverse a positive
            # X_NO_POE judgement!!
            if ades_trust_status == AdESIndeterminate.REVOKED_NO_POE:
                revo_details: RevocationDetails = temp_status.revocation_details
                cutoff = revo_details.revocation_date
                perm_status = AdESFailure.REVOKED
            else:
                cutoff = temp_status.signing_cert.not_valid_after
                perm_status = AdESIndeterminate.EXPIRED

            if signature_not_before_time >= cutoff:
                ades_trust_status = perm_status
    # TODO process all attributes in signature acceptance validation step!!

    ades_subindic = ades_trust_status or AdESPassed.OK
    return _InternalBasicValidationResult(
        ades_subindic=ades_subindic,
        trust_subindic_update=ades_trust_status,
        content_ts_validity=ts_status,
        signature_not_before_time=signature_not_before_time,
        signature_poe_time=None
    )


# ETSI EN 319 102-1 § 5.3

async def ades_basic_validation(
        signed_data: cms.SignedData,
        # FIXME: streamline validation context bootstrapping, in particular
        #  it's not yet clear to me how we should handle init for
        #  ValidationDataHandlers in the general case
        cert_validation_policy: CertValidationPolicySpec,
        timing_info: ValidationTimingInfo,
        validation_data_handlers: ValidationDataHandlers,
        key_usage_settings: KeyUsageConstraints,
        raw_digest: Optional[bytes] = None,
        signature_not_before_time: Optional[datetime] = None) \
        -> AdESBasicValidationResult:
    validation_context = cert_validation_policy.build_validation_context(
        timing_info=timing_info,
        handlers=validation_data_handlers
    )
    interm_result = await _ades_basic_validation(
        signed_data=signed_data,
        validation_context=validation_context,
        key_usage_settings=key_usage_settings,
        raw_digest=raw_digest,
        signature_not_before_time=signature_not_before_time
    )
    if isinstance(interm_result, AdESBasicValidationResult):
        return interm_result

    return AdESBasicValidationResult(
        ades_subindic=interm_result.ades_subindic,
        api_status=interm_result.update(SignatureStatus, with_ts=False),
        failure_msg=None
    )


async def _ades_basic_validation(
        signed_data: cms.SignedData,
        validation_context: ValidationContext,
        key_usage_settings: KeyUsageConstraints,
        raw_digest: Optional[bytes],
        signature_not_before_time: Optional[datetime]):
    try:
        status_kwargs = await generic_cms.cms_basic_validation(
            signed_data, raw_digest=raw_digest,
            validation_context=validation_context,
            key_usage_settings=key_usage_settings
        )
    except errors.SignatureValidationError as e:
        return AdESBasicValidationResult(
            ades_subindic=e.ades_subindication, failure_msg=e.failure_message,
            api_status=None
        )

    # put the temp status into a SignatureStatus object for convenience
    status: SignatureStatus = SignatureStatus(**status_kwargs)
    if not status.intact:
        return AdESBasicValidationResult(
            ades_subindic=AdESFailure.HASH_FAILURE,
            api_status=status,
            failure_msg=None
        )
    elif not status.valid:
        return AdESBasicValidationResult(
            ades_subindic=AdESFailure.SIG_CRYPTO_FAILURE,
            api_status=status,
            failure_msg=None
        )

    interm_result = await _process_basic_validation(
        signed_data, status, validation_context,
        signature_not_before_time=signature_not_before_time
    )
    interm_result.status_kwargs = status_kwargs
    return interm_result


@dataclass(frozen=True)
class AdESWithTimeValidationResult(AdESBasicValidationResult):
    best_signature_time: datetime
    signature_not_before_time: Optional[datetime]


_WITH_TIME_FURTHER_PROC = frozenset({
    AdESPassed.OK,
    # This is a permanent failure for us
    # AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
    AdESIndeterminate.REVOKED_NO_POE,
    AdESIndeterminate.REVOKED_CA_NO_POE,
    # TODO process TRY_LATER
    # AdESIndeterminate.TRY_LATER,
    AdESIndeterminate.OUT_OF_BOUNDS_NO_POE
})


# ETSI EN 319 102-1 § 5.5

async def ades_with_time_validation(
        signed_data: cms.SignedData,
        cert_validation_policy: CertValidationPolicySpec,
        timing_info: ValidationTimingInfo,
        validation_data_handlers: ValidationDataHandlers,
        key_usage_settings: KeyUsageConstraints,
        raw_digest: Optional[bytes] = None,
        signature_not_before_time: Optional[datetime] = None) \
        -> AdESWithTimeValidationResult:
    validation_context = cert_validation_policy.build_validation_context(
        timing_info=timing_info,
        handlers=validation_data_handlers
    )

    sig_bytes = signed_data['signer_infos'][0]['signature'].native
    signature_poe_time = validation_data_handlers.poe_manager[sig_bytes]

    # FIXME instead of passing in validation contexts here, the AdES logic
    #  should take care of that in a spec compliant way (from more basic inputs)
    # NOTE: in particular, revinfo should be handled by the AdES component

    interm_result = await _ades_basic_validation(
        signed_data, validation_context=validation_context,
        key_usage_settings=key_usage_settings, raw_digest=raw_digest,
        signature_not_before_time=signature_not_before_time
    )
    signature_not_before_time = interm_result.signature_not_before_time
    if isinstance(interm_result, AdESBasicValidationResult) \
            or interm_result.ades_subindic not in _WITH_TIME_FURTHER_PROC:
        return AdESWithTimeValidationResult(
            ades_subindic=interm_result.ades_subindic,
            api_status=interm_result.api_status,
            failure_msg=interm_result.failure_msg,
            best_signature_time=signature_poe_time,
            signature_not_before_time=signature_not_before_time
        )

    signer_info = generic_cms.extract_signer_info(signed_data)

    # process signature timestamps
    # TODO allow selecting one of multiple timestamps here
    sig_ts_result = await _ades_process_attached_ts(
        signer_info, validation_context, signed=False
    )
    temp_status = interm_result.update(SignatureStatus, with_ts=False)

    if sig_ts_result.ades_subindic != AdESPassed.OK:
        return AdESWithTimeValidationResult(
            ades_subindic=interm_result.ades_subindic,
            api_status=temp_status,
            failure_msg=None,
            best_signature_time=signature_poe_time,
            signature_not_before_time=signature_not_before_time
        )

    ts_status = sig_ts_result.api_status

    if signature_poe_time is not None:
        signature_poe_time = min(ts_status.timestamp, signature_poe_time)
    else:
        signature_poe_time = ts_status.timestamp
    interm_result.signature_ts_validity = ts_status
    interm_result.signature_poe_time = signature_poe_time

    if interm_result.ades_subindic == AdESIndeterminate.REVOKED_NO_POE:
        revo_details: RevocationDetails = temp_status.revocation_details
        if signature_poe_time >= revo_details.revocation_date:
            # nothing we can do
            return AdESWithTimeValidationResult(
                ades_subindic=interm_result.ades_subindic,
                api_status=temp_status, failure_msg=None,
                best_signature_time=signature_poe_time,
                signature_not_before_time=signature_not_before_time
            )
    elif interm_result.ades_subindic == \
            AdESIndeterminate.OUT_OF_BOUNDS_NO_POE:
        # NOTE: we can't process expiration here since we don't have access
        #  to _timestamped_ revocation information
        if signature_poe_time < temp_status.signing_cert.not_valid_before:
            # FIXME replace temp_status as well
            return AdESWithTimeValidationResult(
                ades_subindic=AdESIndeterminate.NOT_YET_VALID,
                api_status=temp_status, failure_msg=None,
                best_signature_time=signature_poe_time,
                signature_not_before_time=signature_not_before_time
            )

    # TODO TSTInfo ordering/comparison check
    if signature_not_before_time is not None and \
            signature_not_before_time > signature_poe_time:
        return AdESWithTimeValidationResult(
            ades_subindic=AdESIndeterminate.TIMESTAMP_ORDER_FAILURE,
            api_status=temp_status, failure_msg=None,
            best_signature_time=signature_poe_time,
            signature_not_before_time=signature_not_before_time
        )
    # TODO handle time-stamp delay
    # TODO handle TRY_LATER  (now forcibly excluded)
    interm_result.trust_subindic_update = None
    interm_result.status_kwargs['trust_problem_indic'] = None

    status = interm_result.update(StandardCMSSignatureStatus, with_ts=True)
    return AdESWithTimeValidationResult(
        ades_subindic=AdESPassed.OK,
        api_status=status, failure_msg=None,
        best_signature_time=signature_poe_time,
        signature_not_before_time=signature_not_before_time
    )


class _TrustNoOne(TrustManager):

    def is_root(self, cert: x509.Certificate) -> bool:
        return False

    def find_potential_issuers(self, cert: x509.Certificate) \
            -> Iterator[TrustAnchor]:
        return iter(())


def _crl_issuer_cert_poe_boundary(
        crl: CRLOfInterest, cutoff: datetime, poe_manager: POEManager
):
    return any(
        poe_manager[prov_path.path.leaf] <= cutoff
        for prov_path in crl.prov_paths
    )


def _ocsp_issuer_cert_poe_boundary(
        ocsp: OCSPResponseOfInterest, cutoff: datetime, poe_manager: POEManager
):
    return poe_manager[ocsp.prov_path.leaf] <= cutoff


async def _find_revinfo_data_for_leaf_in_past(
        cert: x509.Certificate,
        validation_data_handlers: ValidationDataHandlers,
        control_time: datetime,
        revocation_checking_rule: RevocationCheckingRule):
    # Need to find a piece of revinfo for the signing cert, for which we have
    # POE for the issuer cert, which must be dated before the expiration date of
    # the cert. (Standard is unclear as to which cert this refers to, but
    # it's probably the date on the signing cert. Not much point in requiring
    # PoE for a cert before its self-declared expiration date...)
    # Since our revinfo gathering logic is based on paths, we gather up all
    # candidate issuers and work with those "truncated" candidate paths.
    # Trust is not an issue at this stage.
    registry = validation_data_handlers.cert_registry
    candidate_issuers = registry.find_potential_issuers(
        cert=cert, trust_manager=_TrustNoOne()
    )

    def _for_candidate_issuer(iss: x509.Certificate):
        truncated_path = ValidationPath(
            trust_anchor=CertTrustAnchor(iss),
            interm=[],
            leaf=cert
        )
        return ades_gather_prima_facie_revinfo(
            path=truncated_path,
            revinfo_manager=validation_data_handlers.revinfo_manager,
            control_time=control_time,
            revocation_checking_rule=revocation_checking_rule
        )

    job_futures = asyncio.as_completed(
        _for_candidate_issuer(iss) for iss in candidate_issuers
    )

    poe_manager = validation_data_handlers.poe_manager

    crls: List[CRLOfInterest] = []
    ocsps: List[OCSPResponseOfInterest] = []
    new_crls: Iterable[CRLOfInterest]
    new_ocsps: Iterable[OCSPResponseOfInterest]
    to_evict: Set[bytes] = set()
    for fut_results in job_futures:
        new_crls, new_ocsps = await fut_results
        # Collect the revinfos for which we have POE for the issuer cert
        # predating the expiration of the signer cert
        for crl_oi in new_crls:
            if _crl_issuer_cert_poe_boundary(
                    crl_oi, cert.not_valid_after, poe_manager
            ):
                crls.append(crl_oi)
            else:
                revinfo_data = crl_oi.crl.crl_data.dump()
                to_evict.add(digest_for_poe(revinfo_data))

        for ocsp_oi in new_ocsps:
            if _ocsp_issuer_cert_poe_boundary(
                ocsp_oi, cert.not_valid_after, poe_manager
            ):
                ocsps.append(ocsp_oi)
            else:
                revinfo_data = ocsp_oi.ocsp_response.ocsp_response_data.dump()
                to_evict.add(digest_for_poe(revinfo_data))
    # we only run the eviction logic if we found at least one piece of revinfo
    # that we can actually use (that's what the spec says, shouldn't change
    # validation result, but the reported error probably makes more sense)
    if crls or ocsps:
        validation_data_handlers.revinfo_manager.evict_crls(to_evict)
        validation_data_handlers.revinfo_manager.evict_ocsps(to_evict)
    return crls, ocsps


async def build_and_past_validate_cert(
        cert: x509.Certificate,
        validation_policy_spec: CertValidationPolicySpec,
        validation_data_handlers: ValidationDataHandlers,
        timing_info: ValidationTimingInfo,
) -> Tuple[ValidationPath, datetime]:

    path_builder = PathBuilder(
        trust_manager=validation_policy_spec.trust_manager,
        registry=validation_data_handlers.cert_registry
    )

    current_subindication = None
    last_e = None
    async for cand_path in path_builder.async_build_paths_lazy(cert):
        try:
            validation_time = await past_validate(
                path=cand_path,
                validation_policy_spec=validation_policy_spec,
                validation_data_handlers=validation_data_handlers,
                init_control_time=timing_info.validation_time,
                best_signature_time=timing_info.best_signature_time,
            )
            return cand_path, validation_time
        except TimeSlideFailure as e:
            current_subindication = AdESIndeterminate.NO_POE
            last_e = e
        except errors.DisallowedAlgorithmError as e:
            # This is not the NO_POE variant, but only triggered for
            # outright bans
            current_subindication = \
                AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE
            last_e = e
        except PathValidationError as e:
            current_subindication = \
                AdESIndeterminate.CHAIN_CONSTRAINTS_FAILURE
            last_e = e
        except ValidationError as e:
            # also covers precheck failures in the past validation algo
            current_subindication = \
                AdESIndeterminate.CERTIFICATE_CHAIN_GENERAL_FAILURE
            last_e = e

    subindication = current_subindication \
                    or AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND
    msg = "Unable to construct plausible past validation path"
    if last_e is not None:
        raise errors.SignatureValidationError(
            failure_message=msg,
            ades_subindication=subindication
        ) from last_e
    else:
        raise errors.SignatureValidationError(
            failure_message=f"{msg}: no prima facie paths constructed",
            ades_subindication=subindication
        )


async def ades_past_signature_validation(
        signed_data: cms.SignedData,
        cert_validation_policy: CertValidationPolicySpec,
        validation_time: datetime,
        validation_data_handlers: ValidationDataHandlers,
        current_time_sub_indic: Optional[AdESIndeterminate]):

    signature_bytes = signed_data['signer_infos'][0]['signature'].native
    timing_info = ValidationTimingInfo(
        validation_time,
        best_signature_time=validation_data_handlers.poe_manager[signature_bytes],
        point_in_time_validation=True
    )

    if validation_data_handlers.revinfo_manager.fetching_allowed:
        raise ValidationError(
            "Revinfo managers for past validation must have fetching disabled"
        )

    try:
        cert_info = extract_certificate_info(signed_data)
        cert = cert_info.signer_cert
    except CMSExtractionError:
        raise errors.SignatureValidationError(
            'signer certificate not included in signature',
            ades_subindication=AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND
        )
    leaf_crls, leaf_ocsps = await _find_revinfo_data_for_leaf_in_past(
        cert, validation_data_handlers,
        control_time=timing_info.validation_time,
        revocation_checking_rule=(
            cert_validation_policy
            .revinfo_policy
            .revocation_checking_policy
            .ee_certificate_rule
        )
    )

    # Key usage for the signer is not something that varies over time, so
    # we delegate that to the caller. This is justified both because it's
    # technically simpler, and because the past signature validation block
    # in AdES is predicated on delegating the basic integrity checks anyhow.
    cert_path, validation_time = await build_and_past_validate_cert(
        cert, validation_policy_spec=cert_validation_policy,
        validation_data_handlers=validation_data_handlers,
        timing_info=timing_info
    )

    def _pass_contingent_on_revinfo_issuance_poe():
        if not bool(leaf_crls or leaf_ocsps):
            status = AdESIndeterminate.REVOCATION_OUT_OF_BOUNDS_NO_POE
            raise errors.SignatureValidationError(
                failure_message=(
                    "POE for signature available, but could not obtain "
                    "sufficient POE for the issuance of the "
                    "revocation information",
                ),
                ades_subindication=status
            )

    if timing_info.best_signature_time <= validation_time:
        # TODO here the algorithm also relies on revinfo eviction
        if current_time_sub_indic == AdESIndeterminate.REVOKED_NO_POE:
            _pass_contingent_on_revinfo_issuance_poe()
            return
        elif current_time_sub_indic == AdESIndeterminate.REVOKED_CA_NO_POE:
            # TODO how can we get the revocation date for the CA here?
            # depends on integration
            raise NotImplementedError
        elif current_time_sub_indic in (
            AdESIndeterminate.OUT_OF_BOUNDS_NO_POE,
            AdESIndeterminate.OUT_OF_BOUNDS_NOT_REVOKED
        ):
            if timing_info.best_signature_time < cert.not_valid_before:
                raise errors.SignatureValidationError(
                    failure_message="Signature predates cert validity period",
                    ades_subindication=AdESFailure.NOT_YET_VALID
                )
            elif timing_info.best_signature_time <= cert.not_valid_after:
                _pass_contingent_on_revinfo_issuance_poe()
                return
        elif current_time_sub_indic == \
                AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE_NO_POE:
            # TODO how can we get the required date cutoffs here?
            # depends on integration
            raise NotImplementedError

    # TODO also here, it would help to preserve more than the sub-indication
    #  from before
    raise errors.SigSeedValueValidationError(
        failure_message=(
            "Past signature validation did not manage "
            "to improve current time result."
        ),
        ades_subindication=current_time_sub_indic
    )

