from dataclasses import dataclass
from datetime import datetime
from typing import Optional, TypeVar

import tzlocal
from asn1crypto import cms
from pyhanko_certvalidator import ValidationContext

from pyhanko.sign.ades.report import (
    AdESFailure,
    AdESIndeterminate,
    AdESPassed,
    AdESSubIndic,
)
from pyhanko.sign.validation import generic_cms
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.status import (
    RevocationDetails,
    SignatureStatus,
    StandardCMSSignatureStatus,
    TimestampSignatureStatus,
)

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
        validation_context: ValidationContext,
        key_usage_settings: KeyUsageConstraints,
        raw_digest: Optional[bytes] = None,
        signature_not_before_time: Optional[datetime] = None,
        ts_validation_context: Optional[ValidationContext] = None) \
        -> AdESBasicValidationResult:

    # FIXME instead of passing in validation contexts here, the AdES logic
    #  should take care of that in a spec compliant way (from more basic inputs)
    interm_result = await _ades_basic_validation(
        signed_data=signed_data,
        validation_context=validation_context,
        key_usage_settings=key_usage_settings,
        raw_digest=raw_digest,
        ts_validation_context=ts_validation_context or validation_context,
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
        ts_validation_context: ValidationContext,
        signature_not_before_time: Optional[datetime]):

    try:
        status_kwargs = await generic_cms.cms_basic_validation(
            signed_data, raw_digest=raw_digest,
            validation_context=validation_context,
            key_usage_settings=key_usage_settings
        )
    except SignatureValidationError as e:
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
        signed_data, status, ts_validation_context,
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
        validation_context: ValidationContext,
        key_usage_settings: KeyUsageConstraints,
        raw_digest: Optional[bytes] = None,
        ts_validation_context: Optional[ValidationContext] = None,
        signature_not_before_time: Optional[datetime] = None,
        signature_poe_time: Optional[datetime] = None) \
        -> AdESWithTimeValidationResult:

    signature_poe_time = signature_poe_time \
                         or datetime.now(tz=tzlocal.get_localzone())

    # FIXME instead of passing in validation contexts here, the AdES logic
    #  should take care of that in a spec compliant way (from more basic inputs)
    # NOTE: in particular, revinfo should be handled by the AdES component

    interm_result = await _ades_basic_validation(
        signed_data, validation_context=validation_context,
        key_usage_settings=key_usage_settings, raw_digest=raw_digest,
        ts_validation_context=ts_validation_context or validation_context,
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
        signer_info, ts_validation_context, signed=False
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
