from dataclasses import dataclass
from typing import Optional, TypeVar

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
    api_status: Optional[StatusType] = None
    failure_msg: Optional[str] = None


async def ades_timestamp_validation(
        tst_signed_data: cms.SignedData,
        validation_context: ValidationContext,
        expected_tst_imprint: bytes) -> AdESBasicValidationResult:
    status_kwargs = await generic_cms.validate_tst_signed_data(
        tst_signed_data, validation_context=validation_context,
        expected_tst_imprint=expected_tst_imprint
    )
    status = TimestampSignatureStatus(**status_kwargs)
    return await _finish_basic_validation(
        tst_signed_data, status, status_kwargs, validation_context,
        status_cls=TimestampSignatureStatus
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
    return AdESBasicValidationResult(ades_subindic=AdESIndeterminate.GENERIC)


async def _finish_basic_validation(
        signed_data: cms.SignedData,
        temp_status: SignatureStatus,
        status_kwargs: dict,
        ts_validation_context: ValidationContext,
        status_cls):
    if not temp_status.intact:
        return AdESBasicValidationResult(
            ades_subindic=AdESFailure.HASH_FAILURE,
            api_status=temp_status,
        )
    elif not temp_status.valid:
        return AdESBasicValidationResult(
            ades_subindic=AdESFailure.SIG_CRYPTO_FAILURE,
            api_status=temp_status
        )

    ades_trust_status: Optional[AdESSubIndic] = temp_status.trust_problem_indic
    signer_info = generic_cms.extract_signer_info(signed_data)
    if ades_trust_status in (AdESIndeterminate.REVOKED_NO_POE,
                             AdESIndeterminate.OUT_OF_BOUNDS_NO_POE):
        # check content timestamp
        content_ts_result = await _ades_process_attached_ts(
            signer_info, ts_validation_context, signed=True
        )
        status_kwargs['timestamp_validity'] = content_ts_result.api_status
        if content_ts_result.ades_subindic == AdESPassed.OK:
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

            if content_ts_result.api_status.timestamp >= cutoff:
                status_kwargs['trust_problem_indic'] = \
                    ades_trust_status = perm_status

    # TODO process all attributes in signature acceptance validation step!!
    return AdESBasicValidationResult(
        ades_subindic=ades_trust_status or AdESPassed.OK,
        api_status=status_cls(**status_kwargs),
    )


async def ades_basic_validation(
        signed_data: cms.SignedData,
        validation_context: ValidationContext,
        key_usage_settings: KeyUsageConstraints,
        raw_digest: Optional[bytes] = None,
        ts_validation_context: Optional[ValidationContext] = None) \
        -> AdESBasicValidationResult:

    # FIXME instead of passing in validation contexts here, the AdES logic
    #  should take care of that in a spec compliant way (from more basic inputs)
    ts_validation_context = ts_validation_context or validation_context
    try:
        status_kwargs = await generic_cms.cms_basic_validation(
            signed_data, raw_digest=raw_digest,
            validation_context=validation_context,
            key_usage_settings=key_usage_settings
        )
    except SignatureValidationError as e:
        return AdESBasicValidationResult(
            ades_subindic=e.ades_subindication, failure_msg=e.failure_message
        )

    # put the temp status into a SignatureStatus object for convenience
    status: SignatureStatus = SignatureStatus(**status_kwargs)
    return await _finish_basic_validation(
        signed_data, status, status_kwargs, ts_validation_context,
        status_cls=StandardCMSSignatureStatus
    )
