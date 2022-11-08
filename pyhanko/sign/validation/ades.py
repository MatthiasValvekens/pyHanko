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
import itertools
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import (
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
)

from asn1crypto import cms
from asn1crypto import pdf as asn1_pdf
from asn1crypto import tsp, x509
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.authority import CertTrustAnchor, TrustAnchor
from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
    ValidationDataHandlers,
)
from pyhanko_certvalidator.errors import ValidationError
from pyhanko_certvalidator.ltv.ades_past import past_validate
from pyhanko_certvalidator.ltv.poe import POEManager, digest_for_poe
from pyhanko_certvalidator.ltv.time_slide import ades_gather_prima_facie_revinfo
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import RevocationCheckingRule
from pyhanko_certvalidator.registry import PathBuilder, TrustManager
from pyhanko_certvalidator.revinfo.validate_crl import CRLOfInterest
from pyhanko_certvalidator.revinfo.validate_ocsp import OCSPResponseOfInterest

from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader
from pyhanko.sign.ades.report import (
    AdESFailure,
    AdESIndeterminate,
    AdESPassed,
    AdESSubIndic,
)
from pyhanko.sign.general import (
    CMSExtractionError,
    CMSStructuralError,
    MultivaluedAttributeError,
    NonexistentAttributeError,
    extract_certificate_info,
    find_cms_attribute,
    find_unique_cms_attribute,
)
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    EmbeddedPdfSignature,
    errors,
    generic_cms,
)
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.generic_cms import (
    extract_tst_data,
    validate_tst_signed_data,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.status import (
    RevocationDetails,
    SignatureCoverageLevel,
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
    AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
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
    # TODO allow selecting one of multiple timestamps here?
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
    paths = path_builder.async_build_paths_lazy(cert)
    try:
        async for cand_path in paths:
            current_subindication, revo_details, validation_time = \
                generic_cms.handle_certvalidator_errors(
                    await past_validate(
                        path=cand_path,
                        validation_policy_spec=validation_policy_spec,
                        validation_data_handlers=validation_data_handlers,
                        init_control_time=timing_info.validation_time,
                        best_signature_time=timing_info.best_signature_time,
                    )
                )
            if current_subindication is None:
                return cand_path, validation_time
    finally:
        await paths.cancel()

    msg = "Unable to construct plausible past validation path"
    if current_subindication is not None:
        raise errors.SignatureValidationError(
            failure_message=msg,
            ades_subindication=current_subindication
        )
    else:
        raise errors.SignatureValidationError(
            failure_message=f"{msg}: no prima facie paths constructed",
            ades_subindication=AdESIndeterminate.NO_CERTIFICATE_CHAIN_FOUND
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

    # TODO revisit this once I have a clearer understanding of why this PoE
    #  issuance check is only applied to the EE cert.
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
        if current_time_sub_indic == AdESIndeterminate.REVOKED_NO_POE:
            _pass_contingent_on_revinfo_issuance_poe()
            return
        elif current_time_sub_indic in (
                AdESIndeterminate.REVOKED_CA_NO_POE,
                AdESIndeterminate.CRYPTO_CONSTRAINTS_FAILURE_NO_POE
        ):
            # This is an automatic pass given that certvalidator checks
            # these conditions for us as part of past_validate(...)
            return
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

    # TODO here, it would help to preserve more than the sub-indication
    #  from before
    raise errors.SigSeedValueValidationError(
        failure_message=(
            "Past signature validation did not manage "
            "to improve current time result."
        ),
        ades_subindication=current_time_sub_indic
    )


@dataclass(frozen=True)
class PrimaFaciePOE:
    pdf_revision: int
    timestamp_dt: datetime
    digests_covered: FrozenSet[bytes]
    timestamp_token_signed_data: cms.SignedData


def _extract_cert_digests_from_signed_data(sd: cms.SignedData):
    cert_choice: cms.CertificateChoices
    for cert_choice in sd['certificates']:
        if cert_choice.name in ('certificate', 'v2_attr_set'):
            yield digest_for_poe(cert_choice.chosen.dump())


def _get_tst_timestamp(sd: cms.SignedData) -> datetime:
    tst_info: tsp.TSTInfo = sd['encap_content_info']['content']
    return tst_info['gen_time'].native


async def _tst_integrity_precheck(
        sd: cms.SignedData, expected_tst_imprint: bytes):
    try:
        kwargs = await validate_tst_signed_data(
            tst_signed_data=sd,
            validation_context=None,
            expected_tst_imprint=expected_tst_imprint
        )
        return kwargs['intact']
    except SignatureValidationError:
        return False


async def _build_prima_facie_poe_index_from_pdf_timestamps(
        r: PdfFileReader,
        include_content_ts: bool = False):
    # This subroutine implements the POE gathering part of the evidence record
    # processing algorithm in AdES as applied to PDF. For the purposes of this
    # function, the chain of document timestamps is treated as a single evidence
    # record, and all document data in the revision in which a timestamp is
    # contained is considered fair game.
    # Signature timestamps are not processed as such, but POE for the timestamps
    # themselves will be accumulated.
    # Content timestamps can optionally be included. This is not standard
    # in AdES, but since there's no cryptographic difference (in PDF!) between
    # a content TS in a signature and a document timestamp signature, they
    # can be taken into account at the caller's discretion

    # TODO take algorithm usage policy into account?

    # TODO when ingesting OCSP responses, make an effort to register
    #  POE for the embedded certs as well? Esp. potiential responder certs.

    # timestamp -> hashes index. We haven't validated the chain of trust
    # of the timestamps yet, so we can't put them in an actual
    # POE manager immediately

    # Since the embedded signature context is necessary to validate the POE's
    # integrity, we do run the integrity checker for the TST data at this stage.
    # The actual trust validation is delegated

    collected_so_far: Set[bytes] = set()
    # Holds all digests of objects contained in _document_ content so far
    # (note: this is why it's important to traverse the revisions in order)

    for_next_ts: Set[bytes] = set()
    # Holds digests of objects that will be registered with POE on the next
    # document TS or content TS encountered.

    prima_facie_poe_sets: List[PrimaFaciePOE] = []
    # output array (to avoid having to work with async generators)

    embedded_sig: EmbeddedPdfSignature

    for ix, embedded_sig in enumerate(r.embedded_signatures):

        hist_handler = HistoricalResolver(
            r, revision=embedded_sig.signed_revision
        )

        signed_data: cms.SignedData = embedded_sig.signed_data
        ts_signed_data: Optional[cms.SignedData] = None
        is_doc_ts = False
        if embedded_sig.sig_object_type == '/DocTimeStamp':
            ts_signed_data = signed_data
            is_doc_ts = True
        elif include_content_ts:
            ts_signed_data = extract_tst_data(embedded_sig, signed=True)

        # Important remark: at this time, we do NOT consider signature
        # timestamps when evaluating POE data, only content timestamps &
        # document timestamps!
        # Rationale: the signature timestamp only indirectly protects
        # the document content, and wasn't designed for this purpose.
        # If we want to use signature TSes as well, we'd have to evaluate
        # the integrity of the signature, which requires selecting a certificate
        # (even if just for validation purposes), yada yada. Not doing any of
        # that for now.
        # (This approach might change in the future)

        if ts_signed_data is not None:
            # add DSS content
            dss = DocumentSecurityStore.read_dss(hist_handler)
            collected_so_far.update(
                digest_for_poe(item.dump())
                for item in itertools.chain(dss.crls, dss.ocsps, dss.certs)
            )
            collected_so_far.update(for_next_ts)
            doc_digest = embedded_sig.compute_digest()
            coverage_normal = embedded_sig.evaluate_signature_coverage() \
                              >= SignatureCoverageLevel.ENTIRE_REVISION
            if coverage_normal and \
                    await _tst_integrity_precheck(signed_data, doc_digest):
                prima_facie_poe_sets.append(
                    PrimaFaciePOE(
                        pdf_revision=embedded_sig.signed_revision,
                        timestamp_dt=_get_tst_timestamp(ts_signed_data),
                        digests_covered=frozenset(collected_so_far),
                        timestamp_token_signed_data=ts_signed_data
                    )
                )
                # reset for_next_ts
                for_next_ts = set()
            for_next_ts.update(
                _extract_cert_digests_from_signed_data(ts_signed_data)
            )

        # the certs in the signature container itself are not part of the
        # signed data in that revision, but they're covered
        # by whatever the next (content) TS covers -> keep 'em
        for_next_ts.update(_extract_cert_digests_from_signed_data(signed_data))

        # same for revinfo embedded Adobe-style:
        # part of the signed data, but not directly timestamped
        # => save for next TS
        signed_attrs = embedded_sig.signer_info['signed_attrs']
        if not is_doc_ts:
            try:
                revinfo_attr: asn1_pdf.RevocationInfoArchival = \
                    find_unique_cms_attribute(
                        signed_attrs,
                        'adobe_revocation_info_archival'
                    )

                for_next_ts.update(
                    digest_for_poe(item.dump())
                    for item in itertools.chain(
                        revinfo_attr['crl'], revinfo_attr['ocsp']
                    )
                )
            except (MultivaluedAttributeError, NonexistentAttributeError):
                pass

        # Prepare a POE entry for the signature itself (to be processed
        # with the next timestamp)
        sig_bytes = embedded_sig.signer_info['signature'].native
        for_next_ts.add(digest_for_poe(sig_bytes))

        # add POE entries for the timestamp(s) attached to this signature
        try:
            content_tses = find_cms_attribute(
                signed_attrs, 'content_time_stamp'
            )
        except (NonexistentAttributeError, CMSStructuralError):
            content_tses = ()

        try:
            signature_tses = find_cms_attribute(
                embedded_sig.signer_info['unsigned_attributes'],
                'signature_time_stamp'
            )
        except (NonexistentAttributeError, CMSStructuralError):
            signature_tses = ()

        for ts_data in itertools.chain(signature_tses, content_tses):
            for ts_signer_info in ts_data['content']['signer_infos']:
                ts_sig_bytes = ts_signer_info['signature'].native
                for_next_ts.add(digest_for_poe(ts_sig_bytes))

    return prima_facie_poe_sets
