import asyncio
import hashlib
import logging
import os
import warnings
from collections import namedtuple
from dataclasses import dataclass
from dataclasses import field as data_field
from datetime import datetime
from enum import Enum, unique
from typing import IO, Iterator, Optional, Type, TypeVar, Union

from asn1crypto import cms, core
from asn1crypto import crl as asn1_crl
from asn1crypto import keys
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import pdf as asn1_pdf
from asn1crypto import tsp, x509
from asn1crypto.x509 import Certificate
from cryptography.hazmat.primitives import hashes
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.context import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.path import ValidationPath

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import (
    DEFAULT_CHUNK_SIZE,
    OrderedEnum,
    get_and_apply,
)
from pyhanko.pdf_utils.reader import (
    PdfFileReader,
    XRefCache,
    process_data_at_eof,
)
from pyhanko.pdf_utils.rw_common import PdfHandler

from .diff_analysis import (
    DEFAULT_DIFF_POLICY,
    DiffPolicy,
    DiffResult,
    ModificationLevel,
    SuspiciousModification,
)
from .fields import (
    FieldMDPSpec,
    MDPPerm,
    SeedLockDocument,
    SigSeedSubFilter,
    SigSeedValFlags,
    SigSeedValueSpec,
)
from .general import (
    DEFAULT_WEAK_HASH_ALGORITHMS,
    KeyUsageConstraints,
    MultivaluedAttributeError,
    NonexistentAttributeError,
    SignatureStatus,
    SignatureValidationError,
    UnacceptableSignerError,
    extract_message_digest,
    find_unique_cms_attribute,
    get_pyca_cryptography_hash,
    match_issuer_serial,
    validate_sig_integrity,
)
from .timestamps import TimestampSignatureStatus

__all__ = [
    'SignatureCoverageLevel', 'PdfSignatureStatus', 'DocumentTimestampStatus',
    'StandardCMSSignatureStatus', 'ModificationInfo',
    'EmbeddedPdfSignature', 'DocMDPInfo',
    'RevocationInfoValidationType', 'VRI', 'DocumentSecurityStore',
    'apply_adobe_revocation_info', 'get_timestamp_chain',
    'read_certification_data',
    'validate_pdf_ltv_signature', 'async_validate_pdf_ltv_signature',
    'validate_pdf_signature', 'async_validate_pdf_signature',
    'validate_cms_signature', 'async_validate_cms_signature',
    'validate_detached_cms', 'async_validate_detached_cms',
    'validate_pdf_timestamp', 'async_validate_pdf_timestamp',
    'collect_validation_info',
    'add_validation_info',
    'ValidationInfoReadingError', 'SigSeedValueValidationError'
]

from ..pdf_utils.writer import BasePdfFileWriter

logger = logging.getLogger(__name__)


class ValidationInfoReadingError(ValueError):
    """Error reading validation info."""
    pass


class NoDSSFoundError(ValidationInfoReadingError):
    def __init__(self):
        super().__init__("No DSS found")


class SigSeedValueValidationError(SignatureValidationError):
    """Error validating a signature's seed value constraints."""

    # TODO perhaps we can encode some more metadata here, such as the
    #  seed value that tripped the failure.

    def __init__(self, failure_message):
        self.failure_message = str(failure_message)
        super().__init__(failure_message)


def _get_signer_predicate(sid: cms.SignerIdentifier):
    if sid.name == 'issuer_and_serial_number':
        return lambda c: match_issuer_serial(sid.chosen, c)
    elif sid.name == 'subject_key_identifier':
        # subject key identifier (not all certs have this, but that shouldn't
        # be an issue in this case)
        ski = sid.chosen.native
        logger.warning(
            "The signature in this file seems to be identified by a subject "
            "key identifier --- this is legal in CMS, but many PDF viewers and "
            "SDKs do not support this."
        )
        return lambda c: c.key_identifier == ski
    raise NotImplementedError


def partition_certs(certs, signer_info):
    # The 'certificates' entry is defined as a set in PCKS#7.
    # In particular, we cannot make any assumptions about the order.
    # This means that we have to manually dig through the list to find
    # the actual signer
    predicate = _get_signer_predicate(signer_info['sid'])
    cert = None
    other_certs = []
    for c in certs:
        if predicate(c):
            cert = c
        else:
            other_certs.append(c)
    if cert is None:
        raise SignatureValidationError(
            'signer certificate not included in signature'
        )
    return cert, other_certs


StatusType = TypeVar('StatusType', bound=SignatureStatus)


def _extract_signer_info(signed_data: cms.SignedData) -> cms.SignerInfo:
    try:
        signer_info, = signed_data['signer_infos']
        return signer_info
    except ValueError:  # pragma: nocover
        raise ValueError(
            'signer_infos should contain exactly one entry'
        )


def _extract_self_reported_ts(signer_info: cms.SignerInfo) \
        -> Optional[datetime]:
    try:
        sa = signer_info['signed_attrs']
        st = find_unique_cms_attribute(sa, 'signing_time')
        return st.native
    except (NonexistentAttributeError, MultivaluedAttributeError):
        pass


def _extract_tst_data(signer_info, signed=False) -> Optional[cms.SignedData]:
    try:
        if signed:
            sa = signer_info['signed_attrs']
            tst = find_unique_cms_attribute(sa, 'content_time_stamp')
        else:
            ua = signer_info['unsigned_attrs']
            tst = find_unique_cms_attribute(ua, 'signature_time_stamp_token')
        tst_signed_data = tst['content']
        return tst_signed_data
    except (NonexistentAttributeError, MultivaluedAttributeError):
        pass


def _compute_tst_digest(signer_info: cms.SignerInfo) -> Optional[bytes]:

    tst_data = _extract_tst_data(signer_info)
    if tst_data is None:
        return None

    eci = tst_data['encap_content_info']
    mi = eci['content'].parsed['message_imprint']
    tst_md_algorithm = mi['hash_algorithm']['algorithm'].native

    signature_bytes = signer_info['signature'].native
    tst_md_spec = get_pyca_cryptography_hash(tst_md_algorithm)
    md = hashes.Hash(tst_md_spec)
    md.update(signature_bytes)
    return md.finalize()


def _extract_signer_info_and_certs(signed_data: cms.SignedData):
    certs = [c.parse() for c in signed_data['certificates']]

    signer_info = _extract_signer_info(signed_data)
    cert, other_certs = partition_certs(certs, signer_info)

    return signer_info, cert, other_certs


async def _validate_cms_signature(signed_data: cms.SignedData,
                                  status_cls:
                                  Type[StatusType] = SignatureStatus,
                                  raw_digest: bytes = None,
                                  validation_context: ValidationContext = None,
                                  status_kwargs: dict = None,
                                  key_usage_settings:
                                  KeyUsageConstraints = None,
                                  encap_data_invalid=False):
    """
    Validate CMS and PKCS#7 signatures.
    """
    signer_info, cert, other_certs = _extract_signer_info_and_certs(signed_data)

    weak_hash_algos = None
    if validation_context is not None:
        weak_hash_algos = validation_context.weak_hash_algos
    if weak_hash_algos is None:
        weak_hash_algos = DEFAULT_WEAK_HASH_ALGORITHMS

    signature_algorithm: cms.SignedDigestAlgorithm = \
        signer_info['signature_algorithm']
    mechanism = signature_algorithm['algorithm'].native
    md_algorithm = signer_info['digest_algorithm']['algorithm'].native
    eci = signed_data['encap_content_info']
    expected_content_type = eci['content_type'].native
    if raw_digest is None:
        # this means that there should be encapsulated data
        raw = bytes(eci['content'])
        md_spec = get_pyca_cryptography_hash(md_algorithm)
        md = hashes.Hash(md_spec)
        md.update(raw)
        raw_digest = md.finalize()

    # first, do the cryptographic identity checks
    intact, valid = validate_sig_integrity(
        signer_info, cert, expected_content_type=expected_content_type,
        actual_digest=raw_digest, weak_hash_algorithms=weak_hash_algos
    )

    # if the data being encapsulated by the signature is itself invalid,
    #  this flag is set
    intact &= not encap_data_invalid
    valid &= intact

    # next, validate trust
    trusted = revoked = False
    path = None
    if valid:
        validator = CertificateValidator(
            cert, intermediate_certs=other_certs,
            validation_context=validation_context
        )
        trusted, revoked, path = await status_cls.validate_cert_usage(
            validator, key_usage_settings=key_usage_settings
        )

    status_kwargs = status_kwargs or {}
    status_kwargs.update(
        intact=intact, valid=valid, signing_cert=cert,
        md_algorithm=md_algorithm, pkcs7_signature_mechanism=mechanism,
        revoked=revoked, trusted=trusted,
        validation_path=path
    )
    return status_kwargs


def validate_cms_signature(signed_data: cms.SignedData,
                           status_cls: Type[StatusType] = SignatureStatus,
                           raw_digest: bytes = None,
                           validation_context: ValidationContext = None,
                           status_kwargs: dict = None,
                           key_usage_settings: KeyUsageConstraints = None,
                           encap_data_invalid=False):
    """
    .. deprecated:: 0.9.0
        Use :func:`async_validate_cms_signature` instead.

    .. versionchanged:: 0.7.0
        Now handles both detached and enveloping signatures.

    Validate a CMS signature (i.e. a ``SignedData`` object).

    :param signed_data:
        The :class:`.asn1crypto.cms.SignedData` object to validate.
    :param status_cls:
        Status class to use for the validation result.
    :param raw_digest:
        Raw digest, computed from context.
    :param validation_context:
        Validation context to validate the signer's certificate.
    :param status_kwargs:
        Other keyword arguments to pass to the ``status_class`` when reporting
        validation results.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param encap_data_invalid:
        If ``True``, the encapsulated data inside the CMS is invalid,
        but the remaining validation logic still has to be run (e.g. a
        timestamp token, which requires validation of the embedded message
        imprint).

        This option is considered internal API, the semantics of which may
        change without notice in the future.
    :return:
        A :class:`.SignatureStatus` object (or an instance of a proper subclass)
    """

    warnings.warn(
        "'validate_cms_signature' is deprecated, use "
        "'async_validate_cms_signature' instead",
        DeprecationWarning
    )

    coro = async_validate_cms_signature(
        signed_data=signed_data, status_cls=status_cls, raw_digest=raw_digest,
        validation_context=validation_context, status_kwargs=status_kwargs,
        key_usage_settings=key_usage_settings,
        encap_data_invalid=encap_data_invalid
    )
    return asyncio.run(coro)


async def async_validate_cms_signature(
                           signed_data: cms.SignedData,
                           status_cls: Type[StatusType] = SignatureStatus,
                           raw_digest: bytes = None,
                           validation_context: ValidationContext = None,
                           status_kwargs: dict = None,
                           key_usage_settings: KeyUsageConstraints = None,
                           encap_data_invalid=False):
    """
    Validate a CMS signature (i.e. a ``SignedData`` object).

    :param signed_data:
        The :class:`.asn1crypto.cms.SignedData` object to validate.
    :param status_cls:
        Status class to use for the validation result.
    :param raw_digest:
        Raw digest, computed from context.
    :param validation_context:
        Validation context to validate the signer's certificate.
    :param status_kwargs:
        Other keyword arguments to pass to the ``status_class`` when reporting
        validation results.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param encap_data_invalid:
        If ``True``, the encapsulated data inside the CMS is invalid,
        but the remaining validation logic still has to be run (e.g. a
        timestamp token, which requires validation of the embedded message
        imprint).

        This option is considered internal API, the semantics of which may
        change without notice in the future.
    :return:
        A :class:`.SignatureStatus` object (or an instance of a proper subclass)
    """
    status_kwargs = await _validate_cms_signature(
        signed_data, status_cls, raw_digest, validation_context,
        status_kwargs, key_usage_settings, encap_data_invalid
    )
    return status_cls(**status_kwargs)


async def collect_timing_info(signer_info: cms.SignerInfo,
                              ts_validation_context: ValidationContext):

    status_kwargs = {}

    # timestamp-related validation
    signer_reported_dt = _extract_self_reported_ts(signer_info)
    if signer_reported_dt is not None:
        status_kwargs['signer_reported_dt'] = signer_reported_dt

    tst_signed_data = _extract_tst_data(signer_info, signed=False)
    if tst_signed_data is not None:
        tst_validity_kwargs = await _validate_timestamp(
            tst_signed_data, ts_validation_context,
            _compute_tst_digest(signer_info),
        )
        tst_validity = TimestampSignatureStatus(**tst_validity_kwargs)
        status_kwargs['timestamp_validity'] = tst_validity

    content_tst_signed_data = _extract_tst_data(signer_info, signed=True)
    if content_tst_signed_data is not None:
        content_tst_validity_kwargs = await _validate_timestamp(
            content_tst_signed_data, ts_validation_context,
            expected_tst_imprint=extract_message_digest(signer_info)
        )
        content_tst_validity = TimestampSignatureStatus(
            **content_tst_validity_kwargs
        )
        status_kwargs['content_timestamp_validity'] = content_tst_validity

    return status_kwargs


@dataclass(frozen=True)
class StandardCMSSignatureStatus(SignatureStatus):
    """
    Status of a standard "end-entity" CMS signature, potentially with
    timing information embedded inside.
    """

    signer_reported_dt: Optional[datetime] = None
    """
    Signer-reported signing time, if present in the signature.

    Generally speaking, this timestamp should not be taken as fact.
    """

    timestamp_validity: Optional[TimestampSignatureStatus] = None
    """
    Validation status of the signature timestamp token embedded in this 
    signature, if present.
    """

    content_timestamp_validity: Optional[TimestampSignatureStatus] = None
    """
    Validation status of the content timestamp token embedded in this 
    signature, if present.
    """

    @property
    def bottom_line(self) -> bool:
        """
        Formulates a general judgment on the validity of this signature.
        This takes into account the cryptographic validity of the signature,
        the signature's chain of trust and the validity of the timestamp token
        (if present).

        :return:
            ``True`` if all constraints are satisfied, ``False`` otherwise.
        """

        ts = self.timestamp_validity
        if ts is None:
            timestamp_ok = True
        else:
            timestamp_ok = ts.valid and ts.trusted

        content_ts = self.content_timestamp_validity
        if content_ts is None:
            content_timestamp_ok = True
        else:
            content_timestamp_ok = content_ts.valid and content_ts.trusted
        return (
                self.intact and self.valid and self.trusted and timestamp_ok
                and content_timestamp_ok
        )

    def summary_fields(self):
        yield from super().summary_fields()

        if self.timestamp_validity is not None:
            yield 'TIMESTAMP_TOKEN<%s>' % (
                '|'.join(self.timestamp_validity.summary_fields())
            )

    def pretty_print_details(self):
        def fmt_section(hdr, body):
            return '\n'.join(
                (hdr, '-' * len(hdr), body, '\n')
            )
        sections = self.pretty_print_sections()
        bottom_line = (
            f"The signature is judged {'' if self.bottom_line else 'IN'}VALID."
        )
        sections.append(("Bottom line", bottom_line))
        return '\n'.join(
            fmt_section(hdr, body) for hdr, body in sections
        )

    def pretty_print_sections(self):
        cert: x509.Certificate = self.signing_cert

        if self.trusted:
            trust_status = "trusted"
        elif self.revoked:
            trust_status = "revoked"
        else:
            trust_status = "untrusted"
        about_signer = (
            f"Certificate subject: \"{cert.subject.human_friendly}\"\n"
            f"Certificate SHA1 fingerprint: {cert.sha1.hex()}\n"
            f"Certificate SHA256 fingerprint: {cert.sha256.hex()}\n"
            f"Trust anchor: \"{self._trust_anchor}\"\n"
            f"The signer's certificate is {trust_status}."
        )

        validity_info = (
            "The signature is cryptographically "
            f"{'' if self.intact and self.valid else 'un'}sound.\n\n"
            f"The digest algorithm used was '{self.md_algorithm}'.\n"
            f"The signature mechanism used was "
            f"'{self.pkcs7_signature_mechanism}'."
        )
        if 'ecdsa' in self.pkcs7_signature_mechanism:
            ec_params: keys.ECDomainParameters = \
                cert.public_key['algorithm']['parameters']
            if ec_params.name == 'named':
                curve_oid: core.ObjectIdentifier = ec_params.chosen
                validity_info += (
                    f"\nThe elliptic curve used for the signer's ECDSA "
                    f"public key was '{curve_oid.native}' "
                    f"(OID: {curve_oid.dotted})."
                )

        timing_infos = []
        reported_ts = self.signer_reported_dt
        if reported_ts is not None:
            timing_infos.append(
                f"Signing time as reported by signer: {reported_ts.isoformat()}"
            )

        tst_status = self.timestamp_validity
        if tst_status is not None:
            ts = tst_status.timestamp
            timing_infos.append(
                f"Signature timestamp token: {ts.isoformat()}\n"
                f"The token is guaranteed to be newer than the signature.\n"
                f"{tst_status.describe_timestamp_trust()}"
            )
        content_tst_status = self.timestamp_validity
        if tst_status is not None:
            ts = content_tst_status.timestamp
            timing_infos.append(
                f"Content timestamp token: {ts.isoformat()}\n"
                f"The token is guaranteed to be older than the signature.\n"
                f"{content_tst_status.describe_timestamp_trust()}"
            )
        timing_info = (
            "No available information about the signing time."
            if not timing_infos else '\n\n'.join(timing_infos)
        )
        return [
            ("Signer info", about_signer), ("Integrity", validity_info),
            ("Signing time", timing_info),
        ]


def validate_detached_cms(input_data: Union[bytes, IO,
                                            cms.ContentInfo,
                                            cms.EncapsulatedContentInfo],
                          signed_data: cms.SignedData,
                          signer_validation_context: ValidationContext = None,
                          ts_validation_context: ValidationContext = None,
                          key_usage_settings: KeyUsageConstraints = None,
                          chunk_size=DEFAULT_CHUNK_SIZE,
                          max_read=None) -> StandardCMSSignatureStatus:
    """
    .. deprecated:: 0.9.0
        Use :func:`async_validate_detached_cms` instead.

    .. versionadded: 0.7.0

    Validate a detached CMS signature.

    :param input_data:
        The input data to sign. This can be either a :class:`bytes` object,
        a file-like object or a :class:`cms.ContentInfo` /
        :class:`cms.EncapsulatedContentInfo` object.

        If a CMS content info object is passed in, the `content` field
        will be extracted.
    :param signed_data:
        The :class:`cms.SignedData` object containing the signature to verify.
    :param signer_validation_context:
        Validation context to use to verify the signer certificate's trust.
    :param ts_validation_context:
        Validation context to use to verify the TSA certificate's trust, if
        a timestamp token is present.
        By default, the same validation context as that of the signer is used.
    :param key_usage_settings:
        Key usage parameters for the signer.
    :param chunk_size:
        Chunk size to use when consuming input data.
    :param max_read:
        Maximal number of bytes to read from the input stream.
    :return:
        A description of the signature's status.
    """

    warnings.warn(
        "'validate_detached_cms' is deprecated, use "
        "'async_validate_detached_cms' instead",
        DeprecationWarning
    )

    coro = async_validate_detached_cms(
        input_data=input_data,
        signed_data=signed_data,
        signer_validation_context=signer_validation_context,
        ts_validation_context=ts_validation_context,
        key_usage_settings=key_usage_settings,
        chunk_size=chunk_size,
        max_read=max_read
    )
    return asyncio.run(coro)


async def async_validate_detached_cms(
        input_data: Union[bytes, IO,
                          cms.ContentInfo, cms.EncapsulatedContentInfo],
        signed_data: cms.SignedData,
        signer_validation_context: ValidationContext = None,
        ts_validation_context: ValidationContext = None,
        key_usage_settings: KeyUsageConstraints = None,
        chunk_size=DEFAULT_CHUNK_SIZE,
        max_read=None
    ) -> StandardCMSSignatureStatus:
    """
    .. versionadded: 0.9.0

    Validate a detached CMS signature.

    :param input_data:
        The input data to sign. This can be either a :class:`bytes` object,
        a file-like object or a :class:`cms.ContentInfo` /
        :class:`cms.EncapsulatedContentInfo` object.

        If a CMS content info object is passed in, the `content` field
        will be extracted.
    :param signed_data:
        The :class:`cms.SignedData` object containing the signature to verify.
    :param signer_validation_context:
        Validation context to use to verify the signer certificate's trust.
    :param ts_validation_context:
        Validation context to use to verify the TSA certificate's trust, if
        a timestamp token is present.
        By default, the same validation context as that of the signer is used.
    :param key_usage_settings:
        Key usage parameters for the signer.
    :param chunk_size:
        Chunk size to use when consuming input data.
    :param max_read:
        Maximal number of bytes to read from the input stream.
    :return:
        A description of the signature's status.
    """

    if ts_validation_context is None:
        ts_validation_context = signer_validation_context
    signer_info = _extract_signer_info(signed_data)
    digest_algorithm = signer_info['digest_algorithm']['algorithm'].native
    h = hashes.Hash(get_pyca_cryptography_hash(digest_algorithm))
    if isinstance(input_data, bytes):
        h.update(input_data)
    elif isinstance(input_data, (cms.ContentInfo, cms.EncapsulatedContentInfo)):
        h.update(bytes(input_data['content']))
    else:
        temp_buf = bytearray(chunk_size)
        misc.chunked_digest(temp_buf, input_data, h, max_read=max_read)
    digest_bytes = h.finalize()

    status_kwargs = \
        await collect_timing_info(signer_info, ts_validation_context)
    return await async_validate_cms_signature(
        signed_data, status_cls=StandardCMSSignatureStatus,
        raw_digest=digest_bytes,
        validation_context=signer_validation_context,
        status_kwargs=status_kwargs,
        key_usage_settings=key_usage_settings
    )


@unique
class SignatureCoverageLevel(OrderedEnum):
    """
    Indicate the extent to which a PDF signature (cryptographically) covers
    a document. Note that this does *not* pass judgment on whether uncovered
    updates are legitimate or not, but as a general rule, a legitimate signature
    will satisfy at least :attr:`ENTIRE_REVISION`.
    """

    UNCLEAR = 0
    """
    The signature's coverage is unclear and/or disconnected.
    In standard PDF signatures, this is usually a bad sign.
    """

    CONTIGUOUS_BLOCK_FROM_START = 1
    """
    The signature covers a contiguous block in the PDF file stretching from
    the first byte of the file to the last byte in the indicated ``/ByteRange``.
    In other words, the only interruption in the byte range is fully occupied
    by the signature data itself.
    """

    ENTIRE_REVISION = 2
    """
    The signature covers the entire revision in which it occurs, but incremental
    updates may have been added later. This is not necessarily evidence of 
    tampering. In particular, it is expected when a file contains multiple
    signatures. Nonetheless, caution is required.
    """

    ENTIRE_FILE = 3
    """
    The entire file is covered by the signature.
    """


@dataclass(frozen=True)
class ModificationInfo:
    coverage: SignatureCoverageLevel = None
    """
    Indicates how much of the document is covered by the signature.
    """

    diff_result: Optional[Union[DiffResult, SuspiciousModification]] = None
    """
    Result of the difference analysis run on the file:

    * If ``None``, no difference analysis was run.
    * If the difference analysis was successful, this attribute will contain
      a :class:`.DiffResult` object.
    * If the difference analysis failed due to unforeseen or suspicious
      modifications, the :class:`.SuspiciousModification` exception thrown
      by the difference policy will be stored in this attribute.
    """

    @property
    def modification_level(self) -> Optional[ModificationLevel]:
        """
        Indicates the degree to which the document was modified after the
        signature was applied.

        Will be ``None`` if difference analysis results are not available;
        an instance of :class:`.ModificationLevel` otherwise.
        """

        coverage = self.coverage
        if self.diff_result is None:
            if coverage == SignatureCoverageLevel.ENTIRE_REVISION:
                # in this case, we can't know without the diff analysis result
                return None
            return (
                ModificationLevel.NONE
                if coverage == SignatureCoverageLevel.ENTIRE_FILE
                else ModificationLevel.OTHER
            )
        elif isinstance(self.diff_result, DiffResult):
            return self.diff_result.modification_level
        else:
            return ModificationLevel.OTHER


@dataclass(frozen=True)
class PdfSignatureStatus(ModificationInfo, StandardCMSSignatureStatus):
    """Class to indicate the validation status of a PDF signature."""

    docmdp_ok: Optional[bool] = None
    """
    Indicates whether the signature's
    :attr:`~.ModificationInfo.modification_level` is in line with the document
    signature policy in force.
    
    If ``None``, compliance could not be determined.
    """

    has_seed_values: bool = False
    """
    Records whether the signature form field has seed values.
    """

    seed_value_constraint_error: Optional[SigSeedValueValidationError] = None
    """
    Records the reason for failure if the signature field's seed value
    constraints didn't validate.
    """

    @property
    def bottom_line(self) -> bool:
        """
        Formulates a general judgment on the validity of this signature.
        This takes into account the cryptographic validity of the signature,
        the signature's chain of trust, compliance with the document
        modification policy, seed value constraint compliance and the validity
        of the timestamp token (if present).

        :return:
            ``True`` if all constraints are satisfied, ``False`` otherwise.
        """

        ts = self.timestamp_validity
        if ts is None:
            timestamp_ok = True
        else:
            timestamp_ok = ts.intact and ts.valid and ts.trusted
        return (
            self.intact and self.valid and self.trusted and self.seed_value_ok
            and (self.docmdp_ok or self.modification_level is None)
            and timestamp_ok
        )

    @property
    def seed_value_ok(self) -> bool:
        """
        Indicates whether the signature satisfies all mandatory constraints in
        the seed value dictionary of the associated form field.

        .. warning::
            Currently, not all seed value entries are recognised by the signer
            and/or the validator, so this judgment may not be entirely accurate
            in some cases.

            See :class:`~.pyhanko.sign.fields.SigSeedValueSpec`.
        """

        return self.seed_value_constraint_error is None

    def summary_fields(self):
        yield from super().summary_fields()
        if self.coverage == SignatureCoverageLevel.ENTIRE_FILE:
            yield 'UNTOUCHED'
        elif self.coverage == SignatureCoverageLevel.ENTIRE_REVISION:
            if self.modification_level is not None:
                yield 'EXTENDED_WITH_' + self.modification_level.name
            else:
                yield 'EXTENDED'
        else:
            yield 'NONSTANDARD_COVERAGE'
        if self.docmdp_ok:
            if self.coverage != SignatureCoverageLevel.ENTIRE_FILE:
                yield 'ACCEPTABLE_MODIFICATIONS'
        else:
            yield 'ILLEGAL_MODIFICATIONS'

    def pretty_print_sections(self):
        sections = super().pretty_print_sections()
        if self.coverage == SignatureCoverageLevel.ENTIRE_FILE:
            modification_str = "The signature covers the entire file."
        else:
            if self.modification_level is not None:
                if self.modification_level == ModificationLevel.LTA_UPDATES:
                    modlvl_string = \
                        "All modifications relate to signature maintenance"
                elif self.modification_level == ModificationLevel.FORM_FILLING:
                    modlvl_string = (
                        "All modifications relate to signing and form filling "
                        "operations"
                    )
                else:
                    modlvl_string = "Some modifications may be illegitimate"
                modification_str = (
                    "The signature does not cover the entire file.\n"
                    f"{modlvl_string}, and they appear to be "
                    f"{'' if self.docmdp_ok else 'in'}compatible with the "
                    "current document modification policy."
                )
            else:
                modification_str = "Incremental update analysis was skipped"

        sections.append(("Modifications", modification_str))
        if self.has_seed_values:
            if self.seed_value_ok:
                sv_info = "There were no SV issues detected for this signature."
            else:
                sv_info = (
                    "The signature did not satisfy the SV constraints on "
                    "the signature field.\nError message: "
                    + self.seed_value_constraint_error.failure_message
                )
            sections.append(("Seed value constraints", sv_info))

        return sections


@dataclass(frozen=True)
class DocumentTimestampStatus(ModificationInfo, TimestampSignatureStatus):
    """Class to indicate the validation status of a PDF document timestamp."""


def _extract_reference_dict(signature_obj, method) \
        -> Optional[generic.DictionaryObject]:
    try:
        sig_refs = signature_obj['/Reference']
    except KeyError:
        return
    for ref in sig_refs:
        ref = ref.get_object()
        if ref['/TransformMethod'] == method:
            return ref


def _extract_docmdp_for_sig(signature_obj) -> Optional[MDPPerm]:
    ref = _extract_reference_dict(signature_obj, '/DocMDP')
    if ref is None:
        return
    try:
        raw_perms = ref['/TransformParams'].raw_get('/P')
        return MDPPerm(raw_perms)
    except (ValueError, KeyError) as e:  # pragma: nocover
        raise SignatureValidationError(
            "Failed to read document permissions", e
        )


# TODO clarify in docs that "external timestamp" is always None when dealing
#  with a /DocTimeStamp, since there the timestamp token is simply the entire
#  signature object
class EmbeddedPdfSignature:
    """
    Class modelling a signature embedded in a PDF document.
    """

    sig_field: generic.DictionaryObject
    """
    The field dictionary of the form field containing the signature.
    """

    sig_object: generic.DictionaryObject
    """
    The signature dictionary.
    """

    signed_data: cms.SignedData
    """
    CMS signed data in the signature.
    """

    signer_cert: x509.Certificate
    """
    Certificate of the signer.
    """

    def __init__(self, reader: PdfFileReader,
                 sig_field: generic.DictionaryObject, fq_name: str):
        self.reader = reader
        if isinstance(sig_field, generic.IndirectObject):
            sig_field = sig_field.get_object()
        self.sig_field = sig_field
        sig_object_ref = sig_field.raw_get('/V')
        self.sig_object = sig_object = sig_object_ref.get_object()
        assert isinstance(sig_object, generic.DictionaryObject)
        try:
            pkcs7_content = sig_object.raw_get('/Contents', decrypt=False)
            self.byte_range = sig_object['/ByteRange']
        except KeyError:
            raise misc.PdfReadError(
                'Signature PDF object is not correctly formatted'
            )

        # we need the pkcs7_content raw, so we need to deencapsulate a couple
        # pieces of data here.
        if isinstance(pkcs7_content, generic.DecryptedObjectProxy):
            # it was a direct reference, so just grab the raw one
            pkcs7_content = pkcs7_content.raw_object
        elif isinstance(pkcs7_content, generic.IndirectObject):
            raise misc.PdfReadError("/Contents in signature must be direct")

        if not isinstance(pkcs7_content,
                          (generic.TextStringObject, generic.ByteStringObject)):
            raise misc.PdfReadError('/Contents must be string-like')
        self.pkcs7_content = pkcs7_content

        message = cms.ContentInfo.load(pkcs7_content.original_bytes)
        signed_data = message['content']
        self.signed_data: cms.SignedData = signed_data

        self.signer_info, self.signer_cert, _ = \
            _extract_signer_info_and_certs(signed_data)

        # The PDF standard does not define a way to specify the digest algorithm
        # used other than this one.
        # However, RFC 5652 § 11.2 states that the message_digest attribute
        # (which in our case is the PDF's ByteRange digest) is to be computed
        # using the signer's digest algorithm. This can only refer
        # to the corresponding SignerInfo entry.
        digest_algo = self.signer_info['digest_algorithm']
        self.md_algorithm = digest_algo['algorithm'].native.lower()
        eci = signed_data['encap_content_info']
        content_type = eci['content_type'].native
        if content_type == 'data':
            # Case of a normal signature
            self.external_md_algorithm = self.md_algorithm
        elif content_type == 'tst_info':
            # for timestamps, the hash algorithm in the messageImprint
            # need not be the same as the one to digest the encapsulated data!
            # RFC 8933 recommends to unify them, but it's not a given.
            mi = eci['content'].parsed['message_imprint']
            self.external_md_algorithm = \
                mi['hash_algorithm']['algorithm'].native

        # grab the revision to which the signature applies
        # NOTE: We're using get_last_change here as opposed to
        # get_introducing_revision. The distinction won't be relevant in most
        # legitimate use cases, but get_last_change is more likely to be correct
        # in cases where the signature obj was created by overriding an existing
        # object (which is weird, but technically possible, I guess).
        # Important note: the coverage checker will validate whether the
        # xref table for that revision is actually covered by the signature,
        # and raise the alarm if that's not the case.
        # Therefore shenanigans with updating signature objects will be detected
        # even before the diff checker runs.
        self.signed_revision = self.reader.xrefs.get_last_change(
            sig_object_ref.reference
        )
        self.coverage = None
        self.external_digest = None
        self.total_len = None
        self._docmdp = self._fieldmdp = None
        self._docmdp_queried = self._fieldmdp_queried = False
        self.tst_signature_digest = None

        self.diff_result = None
        self._integrity_checked = False
        self.fq_name = fq_name

    @property
    def sig_object_type(self) -> generic.NameObject:
        """
        Returns the type of the embedded signature object.
        For ordinary signatures, this will be ``/Sig``.
        In the case of a document timestamp, ``/DocTimeStamp`` is returned.

        :return:
            A PDF name object describing the type of signature.
        """
        return self.sig_object.get('/Type', pdf_name('/Sig'))

    @property
    def field_name(self):
        """
        :return:
            Name of the signature field.
        """
        return self.fq_name

    @property
    def self_reported_timestamp(self) -> Optional[datetime]:
        """
        :return:
            The signing time as reported by the signer, if embedded in the
            signature's signed attributes.
        """
        ts = _extract_self_reported_ts(self.signer_info)
        if ts is not None:
            return ts

        try:
            st_as_pdf_date = self.sig_object['/M']
            return generic.parse_pdf_date(st_as_pdf_date)
        except KeyError:  # pragma: nocover
            pass

    @property
    def attached_timestamp_data(self) -> Optional[cms.SignedData]:
        """
        :return:
            The signed data component of the timestamp token embedded in this
            signature, if present.
        """
        return _extract_tst_data(self.signer_info)

    def compute_integrity_info(self, diff_policy=None, skip_diff=False):
        """
        Compute the various integrity indicators of this signature.

        :param diff_policy:
            Policy to evaluate potential incremental updates that were appended
            to the signed revision of the document.
            Defaults to
            :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
        :param skip_diff:
            If ``True``, skip the difference analysis step entirely.
        """
        self.compute_digest()
        self.compute_tst_digest()

        # TODO in scenarios where we have to verify multiple signatures, we're
        #  doing a lot of double work here. This could be improved.
        self.coverage = self.evaluate_signature_coverage()
        diff_policy = diff_policy or DEFAULT_DIFF_POLICY
        if not skip_diff:
            self.diff_result = self.evaluate_modifications(diff_policy)

        self._integrity_checked = True

    def summarise_integrity_info(self) -> dict:
        """
        Compile the integrity information for this signature into a dictionary
        that can later be passed to :class:`.PdfSignatureStatus` as kwargs.

        This method is only available after calling
        :meth:`.EmbeddedPdfSignature.compute_integrity_info`.
        """

        if not self._integrity_checked:
            raise SignatureValidationError(
                "Call compute_integrity_info() before invoking"
                "summarise_integrity_info()"
            )  # pragma: nocover

        docmdp = self.docmdp_level
        diff_result = self.diff_result
        coverage = self.coverage
        docmdp_ok = None

        # attempt to set docmdp_ok based on the diff analysis results
        if diff_result is not None:
            mod_level = (
                diff_result.modification_level
                if isinstance(diff_result, DiffResult)
                else ModificationLevel.OTHER
            )
            docmdp_ok = not (
                mod_level == ModificationLevel.OTHER
                or (docmdp is not None and mod_level.value > docmdp.value)
            )
        elif coverage != SignatureCoverageLevel.ENTIRE_REVISION:
            # if the diff analysis didn't run, we can still do something
            # meaningful if coverage is not ENTIRE_REVISION:
            #  - if the signature covers the entire file, we're good.
            #  - if the coverage level is anything else, not so much
            docmdp_ok = coverage == SignatureCoverageLevel.ENTIRE_FILE

        status_kwargs = {
            'coverage': coverage, 'docmdp_ok': docmdp_ok,
            'diff_result': diff_result
        }
        return status_kwargs

    @property
    def seed_value_spec(self) -> Optional[SigSeedValueSpec]:
        try:
            sig_sv_dict = self.sig_field['/SV']
        except KeyError:
            return
        return SigSeedValueSpec.from_pdf_object(sig_sv_dict)

    @property
    def docmdp_level(self) -> Optional[MDPPerm]:
        """
        :return:
            The document modification policy required by this signature or
            its Lock dictionary.

            .. warning::
                This does not take into account the DocMDP requirements of
                earlier signatures (if present).

                The specification forbids signing with a more lenient DocMDP
                than the one currently in force, so this should not happen
                in a compliant document.
                That being said, any potential violations will still invalidate
                the earlier signature with the stricter DocMDP policy.

        """
        if self._docmdp_queried:
            return self._docmdp
        docmdp = _extract_docmdp_for_sig(signature_obj=self.sig_object)

        if docmdp is None:
            try:
                lock_dict = self.sig_field['/Lock']
                docmdp = MDPPerm(lock_dict['/P'])
            except KeyError:
                pass
        self._docmdp = docmdp
        self._docmdp_queried = True
        return docmdp

    @property
    def fieldmdp(self) -> Optional[FieldMDPSpec]:
        """
        :return:
            Read the field locking policy of this signature, if applicable.
            See also :class:`~.pyhanko.sign.fields.FieldMDPSpec`.
        """
        # TODO as above, fall back to /Lock
        if self._fieldmdp_queried:
            return self._fieldmdp
        ref_dict = _extract_reference_dict(self.sig_object, '/FieldMDP')
        self._fieldmdp_queried = True
        if ref_dict is None:
            return
        try:
            sp = FieldMDPSpec.from_pdf_object(ref_dict['/TransformParams'])
        except (ValueError, KeyError) as e:  # pragma: nocover
            raise SignatureValidationError(
                "Failed to read /FieldMDP settings", e
            )
        self._fieldmdp = sp
        return sp

    def compute_digest(self) -> bytes:
        """
        Compute the ``/ByteRange`` digest of this signature.
        The result will be cached.

        :return:
            The digest value.
        """
        if self.external_digest is not None:
            return self.external_digest

        md_spec = get_pyca_cryptography_hash(self.external_md_algorithm)
        md = hashes.Hash(md_spec)
        stream = self.reader.stream

        # compute the digest
        # here, we allow arbitrary byte ranges
        # for the coverage check, we'll impose more constraints
        total_len = 0
        chunk_buf = bytearray(DEFAULT_CHUNK_SIZE)
        for lo, chunk_len in misc.pair_iter(self.byte_range):
            stream.seek(lo)
            misc.chunked_digest(chunk_buf, stream, md, max_read=chunk_len)
            total_len += chunk_len

        self.total_len = total_len
        self.external_digest = digest = md.finalize()
        return digest

    def compute_tst_digest(self) -> Optional[bytes]:
        """
        Compute the digest of the signature needed to validate its timestamp
        token (if present).

        .. warning::
            This computation is only relevant for timestamp tokens embedded
            inside a regular signature.
            If the signature in question is a document timestamp (where the
            entire signature object is a timestamp token), this method
            does not apply.

        :return:
            The digest value, or ``None`` if there is no timestamp token.
        """

        if self.tst_signature_digest is not None:
            return self.tst_signature_digest
        self.tst_signature_digest = digest = _compute_tst_digest(
            self.signer_info
        )
        return digest

    def evaluate_signature_coverage(self) -> SignatureCoverageLevel:
        """
        Internal method used to evaluate the coverage level of a signature.

        :return:
            The coverage level of the signature.
        """

        xref_cache: XRefCache = self.reader.xrefs
        # for the coverage check, we're more strict with regards to the byte
        #  range
        stream = self.reader.stream

        # nonstandard byte range -> insta-fail
        if len(self.byte_range) != 4 or self.byte_range[0] != 0:
            return SignatureCoverageLevel.UNCLEAR

        _, len1, start2, len2 = self.byte_range

        # first check: check if the signature covers the entire file.
        #  (from a cryptographic point of view)
        # In this case, there are no changes at all, so we're good.

        # compute file size
        stream.seek(0, os.SEEK_END)
        # the * 2 is because of the ASCII hex encoding, and the + 2
        # is the wrapping <>
        embedded_sig_content = len(self.pkcs7_content) * 2 + 2
        signed_zone_len = len1 + len2 + embedded_sig_content
        file_covered = stream.tell() == signed_zone_len
        if file_covered:
            return SignatureCoverageLevel.ENTIRE_FILE

        # Now we're in the mixed case: the byte range is a standard one
        #  starting at the beginning of the document, but it doesn't go all
        #  the way to the end of the file. This can be for legitimate reasons,
        #  not all of which we can evaluate right now.

        # First, check if the signature is a contiguous one.
        # In other words, we need to check if the interruption in the byte
        # range is "fully explained" by the signature content.
        contiguous = start2 == len1 + embedded_sig_content
        if not contiguous:
            return SignatureCoverageLevel.UNCLEAR

        # next, we verify that the revision this signature belongs to
        #  is completely covered. This requires a few separate checks.
        # (1) Verify that the xref container (table or stream) is covered
        # (2) Verify the presence of the EOF and startxref markers at the
        #     end of the signed region, and compare them with the values
        #     in the xref cache to make sure we are reading the right revision.

        # Check (2) first, since it's the quickest
        stream.seek(signed_zone_len)
        signed_rev = self.signed_revision
        try:
            startxref = process_data_at_eof(stream)
            expected = xref_cache.get_startxref_for_revision(signed_rev)
            if startxref != expected:
                return SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START
        except misc.PdfReadError:
            return SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START

        # ... then check (1) for all revisions up to and including
        # signed_revision
        for revision in range(signed_rev + 1):
            xref_start, xref_end = xref_cache.get_xref_container_info(revision)
            if xref_end > signed_zone_len:
                return SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START

        return SignatureCoverageLevel.ENTIRE_REVISION

    def evaluate_modifications(self, diff_policy: DiffPolicy) \
            -> Union[DiffResult, SuspiciousModification]:
        """
        Internal method used to evaluate the modification level of a signature.
        """

        if self.coverage < SignatureCoverageLevel.ENTIRE_REVISION:
            return SuspiciousModification(
                'Nonstandard signature coverage level'
            )
        elif self.coverage == SignatureCoverageLevel.ENTIRE_FILE:
            return DiffResult(ModificationLevel.NONE, set())

        return diff_policy.review_file(
            self.reader, self.signed_revision,
            field_mdp_spec=self.fieldmdp, doc_mdp=self.docmdp_level
        )


def _validate_sv_constraints(emb_sig: EmbeddedPdfSignature,
                             signing_cert, validation_path, timestamp_found):

    sv_spec = emb_sig.seed_value_spec
    if sv_spec.cert is not None:
        try:
            sv_spec.cert.satisfied_by(signing_cert, validation_path)
        except UnacceptableSignerError as e:
            raise SigSeedValueValidationError(e) from e

    if not timestamp_found and sv_spec.timestamp_required:
        raise SigSeedValueValidationError(
            "The seed value dictionary requires a trusted timestamp, but "
            "none was found, or the timestamp did not validate."
        )

    sig_obj = emb_sig.sig_object

    if sv_spec.seed_signature_type is not None:
        sv_certify = sv_spec.seed_signature_type.certification_signature()
        try:
            perms: generic.DictionaryObject = emb_sig.reader.root['/Perms']
            cert_sig_ref = perms.get_value_as_reference('/DocMDP')
            was_certified = cert_sig_ref == sig_obj.container_ref
        except (KeyError, generic.IndirectObjectExpected, AttributeError):
            was_certified = False
        if sv_certify != was_certified:
            def _type(certify):
                return 'a certification' if certify else 'an approval'

            raise SigSeedValueValidationError(
                "The seed value dictionary's /MDP entry specifies that "
                f"this field should contain {_type(sv_certify)} "
                f"signature, but {_type(was_certified)} "
                "appears to have been used."
            )
        if sv_certify:
            sv_mdp_perm = sv_spec.seed_signature_type.mdp_perm
            doc_mdp = emb_sig.docmdp_level
            if sv_mdp_perm != doc_mdp:
                raise SigSeedValueValidationError(
                    "The seed value dictionary specified that this "
                    "certification signature should use the MDP policy "
                    f"'{sv_mdp_perm}', but '{doc_mdp}' was "
                    "used in the signature."
                )

    flags = sv_spec.flags
    if not flags:
        return

    selected_sf_str = sig_obj['/SubFilter']
    selected_sf = SigSeedSubFilter(selected_sf_str)
    if (flags & SigSeedValFlags.SUBFILTER) \
            and sv_spec.subfilters is not None:
        # empty array = no supported subfilters
        if not sv_spec.subfilters:
            raise NotImplementedError(
                "The signature encodings mandated by the seed value "
                "dictionary are not supported."
            )
        # standard mandates that we take the first available subfilter
        mandated_sf: SigSeedSubFilter = sv_spec.subfilters[0]
        if selected_sf is not None and mandated_sf != selected_sf:
            raise SigSeedValueValidationError(
                "The seed value dictionary mandates subfilter '%s', "
                "but '%s' was used in the signature." % (
                    mandated_sf.value, selected_sf.value
                )
            )

    if (flags & SigSeedValFlags.APPEARANCE_FILTER) \
            and sv_spec.appearance is not None:
        logger.warning(
            "The signature's seed value dictionary specifies the "
            "/AppearanceFilter entry as mandatory, but this constraint "
            "is impossible to validate."
        )

    if (flags & SigSeedValFlags.LEGAL_ATTESTATION) \
            and sv_spec.legal_attestations is not None:
        raise NotImplementedError(
            "pyHanko does not support legal attestations, but the seed value "
            "dictionary mandates that they be restricted to a specific subset."
        )

    if (flags & SigSeedValFlags.LOCK_DOCUMENT) \
            and sv_spec.lock_document is not None:
        doc_mdp = emb_sig.docmdp_level
        if sv_spec.lock_document == SeedLockDocument.LOCK \
                and doc_mdp != MDPPerm.NO_CHANGES:
            raise SigSeedValueValidationError(
                "Document must be locked, but some changes are still allowed."
            )
        if sv_spec.lock_document == SeedLockDocument.DO_NOT_LOCK \
                and doc_mdp == MDPPerm.NO_CHANGES:
            raise SigSeedValueValidationError(
                "Document must not be locked, but the DocMDP level is set to "
                "NO_CHANGES."
            )
        # value 'auto' is OK.

    signer_info = emb_sig.signer_info
    if (flags & SigSeedValFlags.ADD_REV_INFO) \
            and sv_spec.add_rev_info is not None:
        try:
            apply_adobe_revocation_info(signer_info)
            revinfo_found = True
        except ValueError:
            revinfo_found = False

        if sv_spec.add_rev_info != revinfo_found:
            raise SigSeedValueValidationError(
                "The seed value dict mandates that revocation info %sbe "
                "added, but it was %sfound in the signature." % (
                    "" if sv_spec.add_rev_info else "not ",
                    "" if revinfo_found else "not "
                )
            )
        if sv_spec.add_rev_info and \
                selected_sf != SigSeedSubFilter.ADOBE_PKCS7_DETACHED:
            raise SigSeedValueValidationError(
                "The seed value dict mandates that Adobe-style revocation "
                "info be added; this requires subfilter '%s'" % (
                    SigSeedSubFilter.ADOBE_PKCS7_DETACHED.value
                )
            )

    if (flags & SigSeedValFlags.DIGEST_METHOD) \
            and sv_spec.digest_methods is not None:
        selected_md = emb_sig.md_algorithm.lower()
        if selected_md not in sv_spec.digest_methods:
            raise SigSeedValueValidationError(
                "The selected message digest %s is not allowed by the "
                "seed value dictionary."
                % selected_md
            )

    if flags & SigSeedValFlags.REASONS:
        # standard says that omission of the /Reasons key amounts to
        #  a prohibition in this case
        must_omit = not sv_spec.reasons or sv_spec.reasons == ["."]
        reason_given = sig_obj.get('/Reason')
        if must_omit and reason_given is not None:
            raise SigSeedValueValidationError(
                "The seed value dictionary prohibits giving a reason "
                "for signing."
            )
        if not must_omit and reason_given not in sv_spec.reasons:
            raise SigSeedValueValidationError(
                "The reason for signing \"%s\" is not accepted by the "
                "seed value dictionary." % (
                    reason_given,
                )
            )


def _validate_sv_and_update(embedded_sig, status_kwargs, timestamp_found):
    sv_spec = embedded_sig.seed_value_spec
    if sv_spec is None:
        return
    status_kwargs['has_seed_values'] = True
    try:
        _validate_sv_constraints(
            embedded_sig, status_kwargs['signing_cert'],
            status_kwargs['validation_path'], timestamp_found=timestamp_found
        )
        status_kwargs['seed_value_constraint_error'] = None
    except SigSeedValueValidationError as e:
        logger.warning(
            "Error in seed value validation.", exc_info=e
        )
        status_kwargs['seed_value_constraint_error'] = e


def _validate_subfilter(subfilter_str, permitted_subfilters, err_msg):

    try:
        from pyhanko.sign.fields import SigSeedSubFilter
        subfilter_ok = SigSeedSubFilter(subfilter_str) in permitted_subfilters
    except ValueError:
        subfilter_ok = False

    if not subfilter_ok:
        raise SignatureValidationError(err_msg % subfilter_str)


def validate_pdf_signature(embedded_sig: EmbeddedPdfSignature,
                           signer_validation_context: ValidationContext = None,
                           ts_validation_context: ValidationContext = None,
                           diff_policy: DiffPolicy = None,
                           key_usage_settings: KeyUsageConstraints = None,
                           skip_diff: bool = False) -> PdfSignatureStatus:
    """
    Validate a PDF signature.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param signer_validation_context:
        Validation context to use to validate the signature's chain of trust.
    :param ts_validation_context:
        Validation context to use to validate the timestamp's chain of trust
        (defaults to ``signer_validation_context``).
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the PDF signature in question.
    """
    coro = async_validate_pdf_signature(
        embedded_sig=embedded_sig,
        signer_validation_context=signer_validation_context,
        ts_validation_context=ts_validation_context,
        diff_policy=diff_policy, key_usage_settings=key_usage_settings,
        skip_diff=skip_diff
    )
    return asyncio.run(coro)


async def async_validate_pdf_signature(
                           embedded_sig: EmbeddedPdfSignature,
                           signer_validation_context: ValidationContext = None,
                           ts_validation_context: ValidationContext = None,
                           diff_policy: DiffPolicy = None,
                           key_usage_settings: KeyUsageConstraints = None,
                           skip_diff: bool = False) -> PdfSignatureStatus:
    """
    .. versionadded:: 0.9.0

    Validate a PDF signature.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param signer_validation_context:
        Validation context to use to validate the signature's chain of trust.
    :param ts_validation_context:
        Validation context to use to validate the timestamp's chain of trust
        (defaults to ``signer_validation_context``).
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the PDF signature in question.
    """

    sig_object = embedded_sig.sig_object
    if embedded_sig.sig_object_type != '/Sig':
        raise SignatureValidationError("Signature object type must be /Sig")

    # check whether the subfilter type is one we support
    subfilter_str = sig_object.get('/SubFilter', None)
    _validate_subfilter(
        subfilter_str,
        (SigSeedSubFilter.ADOBE_PKCS7_DETACHED, SigSeedSubFilter.PADES),
        "%s is not a recognized SubFilter type in signatures."
    )

    if ts_validation_context is None:
        ts_validation_context = signer_validation_context

    embedded_sig.compute_integrity_info(
        diff_policy=diff_policy, skip_diff=skip_diff
    )
    status_kwargs = embedded_sig.summarise_integrity_info()

    ts_status_kwargs = await collect_timing_info(
        embedded_sig.signer_info, ts_validation_context
    )
    status_kwargs.update(ts_status_kwargs)
    if 'signer_reported_dt' not in status_kwargs:
        # maybe the PDF signature dictionary declares /M
        signer_reported_dt = embedded_sig.self_reported_timestamp
        if signer_reported_dt is not None:
            status_kwargs['signer_reported_dt'] = signer_reported_dt

    status_kwargs = await _validate_cms_signature(
        embedded_sig.signed_data, status_cls=PdfSignatureStatus,
        raw_digest=embedded_sig.external_digest,
        validation_context=signer_validation_context,
        status_kwargs=status_kwargs, key_usage_settings=key_usage_settings
    )
    tst_validity = status_kwargs.get('timestamp_validity', None)
    timestamp_found = (
        tst_validity is not None
        and tst_validity.valid and tst_validity.trusted
    )
    _validate_sv_and_update(embedded_sig, status_kwargs, timestamp_found)
    return PdfSignatureStatus(**status_kwargs)


def validate_pdf_timestamp(embedded_sig: EmbeddedPdfSignature,
                           validation_context: ValidationContext = None,
                           diff_policy: DiffPolicy = None,
                           skip_diff: bool = False) -> DocumentTimestampStatus:
    """
    .. versionchanged:: 0.9.0
        Wrapper around :func:`async_validate_pdf_timestamp`.

    Validate a PDF document timestamp.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param validation_context:
        Validation context to use to validate the timestamp's chain of trust.
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the PDF timestamp in question.
    """
    coro = async_validate_pdf_timestamp(
        embedded_sig=embedded_sig,
        validation_context=validation_context,
        diff_policy=diff_policy, skip_diff=skip_diff
    )
    return asyncio.run(coro)


async def async_validate_pdf_timestamp(
                           embedded_sig: EmbeddedPdfSignature,
                           validation_context: ValidationContext = None,
                           diff_policy: DiffPolicy = None,
                           skip_diff: bool = False) -> DocumentTimestampStatus:
    """
    .. versionadded:: 0.9.0

    Validate a PDF document timestamp.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param validation_context:
        Validation context to use to validate the timestamp's chain of trust.
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the PDF timestamp in question.
    """

    if embedded_sig.sig_object_type != '/DocTimeStamp':
        raise SignatureValidationError(
            "Signature object type must be /DocTimeStamp"
        )

    # check whether the subfilter type is one we support
    subfilter_str = embedded_sig.sig_object.get('/SubFilter', None)
    _validate_subfilter(
        subfilter_str, (SigSeedSubFilter.ETSI_RFC3161,),
        "%s is not a recognized SubFilter type for timestamps."
    )

    embedded_sig.compute_integrity_info(
        diff_policy=diff_policy, skip_diff=skip_diff
    )

    status_kwargs = await _validate_timestamp(
        embedded_sig.signed_data, validation_context,
        embedded_sig.external_digest
    )

    status_kwargs['coverage'] = embedded_sig.coverage
    status_kwargs['diff_result'] = embedded_sig.diff_result
    return DocumentTimestampStatus(**status_kwargs)


class RevocationInfoValidationType(Enum):
    """
    Indicates a validation profile to use when validating revocation info.
    """

    ADOBE_STYLE = 'adobe'
    """
    Retrieve validation information from the CMS object, using Adobe's
    revocation info archival attribute.
    """

    PADES_LT = 'pades'
    """
    Retrieve validation information from the DSS, and require the signature's 
    embedded timestamp to still be valid.
    """

    PADES_LTA = 'pades-lta'
    """
    Retrieve validation information from the DSS, but read & validate the chain
    of document timestamps leading up to the signature to establish the 
    integrity of the validation information at the time of signing.
    """

    @classmethod
    def as_tuple(cls):
        return tuple(m.value for m in cls)


DEFAULT_LTV_INTERNAL_REVO_POLICY = CertRevTrustPolicy(
    RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.CHECK_IF_DECLARED,
        intermediate_ca_cert_rule=RevocationCheckingRule.CHECK_IF_DECLARED,
    )
)

STRICT_LTV_INTERNAL_REVO_POLICY = CertRevTrustPolicy(
    RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
        intermediate_ca_cert_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
    ),
)


def _strict_vc_context_kwargs(timestamp, validation_context_kwargs):
    # create a new validation context using the timestamp value as the time
    # of evaluation, turn off fetching and load OCSP responses / CRL data
    # from the DSS / revocation info object
    validation_context_kwargs['allow_fetching'] = False
    validation_context_kwargs['moment'] = timestamp

    # Certs with OCSP/CRL endpoints should have the relevant revocation data
    # embedded, if no stricter revocation_mode policy is in place already

    revinfo_policy: CertRevTrustPolicy \
        = validation_context_kwargs.get('revinfo_policy', None)
    if revinfo_policy is None:
        # handle legacy revocation mode
        legacy_rm = validation_context_kwargs.pop('revocation_mode', None)
        if legacy_rm and legacy_rm != 'soft-fail':
            revinfo_policy = CertRevTrustPolicy(
                RevocationCheckingPolicy.from_legacy(legacy_rm),
            )
        elif legacy_rm == 'soft-fail':
            # fall back to the default
            revinfo_policy = DEFAULT_LTV_INTERNAL_REVO_POLICY
    elif not revinfo_policy.revocation_checking_policy.essential:
        # also in this case, we sub in the default
        revinfo_policy = DEFAULT_LTV_INTERNAL_REVO_POLICY

    validation_context_kwargs['revinfo_policy'] = revinfo_policy


async def _validate_timestamp(tst_signed_data, validation_context,
                              expected_tst_imprint):

    assert expected_tst_imprint is not None
    tst_info = tst_signed_data['encap_content_info']['content'].parsed
    assert isinstance(tst_info, tsp.TSTInfo)
    # compare the expected TST digest against the message imprint
    # inside the signed data
    tst_imprint = tst_info['message_imprint']['hashed_message'].native
    if expected_tst_imprint != tst_imprint:
        logger.warning(
            f"Timestamp token imprint is {tst_imprint.hex()}, but expected "
            f"{expected_tst_imprint.hex()}."
        )
        encap_data_invalid = True
    else:
        encap_data_invalid = False
    timestamp = tst_info['gen_time'].native
    return await _validate_cms_signature(
        tst_signed_data, status_cls=TimestampSignatureStatus,
        validation_context=validation_context,
        status_kwargs={'timestamp': timestamp},
        encap_data_invalid=encap_data_invalid
    )


async def _establish_timestamp_trust(
        tst_signed_data, bootstrap_validation_context, expected_tst_imprint):
    timestamp_status_kwargs = await _validate_timestamp(
        tst_signed_data, bootstrap_validation_context, expected_tst_imprint
    )
    timestamp_status = TimestampSignatureStatus(**timestamp_status_kwargs)

    if not timestamp_status.valid or not timestamp_status.trusted:
        logger.warning(
            "Could not validate embedded timestamp token: %s.",
            timestamp_status.summary()
        )
        raise SignatureValidationError(
            "Could not establish time of signing, timestamp token did not "
            "validate with current settings."
        )
    return timestamp_status


def get_timestamp_chain(reader: PdfFileReader) \
        -> Iterator[EmbeddedPdfSignature]:
    """
    Get the document timestamp chain of the associated reader, ordered
    from new to old.

    :param reader:
        A :class:`.PdfFileReader`.
    :return:
        An iterable of :class:`.EmbeddedPdfSignature` objects representing
        document timestamps.
    """
    return filter(
        lambda sig: sig.sig_object.get('/Type', None) == '/DocTimeStamp',
        reversed(reader.embedded_signatures)
    )


async def _establish_timestamp_trust_lta(reader, bootstrap_validation_context,
                                   validation_context_kwargs, until_revision):
    timestamps = get_timestamp_chain(reader)
    validation_context_kwargs = dict(validation_context_kwargs)
    current_vc = bootstrap_validation_context
    ts_status = None
    ts_count = -1
    emb_timestamp = None
    for ts_count, emb_timestamp in enumerate(timestamps):
        if emb_timestamp.signed_revision < until_revision:
            break

        emb_timestamp.compute_digest()
        ts_status = await _establish_timestamp_trust(
            emb_timestamp.signed_data, current_vc, emb_timestamp.external_digest
        )
        # set up the validation kwargs for the next iteration
        _strict_vc_context_kwargs(
            ts_status.timestamp, validation_context_kwargs
        )
        # read the DSS at the current revision into a new
        # validation context object
        try:
            current_vc = DocumentSecurityStore.read_dss(
                reader.get_historical_resolver(emb_timestamp.signed_revision)
            ).as_validation_context(validation_context_kwargs)
        except NoDSSFoundError:
            current_vc = ValidationContext(**validation_context_kwargs)

    return emb_timestamp, ts_status, ts_count + 1, current_vc


# TODO verify formal PAdES requirements for timestamps
# TODO verify other formal PAdES requirements (coverage, etc.)
# TODO signature/verification policy-based validation! (PAdES-EPES-* etc)
#  (this is a different beast, though)
# TODO "tolerant" timestamp validation, where we tolerate problems in the
#  timestamp chain provided that newer timestamps are "strong" enough to
#  cover the gap.
def validate_pdf_ltv_signature(embedded_sig: EmbeddedPdfSignature,
                               validation_type: RevocationInfoValidationType,
                               validation_context_kwargs=None,
                               bootstrap_validation_context=None,
                               force_revinfo=False,
                               diff_policy: DiffPolicy = None,
                               key_usage_settings: KeyUsageConstraints = None,
                               skip_diff: bool = False) -> PdfSignatureStatus:
    """
    .. versionchanged:: 0.9.0
        Wrapper around :func:`async_validate_pdf_ltv_signature`.

    Validate a PDF LTV signature according to a particular profile.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param validation_type:
        Validation profile to use.
    :param validation_context_kwargs:
        Keyword args to instantiate
        :class:`.pyhanko_certvalidator.ValidationContext` objects needed over
        the course of the validation.
    :param bootstrap_validation_context:
        Validation context used to validate the current timestamp.
    :param force_revinfo:
        Require all certificates encountered to have some form of live
        revocation checking provisions.
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the signature.
    """
    coro = async_validate_pdf_ltv_signature(
        embedded_sig=embedded_sig,
        validation_type=validation_type,
        validation_context_kwargs=validation_context_kwargs,
        bootstrap_validation_context=bootstrap_validation_context,
        force_revinfo=force_revinfo,
        diff_policy=diff_policy,
        key_usage_settings=key_usage_settings,
        skip_diff=skip_diff
    )
    return asyncio.run(coro)


async def async_validate_pdf_ltv_signature(
                               embedded_sig: EmbeddedPdfSignature,
                               validation_type: RevocationInfoValidationType,
                               validation_context_kwargs=None,
                               bootstrap_validation_context=None,
                               force_revinfo=False,
                               diff_policy: DiffPolicy = None,
                               key_usage_settings: KeyUsageConstraints = None,
                               skip_diff: bool = False) -> PdfSignatureStatus:
    """
    .. versionadded:: 0.9.0

    Validate a PDF LTV signature according to a particular profile.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param validation_type:
        Validation profile to use.
    :param validation_context_kwargs:
        Keyword args to instantiate
        :class:`.pyhanko_certvalidator.ValidationContext` objects needed over
        the course of the validation.
    :param bootstrap_validation_context:
        Validation context used to validate the current timestamp.
    :param force_revinfo:
        Require all certificates encountered to have some form of live
        revocation checking provisions.
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to
        :const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the signature.
    """

    # create a fresh copy of the validation_kwargs
    validation_context_kwargs: dict = dict(validation_context_kwargs or {})

    # To validate the first timestamp, allow fetching by default
    # we'll turn it off later
    validation_context_kwargs.setdefault('allow_fetching', True)
    # same for revocation_mode: if force_revinfo is false, we simply turn on
    # hard-fail by default for now. Once the timestamp is validated,
    # we switch to hard-fail forcibly.
    if force_revinfo:
        validation_context_kwargs['revinfo_policy'] \
            = STRICT_LTV_INTERNAL_REVO_POLICY
    elif 'revocation_mode' not in validation_context_kwargs:
        validation_context_kwargs.setdefault(
            'revinfo_policy',
            DEFAULT_LTV_INTERNAL_REVO_POLICY
        )

    reader = embedded_sig.reader
    if validation_type == RevocationInfoValidationType.ADOBE_STYLE:
        dss = None
        current_vc = bootstrap_validation_context or ValidationContext(
            **validation_context_kwargs
        )
    else:
        # If there's a DSS, there's no harm in reading additional certs from it
        dss = DocumentSecurityStore.read_dss(reader)
        if bootstrap_validation_context is None:
            current_vc = dss.as_validation_context(
                validation_context_kwargs, include_revinfo=False
            )
        else:
            current_vc = bootstrap_validation_context
            # add the certs from the DSS
            for cert in dss._load_certs():
                current_vc.certificate_registry.add_other_cert(cert)

    embedded_sig.compute_digest()
    embedded_sig.compute_tst_digest()

    # If the validation profile is PAdES-type, then we validate the timestamp
    #  chain now.
    #  This is bootstrapped using the current validation context.
    #  If successful, we obtain a new validation context set to a new
    #  "known good" verification time. We then repeat the process using this
    #  new validation context instead of the current one.
    earliest_good_timestamp_st = None
    ts_chain_length = 0
    # also record the embedded sig object assoc. with the oldest applicable
    # DTS in the timestamp chain
    latest_dts = None
    if validation_type != RevocationInfoValidationType.ADOBE_STYLE:
        latest_dts, earliest_good_timestamp_st, ts_chain_length, current_vc = \
            await _establish_timestamp_trust_lta(
                reader, current_vc, validation_context_kwargs,
                until_revision=embedded_sig.signed_revision
            )
        # In PAdES-LTA, we should only rely on DSS information that is covered
        # by an appropriate document timestamp.
        # If the validation profile is PAdES-LTA, then we must have seen
        # at least one document timestamp pass by, i.e. earliest_known_timestamp
        # must be non-None by now.
        if earliest_good_timestamp_st is None \
                and validation_type == RevocationInfoValidationType.PADES_LTA:
            raise SignatureValidationError(
                "Purported PAdES-LTA signature does not have a timestamp chain."
            )
        # if this assertion fails, there's a bug in the validation code
        assert validation_type == RevocationInfoValidationType.PADES_LT \
               or ts_chain_length >= 1

    # now that we have arrived at the revision with the signature,
    # we can check for a timestamp token attribute there
    # (This is allowed, regardless of whether we use Adobe-style LTV or
    # a PAdES validation profile)
    tst_signed_data = embedded_sig.attached_timestamp_data
    if tst_signed_data is not None:
        earliest_good_timestamp_st = await _establish_timestamp_trust(
            tst_signed_data, current_vc, embedded_sig.tst_signature_digest
        )
    elif validation_type == RevocationInfoValidationType.PADES_LTA \
            and ts_chain_length == 1:
        # TODO Pretty sure that this is the spirit of the LTA profile,
        #  but are we being too harsh here? I don't think so, but it's worth
        #  revisiting later
        # For later review: I believe that this check is appropriate, because
        # the timestamp that protects the signature should be verifiable
        # using only information from the next DSS, which should in turn
        # also be protected using a DTS. This requires at least two timestamps.
        raise SignatureValidationError(
            "PAdES-LTA signature requires separate timestamps protecting "
            "the signature & the rest of the revocation info."
        )

    # if, by now, we still don't have a trusted timestamp, there's a problem
    # regardless of the validation profile in use.
    if earliest_good_timestamp_st is None:
        raise SignatureValidationError(
            'LTV signatures require a trusted timestamp.'
        )

    _strict_vc_context_kwargs(
        earliest_good_timestamp_st.timestamp, validation_context_kwargs
    )

    if validation_type == RevocationInfoValidationType.ADOBE_STYLE:
        ocsps, crls = retrieve_adobe_revocation_info(
            embedded_sig.signer_info
        )
        validation_context_kwargs['ocsps'] = ocsps
        validation_context_kwargs['crls'] = crls
        stored_vc = ValidationContext(**validation_context_kwargs)
    elif validation_type == RevocationInfoValidationType.PADES_LT:
        # in this case, we don't care about whether the information
        # in the DSS is protected by any timestamps, so just ingest everything
        stored_vc = dss.as_validation_context(validation_context_kwargs)
    else:
        # in the LTA profile, we should use only DSS information covered
        # by the last relevant timestamp, so the correct VC is current_vc
        current_vc.moment = earliest_good_timestamp_st.timestamp
        stored_vc = current_vc

    # Now, we evaluate the validity of the timestamp guaranteeing the signature
    #  *within* the LTV context.
    #   (i.e. we check whether there's enough revinfo to keep tabs on the
    #   timestamp's validity)
    # If the last timestamp comes from a timestamp token attached to the
    # signature, it should be possible to validate it using only data from the
    # DSS / revocation info store, so validate the timestamp *again*
    # using those settings.

    if tst_signed_data is not None or \
            validation_type == RevocationInfoValidationType.PADES_LT:
        if tst_signed_data is not None:
            ts_to_validate = tst_signed_data
        else:
            # we're in the PAdES-LT case with a detached TST now.
            # this should be conceptually equivalent to the above
            # so we run the same check here
            ts_to_validate = latest_dts.signed_data
        ts_status_coro = async_validate_cms_signature(
            ts_to_validate, status_cls=TimestampSignatureStatus,
            validation_context=stored_vc, status_kwargs={
                'timestamp': earliest_good_timestamp_st.timestamp
            }
        )
        timestamp_status: TimestampSignatureStatus = await ts_status_coro
    else:
        # In the LTA case, we don't have to do any further checks, since the
        # _establish_timestamp_trust_lta handled that for us.
        # We can therefore just take earliest_good_timestamp_st at face value.
        timestamp_status = earliest_good_timestamp_st

    embedded_sig.compute_integrity_info(
        diff_policy=diff_policy, skip_diff=skip_diff
    )
    status_kwargs = embedded_sig.summarise_integrity_info()
    status_kwargs.update({
        'signer_reported_dt': earliest_good_timestamp_st.timestamp,
        'timestamp_validity': timestamp_status
    })
    status_kwargs = await _validate_cms_signature(
        embedded_sig.signed_data, status_cls=PdfSignatureStatus,
        raw_digest=embedded_sig.external_digest,
        validation_context=stored_vc, status_kwargs=status_kwargs,
        key_usage_settings=key_usage_settings
    )

    _validate_sv_and_update(embedded_sig, status_kwargs, timestamp_found=True)

    return PdfSignatureStatus(**status_kwargs)


def retrieve_adobe_revocation_info(signer_info: cms.SignerInfo):
    try:
        revinfo: asn1_pdf.RevocationInfoArchival = find_unique_cms_attribute(
            signer_info['signed_attrs'], "adobe_revocation_info_archival"
        )
    except (NonexistentAttributeError, MultivaluedAttributeError) as e:
        raise ValidationInfoReadingError(
            "No revocation info archival attribute found, or multiple present"
        ) from e

    ocsps = list(revinfo['ocsp'] or ())
    crls = list(revinfo['crl'] or ())
    return ocsps, crls


def apply_adobe_revocation_info(signer_info: cms.SignerInfo,
                                validation_context_kwargs=None) \
                               -> ValidationContext:
    """
    Read Adobe-style revocation information from a CMS object, and load it
    into a validation context.

    :param signer_info:
        Signer info CMS object.
    :param validation_context_kwargs:
        Extra kwargs to pass to the ``__init__`` function.
    :return:
        A validation context preloaded with the relevant revocation information.
    """
    validation_context_kwargs = validation_context_kwargs or {}
    ocsps, crls = retrieve_adobe_revocation_info(signer_info)
    return ValidationContext(
        ocsps=ocsps, crls=crls, **validation_context_kwargs
    )


DocMDPInfo = namedtuple(
    'DocMDPInfo', ['permission', 'author_sig']
)
"""
Encodes certification information for a signed document, consisting of a 
reference to the author signature, together with the associated DocMDP policy.
"""


def read_certification_data(reader: PdfFileReader) -> Optional[DocMDPInfo]:
    """
    Read the certification information for a PDF document, if present.

    :param reader:
        Reader representing the input document.
    :return:
        A :class:`.DocMDPInfo` object containing the relevant data, or ``None``.
    """
    try:
        certification_sig = reader.root['/Perms']['/DocMDP']
    except KeyError:
        return

    perm = _extract_docmdp_for_sig(certification_sig)
    return DocMDPInfo(perm, certification_sig)


@dataclass
class VRI:
    """
    VRI dictionary as defined in PAdES / ISO 32000-2.
    These dictionaries collect data that may be relevant for the validation of
    a specific signature.

    .. note::
        The data are stored as PDF indirect objects, not asn1crypto values.
        In particular, values are tied to a specific PDF handler.
    """

    certs: set = data_field(default_factory=set)
    """
    Relevant certificates.
    """

    ocsps: set = data_field(default_factory=set)
    """
    Relevant OCSP responses.
    """

    crls: set = data_field(default_factory=set)
    """
    Relevant CRLs.
    """

    def as_pdf_object(self) -> generic.DictionaryObject:
        """
        :return:
            A PDF dictionary representing this VRI entry.
        """
        vri = generic.DictionaryObject({pdf_name('/Type'): pdf_name('/VRI')})
        if self.ocsps:
            vri[pdf_name('/OCSP')] = generic.ArrayObject(self.ocsps)
        if self.crls:
            vri[pdf_name('/CRL')] = generic.ArrayObject(self.crls)
        vri[pdf_name('/Cert')] = generic.ArrayObject(self.certs)
        return vri


def enumerate_ocsp_certs(ocsp_response):
    """
    Essentially nabbed from _extract_ocsp_certs in ValidationContext
    """

    status = ocsp_response['response_status'].native
    if status == 'successful':
        response_bytes = ocsp_response['response_bytes']
        if response_bytes['response_type'].native == 'basic_ocsp_response':
            response = response_bytes['response'].parsed
            yield from response['certs']


async def collect_validation_info(embedded_sig: EmbeddedPdfSignature,
                                  validation_context: ValidationContext,
                                  skip_timestamp=False):
    """
    Query revocation info for a PDF signature using a validation context,
    and store the results in a validation context.

    This works by validating the signer's certificate against the provided
    validation context, which causes revocation info to be cached for
    later retrieval.

    .. warning::
        This function does *not* actually validate the signature, but merely
        checks the signer certificate's chain of trust.

    :param embedded_sig:
        Embedded PDF signature to operate on.
    :param validation_context:
        Validation context to use.
    :param skip_timestamp:
        If the signature has a time stamp token attached to it, also collect
        revocation information for the timestamp.
    :return:
        A list of validation paths.
    """

    revinfo_fetch_policy = \
        validation_context.revinfo_policy.revocation_checking_policy
    if not revinfo_fetch_policy.essential:
        logger.warning(
            "Revocation mode is set to soft-fail/tolerant mode; collected "
            "revocation information may be incomplete."
        )

    paths = []

    async def _validate_signed_data(signed_data):
        signer_info, cert, other_certs = \
            _extract_signer_info_and_certs(signed_data)

        validator = CertificateValidator(
            cert, intermediate_certs=other_certs,
            validation_context=validation_context
        )
        path = await validator.async_validate_usage(key_usage=set())
        paths.append(path)

    await _validate_signed_data(embedded_sig.signed_data)
    if not skip_timestamp and embedded_sig.attached_timestamp_data is not None:
        await _validate_signed_data(embedded_sig.attached_timestamp_data)

    return paths


def add_validation_info(embedded_sig: EmbeddedPdfSignature,
                        validation_context: ValidationContext,
                        skip_timestamp=False, add_vri_entry=True,
                        in_place=False, output=None, force_write=False,
                        chunk_size=DEFAULT_CHUNK_SIZE):
    """
    .. versionchanged:: 0.9.0
        Wrapper around :func:`async_add_validation_info`

    Add validation info (CRLs, OCSP responses, extra certificates) for a
    signature to the DSS of a document in an incremental update.

    :param embedded_sig:
        The signature for which the revocation information needs to be
        collected.
    :param validation_context:
        The validation context to use.
    :param skip_timestamp:
        If ``True``, do not attempt to validate the timestamp attached to
        the signature, if one is present.
    :param add_vri_entry:
        Add a ``/VRI`` entry for this signature to the document security store.
        Default is ``True``.
    :param output:
        Write the output to the specified output stream.
        If ``None``, write to a new :class:`.BytesIO` object.
        Default is ``None``.
    :param in_place:
        Sign the original input stream in-place.
        This parameter overrides ``output``.
    :param chunk_size:
        Chunk size parameter to use when copying output to a new stream
        (irrelevant if ``in_place`` is ``True``).
    :param force_write:
        Force a new revision to be written, even if not necessary (i.e.
        when all data in the validation context is already present in the DSS).
    :return:
        The (file-like) output object to which the result was written.
    """

    coro = async_add_validation_info(
        embedded_sig=embedded_sig, validation_context=validation_context,
        skip_timestamp=skip_timestamp, add_vri_entry=add_vri_entry,
        output=output, in_place=in_place, chunk_size=chunk_size,
        force_write=force_write
    )
    return asyncio.run(coro)


async def async_add_validation_info(embedded_sig: EmbeddedPdfSignature,
                                    validation_context: ValidationContext,
                                    skip_timestamp=False, add_vri_entry=True,
                                    in_place=False, output=None,
                                    force_write=False,
                                    chunk_size=DEFAULT_CHUNK_SIZE,
                                    embed_roots: bool = True):
    """
    .. versionadded: 0.9.0

    Add validation info (CRLs, OCSP responses, extra certificates) for a
    signature to the DSS of a document in an incremental update.
    This is a wrapper around :func:`collect_validation_info`.

    :param embedded_sig:
        The signature for which the revocation information needs to be
        collected.
    :param validation_context:
        The validation context to use.
    :param skip_timestamp:
        If ``True``, do not attempt to validate the timestamp attached to
        the signature, if one is present.
    :param add_vri_entry:
        Add a ``/VRI`` entry for this signature to the document security store.
        Default is ``True``.
    :param output:
        Write the output to the specified output stream.
        If ``None``, write to a new :class:`.BytesIO` object.
        Default is ``None``.
    :param in_place:
        Sign the original input stream in-place.
        This parameter overrides ``output``.
    :param chunk_size:
        Chunk size parameter to use when copying output to a new stream
        (irrelevant if ``in_place`` is ``True``).
    :param force_write:
        Force a new revision to be written, even if not necessary (i.e.
        when all data in the validation context is already present in the DSS).
    :param embed_roots:
        Option that controls whether the root certificate of each validation
        path should be embedded into the DSS. The default is ``True``.

        .. note::
            Trust roots are configured by the validator, so embedding them
            typically does nothing in a typical validation process.
            Therefore they can be safely omitted in most cases.
            Nonetheless, embedding the roots can be useful for documentation
            purposes.
    :return:
        The (file-like) output object to which the result was written.
    """

    reader: PdfFileReader = embedded_sig.reader
    # Take care of this first, so we get any errors re: stream properties
    # out of the way before doing the (potentially) expensive validation
    # operations
    if in_place:
        working_output = output = reader.stream
        # Note: random-access I/O is checked at this point.
        # At the time of writing, this means that all this assertion does is
        # raise an error if the output is not writable.
        # We put it in for forwards compatibility & consistency with future
        # changes to I/O internals.
        misc.assert_writable_and_random_access(output)
    else:
        working_output = misc.prepare_rw_output_stream(output)

    paths = await collect_validation_info(
        embedded_sig, validation_context, skip_timestamp=skip_timestamp
    )

    if add_vri_entry:
        sig_contents = embedded_sig.pkcs7_content.hex().encode('ascii')
    else:
        sig_contents = None

    pdf_out = IncrementalPdfFileWriter.from_reader(reader)
    pdf_out.IO_CHUNK_SIZE = chunk_size
    resulting_dss = DocumentSecurityStore.supply_dss_in_writer(
        pdf_out, sig_contents, validation_context=validation_context,
        paths=paths, embed_roots=embed_roots
    )
    if force_write or resulting_dss.modified:
        if in_place:
            pdf_out.write_in_place()
        else:
            pdf_out.write(working_output)
    elif not in_place:
        # not in place, but we don't have anything to add -> copy the input
        # buffer
        reader.stream.seek(0)
        misc.chunked_write(bytearray(chunk_size), reader.stream, working_output)
    return misc.finalise_output(output, working_output)


class DocumentSecurityStore:
    """
    Representation of a DSS in Python.
    """

    def __init__(self, writer: BasePdfFileWriter,
                 certs=None, ocsps=None, crls=None,
                 vri_entries=None, backing_pdf_object=None):
        self.vri_entries = vri_entries if vri_entries is not None else {}
        self.certs = certs if certs is not None else {}
        self.ocsps = ocsps if ocsps is not None else []
        self.crls = crls if crls is not None else []

        self.writer = writer
        self.backing_pdf_object = (
            backing_pdf_object if backing_pdf_object is not None
            else generic.DictionaryObject()
        )

        ocsps_seen = {}
        for ocsp_ref in self.ocsps:
            ocsp_bytes = ocsp_ref.get_object().data
            ocsps_seen[ocsp_bytes] = ocsp_ref
        self._ocsps_seen = ocsps_seen

        crls_seen = {}
        for crl_ref in self.crls:
            crl_bytes = crl_ref.get_object().data
            crls_seen[crl_bytes] = crl_ref
        self._crls_seen = crls_seen
        self._modified = False

    @property
    def modified(self):
        return self._modified

    def _mark_modified(self):
        if not self._modified:
            self._modified = True
            if self.backing_pdf_object is not None:
                self.writer.update_container(self.backing_pdf_object)

    def _cms_objects_to_streams(self, objs, seen, dest):
        for obj in objs:
            obj_bytes = obj.dump()
            try:
                yield seen[obj_bytes]
            except KeyError:
                ref = self.writer.add_object(
                    generic.StreamObject(stream_data=obj_bytes)
                )
                self._mark_modified()
                seen[obj_bytes] = ref
                dest.append(ref)
                yield ref

    def _embed_certs_from_ocsp(self, ocsps):
        def extra_certs():
            for resp in ocsps:
                yield from enumerate_ocsp_certs(resp)

        return [self._embed_cert(cert_) for cert_ in extra_certs()]

    def _embed_cert(self, cert):
        if self.writer is None:
            raise TypeError('This DSS does not support updates.')

        try:
            return self.certs[cert.issuer_serial]
        except KeyError:
            pass

        ref = self.writer.add_object(
            generic.StreamObject(stream_data=cert.dump())
        )
        self._mark_modified()
        self.certs[cert.issuer_serial] = ref
        return ref

    @staticmethod
    def sig_content_identifier(contents) -> generic.NameObject:
        """
        Hash the contents of a signature object to get the corresponding VRI
        identifier.

        This is internal API.

        :param contents:
            Signature contents.
        :return:
            A name object to put into the DSS.
        """
        ident = hashlib.sha1(contents).digest().hex().upper()
        return pdf_name('/' + ident)

    def register_vri(self, identifier, *, certs=(), ocsps=(), crls=()):
        """
        Register validation information for a set of signing certificates
        associated with a particular signature.

        :param identifier:
            Identifier of the signature object (see `sig_content_identifier`).
            If ``None``, only embed the data into the DSS without associating
            it with any VRI.
        :param certs:
            Certificates to add.
        :param ocsps:
            OCSP responses to add.
        :param crls:
            CRLs to add.
        """

        if self.writer is None:
            raise TypeError('This DSS does not support updates.')

        ocsps = list(ocsps)
        crls = list(crls)

        ocsp_refs = set()
        crl_refs = set()
        cert_refs = {self._embed_cert(cert) for cert in certs}
        if ocsps:
            ocsp_refs = set(
                self._cms_objects_to_streams(
                    ocsps, self._ocsps_seen, self.ocsps
                )
            )
        if crls:
            crl_refs = set(
                self._cms_objects_to_streams(crls, self._crls_seen, self.crls)
            )
        # TODO while somewhat less common, CRL signing can also be delegated
        #  we should take that into account
        cert_refs.update(set(self._embed_certs_from_ocsp(ocsps)))

        # TODO do a better job of determining whether the VRI dictionary even
        #  needs updating.
        if identifier is not None:
            vri = VRI(certs=cert_refs, ocsps=ocsp_refs, crls=crl_refs)
            self.vri_entries[identifier] = self.writer.add_object(
                vri.as_pdf_object()
            )
            self._mark_modified()

    def as_pdf_object(self):
        """
        Convert the :class:`.DocumentSecurityStore` object to a python
        dictionary. This method also handles DSS updates.

        :return:
            A PDF object representing this DSS.
        """
        pdf_dict = self.backing_pdf_object
        pdf_dict['/Certs'] = generic.ArrayObject(list(self.certs.values()))
        if self.vri_entries:
            pdf_dict['/VRI'] = generic.DictionaryObject(self.vri_entries)

        if self.ocsps:
            pdf_dict[pdf_name('/OCSPs')] = generic.ArrayObject(self.ocsps)

        if self.crls:
            pdf_dict[pdf_name('/CRLs')] = generic.ArrayObject(self.crls)

        return pdf_dict

    def _load_certs(self):
        for cert_ref in self.certs.values():
            cert_stream: generic.StreamObject = cert_ref.get_object()
            cert = Certificate.load(cert_stream.data)
            yield cert

    def as_validation_context(self, validation_context_kwargs,
                              include_revinfo=True) -> ValidationContext:
        """
        Construct a validation context from the data in this DSS.

        :param validation_context_kwargs:
            Extra kwargs to pass to the ``__init__`` function.
        :param include_revinfo:
            If ``False``, revocation info is skipped.
        :return:
            A validation context preloaded with information from this DSS.
        """

        validation_context_kwargs = dict(validation_context_kwargs)
        extra_certs = validation_context_kwargs.pop('other_certs', [])
        certs = list(self._load_certs()) + extra_certs

        if include_revinfo:
            ocsps = list(validation_context_kwargs.pop('ocsps', ()))
            for ocsp_ref in self.ocsps:
                ocsp_stream: generic.StreamObject = ocsp_ref.get_object()
                resp = asn1_ocsp.OCSPResponse.load(ocsp_stream.data)
                ocsps.append(resp)
            validation_context_kwargs['ocsps'] = ocsps

            crls = list(validation_context_kwargs.pop('crls', ()))
            for crl_ref in self.crls:
                crl_stream: generic.StreamObject = crl_ref.get_object()
                crl = asn1_crl.CertificateList.load(crl_stream.data)
                crls.append(crl)
            validation_context_kwargs['crls'] = crls

        return ValidationContext(
            other_certs=certs, **validation_context_kwargs
        )

    @classmethod
    def read_dss(cls, handler: PdfHandler) -> 'DocumentSecurityStore':
        """
        Read a DSS record from a file and add the data to a validation context.

        :param handler:
            PDF handler from which to read the DSS.
        :return:
            A DocumentSecurityStore object describing the current state of the
            DSS.
        """
        try:
            dss_dict = handler.root['/DSS']
        except KeyError as e:
            raise NoDSSFoundError() from e

        cert_refs = {}
        cert_ref_list = get_and_apply(dss_dict, '/Certs', list, default=())
        for cert_ref in cert_ref_list:
            cert_stream: generic.StreamObject = cert_ref.get_object()
            cert: Certificate = Certificate.load(cert_stream.data)
            cert_refs[cert.issuer_serial] = cert_ref

        ocsp_refs = get_and_apply(dss_dict, '/OCSPs', list, default=())
        ocsps = []
        for ocsp_ref in ocsp_refs:
            ocsp_stream: generic.StreamObject = ocsp_ref.get_object()
            resp = asn1_ocsp.OCSPResponse.load(ocsp_stream.data)
            ocsps.append(resp)

        crl_refs = get_and_apply(dss_dict, '/CRLs', list, default=())
        crls = []
        for crl_ref in crl_refs:
            crl_stream: generic.StreamObject = crl_ref.get_object()
            crl = asn1_crl.CertificateList.load(crl_stream.data)
            crls.append(crl)

        # shallow-copy the VRI dictionary
        try:
            vri_entries = dict(dss_dict['/VRI'])
        except KeyError:
            vri_entries = None

        # if the handler is a writer, the DSS will support updates
        if isinstance(handler, BasePdfFileWriter):
            writer = handler
        else:
            writer = None

        # the DSS returned will be backed by the original DSS object, so CRLs
        # are automagically preserved if they happened to be included in
        # the original file
        dss = cls(
            writer=writer, certs=cert_refs, ocsps=ocsp_refs,
            vri_entries=vri_entries, crls=crl_refs, backing_pdf_object=dss_dict
        )
        return dss

    @classmethod
    def supply_dss_in_writer(cls, pdf_out: BasePdfFileWriter,
                             sig_contents, *, certs=None,
                             ocsps=None, crls=None, paths=None,
                             validation_context=None,
                             embed_roots: bool = True) \
            -> 'DocumentSecurityStore':
        """
        Add or update a DSS, and optionally associate the new information with a
        VRI entry tied to a signature object.

        You can either specify the CMS objects to include directly, or
        pass them in as output from `pyhanko_certvalidator`.

        :param pdf_out:
            PDF writer to write to.
        :param sig_contents:
            Contents of the new signature (used to compute the VRI hash), as
            as a hexadecimal string, including any padding.
            If ``None``, the information will not be added to any VRI
            dictionary.
        :param certs:
            Certificates to include in the VRI entry.
        :param ocsps:
            OCSP responses to include in the VRI entry.
        :param crls:
            CRLs to include in the VRI entry.
        :param paths:
            Validation paths that have been established, and need to be added
            to the DSS.
        :param validation_context:
            Validation context from which to draw OCSP responses and CRLs.
        :param embed_roots:
            .. versionadded:: 0.9.0

            Option that controls whether the root certificate of each validation
            path should be embedded into the DSS. The default is ``True``.

            .. note::
                Trust roots are configured by the validator, so embedding them
                typically does nothing in a typical validation process.
                Therefore they can be safely omitted in most cases.
                Nonetheless, embedding the roots can be useful for documentation
                purposes.

            .. warning::
                This only applies to paths, not the ``certs`` parameter.

        :return:
            a :class:`DocumentSecurityStore` object containing both the new
            and existing contents of the DSS (if any).
        """
        try:
            dss = cls.read_dss(pdf_out)
            created = False
        except ValidationInfoReadingError:
            created = True
            dss = cls(writer=pdf_out)

        if sig_contents is not None:
            identifier = \
                DocumentSecurityStore.sig_content_identifier(sig_contents)
        else:
            identifier = None

        def _certs():
            yield from certs or ()
            path: ValidationPath
            for path in (paths or ()):
                path_parts = iter(path)
                if not embed_roots:
                    # skip the first cert (i.e. the root)
                    next(path_parts)
                yield from path_parts

        def _ocsps():
            yield from ocsps or ()
            if validation_context is not None:
                yield from validation_context.ocsps

        def _crls():
            yield from crls or ()
            if validation_context is not None:
                yield from validation_context.crls

        dss.register_vri(
            identifier, certs=_certs(), ocsps=_ocsps(), crls=_crls()
        )
        dss_dict = dss.as_pdf_object()
        # if we're updating the DSS, this is all we need to do.
        # if we're adding a fresh DSS, we need to register it.

        if created:
            dss_ref = pdf_out.add_object(dss_dict)
            pdf_out.root[pdf_name('/DSS')] = dss_ref
            pdf_out.update_root()
        return dss

    @classmethod
    def add_dss(cls, output_stream, sig_contents, *, certs=None,
                ocsps=None, crls=None, paths=None, validation_context=None,
                force_write: bool = False, embed_roots: bool = True):
        """
        Wrapper around :meth:`supply_dss_in_writer`.

        The result is applied to the output stream as an incremental update.

        :param output_stream:
            Output stream to write to.
        :param sig_contents:
            Contents of the new signature (used to compute the VRI hash), as
            as a hexadecimal string, including any padding.
            If ``None``, the information will not be added to any VRI
            dictionary.
        :param certs:
            Certificates to include in the VRI entry.
        :param ocsps:
            OCSP responses to include in the VRI entry.
        :param crls:
            CRLs to include in the VRI entry.
        :param paths:
            Validation paths that have been established, and need to be added
            to the DSS.
        :param force_write:
            Force a write even if the DSS doesn't have any new content.
        :param validation_context:
            Validation context from which to draw OCSP responses and CRLs.
        :param embed_roots:
            .. versionadded:: 0.9.0

            Option that controls whether the root certificate of each validation
            path should be embedded into the DSS. The default is ``True``.

            .. note::
                Trust roots are configured by the validator, so embedding them
                typically does nothing in a typical validation process.
                Therefore they can be safely omitted in most cases.
                Nonetheless, embedding the roots can be useful for documentation
                purposes.

            .. warning::
                This only applies to paths, not the ``certs`` parameter.

        """
        pdf_out = IncrementalPdfFileWriter(output_stream)
        dss = cls.supply_dss_in_writer(
            pdf_out, sig_contents, certs=certs, ocsps=ocsps,
            crls=crls, paths=paths, validation_context=validation_context,
            embed_roots=embed_roots
        )
        if force_write or dss.modified:
            pdf_out.write_in_place()
