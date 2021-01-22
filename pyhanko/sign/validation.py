import hashlib
import os
import logging
from collections import namedtuple
from dataclasses import dataclass, field as data_field
from datetime import datetime
from enum import Enum, unique
from typing import TypeVar, Type, Optional, Union

from asn1crypto import (
    cms, tsp, ocsp as asn1_ocsp, pdf as asn1_pdf, crl as asn1_crl, x509,
)
from asn1crypto.x509 import Certificate
from certvalidator import ValidationContext, CertificateValidator
from certvalidator.path import ValidationPath
from oscrypto import asymmetric
from oscrypto.errors import SignatureError

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import OrderedEnum, get_and_apply
from pyhanko.pdf_utils.reader import (
    PdfFileReader, XRefCache, process_data_at_eof,
)
from pyhanko.pdf_utils.rw_common import PdfHandler
from .diff_analysis import (
    SuspiciousModification, ModificationLevel, DEFAULT_DIFF_POLICY, DiffPolicy,
    DiffResult,
)
from .fields import (
    MDPPerm, FieldMDPSpec, SeedLockDocument, SigSeedValueSpec,
    SigSeedValFlags, SigSeedSubFilter
)
from .general import (
    SignatureStatus, find_cms_attribute,
    UnacceptableSignerError, KeyUsageConstraints, _validate_pss_raw,
)
from .timestamps import TimestampSignatureStatus

__all__ = [
    'SignatureCoverageLevel', 'PdfSignatureStatus',
    'EmbeddedPdfSignature', 'DocMDPInfo',
    'RevocationInfoValidationType', 'VRI', 'DocumentSecurityStore',
    'apply_adobe_revocation_info',
    'read_certification_data', 'validate_pdf_ltv_signature',
    'validate_pdf_signature', 'validate_cms_signature',
    'ValidationInfoReadingError', 'SignatureValidationError',
    'SigSeedValueValidationError'
]

logger = logging.getLogger(__name__)


class ValidationInfoReadingError(ValueError):
    """Error reading validation info."""
    pass


class SignatureValidationError(ValueError):
    """Error validating a signature."""
    pass


class SigSeedValueValidationError(SignatureValidationError):
    """Error validating a signature's seed value constraints."""

    # TODO perhaps we can encode some more metadata here, such as the
    #  seed value that tripped the failure.

    def __init__(self, failure_message):
        self.failure_message = failure_message
        super().__init__(failure_message)


def partition_certs(certs, signer_info):
    # The 'certificates' entry is defined as a set in PCKS#7.
    # In particular, we cannot make any assumptions about the order.
    # This means that we have to manually dig through the list to find
    # the actual signer
    iss_sn = signer_info['sid']
    # TODO Figure out how the subject key identifier thing works
    if iss_sn.name != 'issuer_and_serial_number':
        raise NotImplementedError(
            'Can only look up certificates by issuer and serial number'
        )
    issuer = iss_sn.chosen['issuer']
    serial_number = iss_sn.chosen['serial_number'].native
    cert = None
    other_certs = []
    for c in certs:
        if c.issuer == issuer and c.serial_number == serial_number:
            cert = c
        else:
            other_certs.append(c)
    if cert is None:
        raise SignatureValidationError(
            'signer certificate not included in signature'
        )
    return cert, other_certs


StatusType = TypeVar('StatusType', bound=SignatureStatus)


def _extract_signer_info_and_certs(signed_data: cms.SignedData):
    certs = [c.parse() for c in signed_data['certificates']]

    try:
        signer_info, = signed_data['signer_infos']
    except ValueError:  # pragma: nocover
        raise ValueError(
            'signer_infos should contain exactly one entry'
        )

    cert, other_certs = partition_certs(certs, signer_info)

    return signer_info, cert, other_certs


def _validate_raw(signature: bytes, signed_blob: bytes, cert: x509.Certificate,
                  signature_algorithm: cms.SignedDigestAlgorithm,
                  md_algorithm: str):
    try:
        verify_md = signature_algorithm.hash_algo
    except ValueError:
        verify_md = md_algorithm
    sig_algo = signature_algorithm.signature_algo
    if sig_algo == 'rsassa_pkcs1v15':
        verify_func = asymmetric.rsa_pkcs1v15_verify
    elif sig_algo == 'rsassa_pss':
        _validate_pss_raw(
            signature, signed_blob, cert, signature_algorithm['parameters'],
            digest_algorithm=verify_md
        )
        return
    elif sig_algo == 'ecdsa':
        verify_func = asymmetric.ecdsa_verify
    else:  # pragma: nocover
        raise SignatureValidationError(
            f"Signature mechanism {sig_algo} is not supported."
        )

    verify_func(
        asymmetric.load_public_key(cert.public_key), signature,
        signed_blob, hash_algorithm=verify_md
    )


def _validate_cms_signature(signed_data: cms.SignedData,
                            status_cls: Type[StatusType] = SignatureStatus,
                            raw_digest: bytes = None,
                            validation_context: ValidationContext = None,
                            status_kwargs: dict = None,
                            key_usage_settings: KeyUsageConstraints = None,
                            externally_invalid=False):
    """
    Validate CMS and PKCS#7 signatures.
    """
    signer_info, cert, other_certs = _extract_signer_info_and_certs(signed_data)

    signature_algorithm: cms.SignedDigestAlgorithm = \
        signer_info['signature_algorithm']
    mechanism = signature_algorithm['algorithm'].native.lower()
    md_algorithm = \
        signer_info['digest_algorithm']['algorithm'].native.lower()
    signature = signer_info['signature'].native
    # signed_attrs comes with some context-specific tagging
    # because it's an implicit field. This breaks validation
    signed_attrs = signer_info['signed_attrs'].untag()

    # TODO What to do if signed_attrs is absent?
    # I guess I'll wait until someone complains that a valid signature
    # isn't being validated correctly
    if raw_digest is None:
        # this means that there should be encapsulated data
        # TODO Carefully read § 5.2.1 in RFC 5652, and compare with
        #  the implementation in asn1crypto.
        raw = signed_data['encap_content_info']['content'].parsed.dump()
        raw_digest = getattr(hashlib, md_algorithm)(raw).digest()

    signed_blob = signed_attrs.dump(force=True)
    try:
        embedded_digest = find_cms_attribute(signed_attrs, 'message_digest')
    except KeyError:
        raise SignatureValidationError('Message digest not found in signature')
    intact = raw_digest == embedded_digest[0].native

    valid = False
    if intact:
        try:
            _validate_raw(
                signature, signed_blob, cert, signature_algorithm, md_algorithm
            )
            valid = True
        except SignatureError:
            valid = False

    # if the signature is invalid for some external reason, this flag is set
    #  (e.g. when the thing being signed is itself wrong)
    valid &= not externally_invalid
    trusted = revoked = False
    path = None
    if valid:
        validator = CertificateValidator(
            cert, intermediate_certs=other_certs,
            validation_context=validation_context
        )
        trusted, revoked, path = status_cls.validate_cert_usage(
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
                           externally_invalid=False):
    """
    Validate a detached CMS signature (i.e. a ``SignedData`` object).

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
        A :class:`.KeyUsageConstraints` object specifying which key usage
        extensions must or must not be present in the signer's certificate.
    :param externally_invalid:
        If ``True``, there is an external reason why the signature cannot
        be valid, but the remaining validation logic still has to be run.

        This option is considered internal API, the semantics of which may
        change without notice in the future.
    :return:
        A :class:`SignatureStatus` object (or an instance of a proper subclass)
    """
    status_kwargs = _validate_cms_signature(
        signed_data, status_cls, raw_digest, validation_context,
        status_kwargs, key_usage_settings, externally_invalid
    )
    return status_cls(**status_kwargs)


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
class PdfSignatureStatus(SignatureStatus):
    """Class to indicate the validation status of a PDF signature."""

    coverage: SignatureCoverageLevel
    """
    Indicates how much of the document is covered by the signature.
    """

    diff_result: Optional[Union[DiffResult, SuspiciousModification]]
    """
    Result of the difference analysis run on the file:
    
    * If ``None``, no difference analysis was run.
    * If the difference analysis was successful, this attribute will contain
      a :class:`DiffResult` object.
    * If the difference analysis failed due to unforeseen or suspicious
      modifications, the :class:`SuspiciousModification` exception thrown
      by the difference policy will be stored in this attribute.
    """

    docmdp_ok: Optional[bool]
    """
    Indicates whether the signature's :attr:`modification_level` is in line with
    the document signature policy in force.
    
    If ``None``, compliance could not be determined.
    """

    signer_reported_dt: Optional[datetime] = None
    """
    Signer-reported signing time, if present in the signature.
    
    Generally speaking, this timestamp should not be taken as fact.
    """

    timestamp_validity: Optional[TimestampSignatureStatus] = None
    """
    Validation status of the timestamp token embedded in this signature, 
    if present.
    """

    seed_value_constraint_error: Optional[SigSeedValueValidationError] = None
    """
    Records the reason for failure if the signature field's seed value
    constraints didn't validate.
    """

    @property
    def modification_level(self) -> Optional[ModificationLevel]:
        """
        Indicates the degree to which the document was modified after the
        signature was applied.

        Will be ``None`` if difference analysis results are not available;
        an instance of :class:`.ModificationLevel` otherwise.
        """

        if self.diff_result is None:
            if self.coverage == SignatureCoverageLevel.ENTIRE_REVISION:
                # in this case, we can't know without the diff analysis result
                return None
            return (
                ModificationLevel.NONE if SignatureCoverageLevel.ENTIRE_FILE
                else ModificationLevel.OTHER
            )
        elif isinstance(self.diff_result, DiffResult):
            return self.diff_result.modification_level
        else:
            return ModificationLevel.OTHER

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
            timestamp_ok = ts.valid and ts.trusted
        return (
            self.valid and self.trusted and self.seed_value_ok
            and self.docmdp_ok and timestamp_ok
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
            yield 'EXTENDED_WITH_' + self.modification_level.name
        else:
            yield 'NONSTANDARD_COVERAGE'
        if self.docmdp_ok:
            if self.coverage != SignatureCoverageLevel.ENTIRE_FILE:
                yield 'ACCEPTABLE_MODIFICATIONS'
        else:
            yield 'ILLEGAL_MODIFICATIONS'
        if self.timestamp_validity is not None:
            yield 'TIMESTAMP_TOKEN<%s>' % (
                '|'.join(self.timestamp_validity.summary_fields())
            )

    def pretty_print_details(self):
        cert: x509.Certificate = self.signing_cert

        def _trust_anchor(status: SignatureStatus):
            if status.validation_path is not None:
                trust_anchor: x509.Certificate = status.validation_path[0]
                return trust_anchor.subject.human_friendly
            else:
                return "No path to trust anchor found."

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
            f"Trust anchor: \"{_trust_anchor(self)}\"\n"
            f"The signer's certificate is {trust_status}."
        )

        if self.coverage == SignatureCoverageLevel.ENTIRE_FILE:
            modification_str = "The signature covers the entire file."
        else:
            modlvl_string = "Some modifications may be illegitimate"
            if self.modification_level is not None:
                if self.modification_level == ModificationLevel.LTA_UPDATES:
                    modlvl_string = \
                        "All modifications relate to signature maintenance"
                elif self.modification_level == ModificationLevel.FORM_FILLING:
                    modlvl_string = (
                        "All modifications relate to signing and form filling "
                        "operations"
                    )
            modification_str = (
                "The signature does not cover the entire file.\n"
                f"{modlvl_string}, and they appear to be "
                f"{'' if self.docmdp_ok else 'in'}compatible with the "
                "current document modification policy."
            )

        validity_info = (
            "The signature is cryptographically "
            f"{'' if self.intact and self.valid else 'un'}sound.\n"
            f"{modification_str}"
        )

        ts = self.signer_reported_dt
        tst_status = self.timestamp_validity
        about_tsa = ''
        if tst_status is not None:
            ts = tst_status.timestamp
            tsa = tst_status.signing_cert

            about_tsa = (
                "The signing time is guaranteed by a time stamping authority.\n"
                f"TSA certificate subject: \"{tsa.subject.human_friendly}\"\n"
                f"TSA certificate SHA1 fingerprint: {tsa.sha1.hex()}\n"
                f"TSA certificate SHA256 fingerprint: {tsa.sha256.hex()}\n"
                f"TSA cert trust anchor: \"{_trust_anchor(tst_status)}\"\n"
                "The TSA certificate is "
                f"{'' if tst_status.trusted else 'un'}trusted."
            )
        elif ts is not None:
            about_tsa = "The signing time is self-reported by the signer."

        if ts is not None:
            signing_time_str = ts.isoformat()
        else:
            signing_time_str = "unknown"

        timing_info = (
            f"Signing time: {signing_time_str}\n{about_tsa}"
        )

        def fmt_section(hdr, body):
            return '\n'.join(
                (hdr, '-' * len(hdr), body, '\n')
            )

        bottom_line = (
            f"The signature is judged {'' if self.bottom_line else 'IN'}VALID."
        )

        if self.seed_value_ok:
            sv_info = "There were no SV issues detected for this signature."
        else:
            sv_info = (
                "The signature did not satisfy the SV constraints on "
                "the signature field.\nError message: "
                + self.seed_value_constraint_error.failure_message
            )

        sections = [
            ("Signer info", about_signer), ("Integrity", validity_info),
            ("Signing time", timing_info),
            ("Seed value constraints", sv_info),
            ("Bottom line", bottom_line)
        ]
        return '\n'.join(
            fmt_section(hdr, body) for hdr, body in sections
        )


def _extract_reference_dict(signature_obj, method) \
        -> Optional[generic.DictionaryObject]:
    try:
        sig_refs = signature_obj['/Reference']
    except KeyError:
        return
    for ref in sig_refs:
        if ref['/TransformMethod'] == method:
            return ref


def _extract_docmdp_for_sig(signature_obj) -> Optional[MDPPerm]:
    ref = _extract_reference_dict(signature_obj, '/DocMDP')
    if ref is None:
        return
    try:
        raw_perms = ref.raw_get('/TransformParams').raw_get('/P')
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
                 sig_field: generic.DictionaryObject):
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
            raise ValueError('Signature PDF object is not correctly formatted')

        # we need the pkcs7_content raw, so we need to deencapsulate a couple
        # pieces of data here.
        if isinstance(pkcs7_content, generic.DecryptedObjectProxy):
            # it was a direct reference, so just grab the raw one
            pkcs7_content = pkcs7_content.raw_object
        elif isinstance(pkcs7_content, generic.IndirectObject):
            pkcs7_content = reader.get_object(
                pkcs7_content.reference, transparent_decrypt=False
            )
        self.pkcs7_content = pkcs7_content

        message = cms.ContentInfo.load(pkcs7_content)
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

        # grab the revision to which the signature applies
        self.signed_revision = self.reader.xrefs.get_introducing_revision(
            sig_object_ref.reference
        )
        self.coverage = None
        self.raw_digest = None
        self.total_len = None
        self._docmdp = self._fieldmdp = None
        self._docmdp_queried = self._fieldmdp_queried = False
        self.tst_signature_digest = None

        self.diff_result = None
        self._integrity_checked = False

    @property
    def field_name(self):
        """
        :return:
            Name of the signature field.
        """
        return self.sig_field['/T']

    # TODO also parse the signature object's /M entry
    @property
    def self_reported_timestamp(self) -> Optional[datetime]:
        """
        :return:
            The signing time as reported by the signer, if embedded in the
            signature's signed attributes.
        """
        try:
            sa = self.signer_info['signed_attrs']
            st = find_cms_attribute(sa, 'signed_time')[0]
            return st.native
        except KeyError:
            pass

        try:
            st_as_pdf_date = self.sig_object['/M']
            return generic.parse_pdf_date(st_as_pdf_date)
        except KeyError:  # pragma: nocover
            pass

    @property
    def external_timestamp_data(self) -> Optional[cms.SignedData]:
        """
        :return:
            The signed data component of the timestamp token embedded in this
            signature, if present.
        """
        try:
            ua = self.signer_info['unsigned_attrs']
            tst = find_cms_attribute(ua, 'signature_time_stamp_token')[0]
            tst_signed_data = tst['content']
            return tst_signed_data
        except KeyError:
            pass

    def compute_integrity_info(self, diff_policy=None, skip_diff=False):
        """
        Compute the various integrity indicators of this signature.

        :param diff_policy:
            Policy to evaluate potential incremental updates that were appended
            to the signed revision of the document.
            Defaults to :attr:`.DEFAULT_DIFF_POLICY`.
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
        that can later be passed to :class:`PdfSignatureStatus` as kwargs.

        This method is only available after calling
        :meth:`.EmbeddedSig.compute_integrity_info`.
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
            The document modification policy required by this signature.

            .. warning::
                This does not take into account the DocMDP requirements of
                earlier signatures (if present).

                The specification forbids signing with a more lenient DocMDP
                than the one currently in force, so this should not happen
                in a compliant document.
                That being said, any potential violations will still invalidate
                the earlier signature with the stricter DocMDP policy.

        """
        # TODO fall back to reading /Lock in case the signing software
        #  ignored the /Lock dictionary when building up the signature object
        if self._docmdp_queried:
            return self._docmdp
        docmdp = _extract_docmdp_for_sig(signature_obj=self.sig_object)
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
        if self.raw_digest is not None:
            return self.raw_digest

        md = getattr(hashlib, self.md_algorithm)()
        stream = self.reader.stream

        # compute the digest
        # here, we allow arbitrary byte ranges
        # for the coverage check, we'll impose more constraints
        total_len = 0
        for lo, chunk_len in misc.pair_iter(self.byte_range):
            stream.seek(lo)
            chunk = stream.read(chunk_len)
            assert len(chunk) == chunk_len
            md.update(chunk)
            total_len += chunk_len

        self.total_len = total_len
        self.raw_digest = digest = md.digest()
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
        # for timestamp validation: compute the digest of the signature
        #  (as embedded in the CMS object)
        tst_data = self.external_timestamp_data
        if tst_data is None:
            return None

        signature_bytes = self.signer_info['signature'].native
        md = getattr(hashlib, self.md_algorithm)(signature_bytes)
        self.tst_signature_digest = digest = md.digest()
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
    if sv_spec is None:
        return

    if sv_spec.cert is not None:
        try:
            sv_spec.cert.satisfied_by(signing_cert, validation_path)
        except UnacceptableSignerError as e:
            raise SigSeedValueValidationError(e)

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
        Defaults to :attr:`.DEFAULT_DIFF_POLICY`.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usage
        extensions must or must not be present in the signer's certificate.
    :param skip_diff:
        If ``True``, skip the difference analysis step entirely.
    :return:
        The status of the PDF signature in question.
    """

    sig_object = embedded_sig.sig_object
    # check whether the subfilter type is one we support
    subfilter_str = sig_object['/SubFilter']
    try:
        from pyhanko.sign.fields import SigSeedSubFilter
        SigSeedSubFilter(subfilter_str)
    except ValueError:
        raise NotImplementedError(
            "%s is not a recognized SubFilter type." % subfilter_str
        )

    if ts_validation_context is None:
        ts_validation_context = signer_validation_context

    embedded_sig.compute_integrity_info(
        diff_policy=diff_policy, skip_diff=skip_diff
    )
    status_kwargs = embedded_sig.summarise_integrity_info()

    # try to find an embedded timestamp
    signer_reported_dt = embedded_sig.self_reported_timestamp
    if signer_reported_dt is not None:
        status_kwargs['signer_reported_dt'] = signer_reported_dt

    # if we managed to find an (externally) signed timestamp,
    # we now proceed to validate it
    tst_signed_data = embedded_sig.external_timestamp_data
    # TODO compare value of embedded timestamp token with the timestamp
    #  attribute if both are present
    tst_validity: Optional[SignatureStatus] = None
    if tst_signed_data is not None:
        assert embedded_sig.tst_signature_digest is not None
        tst_validity = _validate_timestamp(
            tst_signed_data, ts_validation_context,
            embedded_sig.tst_signature_digest
        )
        status_kwargs['timestamp_validity'] = tst_validity

    status_kwargs = _validate_cms_signature(
        embedded_sig.signed_data, status_cls=PdfSignatureStatus,
        raw_digest=embedded_sig.raw_digest,
        validation_context=signer_validation_context,
        status_kwargs=status_kwargs, key_usage_settings=key_usage_settings
    )
    timestamp_found = (
        tst_validity is not None
        and tst_validity.valid and tst_validity.trusted
    )
    _validate_sv_and_update(embedded_sig, status_kwargs, timestamp_found)
    return PdfSignatureStatus(**status_kwargs)


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


def _strict_vc_context_kwargs(timestamp, validation_context_kwargs):
    # create a new validation context using the timestamp value as the time
    # of evaluation, turn off fetching and load OCSP responses / CRL data
    # from the DSS / revocation info object
    validation_context_kwargs['allow_fetching'] = False
    validation_context_kwargs['moment'] = timestamp

    # Certs with OCSP/CRL endpoints should have the relevant revocation data
    # embedded, if no stricter revocation_mode policy is in place already
    rm = validation_context_kwargs.get('revocation_mode', None)
    if not rm or rm == 'soft-fail':
        validation_context_kwargs['revocation_mode'] = 'hard-fail'


def _validate_timestamp(tst_signed_data, validation_context,
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
        externally_invalid = True
    else:
        externally_invalid = False
    timestamp = tst_info['gen_time'].native
    timestamp_status: TimestampSignatureStatus = validate_cms_signature(
        tst_signed_data, status_cls=TimestampSignatureStatus,
        validation_context=validation_context,
        status_kwargs={'timestamp': timestamp},
        externally_invalid=externally_invalid
    )
    return timestamp_status


def _establish_timestamp_trust(tst_signed_data, bootstrap_validation_context,
                               expected_tst_imprint):
    timestamp_status = _validate_timestamp(
        tst_signed_data, bootstrap_validation_context, expected_tst_imprint
    )

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


def _establish_timestamp_trust_lta(reader, bootstrap_validation_context,
                                   validation_context_kwargs, until_revision):
    timestamps = [
        emb_sig for emb_sig in reader.embedded_signatures
        if emb_sig.sig_object['/Type'] == '/DocTimeStamp'
    ]
    validation_context_kwargs = dict(validation_context_kwargs)
    current_vc = bootstrap_validation_context
    for emb_timestamp in reversed(timestamps):
        if emb_timestamp.signed_revision < until_revision:
            break

        emb_timestamp.compute_digest()
        ts_status = _establish_timestamp_trust(
            emb_timestamp.signed_data, current_vc, emb_timestamp.raw_digest
        )
        # set up the validation kwargs for the next iteration
        _strict_vc_context_kwargs(
            ts_status.timestamp, validation_context_kwargs
        )
        # read the DSS at the current revision into a new
        # validation context object
        current_vc = DocumentSecurityStore.read_dss(
            reader.get_historical_resolver(emb_timestamp.signed_revision)
        ).as_validation_context(validation_context_kwargs)

    return current_vc


# TODO verify formal PAdES requirements for timestamps
# TODO verify other formal PAdES requirements (coverage, etc.)
def validate_pdf_ltv_signature(embedded_sig: EmbeddedPdfSignature,
                               validation_type: RevocationInfoValidationType,
                               validation_context_kwargs=None,
                               bootstrap_validation_context=None,
                               force_revinfo=False,
                               diff_policy: DiffPolicy = None,
                               key_usage_settings: KeyUsageConstraints = None,
                               skip_diff: bool = False) -> PdfSignatureStatus:
    """
    Validate a PDF LTV signature according to a particular profile.

    :param embedded_sig:
        Embedded signature to evaluate.
    :param validation_type:
        Validation profile to use.
    :param validation_context_kwargs:
        Keyword args to instantiate :class:`.certvalidator.ValidationContext`
        objects needed over the course of the validation.
    :param bootstrap_validation_context:
        Validation context used to validate the current timestamp.
    :param force_revinfo:
        Require all certificates encountered to have some form of live
        revocation checking provisions.
    :param diff_policy:
        Policy to evaluate potential incremental updates that were appended
        to the signed revision of the document.
        Defaults to :attr:`.DEFAULT_DIFF_POLICY`.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usage
        extensions must or must not be present in the signer's certificate.
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
        validation_context_kwargs['revocation_mode'] = 'require'
    else:
        validation_context_kwargs.setdefault('revocation_mode', 'hard-fail')

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

    # first, we need to validate the timestamp (or timestamp chain) *now*
    # in particular, this implies that we can't just use revocation info
    # from the DSS yet, since we don't yet trust the timestamp to be accurate
    # There are two main cases:
    #  (a) We're doing PAdES B-LT or Adobe-style verification.
    #      In that case, we simply attempt to validate the timestamp as-is.
    #  (b) We're doing PAdES B-LTA. In this case, we first verify the document
    #      timestamp chain until the revision in which the signature appears.
    #      This is bootstrapped using the current validation context.
    #      If successful, we obtain a new validation context set to a new
    #      "known good" verification time. We then proceed as in (a) using this
    #      new validation context instead of the current one.
    if validation_type == RevocationInfoValidationType.PADES_LTA:
        current_vc = _establish_timestamp_trust_lta(
            reader, current_vc, validation_context_kwargs,
            until_revision=embedded_sig.signed_revision
        )

    # FIXME in the LTA case, this is an unreasonable requirement (since the
    #  /DocTimeStamps can serve this purpose)
    tst_signed_data = embedded_sig.external_timestamp_data
    if tst_signed_data is None:
        raise SignatureValidationError(
            'LTV signatures require a trusted timestamp.'
        )

    ts_result = _establish_timestamp_trust(
        tst_signed_data, current_vc, embedded_sig.tst_signature_digest
    )
    timestamp = ts_result.timestamp
    _strict_vc_context_kwargs(timestamp, validation_context_kwargs)

    if validation_type == RevocationInfoValidationType.ADOBE_STYLE:
        ocsps, crls = retrieve_adobe_revocation_info(
            embedded_sig.signer_info
        )
        validation_context_kwargs['ocsps'] = ocsps
        validation_context_kwargs['crls'] = crls
        stored_vc = ValidationContext(**validation_context_kwargs)
    else:
        stored_vc = dss.as_validation_context(validation_context_kwargs)

    # next, we validate the timestamp *again*, this time using the data
    # in the DSS / revocation info store.
    timestamp_status: TimestampSignatureStatus = validate_cms_signature(
        tst_signed_data, status_cls=TimestampSignatureStatus,
        validation_context=stored_vc, status_kwargs={'timestamp': timestamp}
    )

    embedded_sig.compute_integrity_info(
        diff_policy=diff_policy, skip_diff=skip_diff
    )
    status_kwargs = embedded_sig.summarise_integrity_info()
    status_kwargs.update({
        'signer_reported_dt': timestamp,
        'timestamp_validity': timestamp_status
    })
    status_kwargs = _validate_cms_signature(
        embedded_sig.signed_data, status_cls=PdfSignatureStatus,
        raw_digest=embedded_sig.raw_digest,
        validation_context=stored_vc, status_kwargs=status_kwargs,
        key_usage_settings=key_usage_settings
    )

    _validate_sv_and_update(embedded_sig, status_kwargs, timestamp_found=True)

    return PdfSignatureStatus(**status_kwargs)


def retrieve_adobe_revocation_info(signer_info: cms.SignerInfo):
    try:
        revinfo: asn1_pdf.RevocationInfoArchival = find_cms_attribute(
            signer_info['signed_attrs'], "adobe_revocation_info_archival"
        )[0]
    except KeyError:
        raise ValidationInfoReadingError("No revocation info found")

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


DocMDPInfo = namedtuple('DocMDPInfo', ['permission', 'author_sig'])
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

    def __iadd__(self, other):
        self.certs.update(other.certs)
        self.crls.update(other.crls)
        self.ocsps.update(other.ocsps)
        return self

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


class DocumentSecurityStore:
    """
    Representation of a DSS in Python.
    """

    def __init__(self, writer, certs=None, ocsps=None, crls=None,
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

    def _cms_objects_to_streams(self, objs, seen, dest):
        for obj in objs:
            obj_bytes = obj.dump()
            try:
                yield seen[obj_bytes]
            except KeyError:
                ref = self.writer.add_object(
                    generic.StreamObject(stream_data=obj_bytes)
                )
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

    def register_vri(self, identifier, paths, validation_context):
        """
        Register validation information for a set of signing certificates
        associated with a particular signature.

        :param identifier:
            Identifier of the signature object (see `sig_content_identifier`)
        :param paths:
            Validation paths to add.
        :param validation_context:
            Validation context to source CRLs and OCSP responses from.
        """

        if self.writer is None:
            raise TypeError('This DSS does not support updates.')

        # embed any hardcoded ocsp responses and CRLs, if applicable
        ocsps = set(
            self._cms_objects_to_streams(
                validation_context.ocsps, self._ocsps_seen, self.ocsps
            )
        )
        crls = set(
            self._cms_objects_to_streams(
                validation_context.crls, self._crls_seen, self.crls
            )
        )
        path: ValidationPath
        # TODO while somewhat less common, CRL signing can also be delegated
        #  we should take that into account
        cert_refs = set(self._embed_certs_from_ocsp(validation_context.ocsps))
        for path in paths:
            for cert in path:
                cert_refs.add(self._embed_cert(cert))

        vri = VRI(certs=cert_refs, ocsps=ocsps, crls=crls)
        self.vri_entries[identifier] = self.writer.add_object(
            vri.as_pdf_object()
        )

    def as_pdf_object(self):
        """
        Convert the :class:`.DocumentSecurityStore` object to a python
        dictionary. This method also handles DSS updates.

        :return:
            A PDF object representing this DSS.
        """
        pdf_dict = self.backing_pdf_object
        pdf_dict.update({
            pdf_name('/VRI'): generic.DictionaryObject(self.vri_entries),
            pdf_name('/Certs'): generic.ArrayObject(list(self.certs.values())),
        })

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
            ocsps = validation_context_kwargs['ocsps'] = []
            for ocsp_ref in self.ocsps:
                ocsp_stream: generic.StreamObject = ocsp_ref.get_object()
                resp = asn1_ocsp.OCSPResponse.load(ocsp_stream.data)
                ocsps.append(resp)

            crls = validation_context_kwargs['crls'] = []
            for crl_ref in self.crls:
                crl_stream: generic.StreamObject = crl_ref.get_object()
                crl = asn1_crl.CertificateList.load(crl_stream.data)
                crls.append(crl)

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
            dss_ref = handler.root.raw_get(pdf_name('/DSS'))
        except KeyError:
            raise ValidationInfoReadingError("No DSS found")

        dss_dict = dss_ref.get_object()

        cert_refs = {}
        for cert_ref in dss_dict.get('/Certs', ()):
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
        if isinstance(handler, IncrementalPdfFileWriter):
            writer = handler
            writer.mark_update(dss_ref)
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
    def add_dss(cls, output_stream, sig_contents, paths,
                validation_context):
        """
        Add or update a DSS, and add the new information to a specific VRI.
        This will be done as an incremental update.

        :param output_stream:
            Output stream to write to.
        :param sig_contents:
            Contents of the new signature (used to compute the VRI hash)
        :param paths:
            Validation paths that have been established, and need to be added
            to the DSS.
        :param validation_context:
            Validation context from which to draw OCSP responses and CRLs.
        """
        writer = IncrementalPdfFileWriter(output_stream)

        try:
            dss = cls.read_dss(writer)
            created = False
        except ValidationInfoReadingError:
            created = True
            dss = cls(writer=writer)

        identifier = DocumentSecurityStore.sig_content_identifier(sig_contents)

        dss.register_vri(identifier, paths, validation_context)
        dss_dict = dss.as_pdf_object()
        # if we're updating the DSS, this is all we need to do.
        # if we're adding a fresh DSS, we need to register it.

        if created:
            dss_ref = writer.add_object(dss_dict)
            writer.root[pdf_name('/DSS')] = dss_ref
            writer.update_root()
        writer.write_in_place()
