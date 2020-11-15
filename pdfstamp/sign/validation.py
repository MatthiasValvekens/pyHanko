import hashlib
import os
import logging
import re
from collections import namedtuple
from dataclasses import dataclass, field as data_field
from datetime import datetime
from enum import Enum, auto, unique
from typing import TypeVar, Type, Optional, Set

from asn1crypto import (
    cms, tsp, ocsp as asn1_ocsp, pdf as asn1_pdf, crl as asn1_crl
)
from asn1crypto.x509 import Certificate
from certvalidator import ValidationContext, CertificateValidator
from certvalidator.path import ValidationPath
from oscrypto import asymmetric
from oscrypto.errors import SignatureError

from pdf_utils import generic, misc
from pdf_utils.generic import pdf_name
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.misc import OrderedEnum, LazyJoin
from pdf_utils.reader import (
    PdfFileReader, XRefCache, process_data_at_eof,
)
from pdf_utils.rw_common import PdfHandler
from .fields import MDPPerm, FieldMDPSpec
from .general import (
    SignatureStatus, find_cms_attribute,
    UnacceptableSignerError,
)
from .timestamps import TimestampSignatureStatus

__all__ = [
    'PdfSignatureStatus', 'validate_pdf_signature', 'validate_cms_signature',
    'read_certification_data', 'validate_pdf_ltv_signature'
]

logger = logging.getLogger(__name__)


class SignatureValidationError(ValueError):
    pass


class SigSeedValueValidationError(SignatureValidationError):
    pass


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
    ca_chain = []
    for c in certs:
        if c.issuer == issuer and c.serial_number == serial_number:
            cert = c
        else:
            ca_chain.append(c)
    if cert is None:
        raise SignatureValidationError(
            'signer certificate not included in signature'
        )
    return cert, ca_chain


StatusType = TypeVar('StatusType', bound=SignatureStatus)


def _validate_cms_signature(signed_data: cms.SignedData,
                            status_cls: Type[StatusType] = SignatureStatus,
                            raw_digest: bytes = None,
                            validation_context: ValidationContext = None,
                            status_kwargs: dict = None,
                            externally_invalid=False):
    """
    Validate CMS and PKCS#7 signatures.
    """

    certs = [c.parse() for c in signed_data['certificates']]

    try:
        signer_info, = signed_data['signer_infos']
    except ValueError:
        raise SignatureValidationError(
            'signer_infos should contain exactly one entry'
        )

    cert, ca_chain = partition_certs(certs, signer_info)

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

    # finally validate the signature
    if mechanism not in MECHANISMS:
        raise NotImplementedError(
            'Signature mechanism %s is not currently supported'
            % mechanism
        )

    valid = False
    if intact:
        try:
            try:
                verify_md = signature_algorithm.hash_algo
            except ValueError:
                verify_md = md_algorithm
            asymmetric.rsa_pkcs1v15_verify(
                asymmetric.load_public_key(cert.public_key), signature,
                signed_blob, hash_algorithm=verify_md
            )
            valid = True
        except SignatureError:
            valid = False

    # if the signature is invalid for some external reason, this flag is set
    #  (e.g. when the thing being signed is itself wrong)
    valid &= not externally_invalid
    trusted = revoked = usage_ok = False
    path = None
    if valid:
        validator = CertificateValidator(
            cert, intermediate_certs=ca_chain,
            validation_context=validation_context
        )
        trusted, revoked, usage_ok, path = \
            status_cls.validate_cert_usage(validator)

    status_kwargs = status_kwargs or {}
    status_kwargs.update(
        intact=intact, ca_chain=ca_chain, valid=valid, signing_cert=cert,
        md_algorithm=md_algorithm, pkcs7_signature_mechanism=mechanism,
        revoked=revoked, usage_ok=usage_ok, trusted=trusted,
        validation_path=path
    )
    return status_kwargs


def validate_cms_signature(signed_data: cms.SignedData,
                           status_cls: Type[StatusType] = SignatureStatus,
                           raw_digest: bytes = None,
                           validation_context: ValidationContext = None,
                           status_kwargs: dict = None,
                           externally_invalid=False):
    status_kwargs = _validate_cms_signature(
        signed_data, status_cls, raw_digest, validation_context,
        status_kwargs, externally_invalid
    )
    return status_cls(**status_kwargs)


@unique
class SignatureCoverageLevel(OrderedEnum):
    """
    Indicate the extent to which a PDF signature (cryptographically) covers
    a document. Note that this does _not_ pass judgment on whether uncovered
    updates are legitimate or not, but as a general rule, a legitimate signature
    will satisfy at least ENTIRE_REVISION.
    """

    UNCLEAR = 0
    """
    The signature's coverage is unclear and/or disconnected.
    In standard PDF signatures, this is usually a bad sign.
    """

    CONTIGUOUS_BLOCK_FROM_START = 1
    """
    The signature covers a contiguous block in the PDF file stretching from
    the first byte of the file to the last byte in the indicated /ByteRange.
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


@unique
class ModificationLevel(OrderedEnum):
    """
    Records the (semantic) modification level of a document.
    """

    NONE = 0
    """
    The document was not modified at all.
    """

    LTA_UPDATES = 1
    """
    The only updates are signature long term archival (LTA) updates.
    That is to say, updates to the document security store or new document
    time stamps. For the purposes of evaluating whether a document has been
    modified in the sense defined in the PAdES and ISO 32000-2 standards,
    these updates do not count.
    Adding form fields is permissible at this level, but only if they are 
    signature fields. This is necessary for proper document timestamp support.
    """

    FORM_FILLING = 2
    """
    The only updates are extra signatures and updates to form field values or
    their appearance streams, in addition to the previous levels.
    """

    ANNOTATIONS = 3
    """
    In addition to the previous levels, manipulating annotations is also allowed 
    at this level.
    
    (NOTE: this level is currently unused, and modifications to annotations
    other than those permitted to fill in forms are treated as suspicious)
    """

    OTHER = 4
    """
    The document has been modified in ways that aren't on the validator's
    whitelist. This always invalidates the corresponding signature, irrespective
    of cryptographical integrity or /DocMDP settings.
    """


@dataclass(frozen=True)
class PdfSignatureStatus(SignatureStatus):
    coverage: SignatureCoverageLevel
    modification_level: ModificationLevel
    seed_value_ok: bool
    docmdp_ok: bool
    signed_dt: Optional[datetime] = None
    timestamp_validity: Optional[TimestampSignatureStatus] = None

    @property
    def bottom_line(self) -> bool:
        ts = self.timestamp_validity
        if ts is None:
            timestamp_ok = True
        else:
            timestamp_ok = ts.valid and ts.trusted
        return (
            self.valid and self.trusted and self.seed_value_ok
            and self.docmdp_ok and timestamp_ok
        )

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


MECHANISMS = (
    'rsassa_pkcs1v15', 'sha1_rsa', 'sha256_rsa', 'sha384_rsa', 'sha512_rsa'
)


def _extract_reference_dict(signature_obj, method) \
        -> Optional[generic.DictionaryObject]:
    # all queries are raw because we don't want to trigger object resolution
    #  (this has to work for historic queries as well, and signature_obj
    #   shouldn't contain any indirect refs anyway)
    try:
        sig_refs = signature_obj.raw_get('/Reference')
    except KeyError:
        return
    for ref in sig_refs:
        if ref.raw_get('/TransformMethod') == method:
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


class SuspiciousModification(ValueError):
    pass


class EmbeddedPdfSignature:

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
                pkcs7_content, transparent_decrypt=False
            )
        self.pkcs7_content = pkcs7_content

        message = cms.ContentInfo.load(pkcs7_content)
        signed_data = message['content']
        self.signed_data: cms.SignedData = signed_data
        sd_digest = signed_data['digest_algorithms'][0]
        # FIXME I don't think this is always the correct choice.
        #  It's the MD algorithm used within the CMS object to compute the
        #  hash of all signed attributes, but the document hash may have
        #  been computed using a different algorithm!
        self.md_algorithm = sd_digest['algorithm'].native.lower()

        try:
            self.signer_info, = self.signed_data['signer_infos']
        except ValueError:
            raise ValueError('signer_infos should contain exactly one entry')

        # grab the revision to which the signature applies
        self.signed_revision = self.reader.xrefs.get_introducing_revision(
            sig_object_ref.reference
        )
        self.coverage = None
        self.modification_level = None
        self.raw_digest = None
        self.total_len = None
        self._docmdp = self._fieldmdp = None
        self._docmdp_queried = self._fieldmdp_queried = False
        self.tst_signature_digest = None

    @property
    def field_name(self):
        return self.sig_field['/T']

    @property
    def self_reported_signed_timestamp(self) -> datetime:
        try:
            sa = self.signer_info['signed_attrs']
            st = find_cms_attribute(sa, 'signed_time')[0]
            return st.native
        except KeyError:
            pass

    @property
    def external_timestamp_data(self) -> cms.SignedData:
        try:
            ua = self.signer_info['unsigned_attrs']
            tst = find_cms_attribute(ua, 'signature_time_stamp_token')[0]
            tst_signed_data = tst['content']
            return tst_signed_data
        except KeyError:
            pass

    def compute_integrity_info(self, skip_diff=False):
        self.compute_digest()

        # TODO in scenarios where we have to verify multiple signatures, we're
        #  doing a lot of double work here. This could be improved.
        self.coverage = self.evaluate_signature_coverage()
        if not skip_diff:
            self.modification_level = self.evaluate_modifications()

    def summarise_integrity_info(self):

        self.compute_integrity_info()

        mod_level = self.modification_level
        docmdp = self.docmdp_level
        docmdp_ok = not (
            mod_level == ModificationLevel.OTHER
            or (docmdp is not None and mod_level.value > docmdp.value)
        )
        status_kwargs = {
            'coverage': self.coverage,
            'modification_level': mod_level,
            'docmdp_ok': docmdp_ok
        }
        return status_kwargs

    @property
    def docmdp_level(self) -> Optional[MDPPerm]:
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

    def compute_digest(self):
        if self.raw_digest is not None:
            return

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
        self.raw_digest = md.digest()

        # for timestamp validation: compute the digest of the signature
        #  (as embedded in the CMS object)
        tst_data = self.external_timestamp_data
        if tst_data is None:
            return

        signature_bytes = self.signer_info['signature'].native
        md = getattr(hashlib, self.md_algorithm)(signature_bytes)
        self.tst_signature_digest = md.digest()

    def evaluate_signature_coverage(self):

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

    def evaluate_modifications(self) -> ModificationLevel:
        if self.coverage < SignatureCoverageLevel.ENTIRE_REVISION:
            return ModificationLevel.OTHER
        elif self.coverage == SignatureCoverageLevel.ENTIRE_FILE:
            return ModificationLevel.NONE

        signed_rev = self.signed_revision
        rev_count = self.reader.xrefs.xref_sections
        current_max = ModificationLevel.LTA_UPDATES
        for revision in range(signed_rev + 1, rev_count):
            try:
                ml = self._mod_level_for_revision(revision)
            except SuspiciousModification as e:
                logger.warning(e)
                return ModificationLevel.OTHER
            current_max = max(current_max, ml)
        return current_max

    def _mod_level_for_revision(self, revision) -> ModificationLevel:
        # refs in this set are cleared at level LTA_UPDATES
        explained_refs_lta = set()
        # refs in this set are cleared at level FORM_FILLING
        explained_refs_formfill = set()
        signed_revision = self.signed_revision
        signed_root = self.reader.get_historical_root(signed_revision)
        current_root = self.reader.get_historical_root(revision)

        signed_resolver = self.reader.get_historical_resolver(signed_revision)
        current_resolver = self.reader.get_historical_resolver(revision)

        whitelist_lta_if_fresh = _whitelist_callback(
            explained_refs_lta, signed_revision, self.reader.xrefs
        )

        # whitelist the xref stream, if there is one
        xref_start, _ = self.reader.xrefs.get_xref_container_info(revision)
        if isinstance(xref_start, generic.Reference):
            whitelist_lta_if_fresh(xref_start)

        # updates to /Info are always OK (and must be through indirect objects)
        # if the /Info dict is direct, we ignore the resulting error
        # Removing the /Info dictionary is also no big deal, since most readers
        # will fall back to older revisions regardless
        try:
            current_info = self.reader.trailer.raw_get(
                '/Info', revision=revision
            )
            current_info = current_info.reference
            try:
                signed_info = self.reader.trailer.raw_get(
                    '/Info', revision=signed_revision
                )
                signed_info = signed_info.reference
            except KeyError:
                signed_info = None

            if current_info == signed_info:
                explained_refs_lta.add(current_info)
            else:
                whitelist_lta_if_fresh(current_info)
        except (KeyError, AttributeError):
            pass

        # we're about to vet changes to the root, so this object ID
        #  will be whitelisted when we go over object updates later.
        current_root_ref = current_root.get_container_ref()
        if current_root_ref != signed_root.get_container_ref():
            # The document catalog has a different ID now. Weird, but OK.
            # Do check that it doesn't clobber an existing object, though.
            whitelist_lta_if_fresh(current_root_ref)
        else:
            explained_refs_lta.add(current_root_ref)

        # first, check if the keys in the document catalog are unchanged
        _compare_dicts(
            signed_root, current_root, 
            {'/AcroForm', '/DSS', '/Extensions', '/Metadata', '/MarkInfo'}
        )

        # Now we compare the /AcroForm entries
        signed_acroform, current_acroform = _compare_key_refs(
            '/AcroForm', signed_root, current_root,
            signed_resolver, current_resolver, explained_refs_lta
        )

        # first, compare the entries that aren't /Fields
        _compare_dicts(signed_acroform, current_acroform, {'/Fields'})

        # next, walk the field tree, and collect newly added signature fields
        signed_fields = signed_acroform.raw_get('/Fields')
        current_fields = current_acroform.raw_get('/Fields')
        if isinstance(current_fields, generic.IndirectObject):
            explained_refs_lta.add(current_fields.reference)
            current_fields = current_resolver(current_fields.reference)
        if isinstance(signed_fields, generic.IndirectObject):
            signed_fields = signed_resolver(signed_fields.reference)

        new_sigfield_refs = set(_diff_field_tree(
            signed_fields, current_fields,
            signed_resolver, current_resolver, explained_refs_lta,
            explained_refs_formfill, field_mdp_spec=self.fieldmdp
        ))

        # As for the keys in the root dictionary that are allowed to change:
        #  - /Extensions requires no further processing since it must consist
        #    of direct objects anyway.
        #  - /MarkInfo: if it's an indirect reference (probably not) we can
        #    whitelist it if the key set makes sense. TODO do this
        #  - /Metadata: is a stream ---> don't allow overrides, only new refs
        try:
            explained_refs_lta.add(
                signed_root.raw_get('/Metadata').reference
            )
        except (KeyError, AttributeError):
            pass

        # for the DSS, we only have to be careful not to allow non-DSS
        # objects to be overridden.
        if '/DSS' in signed_root:
            if '/DSS' not in current_root:
                raise SuspiciousModification('DSS was deleted')

        if '/DSS' in current_root:
            _manage_dss_change(
                signed_root, current_root,
                signed_resolver, current_resolver, explained_refs_lta
            )

        # Next, check annotations: newly added signature fields may be added
        #  to the /Annots entry of any page. These are processed as LTA updates,
        #  because even invisible signature fields / timestamps are sometimes
        #  added to /Annots, unnecessary as that may be.
        # Note: we don't descend into the annotation dictionaries themselves.
        #  For modifications to form field values, this has been taken care of
        #  already.
        # TODO allow other annotation modifications, but at level ANNOTATIONS
        if new_sigfield_refs:
            # if no new sigfields were added, we skip this step.
            #  Any modifications to /Annots will be flagged by the xref
            #  crawler later.

            # note: this is guaranteed to be equal to its signed counterpart,
            # since we already checked the document catalog for unauthorised
            # modifications
            current_page_root = current_root.raw_get('/Pages').reference
            _walk_page_tree_annots(
                current_page_root, new_sigfield_refs, signed_resolver,
                current_resolver, explained_refs_lta
            )

        # finally, verify that there are no xrefs in the revision's xref table
        # other than the ones we can justify.
        new_xrefs = self.reader.xrefs.explicit_refs_in_revision(revision)

        # object streams are OK, but overriding object streams is not.
        for objstm_ref in self.reader.xrefs.object_streams_used_in(revision):
            whitelist_lta_if_fresh(objstm_ref)

        unexplained_lta = new_xrefs - explained_refs_lta
        unexplained_formfill = unexplained_lta - explained_refs_formfill
        if unexplained_formfill:
            msg = LazyJoin(
                '\n', (
                    '%s:%s...' % (
                        repr(x), repr(current_resolver(x))[:300]
                    ) for x in unexplained_formfill
                )
            )
            logger.debug(
                "Unexplained xrefs in revision %d:\n%s",
                revision, msg
            )
            raise SuspiciousModification(
                f"There are unexplained xrefs in revision {revision}: "
                f"{', '.join(repr(x) for x in unexplained_formfill)}."
            )
        elif unexplained_lta:
            return ModificationLevel.FORM_FILLING
        else:
            return ModificationLevel.LTA_UPDATES


def _walk_page_tree_annots(page_root_ref, new_sigfield_refs, signed_resolver,
                           current_resolver, explained_refs):
    signed_pages_obj = signed_resolver(page_root_ref)
    current_pages_obj = current_resolver(page_root_ref)
    signed_kids = signed_pages_obj.raw_get('/Kids')
    if isinstance(signed_kids, generic.IndirectObject):
        signed_kids = signed_resolver(signed_kids.reference)
    current_kids = current_pages_obj.raw_get('/Kids')
    if isinstance(current_kids, generic.IndirectObject):
        current_kids = current_resolver(current_kids.reference)
    # /Kids should only contain indirect refs, so direct comparison is
    # appropriate.
    if current_kids != signed_kids:
        raise SuspiciousModification(
            "Unexpected change to page tree structure."
        )
    for kid_ref in signed_kids:
        kid_ref = kid_ref.reference
        signed_kid = signed_resolver(kid_ref)
        node_type = signed_kid['/Type']
        if node_type == '/Pages':
            _walk_page_tree_annots(
                kid_ref, new_sigfield_refs, signed_resolver, current_resolver,
                explained_refs
            )
        elif node_type == '/Page':
            current_kid = current_resolver(kid_ref)
            current_annots_ref = None
            try:
                current_annots = current_kid.raw_get('/Annots')
                if isinstance(current_annots, generic.IndirectObject):
                    current_annots_ref = current_annots.reference
                    current_annots = current_resolver(current_annots_ref)
                current_annots = set(c.reference for c in current_annots)
            except KeyError:
                # no annotations, continue
                continue
            try:
                signed_annots = signed_kid.raw_get('/Annots')
                signed_annots_ref = None
                if isinstance(signed_annots, generic.IndirectObject):
                    signed_annots_ref = signed_annots.reference
                    signed_annots = signed_resolver(signed_annots.reference)
                signed_annots = set(c.reference for c in signed_annots)
            except KeyError:
                signed_annots_ref = None
                signed_annots = set()

            # check if annotations were added
            if not (signed_annots <= current_annots):
                continue
            annots_diff = current_annots - signed_annots
            if not annots_diff or not (annots_diff <= new_sigfield_refs):
                continue
            # there are new annotations, and they're all for new
            # signature fields. => cleared to edit
            # Make sure the page dictionaries are the same, so that we
            #  can safely clear them for modification
            #  (not necessary if both /Annots entries are indirect references,
            #   but adding even more cases is pushing things)
            _compare_dicts(signed_kid, current_kid, {'/Annots'})
            explained_refs.add(kid_ref)
            if current_annots_ref:
                # current /Annots entry is an indirect reference
                if signed_annots_ref == current_annots_ref:
                    explained_refs.add(current_annots_ref)
                else:
                    # either the /Annots array got reassigned to another
                    # object ID, or it was moved from a direct object to an
                    # indirect one. This is fine, provided that the new  object
                    # ID doesn't clobber an existing one.
                    whitelist_if_fresh = _whitelist_callback(
                        explained_refs, signed_resolver.revision,
                        signed_resolver.reader.xrefs
                    )
                    whitelist_if_fresh(current_annots_ref)


VRI_KEY_PATTERN = re.compile('/[A-Z0-9]{40}')


def _manage_dss_change(signed_root, current_root, signed_resolver,
                       current_resolver, explained_refs):
    wl_if_fresh = _whitelist_callback(
        explained_refs, signed_resolver.revision, signed_resolver.reader.xrefs
    )
    signed_dss, current_dss = _compare_key_refs(
        '/DSS', signed_root, current_root, signed_resolver, current_resolver,
        explained_refs
    )

    # check that there are no strange keys
    dss_der_stream_keys = {'/Certs', '/CRLs', '/OCSPs'}
    dss_expected_keys = {'/Type', '/VRI'} | dss_der_stream_keys
    dss_keys = set(current_dss.keys())
    if not (dss_keys <= dss_expected_keys):
        raise SuspiciousModification(
            f"Unexpected keys in DSS: {dss_keys - dss_expected_keys}."
        )

    for der_obj_type in dss_der_stream_keys:
        try:
            value = current_dss.raw_get(der_obj_type)
        except KeyError:
            continue
        new_deps = current_resolver.collect_dependencies(
            value, since_revision=signed_resolver.revision + 1
        )
        explained_refs.update(new_deps)

    # check that the /VRI dictionary still contains all old keys, unchanged.
    signed_vri, current_vri = _compare_key_refs(
        '/VRI', signed_dss, current_dss, signed_resolver, current_resolver,
        explained_refs
    )
    current_vri_hashes = set(current_vri.keys())

    for key, signed_vri_value in signed_vri.items():
        if not VRI_KEY_PATTERN.match(key):
            raise SuspiciousModification(
                f"VRI key {key} is not formatted correctly."
            )

        try:
            current_vri_dict = current_vri.raw_get(key)
        except KeyError:
            current_vri_dict = None

        if current_vri_dict != signed_vri_value:
            # indirect or direct doesn't matter, they have to be the same
            raise SuspiciousModification(
                f"VRI key {key} was modified or deleted."
            )

    # check the newly added entries
    vri_der_stream_keys = {'/Cert', '/CRL', '/OCSP'}
    vri_expected_keys = {'/Type', '/TU', '/TS'} | vri_der_stream_keys
    for key in current_vri_hashes - signed_vri.keys():
        if not VRI_KEY_PATTERN.match(key):
            raise SuspiciousModification(
                f"VRI key {key} is not formatted correctly."
            )

        current_vri_dict = current_vri.raw_get(key)
        if isinstance(current_vri_dict, generic.IndirectObject):
            wl_if_fresh(current_vri_dict.reference)
            current_vri_dict = current_resolver(current_vri_dict.reference)
        _assert_not_stream(current_vri_dict)

        current_vri_value_keys = current_vri_dict.keys()
        if not (current_vri_value_keys <= vri_expected_keys):
            raise SuspiciousModification(
                "Unexpected keys in VRI dictionary: "
                f"{current_vri_value_keys - vri_expected_keys}."
            )
        for der_obj_type in vri_der_stream_keys:
            try:
                value = current_vri_dict.raw_get(der_obj_type)
            except KeyError:
                continue
            new_deps = current_resolver.collect_dependencies(
                value, since_revision=signed_resolver.revision + 1
            )
            explained_refs.update(new_deps)
        # /TS is also a DER stream
        try:
            wl_if_fresh(current_vri.raw_get('/TS').reference)
        except (KeyError, AttributeError):
            pass


# TODO confirm the rules on name uniqueness
#  (in particular for things like choice fields, where there are potentially
#   multiple widgets)
def _split_sig_fields(resolver, field_list):
    sig_fields = {}
    other_fields = {}
    for field_ref in field_list:
        assert isinstance(field_ref, generic.IndirectObject)
        # look up the field type by moving up the hierarchy
        _field = field = resolver(field_ref)
        name = field.raw_get('/T')
        while True:
            try:
                ft = _field.raw_get('/FT')
                break
            except KeyError:
                try:
                    parent_ref = _field.raw_get('/Parent')
                except KeyError:  # pragma: nocover
                    raise misc.PdfReadError(
                        f"Could not resolve /FT attribute for field {name}."
                    )
                _field = resolver(parent_ref)
        if ft == '/Sig':
            sig_fields[name] = field_ref.reference
        else:
            other_fields[name] = field_ref.reference
    return sig_fields, other_fields


def _diff_field_tree(signed_fields, current_fields,
                     signed_resolver, current_resolver,
                     explained_refs_lta, explained_refs_formfill,
                     field_mdp_spec: Optional[FieldMDPSpec], parent_name=""):
    if not isinstance(signed_fields, generic.ArrayObject):
        raise SuspiciousModification("Field list is not an array.")
    if not isinstance(current_fields, generic.ArrayObject):
        raise SuspiciousModification("Field list is not an array.")
    # set signature fields aside for separate processing
    signed_fields_sigfields, signed_fields_other = \
        _split_sig_fields(signed_resolver, signed_fields)
    current_fields_sigfields, current_fields_other = \
        _split_sig_fields(current_resolver, current_fields)

    # the "other" fields should be matched one-to-one
    nonsig_field_names = set(signed_fields_other.keys())
    if nonsig_field_names != set(current_fields_other.keys()):
        raise SuspiciousModification(
            "Unexpected change in form hierarchy at %s." % {
                "form tree root" if not parent_name else
                f"node {repr(parent_name)}"
            }
        )
    for name in nonsig_field_names:
        fq_name = parent_name + "." + name if parent_name else name
        locked = (
            field_mdp_spec is not None and field_mdp_spec.is_locked(fq_name)
        )
        signed_field, current_field = _diff_field(
            signed_fields_other[name], current_fields_other[name],
            signed_resolver, current_resolver, explained_refs_formfill,
            fq_name=fq_name, locked=locked
        )

        # even a locked field might still have unlocked descendant fields
        try:
            # we know from the diff check that it doesn't matter
            # whether we look up this reference value on the signed field
            # or the current version
            kids_ref = signed_field.raw_get('/Kids')
            try:
                # if there is a /Type entry, it better be /Fields
                node_type = signed_field.raw_get('/Type')
                if node_type != '/Fields':
                    raise SuspiciousModification(
                        f"Node at {fq_name} may not be a field tree node!"
                    )
            except KeyError:
                pass

            if isinstance(kids_ref, generic.IndirectObject):
                # register at LTA_UPDATES level, it's hypothetically still
                #  possible that this field is a container for document
                #  timestamps or somesuch.
                explained_refs_lta.add(kids_ref.reference)
                signed_kids = signed_resolver(kids_ref)
                current_kids = current_resolver(kids_ref)
            else:
                # in this case, the diff rule again guarantees that these
                # two arrays contain the same values.
                signed_kids = current_kids = kids_ref
            # recurse!
            yield from _diff_field_tree(
                signed_kids, current_kids, signed_resolver,
                current_resolver, explained_refs_lta, explained_refs_formfill,
                field_mdp_spec=field_mdp_spec, parent_name=fq_name
            )
        except KeyError:
            pass

    # updates can only add sigfields, not remove them
    old_sigfield_set = set(signed_fields_sigfields.keys())
    if not (old_sigfield_set <= set(current_fields_sigfields.keys())):
        raise SuspiciousModification("Some signature fields were removed.")

    wl_if_fresh_formfill = _whitelist_callback(
        explained_refs_formfill, signed_resolver.revision,
        signed_resolver.reader.xrefs
    )
    wl_if_fresh_lta = _whitelist_callback(
        explained_refs_lta, signed_resolver.revision,
        signed_resolver.reader.xrefs
    )

    for name, sigfield_ref in current_fields_sigfields.items():
        fq_name = parent_name + "." + name if parent_name else name
        # The treatment of the value depends on whether it's a document
        #  time stamp or a signature: document timestamps are allowed at
        #  all DocMDP levels, while "normal" signatures are more strictly
        #  regulated.
        # To compensate, we can make some simplifications w.r.t. the case
        #  of a general field: the value of a signature field must be an
        #  indirect object, and signature dictionaries can only contain
        #  direct objects as per ISO 32000 => no deep-fetching necessary.
        # BUT: Acrobat doesn't respect this rule, so the signature reference
        # array does need some extra care.
        current_field = current_resolver(sigfield_ref)

        if field_mdp_spec is not None and field_mdp_spec.is_locked(fq_name):
            continue

        try:
            current_value_ref = current_field.raw_get('/V').reference
        except KeyError:
            current_value_ref = None

        if name not in old_sigfield_set:
            # new sigfield added, signal to caller
            yield sigfield_ref

            # new field, so all it's dependencies are good to go
            # that said, only the field itself is cleared at LTA update level,
            # the other deps bump the modification level up to FORM_FILL
            # TODO am I being too strict here?
            wl_if_fresh_lta(sigfield_ref)

            def _deps():
                for _key in ('/AP', '/Lock', '/SV'):
                    try:
                        raw_value = current_field.raw_get(_key)
                        yield from current_resolver.collect_dependencies(
                            raw_value,
                            since_revision=signed_resolver.revision + 1
                        )
                    except KeyError:
                        pass
            explained_refs_formfill.update(_deps())

            # the field we just scanned is empty, so move on
            if current_value_ref is None:
                continue
        else:
            old_sigfield_ref = signed_fields_sigfields[name]
            if old_sigfield_ref != sigfield_ref:
                raise SuspiciousModification(
                    "Object ID of signature field changed between revisions."
                )
            signed_field = signed_resolver(sigfield_ref)

            was_signed = '/V' in current_field and '/V' not in signed_field

            if was_signed:
                # here, we check that the form field didn't change
                # beyond the keys that we expect to change when updating
                # a signature field.
                _compare_dicts(signed_field, current_field, VALUE_UPDATE_KEYS)
                # the signature object itself will be evaluated later
                explained_refs_lta.add(sigfield_ref)
                # whitelist appearance updates at FORM_FILL level
                _allow_appearance_update(
                    signed_field, current_field, signed_resolver,
                    current_resolver, explained_refs_formfill
                )
            else:
                # case where the field was already signed, or is still
                # not signed in the current revision.
                # in this case, the state of the field better didn't change
                # at all!
                # ... but Acrobat apparently sometimes sets /Ff rather
                #  liberally, so let's allow that one to change
                _compare_dicts(
                    signed_field, current_field, FORMFIELD_ALWAYS_MODIFIABLE
                )
                explained_refs_lta.add(sigfield_ref)
                # Skip the comparison logic on /V. In particular, if
                # the signature object in question was overridden,
                # it should trigger a suspicious modification later.
                continue

        # We're now in the case where the form field did not exist or did not
        # have a value in the signed revision, but does have one in the revision
        # we're auditing. If the signature is /DocTimeStamp, this is a
        # modification at level LTA_UPDATES. If it's a normal signature, it
        # requires FORM_FILLING.
        sig_obj = current_resolver(current_value_ref)
        x1, y1, x2, y2 = current_field['/Rect']
        area = abs(x1 - x2) * abs(y1 - y2)
        # /DocTimeStamps added for LTA validation purposes shouldn't have
        # an appearance (as per the recommendation in ISO 32000-2, which we
        # enforce as a rigid rule here)
        if sig_obj.raw_get('/Type') == '/DocTimeStamp' and not area:
            sig_whitelist = wl_if_fresh_lta
        else:
            sig_whitelist = wl_if_fresh_formfill

        # first, whitelist the actual signature object
        sig_whitelist(current_value_ref)
        # since apparently Acrobat didn't get the memo about not having
        # indirect references in signature objects, we have to do some tweaking
        # to whitelist /TransformParams if necessary
        current_value = current_resolver(current_value_ref)
        try:
            # the issue is with signature reference dictionaries
            for sigref_dict in current_value.raw_get('/Reference'):
                try:
                    sig_whitelist(
                        sigref_dict.raw_get('/TransformParams').reference
                    )
                except (KeyError, AttributeError):
                    continue
        except KeyError:
            pass


def _allow_appearance_update(signed_field, current_field, signed_resolver,
                             current_resolver, explained_refs):
    try:
        signed_ap_val = signed_field.raw_get('/AP')
    except KeyError:
        signed_ap_val = None

    try:
        current_ap_val = current_field.raw_get('/AP')
    except KeyError:
        current_ap_val = None

    # if the appearance dictionaries are the same
    common_ap_ref = None
    if current_ap_val == signed_ap_val:
        if isinstance(current_ap_val, generic.IndirectObject):
            common_ap_ref = current_ap_val.reference
            current_ap_val = current_resolver(common_ap_ref)
        else:
            # note: this is triggered when both are none, but also when both
            # are direct objects and equal. This is intentional:
            # we *never* want to whitelist an update for an existing
            # stream object (too much potential for abuse), so we insist on
            # modifying the /N, /R, /D keys to point to new streams
            # TODO this could be worked around with a reference counter for
            #  streams, in which case we could allow the stream to be overridden
            #  on the condition that it isn't used anywhere else.
            return

    _assert_not_stream(common_ap_ref)

    if common_ap_ref is not None:
        explained_refs.add(common_ap_ref)

    for key in ('/N', '/R', '/D'):
        try:
            appearance_spec = current_ap_val.raw_get(key)
        except KeyError:
            continue
        appearance_deps = current_resolver.collect_dependencies(
            appearance_spec, since_revision=signed_resolver.revision + 1
        )
        explained_refs.update(appearance_deps)


def _assert_not_stream(dict_obj):
    if isinstance(dict_obj, generic.StreamObject):
        raise SuspiciousModification(
            f"Unexpected stream encountered at f{dict_obj.container_ref}!"
        )


FORMFIELD_ALWAYS_MODIFIABLE = {'/Ff'}
VALUE_UPDATE_KEYS = FORMFIELD_ALWAYS_MODIFIABLE | {'/AP', '/AS', '/V'}


def _diff_field(signed_ref, current_ref, signed_resolver,
                current_resolver, explained_refs, fq_name, locked=False):
    # the indirect references should be the same
    if current_ref != signed_ref:
        raise SuspiciousModification(
            f"Unexpected modification to form field structure: "
            f"object ID of field {fq_name} changed from {repr(signed_ref)}"
            f"to {repr(current_ref)}."
        )
    signed_field = signed_resolver(signed_ref)
    current_field = current_resolver(current_ref)
    _assert_not_stream(signed_field)
    _assert_not_stream(current_field)
    explained_refs.add(current_ref)

    # TODO it's perhaps more prudent to only allow appearance streams
    #  to change if the value was provided in this exact revision, but
    #  that's a bit more involved to verify.
    # TODO double check the standard for other appearance-manipulating keys
    if not locked:
        _compare_dicts(signed_field, current_field, VALUE_UPDATE_KEYS)
        _allow_appearance_update(
            signed_field, current_field, signed_resolver,
            current_resolver, explained_refs
        )
        try:
            current_value = current_field.raw_get('/V')
        except KeyError:
            return signed_field, current_field
        try:
            signed_value = signed_field.raw_get('/V')
        except KeyError:
            signed_value = None

        # if the value was changed, pull in newly defined objects.
        # TODO is this sufficient?
        if current_value != signed_value:
            new_refs = current_resolver.collect_dependencies(
                current_value, since_revision=signed_resolver.revision + 1
            )
            explained_refs.update(new_refs)
    else:
        _compare_dicts(
            signed_field, current_field, FORMFIELD_ALWAYS_MODIFIABLE
        )

    return signed_field, current_field


def _compare_dicts(signed_dict, current_dict, ignored: Set[str] = frozenset()):
    _assert_not_stream(signed_dict)
    _assert_not_stream(current_dict)
    current_dict_keys = set(current_dict.keys()) - ignored
    signed_dict_keys = set(signed_dict.keys()) - ignored
    if current_dict_keys != signed_dict_keys:
        raise SuspiciousModification(
            f"Dict keys differ: {current_dict_keys} vs. "
            f"{signed_dict_keys}."
        )

    for k in current_dict_keys:
        if current_dict.raw_get(k) != signed_dict.raw_get(k):
            raise SuspiciousModification(f"Values for dict key {k} differ.")


def _compare_key_refs(key, signed_dict, current_dict,
                      signed_resolver, current_resolver, explained_refs):
    """
    Note: this routine is only safe to use if the structure of the resulting
    values is also checked. Otherwise, it can lead to reference leaks if
    one is not careful.
    """

    try:
        signed_value_ref = signed_dict.raw_get(key)
    except KeyError:
        signed_value_ref = generic.DictionaryObject()
    current_value_ref = current_dict.raw_get(key)

    whitelist_if_fresh = _whitelist_callback(
        explained_refs, signed_resolver.revision, signed_resolver.reader.xrefs
    )
    # normalize IndirectObjects to References
    if isinstance(signed_value_ref, generic.IndirectObject):
        signed_value_ref = signed_value_ref.reference
        signed_value = signed_resolver(signed_value_ref)
    else:
        signed_value = signed_value_ref

    if isinstance(current_value_ref, generic.IndirectObject):
        current_value_ref = current_value_ref.reference
        if current_value_ref != signed_value_ref:
            # These two not agreeing is perhaps a bit weird, but not prima facie
            # illegal => apply standard whitelisting logic
            whitelist_if_fresh(current_value_ref)
        else:
            # whitelist the reference unconditionally
            explained_refs.add(current_value_ref)
        current_value = current_resolver(current_value_ref)
    else:
        current_value = current_value_ref

    _assert_not_stream(signed_value)
    _assert_not_stream(current_value)
    return signed_value, current_value


# closure for whitelisting objects in validation logic
def _whitelist_callback(explained_refs, signed_revision, xref_cache):
    def _wl(ref):
        assert isinstance(ref, generic.Reference), ref
        # Whitelist a reference *if* the new object reference doesn't
        # override an object that existed in the signed revision
        try:
            xref_cache.get_historical_ref(ref, signed_revision)
            # no error -> suspicious -> do not whitelist
            return
        except misc.PdfReadError:
            explained_refs.add(ref)
    return _wl


def _validate_sv_constraints(sig_field, emb_sig: EmbeddedPdfSignature,
                             signing_cert, validation_path, timestamp_found):
    from pdfstamp.sign.fields import (
        SigSeedValueSpec, SigSeedValFlags, SigSeedSubFilter
    )
    sig_field = sig_field.get_object()
    try:
        sig_sv_dict = sig_field['/SV']
    except KeyError:
        return
    sv_spec = SigSeedValueSpec.from_pdf_object(sig_sv_dict)

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

    flags = sv_spec.flags
    if not flags:
        return

    sig_obj = sig_field['/V']

    if flags & SigSeedValFlags.UNSUPPORTED:
        raise NotImplementedError(
            "Unsupported mandatory seed value items: " + repr(
                flags & SigSeedValFlags.UNSUPPORTED
            )
        )

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


def validate_pdf_signature(reader: PdfFileReader, sig_field,
                           signer_validation_context: ValidationContext = None,
                           ts_validation_context: ValidationContext = None) \
                           -> PdfSignatureStatus:
    try:
        sig_object = sig_field.get_object()['/V']
    except KeyError:
        raise SignatureValidationError('Signature is empty')

    # check whether the subfilter type is one we support
    subfilter_str = sig_object['/SubFilter']
    try:
        from pdfstamp.sign.fields import SigSeedSubFilter
        SigSeedSubFilter(subfilter_str)
    except ValueError:
        raise NotImplementedError(
            "%s is not a recognized SubFilter type." % subfilter_str
        )

    if ts_validation_context is None:
        ts_validation_context = signer_validation_context

    embedded_sig = EmbeddedPdfSignature(reader, sig_field)
    status_kwargs = embedded_sig.summarise_integrity_info()

    # try to find an embedded timestamp
    signed_dt = embedded_sig.self_reported_signed_timestamp
    if signed_dt is not None:
        status_kwargs['signed_dt'] = signed_dt

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
        status_kwargs=status_kwargs
    )
    timestamp_found = (
        tst_validity is not None
        and tst_validity.valid and tst_validity.trusted
    )
    try:
        _validate_sv_constraints(
            sig_field, embedded_sig, status_kwargs['signing_cert'],
            status_kwargs['validation_path'], timestamp_found
        )
        seed_value_ok = True
    except SigSeedValueValidationError as e:
        logger.warning(e)
        seed_value_ok = False
    return PdfSignatureStatus(seed_value_ok=seed_value_ok, **status_kwargs)


class RevocationInfoValidationType(Enum):
    ADOBE_STYLE = auto()
    PADES_LT = auto()
    PADES_LTA = auto()


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
                               force_revinfo=False):
    sig_field = embedded_sig.sig_field
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
            for cert in dss.load_certs():
                current_vc.certificate_registry.add_other_cert(cert)

    embedded_sig.compute_digest()

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
        raise ValueError('LTV signatures require a trusted timestamp.')

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

    status_kwargs = embedded_sig.summarise_integrity_info()
    status_kwargs.update({
        'signed_dt': timestamp,
        'timestamp_validity': timestamp_status
    })
    status_kwargs = _validate_cms_signature(
        embedded_sig.signed_data, status_cls=PdfSignatureStatus,
        raw_digest=embedded_sig.raw_digest,
        validation_context=stored_vc, status_kwargs=status_kwargs
    )

    try:
        _validate_sv_constraints(
            sig_field, embedded_sig, status_kwargs['signing_cert'],
            status_kwargs['validation_path'], timestamp_found=True
        )
        seed_value_ok = True
    except SigSeedValueValidationError as e:
        logger.warning(e)
        seed_value_ok = False
    return PdfSignatureStatus(seed_value_ok=seed_value_ok, **status_kwargs)


def retrieve_adobe_revocation_info(signer_info: cms.SignerInfo):
    try:
        revinfo: asn1_pdf.RevocationInfoArchival = find_cms_attribute(
            signer_info['signed_attrs'], "adobe_revocation_info_archival"
        )[0]
    except KeyError:
        raise ValueError("No revocation info found")

    ocsps = list(revinfo['ocsp'] or ())
    crls = list(revinfo['crl'] or ())
    return ocsps, crls


def apply_adobe_revocation_info(signer_info: cms.SignerInfo,
                                validation_context_kwargs=None) \
                               -> ValidationContext:
    validation_context_kwargs = validation_context_kwargs or {}
    ocsps, crls = retrieve_adobe_revocation_info(signer_info)
    return ValidationContext(
        ocsps=ocsps, crls=crls, **validation_context_kwargs
    )


DocMDPInfo = namedtuple('DocMDPInfo', ['permission_bits', 'author_sig'])


def read_certification_data(reader: PdfFileReader):
    try:
        certification_sig = reader.root['/Perms']['/DocMDP']
    except KeyError:
        return

    perm = _extract_docmdp_for_sig(certification_sig)

    return DocMDPInfo(perm, certification_sig)


# TODO validate DocMDP compliance and PAdES compliance
#  There are some compatibility subtleties here: e.g. valid (!) cryptographic
#  data covered by DSS and/or DocumentTimeStamps should never trigger the DocMDP
#  policy.


@dataclass
class VRI:
    certs: set = data_field(default_factory=set)
    ocsps: set = data_field(default_factory=set)
    crls: set = data_field(default_factory=set)

    def __iadd__(self, other):
        self.certs.update(other.certs)
        self.crls.update(other.crls)
        self.ocsps.update(other.ocsps)
        return self

    def as_pdf_object(self):
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
    def sig_content_identifier(contents):
        ident = hashlib.sha1(contents).digest().hex().upper()
        return pdf_name('/' + ident)

    def register_vri(self, identifier, paths, validation_context):
        """
        Register validation information for a set of signing certificates
        associated with a particular signature.
        Typically, signer_certs has only one entry (i.e. the main signer),
        but if timestamps are embedded into the signature, more entries may be
        included to account for timestamping authorities etc.

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

    def load_certs(self):
        for cert_ref in self.certs.values():
            cert_stream: generic.StreamObject = cert_ref.get_object()
            cert = Certificate.load(cert_stream.data)
            yield cert

    def as_validation_context(self, validation_context_kwargs,
                              include_revinfo=True):

        validation_context_kwargs = dict(validation_context_kwargs)
        extra_certs = validation_context_kwargs.pop('other_certs', [])
        certs = list(self.load_certs()) + extra_certs

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
        :return:
            A DocumentSecurityStore object describing the current state of the
            DSS.
        """
        try:
            dss_ref = handler.root.raw_get(pdf_name('/DSS'))
        except KeyError:
            raise ValueError("No DSS found")

        dss_dict = dss_ref.get_object()

        cert_refs = {}
        for cert_ref in dss_dict.get('/Certs', ()):
            cert_stream: generic.StreamObject = cert_ref.get_object()
            cert: Certificate = Certificate.load(cert_stream.data)
            cert_refs[cert.issuer_serial] = cert_ref

        ocsp_refs = list(dss_dict.get('/OCSPs', ()))
        ocsps = []
        for ocsp_ref in ocsp_refs:
            ocsp_stream: generic.StreamObject = ocsp_ref.get_object()
            resp = asn1_ocsp.OCSPResponse.load(ocsp_stream.data)
            ocsps.append(resp)

        crl_refs = list(dss_dict.get('/CRLs', ()))
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
        writer = IncrementalPdfFileWriter(output_stream)

        try:
            dss = cls.read_dss(writer)
            created = False
        except ValueError:
            # FIXME ValueError is way too general
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
