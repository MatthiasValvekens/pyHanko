import logging
import uuid
import tzlocal
from datetime import datetime
from dataclasses import dataclass, field
from io import BytesIO
from typing import Set, Optional, List

from asn1crypto import cms
from cryptography.hazmat.primitives import hashes

from pyhanko.sign.fields import (
    SigSeedSubFilter, MDPPerm, SigFieldSpec, FieldMDPSpec, SigSeedValueSpec,
    SeedLockDocument, SigSeedValFlags
)
from pyhanko_certvalidator import ValidationContext, CertificateValidator
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.errors import PathValidationError, PathBuildingError

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.stamp import BaseStampStyle

from pyhanko.sign.general import SigningError, get_pyca_cryptography_hash
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.sign.ades.api import CAdESSignedAttrSpec

from . import constants
from .pdf_cms import Signer
from .cms_embedder import (
    PdfCMSEmbedder, SigObjSetup, SigMDPSetup, SigIOSetup, SigAppearanceSetup,
)
from .pdf_byterange import (
    DocumentTimestamp, PreparedByteRangeDigest, SignatureObject
)

__all__ = [
    'PdfSignatureMetadata', 'PdfTimeStamper', 'PdfSigner',
    'PdfSigningSession', 'PdfTBSDocument', 'PdfPostSignatureDocument',
    'PreSignValidationStatus', 'PdfCMSSignedAttributes', 'PostSignInstructions'
]


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PdfSignatureMetadata:
    """
    Specification for a PDF signature.
    """

    field_name: str = None
    """
    The name of the form field to contain the signature.
    If there is only one available signature field, the name may be inferred.
    """

    md_algorithm: str = None
    """
    The name of the digest algorithm to use.
    It should be supported by `pyca/cryptography`.

    If ``None``, this will ordinarily default to the value of
    :const:`constants.DEFAULT_MD`, unless a seed value dictionary and/or a prior
    certification signature happen to be available.
    """

    location: str = None
    """
    Location of signing.
    """

    reason: str = None
    """
    Reason for signing (textual).
    """

    name: str = None
    """
    Name of the signer. This value is usually not necessary to set, since
    it should appear on the signer's certificate, but there are cases
    where it might be useful to specify it here (e.g. in situations where 
    signing is delegated to a trusted third party).
    """

    certify: bool = False
    """
    Sign with an author (certification) signature, as opposed to an approval
    signature. A document can contain at most one such signature, and it must
    be the first one.
    """
    # TODO Does this restriction also apply to prior document timestamps?

    subfilter: SigSeedSubFilter = None
    """
    Signature subfilter to use.

    This should be one of 
    :attr:`~.fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED` or
    :attr:`~.fields.SigSeedSubFilter.PADES`.
    If not specified, the value may be inferred from the signature field's
    seed value dictionary. Failing that,
    :attr:`~.fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED` is used as the
    default value.
    """

    embed_validation_info: bool = False
    """
    Flag indicating whether validation info (OCSP responses and/or CRLs)
    should be embedded or not. This is necessary to be able to validate
    signatures long after they have been made.
    This flag requires :attr:`validation_context` to be set.

    The precise manner in which the validation info is embedded depends on
    the (effective) value of :attr:`subfilter`:

    * With :attr:`~.fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED`, the
      validation information will be embedded inside the CMS object containing
      the signature.
    * With :attr:`~.fields.SigSeedSubFilter.PADES`, the validation information
      will be embedded into the document security store (DSS).
    """

    use_pades_lta: bool = False
    """
    If ``True``, the signer will append an additional document timestamp after
    writing the signature's validation information to the document security
    store (DSS).
    This flag is only meaningful if :attr:`subfilter` is 
    :attr:`~.fields.SigSeedSubFilter.PADES`.

    The PAdES B-LTA profile solves the long-term validation problem by
    adding a timestamp chain to the document after the regular signatures, which
    is updated with new timestamps at regular intervals.
    This provides an audit trail that ensures the long-term integrity of the 
    validation information in the DSS, since OCSP responses and CRLs also have 
    a finite lifetime.

    See also :meth:`.PdfTimeStamper.update_archival_timestamp_chain`.
    """

    timestamp_field_name: str = None
    """
    Name of the timestamp field created when :attr:`use_pades_lta` is ``True``.
    If not specified, a unique name will be generated using :mod:`uuid`.
    """

    validation_context: ValidationContext = None
    """
    The validation context to use when validating signatures.
    If provided, the signer's certificate and any timestamp certificates
    will be validated before signing.

    This parameter is mandatory when :attr:`embed_validation_info` is ``True``.
    """

    docmdp_permissions: MDPPerm = MDPPerm.FILL_FORMS
    """
    Indicates the document modification policy that will be in force after    
    this signature is created. Only relevant for certification signatures
    or signatures that apply locking.

    .. warning::
        For non-certification signatures, this is only explicitly allowed since 
        PDF 2.0 (ISO 32000-2), so older software may not respect this setting
        on approval signatures.
    """

    signer_key_usage: Set[str] = field(
        default_factory=lambda: constants.DEFAULT_SIGNER_KEY_USAGE
    )
    """
    Key usage extensions required for the signer's certificate.
    Defaults to ``non_repudiation`` only, but sometimes ``digital_signature``
    or a combination of both may be more appropriate.
    See :class:`x509.KeyUsage` for a complete list.

    Only relevant if a validation context is also provided.
    """

    cades_signed_attr_spec: Optional[CAdESSignedAttrSpec] = None
    """
    .. versionadded:: 0.5.0

    Specification for CAdES-specific attributes.
    """


def _finalise_output(orig_output, returned_output):
    # The internal API transparently replaces non-readable/seekable
    # buffers with BytesIO for signing operations, but we don't want to
    # expose that to the public API user.

    if orig_output is not None and orig_output is not returned_output:
        # original output is a write-only buffer
        assert isinstance(returned_output, BytesIO)
        raw_buf = returned_output.getbuffer()
        orig_output.write(raw_buf)
        raw_buf.release()
        return orig_output
    return returned_output


class PdfTimeStamper:
    """
    Class to encapsulate the process of appending document timestamps to
    PDF files.
    """

    def __init__(self, timestamper: TimeStamper,
                 field_name: Optional[str] = None):
        self.default_timestamper = timestamper
        self._field_name = field_name

    @property
    def field_name(self) -> str:
        """
        Retrieve or generate the field name for the signature field to contain
        the document timestamp.

        :return:
            The field name, as a (Python) string.
        """
        return self._field_name or ('Timestamp-' + str(uuid.uuid4()))

    # TODO I'm not entirely sure that allowing validation_paths to be cached
    #  is wise. In principle, the TSA could issue their next timestamp with a
    #  different certificate (e.g. due to load balancing), which would require
    #  validation regardless.

    def timestamp_pdf(self, pdf_out: IncrementalPdfFileWriter,
                      md_algorithm, validation_context=None,
                      bytes_reserved=None, validation_paths=None,
                      timestamper: Optional[TimeStamper] = None, *,
                      in_place=False, output=None,
                      chunk_size=misc.DEFAULT_CHUNK_SIZE):
        """Timestamp the contents of ``pdf_out``.
        Note that ``pdf_out`` should not be written to after this operation.

        :param pdf_out:
            An :class:`.IncrementalPdfFileWriter`.
        :param md_algorithm:
            The hash algorithm to use when computing message digests.
        :param validation_context:
            The :class:`.pyhanko_certvalidator.ValidationContext`
            against which the TSA response should be validated.
            This validation context will also be used to update the DSS.
        :param bytes_reserved:
            Bytes to reserve for the CMS object in the PDF file.
            If not specified, make an estimate based on a dummy signature.
        :param validation_paths:
            If the validation path(s) for the TSA's certificate are already
            known, you can pass them using this parameter to avoid having to
            run the validation logic again.
        :param timestamper:
            Override the default :class:`.TimeStamper` associated with this
            :class:`.PdfTimeStamper`.
        :param output:
            Write the output to the specified output stream.
            If ``None``, write to a new :class:`.BytesIO` object.
            Default is ``None``.
        :param in_place:
            Sign the original input stream in-place.
            This parameter overrides ``output``.
        :param chunk_size:
            Size of the internal buffer (in bytes) used to feed data to the
            message digest function if the input stream does not support
            ``memoryview``.
        :return:
            The output stream containing the signed output.
        """

        timestamper = timestamper or self.default_timestamper
        field_name = self.field_name
        if bytes_reserved is None:
            test_signature_cms = timestamper.dummy_response(md_algorithm)
            test_len = len(test_signature_cms.dump()) * 2
            # see sign_pdf comments
            bytes_reserved = test_len + 2 * (test_len // 4)

        timestamp_obj = DocumentTimestamp(bytes_reserved=bytes_reserved)

        cms_writer = PdfCMSEmbedder().write_cms(
            field_name=field_name, writer=pdf_out,
            # for LTA, requiring existing_fields_only doesn't make sense
            # since we should in principle be able to add document timestamps
            # ad infinitum.
            existing_fields_only=False
        )

        next(cms_writer)
        cms_writer.send(SigObjSetup(sig_placeholder=timestamp_obj))

        sig_io = SigIOSetup(
            md_algorithm=md_algorithm,
            in_place=in_place, output=output, chunk_size=chunk_size
        )
        prep_digest: PreparedByteRangeDigest = cms_writer.send(sig_io)
        timestamp_cms = timestamper.timestamp(
            prep_digest.document_digest, md_algorithm
        )
        res_output, sig_contents = prep_digest.fill_with_cms(timestamp_cms)

        # update the DSS
        if validation_context is not None:
            from pyhanko.sign import validation
            if validation_paths is None:
                validation_paths = list(
                    timestamper.validation_paths(validation_context)
                )

            validation.DocumentSecurityStore.add_dss(
                output_stream=res_output, sig_contents=sig_contents,
                paths=validation_paths, validation_context=validation_context
            )

        output = _finalise_output(output, res_output)

        return output

    def update_archival_timestamp_chain(
            self, reader: PdfFileReader, validation_context, in_place=True,
            output=None, chunk_size=misc.DEFAULT_CHUNK_SIZE,
            default_md_algorithm=constants.DEFAULT_MD):
        """
        Validate the last timestamp in the timestamp chain on a PDF file, and
        write an updated version to an output stream.

        :param reader:
            A :class:`PdfReader` encapsulating the input file.
        :param validation_context:
            :class:`.pyhanko_certvalidator.ValidationContext` object to validate
            the last timestamp.
        :param output:
            Write the output to the specified output stream.
            If ``None``, write to a new :class:`.BytesIO` object.
            Default is ``None``.
        :param in_place:
            Sign the original input stream in-place.
            This parameter overrides ``output``.
        :param chunk_size:
            Size of the internal buffer (in bytes) used to feed data to the
            message digest function if the input stream does not support
            ``memoryview``.
        :param default_md_algorithm:
            Message digest to use if there are no preceding timestamps in the
            file.
        :return:
            The output stream containing the signed output.
        """
        # In principle, we only have to validate that the last timestamp token
        # in the current chain is valid.
        # TODO: add an option to validate the entire timestamp chain
        #  plus all signatures
        from pyhanko.sign.validation import (
            _establish_timestamp_trust, DocumentSecurityStore,
            get_timestamp_chain
        )

        timestamps = get_timestamp_chain(reader)
        try:
            last_timestamp = next(timestamps)
        except StopIteration:
            logger.warning(
                "Document does not have any document timestamps yet. "
                "This may cause unexpected results."
            )
            last_timestamp = None

        # Validate the previous timestamp if present
        tst_status = None
        if last_timestamp is None:
            md_algorithm = default_md_algorithm
        else:
            last_timestamp.compute_digest()
            last_timestamp.compute_tst_digest()

            tst_token = last_timestamp.signed_data
            expected_imprint = last_timestamp.external_digest

            # run validation logic
            tst_status = _establish_timestamp_trust(
                tst_token, validation_context, expected_imprint
            )

            md_algorithm = tst_status.md_algorithm

        # Prepare output
        if in_place:
            output = reader.stream
        else:
            output = misc.prepare_rw_output_stream(output)
            reader.stream.seek(0)
            misc.chunked_write(
                bytearray(chunk_size), reader.stream, output
            )

        if last_timestamp is not None:
            # update the DSS
            DocumentSecurityStore.add_dss(
                output, last_timestamp.pkcs7_content,
                paths=(tst_status.validation_path,),
                validation_context=validation_context
            )

        # append a new timestamp
        return self.timestamp_pdf(
            IncrementalPdfFileWriter(output), md_algorithm,
            validation_context, in_place=True
        )


class PdfSigner:
    """
    Class to handle PDF signatures in general.

    :param signature_meta:
        The specification of the signature to add.
    :param signer:
        :class:`.Signer` object to use to produce the signature object.
    :param timestamper:
        :class:`.TimeStamper` object to use to produce any time stamp tokens
        that might be required.
    :param stamp_style:
        Stamp style specification to determine the visible style of the
        signature, typically an object of type :class:`.TextStampStyle` or
        :class:`.QRStampStyle`. Defaults to
        :const:`constants.DEFAULT_SIGNING_STAMP_STYLE`.
    :param new_field_spec:
        If a new field is to be created, this parameter allows the caller
        to specify the field's properties in the form of a
        :class:`.SigFieldSpec`. This parameter is only meaningful if
        ``existing_fields_only`` is ``False``.
    """
    _ignore_sv = False

    def __init__(self, signature_meta: PdfSignatureMetadata,
                 signer: Signer, *, timestamper: TimeStamper = None,
                 stamp_style: Optional[BaseStampStyle] = None,
                 new_field_spec: Optional[SigFieldSpec] = None):
        self.signature_meta = signature_meta
        if new_field_spec is not None and \
                new_field_spec.sig_field_name != signature_meta.field_name:
            raise SigningError(
                "Field names specified in SigFieldSpec and "
                "PdfSignatureMetadata do not agree."
            )

        self.signer = signer
        stamp_style = stamp_style or constants.DEFAULT_SIGNING_STAMP_STYLE
        self.stamp_style: BaseStampStyle = stamp_style
        try:
            self.signer_hash_algo = \
                self.signer.get_signature_mechanism(None).hash_algo
        except ValueError:
            self.signer_hash_algo = None

        self.new_field_spec = new_field_spec
        self.default_timestamper = timestamper

    @property
    def default_md_for_signer(self) -> Optional[str]:
        return self.signature_meta.md_algorithm or self.signer_hash_algo

    def _enforce_certification_constraints(self, reader: PdfFileReader):
        # TODO we really should take into account the /DocMDP constraints
        #  of _all_ previous signatures

        from pyhanko.sign.validation import read_certification_data
        cd = read_certification_data(reader)
        # if there is no author signature, we don't have to do anything
        if cd is None:
            return
        if self.signature_meta.certify:
            raise SigningError(
                "Document already contains a certification signature"
            )
        if cd.permission == MDPPerm.NO_CHANGES:
            raise SigningError("Author signature forbids all changes")
        return cd.digest_method

    def _retrieve_seed_value_spec(self, sig_field) \
            -> Optional[SigSeedValueSpec]:
        # for testing & debugging
        if self._ignore_sv:
            return None
        sv_dict = sig_field.get('/SV')
        if sv_dict is None:
            return None
        return SigSeedValueSpec.from_pdf_object(sv_dict)

    def _select_md_algorithm(self, sv_spec: Optional[SigSeedValueSpec],
                             author_sig_md_algorithm: Optional[str]) -> str:

        signature_meta = self.signature_meta

        # priority order for the message digest algorithm
        #  (1) If signature_meta specifies a message digest algorithm, use it
        #      (it has been cleared by the SV dictionary checker already)
        #  (2) Use the first algorithm specified in the seed value dictionary,
        #      if a suggestion is present
        #  (3) If there is a certification signature, use the digest method
        #      specified there.
        #  (4) fall back to DEFAULT_MD
        if sv_spec is not None and sv_spec.digest_methods:
            sv_md_algorithm = sv_spec.digest_methods[0]
        else:
            sv_md_algorithm = None

        if self.default_md_for_signer is not None:
            md_algorithm = self.default_md_for_signer
        elif sv_md_algorithm is not None:
            md_algorithm = sv_md_algorithm
        elif author_sig_md_algorithm is not None:
            md_algorithm = author_sig_md_algorithm
        else:
            md_algorithm = constants.DEFAULT_MD

        # TODO fall back to more useful default for weak_hash_algos
        weak_hash_algos = (
            signature_meta.validation_context.weak_hash_algos
            if signature_meta.validation_context is not None
            else ()
        )
        if md_algorithm in weak_hash_algos:
            raise SigningError(
                f"The hash algorithm {md_algorithm} is considered weak in the "
                f"specified validation context. Please choose another."
            )
        return md_algorithm

    def init_signing_session(self, pdf_out: BasePdfFileWriter,
                             existing_fields_only=False) \
            -> 'PdfSigningSession':

        # TODO document
        timestamper = self.default_timestamper

        # TODO if PAdES is requested, set the ESIC extension to the proper value

        signature_meta: PdfSignatureMetadata = self.signature_meta

        cms_writer = PdfCMSEmbedder(
            new_field_spec=self.new_field_spec
        ).write_cms(
            field_name=signature_meta.field_name, writer=pdf_out,
            existing_fields_only=existing_fields_only
        )

        # let the CMS writer put in a field for us, if necessary
        sig_field_ref = next(cms_writer)

        sig_field = sig_field_ref.get_object()

        # Fetch seed values (if present) to prepare for signing
        sv_spec = self._retrieve_seed_value_spec(sig_field)

        # look up the certification signature's MD (if present), as a fallback
        # if the settings don't specify one
        author_sig_md_algorithm = None
        if isinstance(pdf_out, IncrementalPdfFileWriter):
            author_sig_md_algorithm = self._enforce_certification_constraints(
                pdf_out.prev
            )

        md_algorithm = self._select_md_algorithm(
            sv_spec, author_sig_md_algorithm
        )
        ts_required = sv_spec is not None and sv_spec.timestamp_required
        if ts_required and timestamper is None:
            timestamper = sv_spec.build_timestamper()

        if timestamper is not None:
            # this might hit the TS server, but the response is cached
            # and it collects the certificates we need to verify the TS response
            timestamper.dummy_response(md_algorithm)

        # subfilter: try signature_meta and SV dict, fall back
        #  to /adbe.pkcs7.detached by default
        subfilter = signature_meta.subfilter
        if subfilter is None:
            if sv_spec is not None and sv_spec.subfilters:
                subfilter = sv_spec.subfilters[0]
            else:
                subfilter = SigSeedSubFilter.ADOBE_PKCS7_DETACHED

        session = PdfSigningSession(
            self, cms_writer, sig_field, md_algorithm, timestamper, subfilter,
            sv_spec=sv_spec
        )

        return session

    def sign_pdf(self, pdf_out: BasePdfFileWriter,
                 existing_fields_only=False, bytes_reserved=None, *,
                 appearance_text_params=None, in_place=False,
                 output=None, chunk_size=misc.DEFAULT_CHUNK_SIZE):
        """
        Sign a PDF file using the provided output writer.

        :param pdf_out:
            A PDF file writer (usually an :class:`.IncrementalPdfFileWriter`)
            containing the data to sign.
        :param existing_fields_only:
            If ``True``, never create a new empty signature field to contain
            the signature.
            If ``False``, a new field may be created if no field matching
            :attr:`~.PdfSignatureMetadata.field_name` exists.
        :param bytes_reserved:
            Bytes to reserve for the CMS object in the PDF file.
            If not specified, make an estimate based on a dummy signature.
        :param appearance_text_params:
            Dictionary with text parameters that will be passed to the
            signature appearance constructor (if applicable).
        :param output:
            Write the output to the specified output stream.
            If ``None``, write to a new :class:`.BytesIO` object.
            Default is ``None``.
        :param in_place:
            Sign the original input stream in-place.
            This parameter overrides ``output``.
        :param chunk_size:
            Size of the internal buffer (in bytes) used to feed data to the
            message digest function if the input stream does not support
            ``memoryview``.
        :return:
            The output stream containing the signed data.
        """

        signing_session = self.init_signing_session(
            pdf_out, existing_fields_only=existing_fields_only,
        )
        validation_info = signing_session.perform_presign_validation(pdf_out)
        tbs_document = signing_session.prepare_tbs_document(
            validation_info=validation_info,
            bytes_reserved=bytes_reserved,
            appearance_text_params=appearance_text_params
        )
        prepared_br_digest = tbs_document.digest_tbs_document(
            in_place=in_place, chunk_size=chunk_size, output=output
        )

        post_signing_doc = tbs_document.embed_cms(
            prepared_br_digest.document_digest,
            pdf_cms_signed_attrs=PdfCMSSignedAttributes(
                signing_time=signing_session.system_time,
                adobe_revinfo_attr=(
                    None if validation_info is None else
                    validation_info.adobe_revinfo_attr
                ),
                cades_signed_attrs=self.signature_meta.cades_signed_attr_spec
            )
        )

        res_output = post_signing_doc.post_signature_processing(
            chunk_size=chunk_size
        )
        # we put the finalisation step after the DSS manipulations, since
        # otherwise we'd also run into issues with non-seekable output buffers
        output = _finalise_output(output, res_output)
        return output


@dataclass(frozen=True)
class PreSignValidationStatus:
    validation_context: ValidationContext
    validation_paths: List[ValidationPath]
    signer_path: ValidationPath
    ts_validation_paths: Optional[List[ValidationPath]] = None
    adobe_revinfo_attr: Optional[cms.CMSAttribute] = None


class PdfSigningSession:

    def __init__(self, pdf_signer: PdfSigner, cms_writer,
                 sig_field, md_algorithm: str, timestamper: TimeStamper,
                 subfilter: SigSeedSubFilter, system_time: datetime = None,
                 sv_spec: Optional[SigSeedValueSpec] = None):
        self.pdf_signer = pdf_signer
        self.sig_field = sig_field
        self.cms_writer = cms_writer
        self.md_algorithm = md_algorithm
        self.timestamper = timestamper
        self.subfilter = subfilter
        self.use_pades = subfilter == SigSeedSubFilter.PADES
        self.system_time = \
            system_time or datetime.now(tz=tzlocal.get_localzone())
        self.sv_spec = sv_spec

    def perform_presign_validation(self, pdf_out: BasePdfFileWriter) \
            -> Optional[PreSignValidationStatus]:
        pdf_signer = self.pdf_signer
        validation_paths = []
        signature_meta = pdf_signer.signature_meta
        validation_context = signature_meta.validation_context

        if signature_meta.embed_validation_info:
            if validation_context is None:
                raise SigningError(
                    'A validation context must be provided if '
                    'validation/revocation info is to be embedded into the '
                    'signature.'
                )
            elif not validation_context._allow_fetching:
                logger.warning(
                    "Validation/revocation info will be embedded, but "
                    "fetching is not allowed. This may give rise to unexpected "
                    "results."
                )
        validation_context = signature_meta.validation_context
        # if there's no validation context, bail early
        if validation_context is None:
            return None

        signer_path = self._perform_presign_signer_validation(
            validation_context, signature_meta.signer_key_usage
        )
        validation_paths.append(signer_path)

        # If LTA:
        # if the original document already included a document timestamp,
        # we need to collect revocation information for it, to preserve
        # the integrity of the timestamp chain
        if signature_meta.use_pades_lta \
                and isinstance(pdf_out, IncrementalPdfFileWriter):
            prev_tsa_path = self._perform_prev_ts_validation(
                validation_context, pdf_out.prev
            )
            if prev_tsa_path is not None:
                validation_paths.append(prev_tsa_path)

        timestamper = self.timestamper
        # Finally, fetch validation information for the TSA that we're going to
        # use for our own TS
        ts_validation_paths = None
        if timestamper is not None:
            ts_validation_paths = list(
                timestamper.validation_paths(validation_context)
            )
            validation_paths.extend(ts_validation_paths)
            ts_validation_paths = ts_validation_paths

        # do we need adobe-style revocation info?
        if signature_meta.embed_validation_info and not self.use_pades:
            assert validation_context is not None  # checked earlier
            revinfo = Signer.format_revinfo(
                ocsp_responses=validation_context.ocsps,
                crls=validation_context.crls
            )
        else:
            # PAdES prescribes another mechanism for embedding revocation info
            revinfo = None
        return PreSignValidationStatus(
            validation_context=validation_context,
            validation_paths=validation_paths,
            signer_path=signer_path, ts_validation_paths=ts_validation_paths,
            adobe_revinfo_attr=revinfo
        )

    def _perform_presign_signer_validation(self, validation_context, key_usage):

        signer = self.pdf_signer.signer
        # validate cert
        # (this also keeps track of any validation data automagically)
        validator = CertificateValidator(
            signer.signing_cert, intermediate_certs=signer.cert_registry,
            validation_context=validation_context
        )
        try:
            signer_cert_validation_path = validator.validate_usage(key_usage)
        except (PathBuildingError, PathValidationError) as e:
            raise SigningError(
                "The signer's certificate could not be validated", e
            )
        return signer_cert_validation_path

    def _perform_prev_ts_validation(self, validation_context, prev_reader):
        signer = self.pdf_signer.signer
        from pyhanko.sign.validation import get_timestamp_chain
        # try to grab the most recent document timestamp
        last_ts = None
        try:
            last_ts = next(get_timestamp_chain(prev_reader))
        except StopIteration:
            pass
        last_ts_validation_path = None
        if last_ts is not None:
            ts_validator = CertificateValidator(
                last_ts.signer_cert,
                intermediate_certs=signer.cert_registry,
                validation_context=validation_context
            )
            try:
                last_ts_validation_path = ts_validator.validate_usage(
                    set(), extended_key_usage={"time_stamping"}
                )
            except (PathBuildingError, PathValidationError) as e:
                raise SigningError(
                    "Requested a PAdES-LTA signature on an existing "
                    "document, but the most recent timestamp "
                    "could not be validated.", e
                )
        return last_ts_validation_path

    def _apply_locking_rules(self) -> SigMDPSetup:
        # TODO allow equivalent functionality to the /Lock dictionary
        #  to be specified in PdfSignatureMetadata

        # this helper method handles /Lock dictionary and certification
        #  semantics.
        # The fallback rules are messy and ad-hoc; behaviour is mostly
        # documented by tests.

        # read recommendations and/or requirements from the SV dictionary
        sv_spec = self.sv_spec
        sig_field = self.sig_field
        signature_meta = self.pdf_signer.signature_meta
        if sv_spec is not None:
            sv_lock_values = {
                SeedLockDocument.LOCK:
                    (MDPPerm.NO_CHANGES,),
                SeedLockDocument.DO_NOT_LOCK:
                    (MDPPerm.FILL_FORMS, MDPPerm.ANNOTATE),
            }.get(sv_spec.lock_document, None)
            sv_lock_value_req = sv_lock_values is not None and (
                    sv_spec.flags & SigSeedValFlags.LOCK_DOCUMENT
            )
        else:
            sv_lock_values = None
            sv_lock_value_req = False

        lock = lock_dict = None
        # init the DocMDP value with what the /LockDocument setting in the SV
        # dict recommends. If the constraint is mandatory, it might conflict
        # with the /Lock dictionary, but we'll deal with that later.
        docmdp_perms = sv_lock_values[0] if sv_lock_values is not None else None
        try:
            lock_dict = sig_field['/Lock']
            lock = FieldMDPSpec.from_pdf_object(lock_dict)
            docmdp_value = lock_dict['/P']
            docmdp_perms = MDPPerm(docmdp_value)
            if sv_lock_value_req and docmdp_perms not in sv_lock_values:
                raise SigningError(
                    "Inconsistency in form field data. "
                    "The field lock dictionary imposes the DocMDP policy "
                    f"'{docmdp_perms}', but the seed value "
                    "dictionary's /LockDocument does not allow that."
                )
        except KeyError:
            pass
        except ValueError as e:
            raise SigningError("Failed to read /Lock dictionary", e)

        meta_perms = signature_meta.docmdp_permissions
        meta_certify = signature_meta.certify

        # only pull meta_perms into the validation if we're trying to make a
        # cert sig, or there already is some other docmdp_perms value available.
        # (in other words, if there's no SV dict or /Lock, and we're not
        # certifying, this will be skipped)
        if meta_perms is not None \
                and (meta_certify or docmdp_perms is not None):
            if sv_lock_value_req and meta_perms not in sv_lock_values:
                # in this case, we have to override
                docmdp_perms = sv_lock_values[0]
            else:
                # choose the stricter option if both are available
                docmdp_perms = meta_perms if docmdp_perms is None else (
                    min(docmdp_perms, meta_perms)
                )
            if docmdp_perms != meta_perms:
                logger.warning(
                    f"DocMDP policy '{meta_perms}', was requested, "
                    f"but the signature field settings do "
                    f"not allow that. Setting '{docmdp_perms}' instead."
                )

        # if not certifying and docmdp_perms is not None, ensure the
        # appropriate permission in the Lock dictionary is set
        if not meta_certify and docmdp_perms is not None:
            if lock_dict is None:
                # set a field lock that doesn't do anything
                sig_field['/Lock'] = lock_dict = generic.DictionaryObject({
                    pdf_name('/Action'): pdf_name('/Include'),
                    pdf_name('/Fields'): generic.ArrayObject()
                })
            lock_dict['/P'] = generic.NumberObject(docmdp_perms.value)

        return SigMDPSetup(
            certify=meta_certify, field_lock=lock, docmdp_perms=docmdp_perms,
            md_algorithm=self.md_algorithm
        )

    def _enforce_seed_value_constraints(self, validation_path):

        sv_spec = self.sv_spec
        pdf_signer = self.pdf_signer
        signature_meta = pdf_signer.signature_meta

        # Enforce mandatory seed values (except LOCK_DOCUMENT, which is handled
        #  elsewhere)
        flags: SigSeedValFlags = sv_spec.flags

        if sv_spec.cert is not None:
            sv_spec.cert.satisfied_by(
                pdf_signer.signer.signing_cert, validation_path
            )

        if sv_spec.seed_signature_type is not None:
            sv_certify = sv_spec.seed_signature_type.certification_signature()
            if sv_certify != signature_meta.certify:
                def _type(certify):
                    return 'a certification' if certify else 'an approval'

                raise SigningError(
                    "The seed value dictionary's /MDP entry specifies that "
                    f"this field should contain {_type(sv_certify)} "
                    f"signature, but {_type(signature_meta.certify)} "
                    "was requested."
                )
            sv_mdp_perm = sv_spec.seed_signature_type.mdp_perm
            if sv_certify \
                    and sv_mdp_perm != signature_meta.docmdp_permissions:
                raise SigningError(
                    "The seed value dictionary specified that this "
                    "certification signature should use the MDP policy "
                    f"'{sv_mdp_perm}', "
                    f"but '{signature_meta.docmdp_permissions}' was "
                    "requested."
                )

        if not flags:
            return sv_spec

        selected_sf = signature_meta.subfilter
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
                raise SigningError(
                    "The seed value dictionary mandates subfilter '%s', "
                    "but '%s' was requested." % (
                        mandated_sf.value, selected_sf.value
                    )
                )

        # SV dict serves as a source of defaults as well
        if selected_sf is None and sv_spec.subfilters is not None:
            selected_sf = sv_spec.subfilters[0]

        if (flags & SigSeedValFlags.APPEARANCE_FILTER) \
                and sv_spec.appearance is not None:
            raise SigningError(
                "pyHanko does not define any named appearances, but "
                "the seed value dictionary requires that the named appearance "
                f"'{sv_spec.appearance}' be used."
            )

        if (flags & SigSeedValFlags.ADD_REV_INFO) \
                and sv_spec.add_rev_info is not None:
            if sv_spec.add_rev_info != signature_meta.embed_validation_info:
                raise SigningError(
                    "The seed value dict mandates that revocation info %sbe "
                    "added; adjust PdfSignatureMetadata settings accordingly."
                    % ("" if sv_spec.add_rev_info else "not ")
                )
            if sv_spec.add_rev_info and \
                    selected_sf != SigSeedSubFilter.ADOBE_PKCS7_DETACHED:
                raise SigningError(
                    "The seed value dict mandates that Adobe-style revocation "
                    "info be added; this requires subfilter '%s'" % (
                        SigSeedSubFilter.ADOBE_PKCS7_DETACHED.value
                    )
                )
        if (flags & SigSeedValFlags.DIGEST_METHOD) \
                and sv_spec.digest_methods is not None:
            selected_md = pdf_signer.default_md_for_signer
            if selected_md is not None:
                selected_md = selected_md.lower()
                if selected_md not in sv_spec.digest_methods:
                    raise SigningError(
                        "The selected message digest %s is not allowed by the "
                        "seed value dictionary. Please select one of %s."
                        % (selected_md, ", ".join(sv_spec.digest_methods))
                    )

        if flags & SigSeedValFlags.REASONS:
            # standard says that omission of the /Reasons key amounts to
            #  a prohibition in this case
            must_omit = not sv_spec.reasons or sv_spec.reasons == ["."]
            reason_given = signature_meta.reason
            if must_omit and reason_given is not None:
                raise SigningError(
                    "The seed value dictionary prohibits giving a reason "
                    "for signing."
                )
            if not must_omit and reason_given not in sv_spec.reasons:
                raise SigningError(
                    "Reason \"%s\" is not a valid reason for signing, "
                    "please choose one of the following: %s." % (
                        reason_given,
                        ", ".join("\"%s\"" % s for s in sv_spec.reasons)
                    )
                )

    def prepare_tbs_document(self, validation_info: PreSignValidationStatus,
                             bytes_reserved=None, appearance_text_params=None) \
            -> 'PdfTBSDocument':

        pdf_signer = self.pdf_signer
        signature_meta = self.pdf_signer.signature_meta
        if self.sv_spec is not None:
            # process the field's seed value constraints
            self._enforce_seed_value_constraints(
                None if validation_info is None else
                validation_info.signer_path
            )

        signer = pdf_signer.signer
        md_algorithm = self.md_algorithm
        if bytes_reserved is None:
            # estimate bytes_reserved by creating a fake CMS object
            md_spec = get_pyca_cryptography_hash(md_algorithm)
            test_md = hashes.Hash(md_spec).finalize()
            test_signature_cms = signer.sign(
                test_md, md_algorithm,
                timestamp=self.system_time, use_pades=self.use_pades,
                dry_run=True, timestamper=self.timestamper,
                revocation_info=(
                    None if validation_info is None else
                    validation_info.adobe_revinfo_attr
                ),
                cades_signed_attr_meta=signature_meta.cades_signed_attr_spec
            )
            test_len = len(test_signature_cms.dump()) * 2
            # External actors such as timestamping servers can't be relied on to
            # always return exactly the same response, so we build in a 50%
            # error margin (+ ensure that bytes_reserved is even)
            bytes_reserved = test_len + 2 * (test_len // 4)

        sig_mdp_setup = self._apply_locking_rules()

        # Prepare instructions to the CMS writer to set up the
        # (PDF) signature object and its appearance
        system_time = self.system_time
        name_specified = signature_meta.name
        sig_appearance = SigAppearanceSetup(
            style=pdf_signer.stamp_style,
            name=name_specified or signer.subject_name,
            timestamp=system_time, text_params=appearance_text_params
        )
        sig_obj = SignatureObject(
            bytes_reserved=bytes_reserved, subfilter=self.subfilter,
            timestamp=system_time,
            name=name_specified if name_specified else None,
            location=signature_meta.location, reason=signature_meta.reason,
        )

        # Pass in the SignatureObject settings
        self.cms_writer.send(SigObjSetup(
            sig_placeholder=sig_obj,
            mdp_setup=sig_mdp_setup,
            appearance_setup=sig_appearance
        ))

        # At this point, the document is in its final pre-signing state

        # Last job: prepare instructions for the post-signing workflow
        signature_meta = pdf_signer.signature_meta
        validation_context = signature_meta.validation_context
        post_signing_instr = doc_timestamper = None
        if self.use_pades and signature_meta.embed_validation_info:
            if signature_meta.use_pades_lta:
                doc_timestamper = self.timestamper
            post_signing_instr = PostSignInstructions(
                validation_info=validation_info,
                # use the same algorithm
                # TODO make this configurable? Some TSAs only allow one choice
                #  of MD, and forcing our signers to use the same one to handle
                #  might be overly restrictive (esp. for things like EdDSA where
                #  the MD is essentially fixed)
                timestamp_md_algorithm=md_algorithm,
                validation_context=validation_context,
                timestamper=doc_timestamper,
                timestamp_field_name=signature_meta.timestamp_field_name,
            )
        return PdfTBSDocument(
            cms_writer=self.cms_writer, signer=pdf_signer.signer,
            md_algorithm=md_algorithm, timestamper=self.timestamper,
            use_pades=self.use_pades,
            post_sign_instructions=post_signing_instr
        )


@dataclass(frozen=True)
class PdfCMSSignedAttributes:
    signing_time: Optional[datetime] = None
    adobe_revinfo_attr: Optional[cms.CMSAttribute] = None
    cades_signed_attrs: Optional[CAdESSignedAttrSpec] = None


@dataclass(frozen=True)
class PostSignInstructions:
    validation_info: PreSignValidationStatus
    timestamp_md_algorithm: str
    validation_context: ValidationContext
    timestamper: Optional[TimeStamper] = None
    timestamp_field_name: Optional[str] = None


class PdfTBSDocument:
    def __init__(self, cms_writer, signer: Signer,
                 md_algorithm: str, timestamper: TimeStamper,
                 use_pades: bool,
                 post_sign_instructions: Optional[PostSignInstructions] = None):
        self.cms_writer = cms_writer
        self.signer = signer
        self.md_algorithm = md_algorithm
        self.timestamper = timestamper
        self.use_pades = use_pades
        self.post_sign_instructions = post_sign_instructions

    def digest_tbs_document(self, *, output, in_place: bool,
                            chunk_size=misc.DEFAULT_CHUNK_SIZE) \
            -> PreparedByteRangeDigest:
        # pass in I/O parameters, get back a hash
        return self.cms_writer.send(SigIOSetup(
            md_algorithm=self.md_algorithm,
            in_place=in_place, chunk_size=chunk_size, output=output
        ))

    def embed_cms(self, document_digest: bytes,
                  pdf_cms_signed_attrs: PdfCMSSignedAttributes) \
            -> 'PdfPostSignatureDocument':
        # Tell the signer to construct a CMS object
        signature_cms = self.signer.sign(
            document_digest, self.md_algorithm,
            timestamp=pdf_cms_signed_attrs.signing_time,
            use_pades=self.use_pades, timestamper=self.timestamper,
            revocation_info=pdf_cms_signed_attrs.adobe_revinfo_attr,
            cades_signed_attr_meta=pdf_cms_signed_attrs.cades_signed_attrs
        )
        # ... and feed it to the CMS writer
        output, sig_contents = self.cms_writer.send(signature_cms)
        return PdfPostSignatureDocument(
            output, sig_contents,
            post_sign_instructions=self.post_sign_instructions
        )


class PdfPostSignatureDocument:
    """
    Represents the final phase of the PDF signing process
    """

    def __init__(self, output, sig_contents: bytes,
                 post_sign_instructions: Optional[PostSignInstructions] = None):
        self.output = output
        self.sig_contents = sig_contents
        self.post_sign_instructions = post_sign_instructions

    def post_signature_processing(self, chunk_size=misc.DEFAULT_CHUNK_SIZE):
        """
        Handle DSS updates and LTA timestamps, if applicable.

        :param chunk_size:
            Chunk size to use for I/O operations that do not support the buffer
            protocol.
        """
        instr = self.post_sign_instructions
        output = self.output
        if instr is None:
            return output

        validation_context = instr.validation_context
        validation_info = instr.validation_info

        from pyhanko.sign import validation
        validation.DocumentSecurityStore.add_dss(
            output_stream=output, sig_contents=self.sig_contents,
            paths=validation_info.validation_paths,
            validation_context=validation_context
        )
        timestamper = instr.timestamper
        if timestamper is not None:
            # append a document timestamp after the DSS update
            w = IncrementalPdfFileWriter(output)
            pdf_timestamper = PdfTimeStamper(
                timestamper, field_name=instr.timestamp_field_name
            )
            pdf_timestamper.timestamp_pdf(
                w, instr.timestamp_md_algorithm, validation_context,
                validation_paths=validation_info.validation_paths,
                in_place=True, timestamper=timestamper, chunk_size=chunk_size
            )
        return output
