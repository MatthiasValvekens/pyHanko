import asyncio
from typing import TypeVar

from pyhanko.pdf_utils import misc
from pyhanko_certvalidator import ValidationContext

from .._session_scope import run_and_release
from ..diff_analysis import DiffPolicy
from .dss import (
    VRI,
    DocumentSecurityStore,
    async_add_validation_info,
    collect_validation_info,
)
from .generic_cms import (
    async_validate_cms_signature,
    async_validate_detached_cms,
)
from .pdf_embedded import (
    DocMDPInfo,
    EmbeddedPdfSignature,
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
    read_certification_data,
)
from .settings import KeyUsageConstraints
from .status import (
    DocumentTimestampStatus,
    ModificationInfo,
    PdfSignatureStatus,
    SignatureCoverageLevel,
    SignatureStatus,
    StandardCMSSignatureStatus,
)

__all__ = [
    'VRI',
    'DocMDPInfo',
    'DocumentSecurityStore',
    'DocumentTimestampStatus',
    'EmbeddedPdfSignature',
    'ModificationInfo',
    'PdfSignatureStatus',
    'SignatureCoverageLevel',
    'StandardCMSSignatureStatus',
    'add_validation_info',
    'async_validate_cms_signature',
    'async_validate_detached_cms',
    'async_validate_pdf_signature',
    'async_validate_pdf_timestamp',
    'collect_validation_info',
    'read_certification_data',
    'validate_pdf_signature',
    'validate_pdf_timestamp',
]


StatusType = TypeVar('StatusType', bound=SignatureStatus)


def validate_pdf_signature(
    embedded_sig: EmbeddedPdfSignature,
    signer_validation_context: ValidationContext | None = None,
    ts_validation_context: ValidationContext | None = None,
    diff_policy: DiffPolicy | None = None,
    key_usage_settings: KeyUsageConstraints | None = None,
    skip_diff: bool = False,
) -> PdfSignatureStatus:
    """
    .. versionchanged:: 0.9.0
        Wrapper around :func:`~.pdf_embedded.async_validate_pdf_signature`.

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
        diff_policy=diff_policy,
        key_usage_settings=key_usage_settings,
        skip_diff=skip_diff,
    )
    return asyncio.run(
        run_and_release(coro, signer_validation_context, ts_validation_context)
    )


def validate_pdf_timestamp(
    embedded_sig: EmbeddedPdfSignature,
    validation_context: ValidationContext | None = None,
    diff_policy: DiffPolicy | None = None,
    skip_diff: bool = False,
) -> DocumentTimestampStatus:
    """
    .. versionchanged:: 0.9.0
        Wrapper around :func:`~.pdf_embedded.async_validate_pdf_timestamp`.

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
        diff_policy=diff_policy,
        skip_diff=skip_diff,
    )
    return asyncio.run(run_and_release(coro, validation_context))


def add_validation_info(
    embedded_sig: EmbeddedPdfSignature,
    validation_context: ValidationContext,
    skip_timestamp=False,
    add_vri_entry=True,
    in_place=False,
    output=None,
    force_write=False,
    chunk_size=misc.DEFAULT_CHUNK_SIZE,
):
    """
    .. versionchanged:: 0.9.0
        Wrapper around :func:`~.dss.async_add_validation_info`

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
        embedded_sig=embedded_sig,
        validation_context=validation_context,
        skip_timestamp=skip_timestamp,
        add_vri_entry=add_vri_entry,
        output=output,
        in_place=in_place,
        chunk_size=chunk_size,
        force_write=force_write,
    )
    return asyncio.run(run_and_release(coro, validation_context))
