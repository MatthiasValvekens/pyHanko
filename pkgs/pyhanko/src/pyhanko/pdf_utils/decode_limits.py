"""
Limits on the amount of data produced when decoding PDF streams.

Compression filters such as ``/FlateDecode`` allow a small file to expand to
a very large amount of data when decoded. The limits in this module bound that
expansion for documents read from untrusted sources.

Only the classes and constants used to configure the limits are public API.
The machinery that enforces them (:class:`.DecodeContext` and related
functions and methods) is internal API.

.. versionadded:: 0.38.0
"""

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field

from .misc import PdfDecodeLimitError

__all__ = [
    'DEFAULT_DECODE_CONTEXT',
    'DEFAULT_PURPOSE_LIMITS',
    'DecodeContext',
    'DecodeLimits',
    'DecodePurpose',
    'DocumentDecodeBudget',
    'StreamDecodeLimits',
]

MiB = 1024 * 1024


@dataclass(frozen=True)
class StreamDecodeLimits:
    """
    Limits that apply to decoding a single stream.

    All ratios are measured against the length of the encoded stream data,
    taken over the stream's entire filter chain. In particular, stacking
    filters does not reset the ratio.
    """

    max_ratio: float | None = 1100
    """
    Maximal ratio of decoded size to encoded size, for streams that decode to
    more than :attr:`ratio_floor` bytes. ``None`` means no limit.

    The default sits just above the theoretical maximum of ~1032:1 for a single
    layer of Deflate compression, so it only rejects streams that stack
    compression filters to amplify their size.
    """

    ratio_floor: int = MiB
    """
    Decoded size (in bytes) below which :attr:`max_ratio` is not enforced.
    """

    max_output_size: int | None = 256 * MiB
    """
    Absolute upper bound on the decoded size of a single stream (in bytes).
    ``None`` means no limit.
    """

    def output_cap(self, encoded_size: int) -> int | None:
        """
        Compute the maximal number of decoded bytes allowed for a stream
        with the given encoded size.

        This is internal API.

        :param encoded_size:
            Length of the encoded stream data.
        :return:
            The maximal decoded size, or ``None`` if unbounded.
        """
        caps = []
        if self.max_ratio is not None:
            caps.append(
                max(self.ratio_floor, int(self.max_ratio * encoded_size))
            )
        if self.max_output_size is not None:
            caps.append(self.max_output_size)
        return min(caps, default=None)


@enum.unique
class DecodePurpose(enum.Enum):
    """
    The reason why a stream is being decoded. PyHanko uses this to apply
    tighter limits to streams with predictable contents.
    """

    GENERIC = enum.auto()
    """
    No particular purpose.
    """

    OBJECT_STREAM = enum.auto()
    """
    An object stream (``/Type /ObjStm``).
    """

    XREF_STREAM = enum.auto()
    """
    A cross-reference stream (``/Type /XRef``).
    """

    XMP_METADATA = enum.auto()
    """
    An XMP metadata stream.
    """

    CERTIFICATE = enum.auto()
    """
    A DER-encoded X.509 certificate.
    """

    OCSP_RESPONSE = enum.auto()
    """
    A DER-encoded OCSP response.
    """

    CRL = enum.auto()
    """
    A DER-encoded certificate revocation list.
    """


DEFAULT_PURPOSE_LIMITS: Mapping[DecodePurpose, StreamDecodeLimits] = {
    DecodePurpose.OBJECT_STREAM: StreamDecodeLimits(
        max_ratio=100, ratio_floor=4 * MiB, max_output_size=64 * MiB
    ),
    DecodePurpose.XMP_METADATA: StreamDecodeLimits(
        max_ratio=100, ratio_floor=4 * MiB, max_output_size=32 * MiB
    ),
    DecodePurpose.CERTIFICATE: StreamDecodeLimits(
        max_ratio=None, max_output_size=MiB
    ),
    DecodePurpose.OCSP_RESPONSE: StreamDecodeLimits(
        max_ratio=None, max_output_size=4 * MiB
    ),
    # CRLs can legitimately be very large, but they are not very compressible
    DecodePurpose.CRL: StreamDecodeLimits(
        max_ratio=50, ratio_floor=4 * MiB, max_output_size=None
    ),
}
"""
Default purpose-specific limits.
"""


@dataclass(frozen=True)
class DocumentDecodeBudget:
    """
    Bound on the total number of bytes produced by stream decoders while
    processing a single document.

    Every decoding operation counts towards the budget, including repeated
    decoding of the same stream data (e.g. when inspecting earlier revisions
    of a document). The total budget is the larger of :attr:`base_allowance`
    and :attr:`max_ratio` times the size of the input file.
    """

    base_allowance: int = 256 * MiB
    """
    Number of bytes that may always be decoded, regardless of the size of the
    input file.
    """

    max_ratio: float = 100
    """
    Maximal ratio of the total number of decoded bytes to the size of
    the input file.
    """

    def total(self, input_size: int) -> int:
        """
        Compute the total budget for an input file of the given size.

        This is internal API.

        :param input_size:
            The size of the input file in bytes.
        :return:
            The total number of bytes that may be decoded.
        """
        return max(self.base_allowance, int(self.max_ratio * input_size))


@dataclass(frozen=True)
class DecodeLimits:
    """
    Decoding limits that apply to a document as a whole.

    The default values are intended for documents from untrusted sources
    (see :meth:`for_untrusted_input`). Use :meth:`for_trusted_input` to
    disable all limits.
    """

    per_stream: StreamDecodeLimits = field(default_factory=StreamDecodeLimits)
    """
    Limits that apply to every stream in the document.
    """

    per_purpose: Mapping[DecodePurpose, StreamDecodeLimits] = field(
        default_factory=lambda: dict(DEFAULT_PURPOSE_LIMITS)
    )
    """
    Additional limits that apply when decoding a stream for a specific
    purpose. These can only tighten the limits in :attr:`per_stream`.
    Purposes without an entry are only subject to :attr:`per_stream`.

    To override the limits for a single purpose, start from
    :const:`DEFAULT_PURPOSE_LIMITS`, e.g.
    ``{**DEFAULT_PURPOSE_LIMITS, DecodePurpose.CRL: StreamDecodeLimits()}``.
    """

    expected_size_slack: int | None = 4096
    """
    Number of bytes by which a stream may exceed its expected decoded size,
    for streams where pyHanko can derive an expected size from the stream
    dictionary (e.g. cross-reference streams).
    ``None`` means that expected sizes are not enforced.
    """

    document_budget: DocumentDecodeBudget | None = field(
        default_factory=DocumentDecodeBudget
    )
    """
    Bound on the total amount of decoded data for the entire document.
    ``None`` means no limit.
    Only enforced for documents read from a file.
    """

    @classmethod
    def for_untrusted_input(cls) -> 'DecodeLimits':
        """
        Limits for documents from untrusted sources, e.g. documents submitted
        for signature validation. These are the defaults.

        :return:
            A :class:`.DecodeLimits` object.
        """
        return cls()

    @classmethod
    def for_trusted_input(cls) -> 'DecodeLimits':
        """
        Disable all decoding limits. Only use this for documents from
        trusted sources.

        :return:
            A :class:`.DecodeLimits` object.
        """
        return cls(
            per_stream=StreamDecodeLimits(max_ratio=None, max_output_size=None),
            per_purpose={},
            expected_size_slack=None,
            document_budget=None,
        )


def _min_cap(*caps: int | None) -> int | None:
    return min((c for c in caps if c is not None), default=None)


class DecodeContext:
    """
    Applies a set of :class:`.DecodeLimits` to the streams of a document.

    This class is internal API.

    :param limits:
        The limits to enforce.
    :param input_size:
        The size of the input file. If not specified, the document budget is
        not enforced.
    """

    def __init__(self, limits: DecodeLimits, input_size: int | None = None):
        self.limits = limits
        self.input_size = input_size
        budget = limits.document_budget
        self._remaining_budget: int | None = (
            budget.total(input_size)
            if budget is not None and input_size is not None
            else None
        )

    @property
    def remaining_budget(self) -> int | None:
        """
        The number of bytes that can still be decoded before exhausting the
        document budget, or ``None`` if there is no document budget.
        """
        return self._remaining_budget

    def fresh(self) -> 'DecodeContext':
        """
        Create a new context with the same limits and input size, but with
        the full document budget available.

        :return:
            A :class:`.DecodeContext`.
        """
        return DecodeContext(self.limits, input_size=self.input_size)

    def stage_output_cap(self, stream_cap: int | None) -> int | None:
        """
        Compute the maximal output size of a single filter in a stream's
        filter chain.

        :param stream_cap:
            The cap for the stream as a whole, as computed by
            :meth:`stream_output_cap`.
        :return:
            The maximal output size, or ``None`` if unbounded.
        """
        return _min_cap(stream_cap, self._remaining_budget)

    def record_output(self, size: int):
        """
        Record that a filter produced the given number of bytes, and charge
        them to the document budget.

        :param size:
            Number of bytes produced.
        """
        if self._remaining_budget is not None:
            self._remaining_budget -= size

    def stream_output_cap(
        self,
        encoded_size: int,
        purpose: DecodePurpose = DecodePurpose.GENERIC,
        expected_size: int | None = None,
    ) -> int | None:
        """
        Compute the maximal decoded size of a stream.

        :param encoded_size:
            Length of the encoded stream data.
        :param purpose:
            The purpose for which the stream is decoded.
        :param expected_size:
            The expected decoded size of the stream, if known.
        :return:
            The maximal decoded size, or ``None`` if unbounded.
        """
        limits = self.limits
        purpose_limits = limits.per_purpose.get(purpose)
        return _min_cap(
            limits.per_stream.output_cap(encoded_size),
            (
                purpose_limits.output_cap(encoded_size)
                if purpose_limits is not None
                else None
            ),
            (
                max(0, expected_size) + limits.expected_size_slack
                if expected_size is not None
                and limits.expected_size_slack is not None
                else None
            ),
        )


DEFAULT_DECODE_CONTEXT = DecodeContext(DecodeLimits())
"""
Decoding context used for streams that are not associated with a document
reader.

This is internal API.
"""


def check_output_size(size: int, cap: int | None):
    """
    Raise an error if a filter produced more output than allowed.

    This is internal API.

    :param size:
        The size of the decoded output.
    :param cap:
        The maximal allowed size, or ``None`` if unbounded.
    :raises PdfDecodeLimitError:
        If the limit was exceeded.
    """
    if cap is not None and size > cap:
        raise PdfDecodeLimitError(
            f"Decoded stream data exceeds the limit of {cap} bytes."
        )
