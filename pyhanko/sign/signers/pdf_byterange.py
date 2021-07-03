from dataclasses import dataclass
from io import BytesIO
import binascii
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from asn1crypto import cms
from typing import Optional, Union, IO
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.generic import pdf_name, pdf_date, pdf_string
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.general import SigningError, get_pyca_cryptography_hash
from . import constants
from ..fields import SigSeedSubFilter

__all__ = [
    'SigByteRangeObject', 'DERPlaceholder', 'DocumentTimestamp',
    'PdfByteRangeDigest', 'SignatureObject',
    'PdfSignedData', 'PreparedByteRangeDigest',
]


class SigByteRangeObject(generic.PdfObject):

    def __init__(self):
        self._filled = False
        self._range_object_offset = None
        self.first_region_len = 0
        self.second_region_offset = 0
        self.second_region_len = 0

    def fill_offsets(self, stream, sig_start, sig_end, eof):
        if self._filled:
            raise ValueError('Offsets already filled')  # pragma: nocover
        if self._range_object_offset is None:
            raise ValueError(
                'Could not determine where to write /ByteRange value'
            )  # pragma: nocover

        old_seek = stream.tell()
        self.first_region_len = sig_start
        self.second_region_offset = sig_end
        self.second_region_len = eof - sig_end
        # our ArrayObject is rigged to have fixed width
        # so we can just write over it

        stream.seek(self._range_object_offset)
        self.write_to_stream(stream, None)

        stream.seek(old_seek)
        self._filled = True

    def write_to_stream(self, stream, handler=None, container_ref=None):
        if self._range_object_offset is None:
            self._range_object_offset = stream.tell()
        string_repr = "[ %08d %08d %08d %08d ]" % (
            0, self.first_region_len,
            self.second_region_offset, self.second_region_len,
        )
        stream.write(string_repr.encode('ascii'))


class DERPlaceholder(generic.PdfObject):

    def __init__(self, bytes_reserved=None):
        self._placeholder = True
        self.value = b'0' * (bytes_reserved or 16 * 1024)
        self._offsets = None

    @property
    def offsets(self):
        if self._offsets is None:
            raise ValueError('No offsets available')  # pragma: nocover
        return self._offsets

    # always ignore encryption key, since this is a placeholder
    def write_to_stream(self, stream, handler=None, container_ref=None):
        start = stream.tell()
        stream.write(b'<')
        stream.write(self.value)
        stream.write(b'>')
        end = stream.tell()
        if self._offsets is None:
            self._offsets = start, end


@dataclass(frozen=True)
class PreparedByteRangeDigest:
    document_digest: bytes
    md_algorithm: str
    document_handle: IO
    reserved_region_start: int
    reserved_region_end: int

    def fill_with_cms(self, cms_data: Union[bytes, cms.ContentInfo]):
        if isinstance(cms_data, bytes):
            der_bytes = cms_data
        else:
            der_bytes = cms_data.dump()
        return self.fill_reserved_region(der_bytes)

    def fill_reserved_region(self, der_bytes: bytes):
        der_hex = binascii.hexlify(der_bytes).upper()

        output = self.document_handle

        start = self.reserved_region_start
        end = self.reserved_region_end
        # might as well compute this
        bytes_reserved = end - start - 2
        length = len(der_hex)
        if length > bytes_reserved:
            raise SigningError(
                f"Final DER payload larger than expected: "
                f"allocated {bytes_reserved} bytes, but DER contents "
                f"required {length} bytes."
            )  # pragma: nocover

        # +1 to skip the '<'
        output.seek(start + 1)
        # NOTE: the PDF spec is not completely clear on this, but
        # signature contents are NOT supposed to be encrypted.
        # Perhaps this falls under the "strings in encrypted containers"
        # denominator in § 7.6.1?
        # Addition: the PDF 2.0 spec *does* spell out that this content
        # is not to be encrypted.
        output.write(der_hex)

        output.seek(0)
        padding = bytes(bytes_reserved // 2 - len(der_bytes))
        return output, der_bytes + padding


class PdfByteRangeDigest(generic.DictionaryObject):

    def __init__(self, data_key=pdf_name('/Contents'), *, bytes_reserved=None):
        super().__init__()
        if bytes_reserved is not None and bytes_reserved % 2 == 1:
            raise ValueError('bytes_reserved must be even')

        self.data_key = data_key
        contents = DERPlaceholder(bytes_reserved=bytes_reserved)
        self[data_key] = self.contents = contents
        byte_range = SigByteRangeObject()
        self[pdf_name('/ByteRange')] = self.byte_range = byte_range

    def fill(self, writer: BasePdfFileWriter, md_algorithm,
             in_place=False, output=None, chunk_size=misc.DEFAULT_CHUNK_SIZE):
        """
        Generator coroutine that handles the document hash computation and
        the actual filling of the placeholder data.

        This is internal API; you should use use :class:`.PdfSigner`
        wherever possible. If you *really* need fine-grained control,
        use :class:`~pyhanko.sign.signers.cms_embedder.PdfCMSEmbedder` instead.
        """

        if in_place:
            if not isinstance(writer, IncrementalPdfFileWriter):
                raise TypeError(
                    "in_place is only meaningful for incremental writers."
                )  # pragma: nocover
            output = writer.prev.stream
            writer.write_in_place()
        else:
            output = misc.prepare_rw_output_stream(output)

            writer.write(output)

        # retcon time: write the proper values of the /ByteRange entry
        #  in the signature object
        eof = output.tell()
        sig_start, sig_end = self.contents.offsets
        self.byte_range.fill_offsets(output, sig_start, sig_end, eof)

        # compute the digests
        md_spec = get_pyca_cryptography_hash(md_algorithm)
        md = hashes.Hash(md_spec)

        # attempt to get a memoryview for automatic buffering
        output_buffer = None
        if isinstance(output, BytesIO):
            output_buffer = output.getbuffer()
        else:
            try:
                output_buffer = memoryview(output)
            except (TypeError, IOError):
                pass

        if output_buffer is not None:
            # these are memoryviews, so slices should not copy stuff around
            #   (also, the interface files for pyca/cryptography don't specify
            #    that memoryviews are allowed, but they are)
            # noinspection PyTypeChecker
            md.update(output_buffer[:sig_start])
            # noinspection PyTypeChecker
            md.update(output_buffer[sig_end:eof])
            output_buffer.release()
        else:
            temp_buffer = bytearray(chunk_size)
            output.seek(0)
            misc.chunked_digest(temp_buffer, output, md, max_read=sig_start)
            output.seek(sig_end)
            misc.chunked_digest(temp_buffer, output, md, max_read=eof-sig_end)

        digest_value = md.finalize()
        prepared_br_digest = PreparedByteRangeDigest(
            document_digest=digest_value, document_handle=output,
            md_algorithm=md_algorithm,
            reserved_region_start=sig_start, reserved_region_end=sig_end
        )
        cms_data = yield prepared_br_digest
        yield prepared_br_digest.fill_with_cms(cms_data)


class PdfSignedData(PdfByteRangeDigest):
    """
    Generic class to model signature dictionaries in a PDF file.
    See also :class:`.SignatureObject` and :class:`.DocumentTimestamp`.

    :param obj_type:
        The type of signature object.
    :param subfilter:
        See :class:`.SigSeedSubFilter`.
    :param timestamp:
        The timestamp to embed into the ``/M`` entry.
    :param bytes_reserved:
        The number of bytes to reserve for the signature.
        Defaults to 16 KiB.

        .. warning::
            Since the CMS object is written to the output file as a hexadecimal
            string, you should request **twice** the (estimated) number of bytes
            in the DER-encoded version of the CMS object.
    """

    def __init__(self, obj_type,
                 subfilter: SigSeedSubFilter = constants.DEFAULT_SIG_SUBFILTER,
                 timestamp: datetime = None, bytes_reserved=None):
        super().__init__(bytes_reserved=bytes_reserved)
        self.update({
            pdf_name('/Type'): obj_type,
            pdf_name('/Filter'): pdf_name('/Adobe.PPKLite'),
            pdf_name('/SubFilter'): subfilter.value,
        })

        if timestamp is not None:
            self[pdf_name('/M')] = pdf_date(timestamp)


class SignatureObject(PdfSignedData):
    """
    Class modelling a (placeholder for) a regular PDF signature.

    :param timestamp:
        The (optional) timestamp to embed into the ``/M`` entry.
    :param subfilter:
        See :class:`.SigSeedSubFilter`.
    :param bytes_reserved:
        The number of bytes to reserve for the signature.
        Defaults to 16 KiB.

        .. warning::
            Since the CMS object is written to the output file as a hexadecimal
            string, you should request **twice** the (estimated) number of bytes
            in the DER-encoded version of the CMS object.
    :param name:
        Signer name. You probably want to leave this blank, viewers should
        default to the signer's subject name.
    :param location:
        Optional signing location.
    :param reason:
        Optional signing reason. May be restricted by seed values.
    """

    def __init__(self, timestamp: Optional[datetime] = None,
                 subfilter: SigSeedSubFilter = constants.DEFAULT_SIG_SUBFILTER,
                 name=None, location=None, reason=None, bytes_reserved=None):
        super().__init__(
            obj_type=pdf_name('/Sig'), subfilter=subfilter,
            timestamp=timestamp, bytes_reserved=bytes_reserved
        )

        if name:
            self[pdf_name('/Name')] = pdf_string(name)
        if location:
            self[pdf_name('/Location')] = pdf_string(location)
        if reason:
            self[pdf_name('/Reason')] = pdf_string(reason)


class DocumentTimestamp(PdfSignedData):
    """
    Class modelling a (placeholder for) a regular PDF signature.

    :param bytes_reserved:
        The number of bytes to reserve for the signature.
        Defaults to 16 KiB.

        .. warning::
            Since the CMS object is written to the output file as a hexadecimal
            string, you should request **twice** the (estimated) number of bytes
            in the DER-encoded version of the CMS object.
    """

    def __init__(self, bytes_reserved=None):
        super().__init__(
            obj_type=pdf_name('/DocTimeStamp'),
            subfilter=SigSeedSubFilter.ETSI_RFC3161,
            bytes_reserved=bytes_reserved
        )

        # use of Name/Location/Reason is discouraged in document timestamps by
        # PAdES, so we don't set those
