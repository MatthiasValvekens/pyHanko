"""
Implementation of stream filters for PDF.

Taken from PyPDF2 with modifications. See :ref:`here <pypdf2-license>`
for the original license of the PyPDF2 project.

Note that not all decoders specified in the standard are supported.
In particular ``/Crypt`` and ``/LZWDecode`` are missing.
"""
import binascii
import re


from .misc import PdfReadError, PdfStreamError
from io import BytesIO
import struct

import zlib

__all__ = [
    'Decoder', 'ASCII85Decode', 'ASCIIHexDecode', 'FlateDecode', 'DECODERS'
]

decompress = zlib.decompress
compress = zlib.compress


class Decoder:
    """
    General filter/decoder interface.
    """

    @classmethod
    def decode(cls, data: bytes, decode_params: dict) -> bytes:
        """
        Decode a stream.

        :param data:
            Data to decode.
        :param decode_params:
            Decoder parameters, sourced from the ``/DecoderParams`` entry
            associated with this filter.
        :return:
            Decoded data.
        """
        raise NotImplementedError

    @classmethod
    def encode(cls, data: bytes, decode_params: dict) -> bytes:
        """
        Encode a stream.

        :param data:
            Data to encode.
        :param decode_params:
            Encoder parameters, sourced from the ``/DecoderParams`` entry
            associated with this filter.
        :return:
            Encoded data.
        """
        raise NotImplementedError


def _png_decode(data: memoryview, columns):

    output = BytesIO()
    # PNG prediction can vary from row to row
    rowlength = columns + 1
    assert len(data) % rowlength == 0

    prev_result = bytes(rowlength - 1)
    for row in range(len(data) // rowlength):
        rowdata = data[(row * rowlength):((row + 1) * rowlength)]
        filter_byte = rowdata[0]
        result_row = bytearray(rowlength - 1)
        if filter_byte == 0:
            pass
        elif filter_byte == 1:
            pairs = zip(rowdata[2:], rowdata[1:])
            result_row[0] = rowdata[1]
            for i, (x, y) in enumerate(pairs):
                result_row[i + 1] = (x + y) % 256
        elif filter_byte == 2:
            pairs = zip(rowdata[1:], prev_result)
            for i, (x, y) in enumerate(pairs):
                result_row[i] = (x + y) % 256
        else:
            # unsupported PNG filter
            raise PdfReadError(
                "Unsupported PNG filter %r" % filter_byte
            )
        prev_result = result_row
        output.write(result_row)
    return output.getvalue()


class FlateDecode(Decoder):
    """
    Implementation of the ``/FlateDecode`` filter.

    .. warning::
        Currently not all predictor values are supported. This may cause
        problems when extracting image data from PDF files.
    """

    @classmethod
    def decode(cls, data: bytes, decode_params):
        # there's lots of slicing ahead, so let's reduce copying overhead
        data = memoryview(decompress(data))
        predictor = 1
        if decode_params:
            try:
                predictor = decode_params.get("/Predictor", 1)
            except AttributeError:
                pass    # usually an array with a null object was read

        # predictor 1 == no predictor
        if predictor == 1:
            return data

        columns = decode_params["/Columns"]
        # PNG prediction:
        if 10 <= predictor <= 15:
            return _png_decode(data, columns)
        else:
            # unsupported predictor
            raise PdfReadError(
                "Unsupported flatedecode predictor %r" % predictor
            )

    @classmethod
    def encode(cls, data, decode_params=None):
        # TODO support the parameters in the spec
        return compress(data)


# TODO check boundary conditions in PDF spec

WS_REGEX = re.compile(b'\\s+')
ASCII_HEX_EOD_MARKER = b'>'


class ASCIIHexDecode(Decoder):
    """
    Wrapper around :func:`binascii.hexlify` that implements the
    :class:`.Decoder` interface.
    """

    @classmethod
    def encode(cls, data: bytes, decode_params=None) -> bytes:
        return binascii.hexlify(data) + b'>'

    @classmethod
    def decode(cls, data, decode_params=None):
        if isinstance(data, str):
            data = data.encode('ascii')
        data, _ = data.split(ASCII_HEX_EOD_MARKER, 1)
        data = WS_REGEX.sub(b'', data)
        return binascii.unhexlify(data)


# TODO reimplement LZW decoder

ASCII_85_EOD_MARKER = b'~>'
POWS = tuple(85 ** p for p in (4, 3, 2, 1, 0))


class ASCII85Decode(Decoder):
    """
    Implementation of the base 85 encoding scheme specified in ISO 32000-1.
    """

    @classmethod
    def encode(cls, data: bytes, decode_params=None) -> bytes:
        # BytesIO is quite clever, in that it doesn't copy things until modified
        data = BytesIO(data)
        out = BytesIO()

        while True:
            grp = data.read(4)
            if not grp:
                break
            # This needs to happen before applying padding!
            # See § 7.4.3 in ISO 32000-1
            if grp == b'\0\0\0\0':
                out.write(b'z')
                continue

            bytes_read = len(grp)
            if bytes_read < 4:
                grp += b'\0' * (4 - bytes_read)
                pows = POWS[:bytes_read + 1]
            else:
                pows = POWS

            # write 5 chars in base85
            grp_int, = struct.unpack('>L', grp)
            for p in pows:
                digit, grp_int = divmod(grp_int, p)
                # use chars from 0x21 to 0x75
                out.write(bytes((digit + 0x21,)))
        out.write(ASCII_85_EOD_MARKER)
        return out.getvalue()

    @classmethod
    def decode(cls, data, decode_params=None):
        if isinstance(data, str):
            data = data.encode('ascii')
        data, _ = data.split(ASCII_85_EOD_MARKER, 1)
        data = BytesIO(WS_REGEX.sub(b'', data))
        out = BytesIO()
        while True:
            next_char = data.read(1)
            if not next_char:
                break
            if next_char == b'z':
                out.write(b'\0\0\0\0')
                continue
            rest = data.read(4)
            if not rest:  # pragma: nocover
                raise PdfStreamError(
                    'Nonzero ASCII85 group must have at least two digits.'
                )

            grp = next_char + rest
            grp_result = 0
            p = 0  # make the linter happy
            # convert back from base 85 to int
            for digit, p in zip(grp, POWS):
                digit -= 0x21
                if 0 <= digit < 85:
                    grp_result += p * digit
                else:  # pragma: nocover
                    raise PdfStreamError(
                        'Bytes in ASCII85 data must lie beteen 0x21 and 0x75.'
                    )
            # 85 and 256 are coprime, so the last digit will always be off by
            # one if we had to throw away a multiple of 256 in the encoding
            # step (due to padding).
            if len(grp) < 5:
                grp_result += p

            # Finally, pack the integer into a 4-byte unsigned int
            # (potentially need to cut off some excess digits)
            decoded = struct.pack('>L', grp_result)
            out.write(decoded[:len(grp) - 1])
        return out.getvalue()


class CryptDecoder(Decoder):  # pragma: nocover
    """
    Dummy class
    """
    @classmethod
    def encode(cls, data: bytes, decode_params) -> bytes:
        pass

    @classmethod
    def decode(cls, data: bytes, decode_params) -> bytes:
        if "/Name" not in decode_params and "/Type" not in decode_params:
            return data
        else:
            raise NotImplementedError(
                "/Crypt filter with /Name or /Type not supported yet")


DECODERS = {
    '/FlateDecode': FlateDecode, '/Fl': FlateDecode,
    '/ASCIIHexDecode': ASCIIHexDecode, '/AHx': ASCIIHexDecode,
    '/ASCII85Decode': ASCII85Decode, '/A85': ASCII85Decode,
    '/Crypt': CryptDecoder
}
"""
Dictionary mapping decoder names to implementations.
"""