"""
Implementation of stream filters for PDF.
Taken from PyPDF2 with modifications (see LICENSE.PyPDF2).
"""
import binascii

from .misc import PdfReadError
from io import BytesIO
import struct

import zlib

decompress = zlib.decompress
compress = zlib.compress


class Decoder:

    @classmethod
    def decode(cls, data: bytes, decode_params) -> bytes:
        raise NotImplementedError

    @classmethod
    def encode(cls, data: bytes) -> bytes:
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
    def encode(cls, data):
        return compress(data)


# TODO check boundary conditions in PDF spec

class ASCIIHexDecode(Decoder):

    @classmethod
    def encode(cls, data: bytes) -> bytes:
        return binascii.hexlify(data)

    @classmethod
    def decode(cls, data, decode_params=None):
        def _build():
            for c in data:
                c_ = bytes((c,))
                if c_.isspace():
                    continue
                if c_ == b'>':
                    break
                yield c
        return binascii.unhexlify(bytes(_build()))


# TODO reimplement LZW decoder

class ASCII85Decode(Decoder):

    @classmethod
    def encode(cls, data: bytes) -> bytes:
        raise NotImplementedError

    @classmethod
    def decode(cls, data, decode_params=None):
        if isinstance(data, str):
            data = data.encode('ascii')
        n = b = 0
        out = bytearray()
        for c in data:
            if ord('!') <= c <= ord('u'):
                n += 1
                b = b*85+(c-33)
                if n == 5:
                    out += struct.pack(b'>L', b)
                    n = b = 0
            elif c == ord('z'):
                assert n == 0
                out += b'\0\0\0\0'
            elif c == ord('~'):
                if n:
                    for _ in range(5-n):
                        b = b*85+84
                    out += struct.pack(b'>L', b)[:n-1]
                break
        return bytes(out)
    decode = staticmethod(decode)


# mostly a dummy
class CryptDecoder(Decoder):
    @classmethod
    def encode(cls, data: bytes) -> bytes:
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


def decode_stream_data(stream):
    from .generic import NameObject
    filters = stream.get("/Filter", ())
    if len(filters) and not isinstance(filters[0], NameObject):
        # we have a single filter instance
        filters = (filters,)
    data = stream._data
    # If there is no data to decode we should not try to decode the data.
    if data:
        for filterType in filters:
            try:
                filter_cls = DECODERS[filterType]
            except KeyError:
                raise NotImplementedError("unsupported filter %s" % filterType)
            decode_params = stream.get("/DecodeParms", {})
            data = filter_cls.decode(data, decode_params)
    return data
