"""
Implementation of generic PDF objects (dictionary, number, string, and so on).
Taken from PyPDF2 with modifications (see LICENSE.PyPDF2).
"""
import os
import re
import binascii
from datetime import datetime
from typing import Iterator, Tuple, Optional
from dataclasses import dataclass, field

from .misc import (
    read_non_whitespace, skip_over_comment, read_until_regex,
    BoxConstraints,
)
from .misc import PdfStreamError, PdfReadError
import logging
from . import filters
from .crypt import rc4_encrypt
import decimal
import codecs

__all__ = [
    'PdfObject', 'NullObject', 'BooleanObject', 'ArrayObject',
    'IndirectObject', 'FloatObject', 'NumberObject', 'pdf_name', 'pdf_string',
    'ByteStringObject', 'TextStringObject', 'NameObject', 'DictionaryObject',
    'StreamObject', 'read_object', 'pdf_date', 'Reference', 'Dereferenceable',
]

OBJECT_PREFIXES = b'/<[tf(n%'
NUMBER_SIGNS = b'+-'
INDIRECT_PATTERN = re.compile(r"(\d+)\s+(\d+)\s+R[^a-zA-Z]".encode('ascii'))

logger = logging.getLogger(__name__)


class Dereferenceable:

    def get_object(self):
        raise NotImplementedError

    def get_pdf_handler(self):
        raise NotImplementedError


class TrailerReference(Dereferenceable):

    def __init__(self, reader):
        self.reader = reader

    def get_object(self):
        return self.reader.trailer

    def get_pdf_handler(self):
        return self.reader


@dataclass(frozen=True)
class Reference(Dereferenceable):

    idnum: int
    generation: int
    pdf: object = field(repr=False, hash=False, compare=False, default=None)

    def get_object(self):
        from pdf_utils.rw_common import PdfHandler
        assert isinstance(self.pdf, PdfHandler)
        return self.pdf.get_object(self).get_object()

    def get_pdf_handler(self):
        return self.pdf


def read_object(stream, container_ref: 'Dereferenceable') -> 'PdfObject':
    tok = stream.read(1)
    stream.seek(-1, os.SEEK_CUR)  # reset to start
    idx = OBJECT_PREFIXES.find(tok)
    strict = container_ref.get_pdf_handler().strict
    if idx == 0:
        # name object
        result = NameObject.read_from_stream(
            stream, strict=strict
        )
    elif idx == 1:
        # hexadecimal string OR dictionary
        peek = stream.read(2)
        stream.seek(-2, os.SEEK_CUR)  # reset to start
        if peek == b'<<':
            result = DictionaryObject.read_from_stream(
                stream, container_ref
            )
        else:
            result = read_hex_string_from_stream(stream)
    elif idx == 2:
        # array object
        result = ArrayObject.read_from_stream(
            stream, container_ref
        )
    elif idx == 3 or idx == 4:
        # boolean object
        result = BooleanObject.read_from_stream(stream)
    elif idx == 5:
        # string object
        result = read_string_from_stream(stream)
    elif idx == 6:
        # null object
        result = NullObject.read_from_stream(stream)
    elif idx == 7:
        # comment
        while tok not in (b'\r', b'\n'):
            tok = stream.read(1)
        read_non_whitespace(stream)
        stream.seek(-1, os.SEEK_CUR)
        result = read_object(stream, container_ref)
    else:
        # number object OR indirect reference
        if tok in NUMBER_SIGNS:
            # number
            result = NumberObject.read_from_stream(stream)
        else:
            peek = stream.read(20)
            stream.seek(-len(peek), os.SEEK_CUR)  # reset to start
            if INDIRECT_PATTERN.match(peek) is not None:
                result = IndirectObject.read_from_stream(stream, container_ref)
            else:
                result = NumberObject.read_from_stream(stream)

    result.container_ref = container_ref
    return result


class PdfObject:
    container_ref: Dereferenceable = None

    # TODO simplify a number of modification routines using this new API
    def get_container_ref(self) -> Dereferenceable:
        """
        Return a reference to the closest parent object containing this object.
        Raises an error if no such reference can be found.
        """
        ref = self.container_ref
        if ref is None:  # pragma: nocover
            raise ValueError(
                'No container reference available. This object probably '
                'wasn\'t read from a file.'
            )
        return ref

    def get_object(self):
        """Resolves indirect references."""
        return self

    def write_to_stream(self, stream, encryption_key):
        raise NotImplementedError


class NullObject(PdfObject):

    def write_to_stream(self, stream, encryption_key):
        stream.write(b"null")

    @staticmethod
    def read_from_stream(stream):
        nulltxt = stream.read(4)
        if nulltxt != b"null":
            raise PdfReadError("Could not read Null object")
        return NullObject()

    def __eq__(self, other):
        return self is other or isinstance(other, NullObject)

    def __bool__(self):
        return False


class BooleanObject(PdfObject):
    def __init__(self, value):
        self.value = value

    def write_to_stream(self, stream, encryption_key):
        if self.value:
            stream.write(b"true")
        else:
            stream.write(b"false")

    @staticmethod
    def read_from_stream(stream):
        word = stream.read(4)
        if word == b"true":
            return BooleanObject(True)
        elif word == b"fals":
            stream.read(1)
            return BooleanObject(False)
        else:
            raise PdfReadError('Could not read Boolean object')

    def __bool__(self):
        return bool(self.value)


class ArrayObject(list, PdfObject):

    # transparently decrypt, but otherwise don't dereference
    #  (keeps PyPDF2 behaviour)
    def __getitem__(self, item):
        value = list.__getitem__(self, item)
        if isinstance(value, DecryptedObjectProxy):
            return value.decrypted
        return value

    def write_to_stream(self, stream, encryption_key):
        stream.write(b"[")
        for data in self:
            stream.write(b" ")
            data.write_to_stream(stream, encryption_key)
        stream.write(b" ]")

    @staticmethod
    def read_from_stream(stream, container_ref):
        arr = ArrayObject()
        tmp = stream.read(1)
        if tmp != b"[":
            raise PdfReadError("Could not read array")
        while True:
            # skip leading whitespace
            tok = stream.read(1)
            while tok.isspace():
                tok = stream.read(1)
            stream.seek(-1, os.SEEK_CUR)
            # check for array ending
            peekahead = stream.read(1)
            if peekahead == b"]":
                break
            stream.seek(-1, os.SEEK_CUR)
            # read and append obj
            arr.append(read_object(stream, container_ref))
        return arr


def is_indirect(obj):
    return isinstance(obj, IndirectObject)


class IndirectObject(PdfObject, Dereferenceable):
    def __init__(self, idnum, generation, pdf):
        self.reference = Reference(idnum, generation, pdf)

    def get_object(self):
        return self.reference.get_object()

    def get_pdf_handler(self):
        return self.reference.get_pdf_handler()

    @property
    def idnum(self):
        return self.reference.idnum

    @property
    def generation(self):
        return self.reference.generation

    def __repr__(self):
        return "IndirectObject(%r, %r)" % (self.idnum, self.generation)

    def __hash__(self):
        return hash((self.idnum, self.generation))

    def __eq__(self, other):
        return (
            other is not None and
            isinstance(other, IndirectObject) and
            self.idnum == other.idnum and
            self.generation == other.generation and
            self.get_pdf_handler() is other.get_pdf_handler()
            )

    def __ne__(self, other):
        return not self.__eq__(other)

    def write_to_stream(self, stream, encryption_key):
        stream.write(b"%d %d R" % (self.idnum, self.generation))

    @staticmethod
    def read_from_stream(stream, container_ref: 'Dereferenceable'):
        idnum = b""
        while True:
            tok = stream.read(1)
            if not tok:
                # stream has truncated prematurely
                raise PdfStreamError("Stream has ended unexpectedly")
            if tok.isspace():
                break
            idnum += tok
        generation = b""
        while True:
            tok = stream.read(1)
            if not tok:
                # stream has truncated prematurely
                raise PdfStreamError("Stream has ended unexpectedly")
            if tok.isspace():
                if not generation:
                    continue
                break
            generation += tok
        r = read_non_whitespace(stream)
        if r != b"R":
            pos = hex(stream.tell())
            raise PdfReadError(
                "Error reading indirect object reference at byte %s" % pos
            )
        return IndirectObject(
            int(idnum), int(generation), container_ref.get_pdf_handler()
        )


class FloatObject(decimal.Decimal, PdfObject):

    # noinspection PyArgumentList,PyTypeChecker
    def __new__(cls, value="0", context=None):
        try:
            return decimal.Decimal.__new__(cls, str(value), context)
        except (ValueError, decimal.DecimalException):
            return decimal.Decimal.__new__(cls, str(value))

    def __repr__(self):
        if self == self.to_integral():
            return str(self.quantize(decimal.Decimal(1)))
        else:
            return "%g" % self

    def as_numeric(self):
        return float(self)

    def write_to_stream(self, stream, encryption_key):
        stream.write(repr(self).encode('ascii'))


class NumberObject(int, PdfObject):
    NumberPattern = re.compile(b'[^+-.0-9]')
    ByteDot = b"."

    # noinspection PyArgumentList
    def __new__(cls, value):
        val = int(value)
        try:
            return int.__new__(cls, val)
        except OverflowError:
            return int.__new__(cls, 0)

    def as_numeric(self):
        return int(self)

    def write_to_stream(self, stream, encryption_key):
        stream.write(repr(self).encode('ascii'))

    @staticmethod
    def read_from_stream(stream):
        num = read_until_regex(stream, NumberObject.NumberPattern)
        if num.find(NumberObject.ByteDot) != -1:
            return FloatObject(num.decode('ascii'))
        else:
            return NumberObject(num.decode('ascii'))


##
# Given a string (either a "str" or "unicode"), create a ByteStringObject or a
# TextStringObject to represent the string.
def pdf_string(string):
    if isinstance(string, str):
        return TextStringObject(string)
    elif isinstance(string, (bytes, bytearray)):
        try:
            if string.startswith(codecs.BOM_UTF16_BE):
                retval = TextStringObject(string.decode("utf-16"))
                retval.autodetect_utf16 = True
                return retval
            else:
                # This is probably a big performance hit here, but we need to
                # convert string objects into the text/unicode-aware version if
                # possible... and the only way to check if that's possible is
                # to try.  Some strings are strings, some are just byte arrays.
                retval = TextStringObject(decode_pdfdocencoding(string))
                retval.autodetect_pdfdocencoding = True
                return retval
        except UnicodeDecodeError:
            return ByteStringObject(string)
    else:
        raise TypeError("pdf_string should have str or bytes arg")


HEX_DIGITS = b'0123456789abcdefABCDEF'


def read_hex_string_from_stream(stream):
    stream.read(1)

    def read_tokens():
        while True:
            tok = read_non_whitespace(stream)
            if not tok:
                # stream has truncated prematurely
                raise PdfStreamError("Stream has ended unexpectedly")
            elif tok == b">":
                return
            elif tok not in HEX_DIGITS:
                raise PdfStreamError(
                    "Unexpected token in hex string: " + repr(tok)
                )
            yield tok
    result = binascii.unhexlify(b''.join(read_tokens()))
    return pdf_string(result)


def read_string_from_stream(stream):
    stream.read(1)
    parens = 1
    txt = b""
    while True:
        tok = stream.read(1)
        if not tok:
            # stream has truncated prematurely
            raise PdfStreamError("Stream has ended unexpectedly")
        if tok == b"(":
            parens += 1
        elif tok == b")":
            parens -= 1
            if parens == 0:
                break
        elif tok == b"\\":
            tok = stream.read(1)
            if tok in b"() /%<>[]#_&$\\":
                pass  # simply use the second byte we read
            elif tok == b"n":
                tok = b"\n"
            elif tok == b"r":
                tok = b"\r"
            elif tok == b"t":
                tok = b"\t"
            elif tok == b"b":
                tok = b"\b"
            elif tok == b"f":
                tok = b"\f"
            elif tok.isdigit():
                # "The number ddd may consist of one, two, or three
                # octal digits; high-order overflow shall be ignored.
                # Three octal digits shall be used, with leading zeros
                # as needed, if the next character of the string is also
                # a digit." (PDF reference 7.3.4.2, p 16)
                for i in range(2):
                    ntok = stream.read(1)
                    if ntok.isdigit():
                        tok += ntok
                    else:
                        break
                octal = int(tok, base=8)
                # interpret as byte
                tok = bytes((octal,))
            elif tok in b"\n\r":
                # This case is  hit when a backslash followed by a line
                # break occurs.  If it's a multi-char EOL, consume the
                # second character:
                tok = stream.read(1)
                if tok not in b"\n\r":
                    stream.seek(-1, os.SEEK_CUR)
                # Then don't add anything to the actual string, since this
                # line break was escaped:
                tok = b''
            else:
                raise PdfReadError(r"Unexpected escaped string: %s" % tok)
        txt += tok
    return pdf_string(txt)


##
# Represents a string object where the text encoding could not be determined.
# This occurs quite often, as the PDF spec doesn't provide an alternate way to
# represent strings -- for example, the encryption data stored in files (like
# /O) is clearly not text, but is still stored in a "String" object.
class ByteStringObject(bytes, PdfObject):

    ##
    # For compatibility with TextStringObject.original_bytes.  This method
    # returns self.
    original_bytes = property(lambda self: self)

    def write_to_stream(self, stream, encryption_key):
        bytearr = self
        if encryption_key:
            bytearr = rc4_encrypt(encryption_key, bytearr)
        stream.write(b"<")
        stream.write(binascii.hexlify(bytearr))
        stream.write(b">")


##
# Represents a string object that has been decoded into a real unicode string.
# If read from a PDF document, this string appeared to match the
# PDFDocEncoding, or contained a UTF-16BE BOM mark to cause UTF-16 decoding to
# occur.
class TextStringObject(str, PdfObject):
    autodetect_pdfdocencoding = False
    autodetect_utf16 = False

    ##
    # It is occasionally possible that a text string object gets created where
    # a byte string object was expected due to the autodetection mechanism --
    # if that occurs, this "original_bytes" property can be used to
    # back-calculate what the original encoded bytes were.
    original_bytes = property(lambda self: self.get_original_bytes())

    def get_original_bytes(self):
        # We're a text string object, but the library is trying to get our raw
        # bytes.  This can happen if we auto-detected this string as text, but
        # we were wrong.  It's pretty common.  Return the original bytes that
        # would have been used to create this object, based upon the autodetect
        # method.
        if self.autodetect_utf16:
            return codecs.BOM_UTF16_BE + self.encode("utf-16be")
        elif self.autodetect_pdfdocencoding:
            return encode_pdfdocencoding(self)
        else:
            raise Exception("no information about original bytes")

    def write_to_stream(self, stream, encryption_key):
        # Try to write the string out as a PDFDocEncoding encoded string.  It's
        # nicer to look at in the PDF file.  Sadly, we take a performance hit
        # here for trying...
        bytearr: bytes
        try:
            bytearr = encode_pdfdocencoding(self)
        except UnicodeEncodeError:
            bytearr = codecs.BOM_UTF16_BE + self.encode("utf-16be")
        if encryption_key:
            bytearr = rc4_encrypt(encryption_key, bytearr)
            obj = ByteStringObject(bytearr)
            obj.write_to_stream(stream, None)
        else:
            stream.write(b"(")
            for c in bytearr:
                c_ = bytes([c])
                if not c_.isalnum() and c != 0x20:
                    stream.write(b"\\%03o" % c)
                else:
                    stream.write(c_)
            stream.write(b")")


class NameObject(str, PdfObject):
    delimiterPattern = re.compile(r"\s+|[\(\)<>\[\]{}/%]".encode('ascii'))
    surfix = b"/"

    def write_to_stream(self, stream, encryption_key):
        # TODO look up the correct encoding to use in the spec
        #  (although these will be alphanumeric in 99% percent of cases)
        stream.write(self.encode('utf-8'))

    @staticmethod
    def read_from_stream(stream, strict=True):
        name = stream.read(1)
        if name != NameObject.surfix:
            raise PdfReadError("name read error")
        name += read_until_regex(stream, NameObject.delimiterPattern,
                                 ignore_eof=True)
        try:
            return NameObject(name.decode('utf-8'))
        except (UnicodeEncodeError, UnicodeDecodeError):
            # Name objects should represent irregular characters
            # with a '#' followed by the symbol's hex number
            if not strict:
                logger.warning("Illegal character in Name Object")
                return NameObject(name)
            else:
                raise PdfReadError("Illegal character in Name Object")


class DictionaryObject(dict, PdfObject):
    def raw_get(self, key, decrypt=True):
        val = dict.__getitem__(self, key)
        if decrypt and isinstance(val, DecryptedObjectProxy):
            return val.decrypted
        else:
            return val

    def __setitem__(self, key, value):
        if not isinstance(key, PdfObject):
            if isinstance(key, str):
                key = NameObject(key)
            else:
                raise ValueError("key must be PdfObject")
        if not isinstance(value, PdfObject):
            raise ValueError("value must be PdfObject")
        if self.container_ref is not None:
            value.container_ref = self.container_ref
        return dict.__setitem__(self, key, value)

    def setdefault(self, key, value=None):
        if not isinstance(key, PdfObject):
            raise ValueError("key must be PdfObject")
        if not isinstance(value, PdfObject):
            raise ValueError("value must be PdfObject")
        if self.container_ref is not None:
            value.container_ref = self.container_ref
        return dict.setdefault(self, key, value)

    def __getitem__(self, key):
        return dict.__getitem__(self, key).get_object()

    def write_to_stream(self, stream, encryption_key):
        stream.write(b"<<\n")
        for key, value in list(self.items()):
            key.write_to_stream(stream, encryption_key)
            stream.write(b" ")
            value.write_to_stream(stream, encryption_key)
            stream.write(b"\n")
        stream.write(b">>")

    @staticmethod
    def read_from_stream(stream, container_ref: 'Dereferenceable'):
        tmp = stream.read(2)
        if tmp != b"<<":
            raise PdfReadError(
                "Dictionary read error at byte %s: "
                "stream must begin with '<<'" % hex(stream.tell())
            )
        data = {}
        handler = container_ref.get_pdf_handler()
        while True:
            tok = read_non_whitespace(stream)
            if tok == b'\x00':
                continue
            elif tok == b'%':
                stream.seek(-1, os.SEEK_CUR)
                skip_over_comment(stream)
                continue
            if not tok:
                # stream has truncated prematurely
                raise PdfStreamError("Stream has ended unexpectedly")

            if tok == b">":
                stream.read(1)
                break
            stream.seek(-1, os.SEEK_CUR)
            key = read_object(stream, container_ref)
            read_non_whitespace(stream)
            stream.seek(-1, os.SEEK_CUR)
            value = read_object(stream, container_ref)
            if key not in data:
                data[key] = value
            else:
                err = (
                    "Multiple definitions in dictionary at byte "
                    "%s for key %s" % (hex(stream.tell()), key)
                )
                if handler.strict:
                    raise PdfReadError(err)
                else:
                    logger.warning(err)

        pos = stream.tell()
        s = read_non_whitespace(stream, allow_eof=True)
        stream_data = None
        if s == b's' and stream.read(5) == b'tream':
            eol = stream.read(1)
            # odd PDF file output has spaces after 'stream' keyword
            # but before EOL. patch provided by Danial Sandler
            while eol == b' ':
                eol = stream.read(1)
            assert eol in (b"\n", b"\r")
            if eol == b"\r":
                # read \n after
                if stream.read(1) != b'\n':
                    stream.seek(-1, os.SEEK_CUR)
            # this is a stream object, not a dictionary
            length = data[pdf_name("/Length")]
            if isinstance(length, IndirectObject):
                t = stream.tell()
                length = handler.get_object(length)
                stream.seek(t)
            stream_data = stream.read(length)
            e = read_non_whitespace(stream)
            ndstream = stream.read(8)
            if (e + ndstream) != b"endstream":
                # (sigh) - the odd PDF file has a length that is too long, so
                # we need to read backwards to find the "endstream" ending.
                # ReportLab (unknown version) generates files with this bug,
                # and Python users into PDF files tend to be our audience.
                # we need to do this to correct the streamdata and chop off
                # an extra character.
                pos = stream.tell()
                stream.seek(-10, os.SEEK_CUR)
                end = stream.read(9)
                if end == b"endstream":
                    # we found it by looking back one character further.
                    stream_data = stream_data[:-1]
                else:
                    stream.seek(pos)
                    raise PdfReadError(
                        "Unable to find 'endstream' marker after "
                        "stream at byte %s." % hex(stream.tell())
                    )
        else:
            stream.seek(pos)
        if stream_data is not None:
            # pass in everything as encoded data, the StreamObject class
            # will take care of decoding as necessary
            return StreamObject(data, encoded_data=stream_data)
        else:
            return DictionaryObject(data)


class StreamObject(DictionaryObject):
    def __init__(self, dict_data=None, stream_data=None, encoded_data=None,
                 **kwargs):
        dict_data = dict_data or {}
        super().__init__(dict_data, **kwargs)
        self._data = stream_data
        self._encoded_data = encoded_data
        self.decodedSelf = None

    def _filters(self) -> Iterator[Tuple[str, Optional[dict]]]:
        try:
            filter_arr = self[pdf_name('/Filter')]
        except KeyError:
            return

        if isinstance(filter_arr, NameObject):
            # we have a single filter instance
            filter_arr = (filter_arr,)
        elif not isinstance(filter_arr, ArrayObject):
            raise TypeError(
                '/Filter should be a name object or an array of names.'
            )

        try:
            decode_params = self[pdf_name('/DecodeParms')]
            if isinstance(decode_params, DictionaryObject):
                # one instance
                decode_params = (decode_params,)
            if isinstance(decode_params, (ArrayObject, tuple)):
                lendiff = len(filter_arr) - len(decode_params)
                # this should be zero, but let's be lenient
                if lendiff > 0:
                    decode_params += [None] * lendiff
        except KeyError:
            decode_params = [None] * len(filter_arr)

        yield from zip(filter_arr, decode_params)

    def _stream_decoders(self) -> Iterator[Tuple[filters.Decoder, dict]]:
        for filter_type, params in self._filters():
            try:
                if params is None or isinstance(params, NullObject):
                    params = {}
                yield filters.DECODERS[filter_type], params
            except KeyError:
                raise NotImplementedError(
                    "Filters of type %s are not supported." % filter_type
                )

    def strip_filters(self):
        """
        Ensure the stream is decoded, and remove any filters.
        :return:
        """
        self._data = self._encoded_data = self.data
        self.pop(pdf_name('/Filter'))
        self.pop(pdf_name('/DecodeParms'))

    @property
    def data(self):
        if self._data is None:
            data = self._encoded_data
            if data is None:
                return None
            for filter_cls, decode_params in self._stream_decoders():
                data = filter_cls.decode(data, decode_params)
            if isinstance(data, memoryview):
                data = data.tobytes()
            self._data = data
        return self._data

    @property
    def encoded_data(self):
        if self._encoded_data is None:
            data = self._data
            if data is None:
                return None
            decoders = tuple(self._stream_decoders())
            for filter_cls, decode_params in reversed(decoders):
                data = filter_cls.encode(data, decode_params)
            self._encoded_data = data
        return self._encoded_data

    def apply_filter(self, filter_name, params=None,
                     allow_duplicates: Optional[bool] = True):
        """
        Apply a new filter to this stream. This filter will be prepended
        to any existing filters.
        This means that is is placed *last* in the encoding order, but first
        in the decoding order.

        :param filter_name:
            Name of the filter (see filters.DECODERS)
        :param params:
            Parameters to the filter (will be written to /DecodeParms)
        :param allow_duplicates:
            If None, silently ignore duplicate filters.
            If False, raise ValueError when attempting to add a duplicate
            filter. If True (default), duplicate filters are allowed.
        :return:
        """
        # first, grab a decoded copy of the data
        data = self.data

        # ... and list all current filters with their parameters.
        cur_filters = list(self._filters())
        # normalise the input parameters
        if not isinstance(filter_name, NameObject):
            filter_name = pdf_name(filter_name)
        if params is not None and not isinstance(params, DictionaryObject):
            params = DictionaryObject(params)
        if not cur_filters:
            # only one filter, so don't write arrays
            self[pdf_name('/Filter')] = filter_name
            if params:
                self[pdf_name('/DecodeParms')] = params
        else:
            # split cur_filters back into two pieces
            filter_names, param_sets = zip(*cur_filters)
            if not allow_duplicates and filter_name in filter_names:
                if allow_duplicates is False:
                    raise ValueError(
                        f'Filter {filter_name} has already been applied to '
                        f'this stream.'
                    )
                else:
                    # Silently ignore
                    return

            # prepend the new filter (order is important!)
            self[pdf_name('/Filter')] = [pdf_name] + filter_names

            if params or any(param_sets):
                self[pdf_name('/DecodeParms')] = [params or NullObject()] + [
                    param_set or NullObject() for param_set in param_sets
                ]
        self._encoded_data = None
        self._data = data

    def compress(self):
        """
        Convenience method to add a /FlateDecode filter with default settings,
        if one is not already present.
        Note: compression is not actually applied until the stream is written.
        """
        self.apply_filter(pdf_name('/FlateDecode'), allow_duplicates=None)

    def write_to_stream(self, stream, encryption_key):
        data = self.encoded_data
        self[NameObject("/Length")] = NumberObject(len(data))
        # write the dictionary
        super().write_to_stream(stream, encryption_key)
        del self["/Length"]
        stream.write(b"\nstream\n")
        if encryption_key:
            data = rc4_encrypt(encryption_key, data)
        stream.write(data)
        stream.write(b"\nendstream")


def encode_pdfdocencoding(unicode_string):
    def _build():
        for c in unicode_string:
            try:
                yield _pdfDocEncoding_rev[c]
            except KeyError:
                raise UnicodeEncodeError(
                    "pdfdocencoding", c, -1, -1,
                    "does not exist in translation table"
                )
    return bytes(_build())


def decode_pdfdocencoding(byte_array):
    def _build():
        for b in byte_array:
            c = _pdfDocEncoding[b]
            if c == '\u0000':
                raise UnicodeDecodeError(
                    "pdfdocencoding", bytes((b,)), -1, -1,
                    "does not exist in translation table"
                )
            yield c
    return ''.join(_build())


_pdfDocEncoding = (
 '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000',
 '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000',
 '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000', '\u0000',
 '\u02d8', '\u02c7', '\u02c6', '\u02d9', '\u02dd', '\u02db', '\u02da', '\u02dc',
 '\u0020', '\u0021', '\u0022', '\u0023', '\u0024', '\u0025', '\u0026', '\u0027',
 '\u0028', '\u0029', '\u002a', '\u002b', '\u002c', '\u002d', '\u002e', '\u002f',
 '\u0030', '\u0031', '\u0032', '\u0033', '\u0034', '\u0035', '\u0036', '\u0037',
 '\u0038', '\u0039', '\u003a', '\u003b', '\u003c', '\u003d', '\u003e', '\u003f',
 '\u0040', '\u0041', '\u0042', '\u0043', '\u0044', '\u0045', '\u0046', '\u0047',
 '\u0048', '\u0049', '\u004a', '\u004b', '\u004c', '\u004d', '\u004e', '\u004f',
 '\u0050', '\u0051', '\u0052', '\u0053', '\u0054', '\u0055', '\u0056', '\u0057',
 '\u0058', '\u0059', '\u005a', '\u005b', '\u005c', '\u005d', '\u005e', '\u005f',
 '\u0060', '\u0061', '\u0062', '\u0063', '\u0064', '\u0065', '\u0066', '\u0067',
 '\u0068', '\u0069', '\u006a', '\u006b', '\u006c', '\u006d', '\u006e', '\u006f',
 '\u0070', '\u0071', '\u0072', '\u0073', '\u0074', '\u0075', '\u0076', '\u0077',
 '\u0078', '\u0079', '\u007a', '\u007b', '\u007c', '\u007d', '\u007e', '\u0000',
 '\u2022', '\u2020', '\u2021', '\u2026', '\u2014', '\u2013', '\u0192', '\u2044',
 '\u2039', '\u203a', '\u2212', '\u2030', '\u201e', '\u201c', '\u201d', '\u2018',
 '\u2019', '\u201a', '\u2122', '\ufb01', '\ufb02', '\u0141', '\u0152', '\u0160',
 '\u0178', '\u017d', '\u0131', '\u0142', '\u0153', '\u0161', '\u017e', '\u0000',
 '\u20ac', '\u00a1', '\u00a2', '\u00a3', '\u00a4', '\u00a5', '\u00a6', '\u00a7',
 '\u00a8', '\u00a9', '\u00aa', '\u00ab', '\u00ac', '\u0000', '\u00ae', '\u00af',
 '\u00b0', '\u00b1', '\u00b2', '\u00b3', '\u00b4', '\u00b5', '\u00b6', '\u00b7',
 '\u00b8', '\u00b9', '\u00ba', '\u00bb', '\u00bc', '\u00bd', '\u00be', '\u00bf',
 '\u00c0', '\u00c1', '\u00c2', '\u00c3', '\u00c4', '\u00c5', '\u00c6', '\u00c7',
 '\u00c8', '\u00c9', '\u00ca', '\u00cb', '\u00cc', '\u00cd', '\u00ce', '\u00cf',
 '\u00d0', '\u00d1', '\u00d2', '\u00d3', '\u00d4', '\u00d5', '\u00d6', '\u00d7',
 '\u00d8', '\u00d9', '\u00da', '\u00db', '\u00dc', '\u00dd', '\u00de', '\u00df',
 '\u00e0', '\u00e1', '\u00e2', '\u00e3', '\u00e4', '\u00e5', '\u00e6', '\u00e7',
 '\u00e8', '\u00e9', '\u00ea', '\u00eb', '\u00ec', '\u00ed', '\u00ee', '\u00ef',
 '\u00f0', '\u00f1', '\u00f2', '\u00f3', '\u00f4', '\u00f5', '\u00f6', '\u00f7',
 '\u00f8', '\u00f9', '\u00fa', '\u00fb', '\u00fc', '\u00fd', '\u00fe', '\u00ff'
)

assert len(_pdfDocEncoding) == 256

_pdfDocEncoding_rev = {char: ix for ix, char in enumerate(_pdfDocEncoding)}

pdf_name = NameObject
PROXYABLE = (TextStringObject, ByteStringObject, DictionaryObject, ArrayObject)


def proxy_encrypted_obj(encrypted_obj, key):
    if isinstance(encrypted_obj, PROXYABLE):
        return DecryptedObjectProxy(encrypted_obj, key)
    else:
        return encrypted_obj


# TODO support 2.0-style encryption
class DecryptedObjectProxy(PdfObject):

    def __init__(self, raw_object: PdfObject, key):
        self.raw_object = raw_object
        self.key = key
        self._decrypted = None

    @property
    def decrypted(self):
        decrypted = self._decrypted
        if decrypted is not None:
            return decrypted

        obj = self.raw_object
        key = self.key
        if isinstance(obj, ByteStringObject) or \
                isinstance(obj, TextStringObject):
            decrypted = pdf_string(rc4_encrypt(key, obj.original_bytes))
        elif isinstance(obj, DictionaryObject):
            decrypted_entries = {
                dictkey: proxy_encrypted_obj(value, key)
                for dictkey, value in obj.items()
            }
            if isinstance(obj, StreamObject):
                # TODO add tests for this specific use case!
                decrypted = StreamObject(
                    decrypted_entries,
                    encoded_data=rc4_encrypt(key, obj.encoded_data)
                )
            else:
                decrypted = DictionaryObject(decrypted_entries)
        elif isinstance(obj, ArrayObject):
            decrypted_map = map(lambda v: proxy_encrypted_obj(v, key), obj)
            decrypted = ArrayObject(decrypted_map)
        else:
            raise TypeError(f'Object of type {type(obj)} is not proxyable.')
        decrypted.container_ref = obj.container_ref
        self._decrypted = decrypted
        return decrypted

    def write_to_stream(self, stream, encryption_key):
        # maybe the encryption key for this object changed (due to it being
        # included as part of a larger object or somesuch, without proper
        # dereferencing), so to avoid unexpected shenanigans, let's start from
        # scratch.
        self.decrypted.write_to_stream(stream, encryption_key)

    def get_object(self):
        return self.decrypted

    @property
    def container_ref(self):
        return self.raw_object.container_ref


ASN_DT_FORMAT = "D:%Y%m%d%H%M%S"


def pdf_date(dt: datetime):
    base_dt = dt.strftime(ASN_DT_FORMAT)
    utc_offset_string = ''
    if dt.tzinfo is not None:
        # compute UTC off set string
        tz_seconds = dt.utcoffset().seconds
        if not tz_seconds:
            utc_offset_string = 'Z'
        else:
            sign = '+'
            if tz_seconds < 0:
                sign = '-'
                tz_seconds = abs(tz_seconds)
            hrs, tz_seconds = divmod(tz_seconds, 3600)
            mins = tz_seconds // 60
            # XXX the apostrophe after the minute part of the offset is NOT
            #  what's in the spec, but Adobe Reader DC refuses to validate
            #  signatures with a date string that doesn't contain it.
            #  No idea why.
            utc_offset_string = sign + ("%02d'%02d'" % (hrs, mins))

    return pdf_string(base_dt + utc_offset_string)


class PdfContent:

    def __init__(self, parent: Optional['PdfContent'],
                 box: BoxConstraints = None):
        self._resources = parent.resources if parent is not None \
            else DictionaryObject()
        self.box = box or BoxConstraints()

    # TODO support a set-if-not-taken mechanism, that suggests alternative names
    #  if necessary.
    def set_resource(self, category: NameObject, name: NameObject,
                     value: PdfObject):
        try:
            cat_dict = self._resources[category]
        except KeyError:
            self._resources[category] = cat_dict = DictionaryObject()
        cat_dict[name] = value

    @property
    def resources(self):
        return self._resources

    def render(self) -> bytes:
        """
        Compile the content to graphics operators.
        """
        raise NotImplementedError

    # TODO allow the bounding box to be overridden/refitted
    #  (using matrix transforms)
    def as_form_xobject(self):
        from pdf_utils.writer import init_xobject_dictionary
        command_stream = self.render()
        return init_xobject_dictionary(
            command_stream=command_stream, box_width=self.box.width,
            box_height=self.box.height, resources=self._resources
        )

    # TODO add methods to append to a page, as a separate content stream
    #  or to an existing one

    # TODO override __add__ method: concat streams and merge all resources


class RawContent(PdfContent):

    def __init__(self, parent: Optional[PdfContent],
                 data: bytes, box: BoxConstraints = None):
        super().__init__(parent, box)
        self.data = data

    def render(self) -> bytes:
        return self.data
