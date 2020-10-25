import os
from fractions import Fraction
from typing import Optional

"""
Utility functions for PDF library.
Taken from PyPDF2 with modifications (see LICENSE.PyPDF2).
"""


rd = lambda x: round(x, 4)


def pair_iter(lst):
    i = iter(lst)
    while True:
        try:
            x1 = next(i)
        except StopIteration:
            return
        try:
            x2 = next(i)
        except StopIteration:
            raise ValueError('List has odd number of elements')
        yield x1, x2


def read_until_whitespace(stream, maxchars=None):
    """
    Reads non-whitespace characters and returns them.
    Stops upon encountering whitespace or when maxchars is reached.
    """
    if maxchars == 0:
        return b''

    def _build():
        stop_at = None if maxchars is None else stream.tell() + maxchars
        while maxchars is None or stream.tell() < stop_at:
            tok = stream.read(1)
            if tok.isspace() or not tok:
                break
            yield tok
    return b''.join(_build())


PDF_WHITESPACE = b' \n\r\t\x00'


def read_non_whitespace(stream, seek_back=False, allow_eof=False):
    """
    Finds and reads the next non-whitespace character (ignores whitespace).
    """
    tok = PDF_WHITESPACE[0]
    while tok in PDF_WHITESPACE:
        if not tok:
            if allow_eof:
                return b''
            else:
                raise PdfStreamError('Stream ended prematurely')
        tok = stream.read(1)
    if seek_back:
        stream.seek(-1, os.SEEK_CUR)
    return tok


def skip_over_whitespace(stream):
    """
    Similar to readNonWhitespace, but returns a Boolean if more than
    one whitespace character was read.
    """
    tok = PDF_WHITESPACE[0]
    cnt = 0
    while tok in PDF_WHITESPACE:
        tok = stream.read(1)
        cnt += 1
    return cnt > 1


def skip_over_comment(stream):
    tok = stream.read(1)
    stream.seek(-1, 1)
    if tok == b'%':
        while tok not in (b'\n', b'\r'):
            tok = stream.read(1)


def read_until_regex(stream, regex, ignore_eof=False):
    """
    Reads until the regular expression pattern matched (ignore the match)
    Raise PdfStreamError on premature end-of-file.
    :param bool ignore_eof: If true, ignore end-of-line and return immediately
    :param regex: regex to match
    :param stream: stream to search
    """
    name = b''
    while True:
        tok = stream.read(16)
        if not tok:
            # stream has truncated prematurely
            if ignore_eof:
                return name
            else:
                raise PdfStreamError("Stream has ended unexpectedly")
        m = regex.search(tok)
        if m is not None:
            name += tok[:m.start()]
            stream.seek(m.start()-len(tok), 1)
            break
        name += tok
    return name


class PyPdfError(Exception):
    pass


class PdfReadError(PyPdfError):
    pass


class PageSizeNotDefinedError(PyPdfError):
    pass


class PdfStreamError(PdfReadError):
    pass


def peek(itr):
    itr = iter(itr)
    first = next(itr)

    def _itr():
        yield first
        yield from itr

    return first, _itr()


class BoxSpecificationError(ValueError):
    pass


class BoxConstraints:
    _width: Optional[int]
    _height: Optional[int]
    _ar: Optional[Fraction]
    _fully_specified: bool

    def __init__(self, width=None, height=None, aspect_ratio: Fraction=None):
        self._width = int(width) if width is not None else None
        self._height = int(height) if height is not None else None

        fully_specified = False

        self._ar = None
        if width is None and height is None and aspect_ratio is None:
            return
        elif width is not None and height is not None:
            if aspect_ratio is not None:
                raise BoxSpecificationError  # overspecified
            self._ar = Fraction(width, height)
            fully_specified = True
        elif aspect_ratio is not None:
            self._ar = aspect_ratio
            if height is not None:
                self._width = height * aspect_ratio
            elif width is not None:
                self._height = width / aspect_ratio

        self._fully_specified = fully_specified

    def _recalculate(self):
        if self._width is not None and self._height is not None:
            self._ar = Fraction(self._width, self._height)
            self._fully_specified = True
        elif self._ar is not None:
            if self._height is not None:
                self._width = int(self._height * self._ar)
                self._fully_specified = True
            elif self._width is not None:
                self._height = int(self._width / self._ar)
                self._fully_specified = True

    @property
    def width(self) -> int:
        if self._width is not None:
            return self._width
        else:
            raise BoxSpecificationError

    @width.setter
    def width(self, width):
        if self._width is None:
            self._width = width
            self._recalculate()
        else:
            raise BoxSpecificationError

    @property
    def width_defined(self) -> bool:
        return self._width is not None

    @property
    def height(self) -> int:
        if self._height is not None:
            return self._height
        else:
            raise BoxSpecificationError

    @height.setter
    def height(self, height):
        if self._height is None:
            self._height = height
            self._recalculate()
        else:
            raise BoxSpecificationError

    @property
    def height_defined(self) -> bool:
        return self._height is not None

    @property
    def aspect_ratio(self) -> Fraction:
        if self._ar is not None:
            return self._ar
        else:
            raise BoxSpecificationError

    @property
    def aspect_ratio_defined(self) -> bool:
        return self._ar is not None


def get_courier():
    from .generic import pdf_name, DictionaryObject
    return DictionaryObject({
        pdf_name('/Type'): pdf_name('/Font'),
        pdf_name('/Subtype'): pdf_name('/Type1'),
        pdf_name('/BaseFont'): pdf_name('/Courier')
    })
