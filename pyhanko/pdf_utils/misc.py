"""
Utility functions for PDF library.
Taken from PyPDF2 with modifications and additions, see
:ref:`here <pypdf2-license>` for the original license of the PyPDF2 project.
"""


import os
from enum import Enum

__all__ = [
    'PdfError', 'PdfReadError', 'PdfWriteError', 'PdfStreamError'
]

from typing import Callable

rd = lambda x: round(x, 4)


def instance_test(cls):

    return lambda x: isinstance(x, cls)


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


class PdfError(Exception):
    pass


class PdfReadError(PdfError):
    pass


class PdfWriteError(PdfError):
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


def get_courier():
    from .generic import pdf_name, DictionaryObject
    return DictionaryObject({
        pdf_name('/Type'): pdf_name('/Font'),
        pdf_name('/Subtype'): pdf_name('/Type1'),
        pdf_name('/BaseFont'): pdf_name('/Courier')
    })


class OrderedEnum(Enum):
    """
    Ordered enum (from the Python documentation)
    """

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class LazyJoin:

    def __init__(self, sep, iterator):
        self.sep = sep
        self.iterator = iterator

    def __str__(self):
        return self.sep.join(self.iterator)


def get_and_apply(dictionary: dict, key, function: Callable, *, default=None):
    try:
        value = dictionary[key]
    except KeyError:
        return default
    return function(value)
