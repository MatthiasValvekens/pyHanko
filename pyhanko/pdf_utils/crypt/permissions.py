import operator
import struct
from enum import Flag
from functools import reduce


class PdfPermissions(Flag):

    @classmethod
    def allow_everything(cls):
        return reduce(operator.or_, cls.__members__.values())

    @classmethod
    def from_uint(cls, uint_flags: int):
        result = cls(0)
        for flag in cls:
            if uint_flags & flag.value:
                result |= flag
        return result

    @classmethod
    def from_bytes(cls, flags: bytes):
        uint_flags = struct.unpack('>I', flags)[0]
        return cls.from_uint(uint_flags)

    @classmethod
    def from_sint32(cls, sint32_flags: int):
        return cls.from_uint(sint32_flags & 0xFFFFFFFF)

    def as_uint32(self):
        raise NotImplementedError

    def as_bytes(self) -> bytes:
        return struct.pack('>I', self.as_uint32())

    def as_sint32(self) -> int:
        return struct.unpack('>i', self.as_bytes())[0]


class StandardPermissions(PdfPermissions, Flag):
    # We purposefully do not inherit from IntFlag since
    # PDF uses 32-bit twos complement to treat flags as ints,
    # which doesn't jive well with what IntFlag would do,
    # so it's hard to detect backwards compatibility issues.

    ALLOW_PRINTING = 4
    ALLOW_MODIFICATION_GENERIC = 8
    ALLOW_CONTENT_EXTRACTION = 16
    ALLOW_ANNOTS_FORM_FILLING = 32
    ALLOW_FORM_FILLING = 256
    ALLOW_ASSISTIVE_TECHNOLOGY = 512
    ALLOW_REASSEMBLY = 1024
    ALLOW_HIGH_QUALITY_PRINTING = 2048

    def as_uint32(self):
        return sum(x.value for x in self.__class__ if x in self) | 0xFFFFF0C0


class PubKeyPermissions(PdfPermissions, Flag):
    ALLOW_ENCRYPTION_CHANGE = 2
    ALLOW_PRINTING = 4
    ALLOW_MODIFICATION_GENERIC = 8
    ALLOW_CONTENT_EXTRACTION = 16
    ALLOW_ANNOTS_FORM_FILLING = 32
    ALLOW_FORM_FILLING = 256
    ALLOW_ASSISTIVE_TECHNOLOGY = 512
    ALLOW_REASSEMBLY = 1024
    ALLOW_HIGH_QUALITY_PRINTING = 2048

    def as_uint32(self):
        # ensure the first bit is set for compatibility with Acrobat
        return sum(x.value for x in self.__class__ if x in self) | 0xFFFFF0C1
