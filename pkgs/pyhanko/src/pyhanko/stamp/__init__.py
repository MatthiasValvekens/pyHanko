"""
Utilities for stamping PDF files.

Here 'stamping' loosely refers to adding small overlays (QR codes, text boxes,
etc.) on top of already existing content in PDF files.

The code in this package is also used by the :package:`pyhanko.sign`
package to render signature appearances.
"""

from .appearances import AnnotAppearances, CoordinateSystem
from .art import STAMP_ART_CONTENT
from .base import BaseStamp, BaseStampStyle
from .functions import qr_stamp_file, text_stamp_file
from .qr import QRPosition, QRStamp, QRStampStyle
from .static import StaticContentStamp, StaticStampStyle
from .text import TextStamp, TextStampStyle

__all__ = [
    "STAMP_ART_CONTENT",
    "AnnotAppearances",
    "BaseStamp",
    "BaseStampStyle",
    "CoordinateSystem",
    "QRPosition",
    "QRStamp",
    "QRStampStyle",
    "StaticContentStamp",
    "StaticStampStyle",
    "TextStamp",
    "TextStampStyle",
    "qr_stamp_file",
    "text_stamp_file",
]
