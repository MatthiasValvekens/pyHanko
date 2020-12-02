from pathlib import Path
from pyhanko.pdf_utils.font import GlyphAccumulatorFactory
from pyhanko.pdf_utils.text import TextBoxStyle
from .samples import *

from pyhanko.stamp import (
    text_stamp_file, qr_stamp_file, TextStampStyle,
    QRStampStyle,
)


def test_simple_text_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"
    text_stamp_file(
        MINIMAL_PATH, str(outfile),
        TextStampStyle(stamp_text="Hi, it's\n%(ts)s"), dest_page=0, x=70, y=50
    )


def test_simple_qr_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"
    qr_stamp_file(
        MINIMAL_PATH, str(outfile),
        QRStampStyle(stamp_text="Hi, it's\n%(ts)s"),
        dest_page=0, x=70, y=50, url='https://example.com'
    )


NOTO_SERIF_JP = 'pyhanko_tests/data/fonts/NotoSerifJP-Regular.otf'


def test_simple_qr_noto_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"

    ga_factory = GlyphAccumulatorFactory(NOTO_SERIF_JP)
    qr_stamp_file(
        MINIMAL_PATH, str(outfile),
        QRStampStyle(stamp_text="Hi, it's\n%(ts)s",
                     text_box_style=TextBoxStyle(font=ga_factory)),
        dest_page=0, x=70, y=50, url='https://example.com',

    )
