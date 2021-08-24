from fractions import Fraction
from pathlib import Path

import pytest

from pyhanko.pdf_utils import generic, layout, writer
from pyhanko.pdf_utils.content import ImportedPdfPage, RawContent
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.stamp import (
    STAMP_ART_CONTENT,
    QRPosition,
    QRStamp,
    QRStampStyle,
    StaticStampStyle,
    TextStamp,
    TextStampStyle,
    qr_stamp_file,
    text_stamp_file,
)

from .layout_test_utils import compare_output, with_layout_comparison
from .samples import *

FONT_DIR = 'pyhanko_tests/data/fonts'
NOTO_SERIF_JP = f'{FONT_DIR}/NotoSerifJP-Regular.otf'
NOTO_SANS_ARABIC = f'{FONT_DIR}/NotoSansArabic-Regular.ttf'
NOTO_SANS = f'{FONT_DIR}/NotoSans-Regular.ttf'

EXPECTED_OUTPUT_DIR = 'pyhanko_tests/data/pdf/layout-tests'


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


def test_simple_qr_noto_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"

    ga_factory = GlyphAccumulatorFactory(NOTO_SERIF_JP)
    qr_stamp_file(
        MINIMAL_PATH, str(outfile),
        QRStampStyle(stamp_text="Hi, it's\n%(ts)s",
                     text_box_style=TextBoxStyle(font=ga_factory)),
        dest_page=0, x=70, y=50, url='https://example.com',

    )


def empty_page():
    w = writer.PdfFileWriter(stream_xrefs=False)
    page = writer.PageObject(
        contents=w.add_object(generic.StreamObject(stream_data=b'')),
        media_box=generic.ArrayObject([0, 0, 595, 842])
    )
    w.insert_page(page)
    return w


@with_layout_comparison
def test_arabic_box():
    w = empty_page()
    style = TextStampStyle(
        stamp_text='اَلْفُصْحَىٰ',
        text_box_style=TextBoxStyle(
            font=GlyphAccumulatorFactory(NOTO_SANS_ARABIC),
        ),
        inner_content_layout=layout.SimpleBoxLayoutRule(
            x_align=layout.AxisAlignment.ALIGN_MID,
            y_align=layout.AxisAlignment.ALIGN_MID,
            inner_content_scaling=layout.InnerScaling.STRETCH_TO_FIT,
            margins=layout.Margins.uniform(5)
        )
    )
    ts = TextStamp(
        writer=w, style=style, box=layout.BoxConstraints(width=300, height=200)
    )
    ts.apply(0, x=10, y=60)

    compare_output(
        writer=w, expected_output_path=f'{EXPECTED_OUTPUT_DIR}/arabic-box.pdf'
    )


@with_layout_comparison
@pytest.mark.parametrize('fixed_size', [True, False])
def test_four_qr_stamps(fixed_size):
    # Share a font subset, the text is the same everywhere
    gaf = GlyphAccumulatorFactory(NOTO_SANS, font_size=10)
    w = empty_page()
    positions = ((10, 700), (10, 500), (10, 10), (260, 10))
    for qr_pos, (x, y) in zip(QRPosition, positions):
        style = QRStampStyle(
            stamp_text='Test stamp text\nAnother line of text',
            text_box_style=TextBoxStyle(font=gaf),
            qr_position=qr_pos, background=STAMP_ART_CONTENT,
            background_opacity=0.4
        )
        if fixed_size:
            if qr_pos.horizontal_flow:
                box = layout.BoxConstraints(width=300, height=100)
            else:
                box = layout.BoxConstraints(width=100, height=300)
        else:
            box = None
        ts = QRStamp(
            writer=w, style=style, box=box, url='https://example.com'
        )
        ts.apply(0, x=x, y=y)
    postfix = 'fixed' if fixed_size else 'natural'
    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/four-stamps-{postfix}.pdf')


@with_layout_comparison
def test_japanese_vertical_text_stamp():
    gaf = GlyphAccumulatorFactory(
        NOTO_SERIF_JP, font_size=10, writing_direction='ttb'
    )
    w = empty_page()
    style = QRStampStyle(
        stamp_text=(
            'テスト\n縦書きテスト\n改行してみましょう（括弧）\nPDF\n'
            'ちょっと長めの文を書いてみた。'
        ),
        text_box_style=TextBoxStyle(font=gaf, vertical_text=True),
        qr_position=QRPosition.ABOVE_TEXT,
        background=STAMP_ART_CONTENT,
        background_opacity=0.4
    )
    box = layout.BoxConstraints(width=100, height=300)
    ts = QRStamp(writer=w, style=style, box=box, url='https://example.com')
    ts.apply(0, x=10, y=415)
    ts = QRStamp(writer=w, style=style, box=None, url='https://example.com')
    ts.apply(0, x=400, y=415)
    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/ja-vert-stamps.pdf')


@with_layout_comparison
def test_stamp_with_unscaled_bitmap_bg():
    w = empty_page()

    long_text = '\n'.join(
        'Test test test test test test test test test '
        'on a bitmap background!'
        for _ in range(60)
    )
    style = TextStampStyle(
        stamp_text=long_text,
        background=PdfImage('pyhanko_tests/data/img/stamp-indexed.png'),
    )

    ts = TextStamp(w, style)
    ts.apply(0, x=30, y=120)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/bitmap-bg.pdf')


@with_layout_comparison
def test_stamp_with_scaled_bitmap_bg():
    w = empty_page()

    text = '\n'.join(
        'Test test test test on a bitmap background!'
        for _ in range(3)
    )
    style = TextStampStyle(
        stamp_text=text,
        background=PdfImage('pyhanko_tests/data/img/stamp-indexed.png'),
    )

    ts = TextStamp(w, style, box=layout.BoxConstraints(400, 100))
    ts.apply(0, x=30, y=600)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/scaled-bitmap-bg.pdf')


@with_layout_comparison
def test_stamp_with_undefined_bg_size():
    w = empty_page()

    undef_bg = RawContent(data=STAMP_ART_CONTENT.data)

    long_text = '\n'.join(
        'Test test test test test test test test test '
        'on an ill-defined background!'
        for _ in range(60)
    )
    style = TextStampStyle(
        stamp_text=long_text,
        background=undef_bg
    )

    ts = TextStamp(w, style)
    ts.apply(0, x=30, y=120)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/undef-bg-size.pdf')


@with_layout_comparison
def test_stamp_with_scaled_pdf_bg():
    w = empty_page()

    text = '\n'.join(
        'Test test test test on a PDF background!'
        for _ in range(3)
    )
    style = TextStampStyle(
        stamp_text=text,
        background=ImportedPdfPage(
            'pyhanko_tests/data/pdf/pdf-background-test.pdf'
        ),
    )

    ts = TextStamp(w, style, box=layout.BoxConstraints(200, 50))
    ts.apply(0, x=30, y=600)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/stamp-on-pdf-bg.pdf')


@with_layout_comparison
def test_stamp_with_fixed_pdf_content():
    w = empty_page()

    style = StaticStampStyle.from_pdf_file(
        'pyhanko_tests/data/pdf/pdf-background-test.pdf'
    )

    stamp = style.create_stamp(
        w, box=layout.BoxConstraints(200, 50), text_params={}
    )
    stamp.apply(0, x=30, y=600)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/stamp-from-static-pdf.pdf')


@pytest.mark.parametrize(
    'box', [
        None, layout.BoxConstraints(width=200),
        layout.BoxConstraints(height=50),
        layout.BoxConstraints(aspect_ratio=Fraction(4, 1)),
        layout.BoxConstraints()
    ]
)
def test_static_stamp_enforce_box_defined(box):
    w = empty_page()

    style = StaticStampStyle.from_pdf_file(
        'pyhanko_tests/data/pdf/pdf-background-test.pdf'
    )

    with pytest.raises(layout.LayoutError, match="predetermined bounding box"):
        style.create_stamp(w, box=box, text_params={})
