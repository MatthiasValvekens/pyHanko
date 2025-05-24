import os
from fractions import Fraction
from io import BytesIO
from pathlib import Path

import pytest
from pyhanko.pdf_utils import generic, layout, writer
from pyhanko.pdf_utils.content import ImportedPdfPage, RawContent
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import (
    AxisAlignment,
    LayoutError,
    Margins,
    SimpleBoxLayoutRule,
)
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.stamp import (
    STAMP_ART_CONTENT,
    CoordinateSystem,
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

FONT_DIR = f'{TEST_DIR}/data/fonts'

# Noto fonts are licensed under the OFL
NOTO_SERIF_JP = f'{FONT_DIR}/NotoSerifJP-Regular.otf'
NOTO_SANS_ARABIC = f'{FONT_DIR}/NotoSansArabic-Regular.ttf'
NOTO_SANS = f'{FONT_DIR}/NotoSans-Regular.ttf'

# This font is licensed under a modified version of the GPLv3.
# See https://www.gnu.org/software/freefont/license.html
# We're only using it here because it's a useful example of a string-keyed
# CFF font.
FREE_SERIF = f'{FONT_DIR}/FreeSerif.otf'
EXPECTED_OUTPUT_DIR = f'{TEST_DIR}/data/pdf/layout-tests'


def test_simple_text_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"
    text_stamp_file(
        MINIMAL_PATH,
        str(outfile),
        TextStampStyle(stamp_text="Hi, it's\n%(ts)s"),
        dest_page=0,
        x=70,
        y=50,
    )


def test_simple_text_stamp_missing_params(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"
    msg = "Stamp text parameter 'foo' is missing"
    with pytest.raises(LayoutError, match=msg):
        text_stamp_file(
            MINIMAL_PATH,
            str(outfile),
            TextStampStyle(stamp_text="%(foo)s missing"),
            dest_page=0,
            x=70,
            y=50,
        )


def test_simple_qr_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"
    qr_stamp_file(
        MINIMAL_PATH,
        str(outfile),
        QRStampStyle(stamp_text="Hi, it's\n%(ts)s"),
        dest_page=0,
        x=70,
        y=50,
        url='https://example.com',
    )


def test_simple_qr_noto_stamp(tmp_path):
    outfile: Path = tmp_path / "test-out.pdf"

    ga_factory = GlyphAccumulatorFactory(NOTO_SERIF_JP)
    qr_stamp_file(
        MINIMAL_PATH,
        str(outfile),
        QRStampStyle(
            stamp_text="Hi, it's\n%(ts)s",
            text_box_style=TextBoxStyle(font=ga_factory),
        ),
        dest_page=0,
        x=70,
        y=50,
        url='https://example.com',
    )


def empty_page(stream_xrefs=False):
    w = writer.PdfFileWriter(stream_xrefs=stream_xrefs)
    page = writer.PageObject(
        contents=w.add_object(generic.StreamObject(stream_data=b'')),
        media_box=generic.ArrayObject([0, 0, 595, 842]),
    )
    w.insert_page(page)
    return w


def _arabic_text_page(stream_xrefs):
    w = empty_page(stream_xrefs=stream_xrefs)
    style = TextStampStyle(
        stamp_text='اَلْفُصْحَىٰ',
        text_box_style=TextBoxStyle(
            font=GlyphAccumulatorFactory(NOTO_SANS_ARABIC),
        ),
        inner_content_layout=layout.SimpleBoxLayoutRule(
            x_align=layout.AxisAlignment.ALIGN_MID,
            y_align=layout.AxisAlignment.ALIGN_MID,
            inner_content_scaling=layout.InnerScaling.STRETCH_TO_FIT,
            margins=layout.Margins.uniform(5),
        ),
    )
    ts = TextStamp(
        writer=w, style=style, box=layout.BoxConstraints(width=300, height=200)
    )
    ts.apply(0, x=10, y=60)
    return w


@with_layout_comparison
def test_arabic_box():
    w = _arabic_text_page(stream_xrefs=False)
    compare_output(
        writer=w, expected_output_path=f'{EXPECTED_OUTPUT_DIR}/arabic-box.pdf'
    )


@with_layout_comparison
def test_fonts_with_obj_streams():
    # this should automatically put some stuff in object streams
    w = _arabic_text_page(stream_xrefs=True)
    compare_output(
        writer=w, expected_output_path=f'{EXPECTED_OUTPUT_DIR}/arabic-box.pdf'
    )
    assert w.objs_in_streams


@pytest.mark.parametrize('stream_xrefs', [True, False])
@with_layout_comparison
def test_font_rewrite_idempotent(stream_xrefs):
    # There was a bug in the font embedding logic that would cause multiple
    # writes of the same file to fail.
    w = _arabic_text_page(stream_xrefs)
    out1 = BytesIO()
    w.write(out1)
    out2 = BytesIO()
    w.write(out2)
    assert abs(out1.seek(0, os.SEEK_END) - out2.seek(0, os.SEEK_END)) < 100


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
            qr_position=qr_pos,
            background=STAMP_ART_CONTENT,
            background_opacity=0.4,
        )
        if fixed_size:
            if qr_pos.horizontal_flow:
                box = layout.BoxConstraints(width=300, height=100)
            else:
                box = layout.BoxConstraints(width=100, height=300)
        else:
            box = None
        ts = QRStamp(writer=w, style=style, box=box, url='https://example.com')
        ts.apply(0, x=x, y=y)
    postfix = 'fixed' if fixed_size else 'natural'
    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/four-stamps-{postfix}.pdf')


@with_layout_comparison
def test_fancy_qr_stamp():
    w = empty_page()
    style = QRStampStyle(
        stamp_text='Test stamp text\nAnother line of text',
        qr_inner_content=STAMP_ART_CONTENT,
    )
    box = layout.BoxConstraints(width=300, height=100)
    QRStamp(writer=w, style=style, box=box, url='https://example.com').apply(
        0, x=10, y=500
    )

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/fancy-qr-stamp-test.pdf')


@with_layout_comparison
def test_japanese_vertical_text_stamp():
    gaf = GlyphAccumulatorFactory(
        NOTO_SERIF_JP,
        font_size=10,
        writing_direction='ttb',
        bcp47_lang_code='ja_JP',
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
        background_opacity=0.4,
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
        background=PdfImage(f'{TEST_DIR}/data/img/stamp-indexed.png'),
    )

    ts = TextStamp(w, style)
    ts.apply(0, x=30, y=120)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/bitmap-bg.pdf')


@with_layout_comparison
def test_stamp_with_scaled_bitmap_bg():
    w = empty_page()

    text = '\n'.join(
        'Test test test test on a bitmap background!' for _ in range(3)
    )
    style = TextStampStyle(
        stamp_text=text,
        background=PdfImage(f'{TEST_DIR}/data/img/stamp-indexed.png'),
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
    style = TextStampStyle(stamp_text=long_text, background=undef_bg)

    ts = TextStamp(w, style)
    ts.apply(0, x=30, y=120)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/undef-bg-size.pdf')


@with_layout_comparison
def test_stamp_with_scaled_pdf_bg():
    w = empty_page()

    text = '\n'.join(
        'Test test test test on a PDF background!' for _ in range(3)
    )
    style = TextStampStyle(
        stamp_text=text,
        background=ImportedPdfPage(
            f'{TEST_DIR}/data/pdf/pdf-background-test.pdf'
        ),
    )

    ts = TextStamp(w, style, box=layout.BoxConstraints(200, 50))
    ts.apply(0, x=30, y=600)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/stamp-on-pdf-bg.pdf')


@with_layout_comparison
def test_stamp_with_fixed_pdf_content():
    w = empty_page()

    style = StaticStampStyle.from_pdf_file(
        f'{TEST_DIR}/data/pdf/pdf-background-test.pdf'
    )

    stamp = style.create_stamp(
        w, box=layout.BoxConstraints(200, 50), text_params={}
    )
    stamp.apply(0, x=30, y=600)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/stamp-from-static-pdf.pdf')


@pytest.mark.parametrize(
    'box',
    [
        None,
        layout.BoxConstraints(width=200),
        layout.BoxConstraints(height=50),
        layout.BoxConstraints(aspect_ratio=Fraction(4, 1)),
        layout.BoxConstraints(),
    ],
)
def test_static_stamp_enforce_box_defined(box):
    w = empty_page()

    style = StaticStampStyle.from_pdf_file(
        f'{TEST_DIR}/data/pdf/pdf-background-test.pdf'
    )

    with pytest.raises(layout.LayoutError, match="predetermined bounding box"):
        style.create_stamp(w, box=box, text_params={})


@with_layout_comparison
def test_simple_text_stamp_string_keyed_font():
    gaf = GlyphAccumulatorFactory(FREE_SERIF, font_size=10)

    w = empty_page()
    style = TextStampStyle(
        stamp_text=(
            "Hi, this is a string-keyed font test.\n"
            "This should have a ligature: difficult"
        ),
        text_box_style=TextBoxStyle(font=gaf),
    )

    ts = TextStamp(w, style, box=layout.BoxConstraints(200, 50))
    ts.apply(dest_page=0, x=70, y=50)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/freeserif-test.pdf')


@with_layout_comparison
def test_double_newline():
    gaf = GlyphAccumulatorFactory(FREE_SERIF, font_size=10)

    w = empty_page()
    style = TextStampStyle(
        stamp_text=(
            "Hi, this is a test. There should be two newlines here:\n\n"
            "And now a single newline:\n"
            "See?"
        ),
        text_box_style=TextBoxStyle(font=gaf),
    )

    ts = TextStamp(w, style, box=layout.BoxConstraints(200, 50))
    ts.apply(dest_page=0, x=70, y=50)

    compare_output(w, f'{EXPECTED_OUTPUT_DIR}/double-newline.pdf')


def test_zero_width_error():
    w = empty_page()
    zero_margins = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MID,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(),
    )
    style = TextStampStyle(
        stamp_text='',
        border_width=0,
        inner_content_layout=zero_margins,
        text_box_style=TextBoxStyle(box_layout_rule=zero_margins),
    )
    box = layout.BoxConstraints(width=100, height=100)
    stamp = TextStamp(writer=w, style=style, box=box)

    inn_commands, (inn_width, inn_height) = stamp._inner_layout_natural_size()
    assert inn_width == 0

    # ...this shouldn't throw a division by zero error
    stamp.apply(0, x=10, y=500)


def test_simple_text_stamp_on_page_with_leaky_graphics_state():
    with open(f"{PDF_DATA_DIR}/leaky-graphics-state-doc.pdf", 'rb') as fin:
        pdf_out = IncrementalPdfFileWriter(fin, strict=False)
        stamp = TextStamp(
            writer=pdf_out, style=TextStampStyle(stamp_text="Hi, it's me")
        )
        stamp.apply(0, 70, 50)
        compare_output(
            pdf_out,
            f'{EXPECTED_OUTPUT_DIR}/leaky-graphics-state-stamp-result.pdf',
        )


def test_simple_text_stamp_on_page_with_leaky_graphics_state_without_coord_correction():
    with open(f"{PDF_DATA_DIR}/leaky-graphics-state-doc.pdf", 'rb') as fin:
        pdf_out = IncrementalPdfFileWriter(fin, strict=False)
        stamp = TextStamp(
            writer=pdf_out,
            style=TextStampStyle(stamp_text="Hi, it's me"),
        )
        stamp.apply(0, 70, 50, coords=CoordinateSystem.AMBIENT)
        compare_output(
            pdf_out,
            f'{EXPECTED_OUTPUT_DIR}/leaky-graphics-state-stamp-no-corr-result.pdf',
        )
