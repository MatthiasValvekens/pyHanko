from io import BytesIO

import pytest

from pyhanko.pdf_utils import generic, text
from pyhanko.pdf_utils.font.opentype import GlyphAccumulator
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_tests.samples import MINIMAL, MINIMAL_XREF


@pytest.mark.parametrize('with_border, natural_size', [[True, True], [False, False], [True, False]])
def test_simple_textbox_render(with_border, natural_size):
    tbs = text.TextBoxStyle(border_width=1 if with_border else 0)
    bc = None if natural_size else BoxConstraints(width=1600, height=900)

    textbox = text.TextBox(
        style=tbs, box=bc, writer=IncrementalPdfFileWriter(BytesIO(MINIMAL))
    )
    textbox.content = 'This is a textbox with some text.\nAnd multiple lines'
    xobj = textbox.as_form_xobject()
    x1, y1, x2, y2 = xobj['/BBox']
    assert '/F1' in textbox.resources.font

    if not natural_size:
        assert abs(x1 - x2) == 1600
        assert abs(y1 - y2) == 900


NOTO_SERIF_JP = 'pyhanko_tests/data/fonts/NotoSerifJP-Regular.otf'


def test_embed_subset():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with open(NOTO_SERIF_JP, 'rb') as ffile:
        ga = GlyphAccumulator(w, ffile, font_size=10)
    res = ga.shape('版')
    assert b'[<66eb>] TJ' in res.graphics_ops
    res = ga.shape('テスト')
    assert b'[<0637> 40 <062a0639>] TJ' in res.graphics_ops

    # check the 'ffi' ligature
    res = ga.shape('difficult')
    assert b'[<0045004ae9e200440056004d0055>] TJ' in res.graphics_ops

    w.write_in_place()
    font_ref = ga.as_resource()
    font = font_ref.get_object()
    df = font['/DescendantFonts'][0].get_object()
    font_file = df['/FontDescriptor']['/FontFile3']
    # assert no ToUnicode assignment for 'f'
    assert b'\n<0066>' not in font['/ToUnicode'].data
    # assert a ToUnicode assignment for the 'ffi' ligature
    assert b'\n<e9e2> <006600660069>' in font['/ToUnicode'].data
    assert len(font_file.data) < 4000


def test_actual_text_toggle():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with open(NOTO_SERIF_JP, 'rb') as ffile:
        ga = GlyphAccumulator(w, ffile, font_size=10)

    res = ga.shape('difficult')
    assert b'[<0045004ae9e200440056004d0055>] TJ' in res.graphics_ops
    assert b'ActualText' in res.graphics_ops

    res = ga.shape('difficult', with_actual_text=False)
    assert b'[<0045004ae9e200440056004d0055>] TJ' in res.graphics_ops
    assert b'ActualText' not in res.graphics_ops


def test_write_embedded_string():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with open(NOTO_SERIF_JP, 'rb') as ffile:
        ga = GlyphAccumulator(w, ffile, font_size=10)
    # shape the string, just to register the glyphs as used
    ga.shape('テスト')
    # ... but we're not going to use the result

    # hardcoded CIDs
    cid_hx = '0637062a0639'
    stream = generic.StreamObject(
        stream_data=f'BT /FEmb 18 Tf 0 100 Td <{cid_hx}> Tj ET'.encode('ascii')
    )
    stream_ref = w.add_object(stream)
    w.add_stream_to_page(
        0, stream_ref, resources=generic.DictionaryObject({
            pdf_name('/Font'): generic.DictionaryObject({
                pdf_name('/FEmb'): ga.as_resource()
            })
        })
    )
    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    page_obj = r.root['/Pages']['/Kids'][0].get_object()
    conts = page_obj['/Contents']
    assert len(conts) == 2
    assert stream_ref.idnum in (c.idnum for c in conts)


def test_write_embedded_string_objstream():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_XREF))
    obj_stream = w.prepare_object_stream()
    with open(NOTO_SERIF_JP, 'rb') as ffile:
        ga = GlyphAccumulator(w, ffile, font_size=10, obj_stream=obj_stream)
    # shape the string, just to register the glyphs as used
    ga.shape('テスト')
    # ... but we're not going to use the result

    # hardcoded CIDs
    cid_hx = '0637062a0639'
    font_ref = ga.as_resource()
    stream = generic.StreamObject(
        stream_data=f'BT /FEmb 18 Tf 0 100 Td <{cid_hx}> Tj ET'.encode('ascii')
    )
    stream_ref = w.add_object(stream)
    w.add_stream_to_page(
        0, stream_ref, resources=generic.DictionaryObject({
            pdf_name('/Font'): generic.DictionaryObject({
                pdf_name('/FEmb'): font_ref
            })
        })
    )
    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    page_obj = r.root['/Pages']['/Kids'][0].get_object()
    conts = page_obj['/Contents']
    assert len(conts) == 2
    assert stream_ref.idnum in (c.idnum for c in conts)
    assert font_ref.idnum in r.xrefs.in_obj_stream
    out.seek(0)

    # attempt to grab the font from the object stream
    font_ref.pdf = r
    font = font_ref.get_object()
    assert font['/Type'] == pdf_name('/Font')