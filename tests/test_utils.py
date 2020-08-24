import pytest
from io import BytesIO

from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.reader import PdfFileReader
from pdf_utils import writer
from fontTools import ttLib
from pdf_utils.font import GlyphAccumulator

from .samples import *


@pytest.mark.parametrize('zip1, zip2',
                         [[True, True], [True, False], [False, False]])
def test_create_fresh(zip1, zip2):
    pdf_out = writer.PdfFileWriter()
    p1 = simple_page(pdf_out, 'Hello world', compress=zip1)
    p2 = simple_page(pdf_out, 'Hello Page 2', compress=zip2)
    pdf_out.insert_page(p1)
    pdf_out.insert_page(p2)

    out = BytesIO()
    pdf_out.write(out)
    out.seek(0)

    r = PdfFileReader(out)
    pages = r.trailer['/Root']['/Pages']
    assert pages['/Count'] == 2
    kids = pages['/Kids']
    assert b'world' in kids[0].get_object()['/Contents'].data
    assert b'Page 2' in kids[1].get_object()['/Contents'].data


def test_embed_subset():
    ffile = ttLib.TTFont('tests/data/fonts/NotoSerifJP-Regular.otf')
    ga = GlyphAccumulator(ffile)
    cid_hx, _ = ga.feed_string('版')
    assert cid_hx == '66eb'
    cid_hx, _ = ga.feed_string('テスト版')
    assert cid_hx == '0637062a063966eb'
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    font_ref = ga.embed_subset(w)
    cid_font = font_ref.get_object()['/DescendantFonts'][0].get_object()
    assert '/FontFile3' in cid_font['/FontDescriptor']
