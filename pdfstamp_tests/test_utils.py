import datetime
from fractions import Fraction

import pytest
from io import BytesIO

import pytz

from pdf_utils.generic import Reference
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.misc import BoxConstraints, BoxSpecificationError
from pdf_utils.reader import PdfFileReader
from pdf_utils import writer, generic, misc
from fontTools import ttLib
from pdf_utils.font import GlyphAccumulator, pdf_name

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
    pages = r.root['/Pages']
    assert pages['/Count'] == 2
    kids = pages['/Kids']
    assert b'world' in kids[0].get_object()['/Contents'].data
    assert b'Page 2' in kids[1].get_object()['/Contents'].data


NOTO_SERIF_JP = 'pdfstamp_tests/data/fonts/NotoSerifJP-Regular.otf'


def test_embed_subset():
    ffile = ttLib.TTFont(NOTO_SERIF_JP)
    ga = GlyphAccumulator(ffile)
    cid_hx, _ = ga.feed_string('版')
    assert cid_hx == '66eb'
    cid_hx, _ = ga.feed_string('テスト版')
    assert cid_hx == '0637062a063966eb'
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    font_ref = ga.embed_subset(w)
    df = font_ref.get_object()['/DescendantFonts'][0].get_object()
    font_file = df['/FontDescriptor']['/FontFile3']
    assert len(font_file.data) == 1919


def test_add_stream():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    def stream_data(y):
        return f'BT /F1 18 Tf 0 {y} Td (Test Test) Tj ET'.encode('ascii')

    stream = generic.StreamObject(stream_data=stream_data(50))

    stream_ref = w.add_object(stream)
    w.add_stream_to_page(0, stream_ref)

    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    # check if the content stream was added
    page_obj_ref = r.root['/Pages']['/Kids'][0]
    assert isinstance(page_obj_ref, generic.IndirectObject)
    page_obj = page_obj_ref.get_object()
    conts = page_obj['/Contents']
    assert len(conts) == 2
    assert stream_ref.idnum in (c.idnum for c in conts)
    # check if resource dictionary is still OK
    assert '/F1' in page_obj['/Resources']['/Font']

    # let's try adding a third
    out.seek(0)
    w = IncrementalPdfFileWriter(out)

    stream = generic.StreamObject(stream_data=stream_data(100))
    new_stream_ref = w.add_object(stream)
    w.add_stream_to_page(0, new_stream_ref)

    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    # check if the content stream was added
    page_obj_ref = r.root['/Pages']['/Kids'][0]
    assert isinstance(page_obj_ref, generic.IndirectObject)
    page_obj = page_obj_ref.get_object()
    conts = page_obj['/Contents']
    assert len(conts) == 3
    ids = [c.idnum for c in conts]
    assert stream_ref.idnum in ids and new_stream_ref.idnum in ids


def test_add_stream_to_direct_arr():
    w = writer.PdfFileWriter()
    w.insert_page(simple_page(w, 'Test Test', extra_stream=True))
    out = BytesIO()
    w.write(out)
    out.seek(0)
    w = IncrementalPdfFileWriter(out)

    new_stream = 'BT /F1 18 Tf 0 50 Td (Test2 Test2) Tj ET'.encode('ascii')
    stream = generic.StreamObject(stream_data=new_stream)
    stream_ref = w.add_object(stream)
    w.add_stream_to_page(0, stream_ref)

    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    # check if the content stream was added
    page_obj_ref = r.root['/Pages']['/Kids'][0]
    assert isinstance(page_obj_ref, generic.IndirectObject)
    page_obj = page_obj_ref.get_object()
    conts = page_obj['/Contents']
    assert len(conts) == 3
    assert stream_ref.idnum in (c.idnum for c in conts)
    # check if resource dictionary is still OK
    assert '/F1' in page_obj['/Resources']['/Font']


def test_write_embedded_string():
    ffile = ttLib.TTFont(NOTO_SERIF_JP)
    ga = GlyphAccumulator(ffile)
    cid_hx, _ = ga.feed_string('テスト')
    assert cid_hx == '0637062a0639'
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    font_ref = ga.embed_subset(w)
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


def test_read_rewrite():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = BytesIO()
    w.write(out)
    out.seek(0)
    assert out.getvalue() == MINIMAL


def test_mildly_malformed_xref_read():
    # this file has an xref table starting at 1
    # and several badly aligned xref rows
    malformed = BytesIO(read_all(PDF_DATA_DIR + '/minimal-badxref.pdf'))
    reader = PdfFileReader(malformed)

    # try something
    root = reader.root
    assert '/Pages' in root


def test_write_embedded_string_objstream():
    ffile = ttLib.TTFont(NOTO_SERIF_JP)
    ga = GlyphAccumulator(ffile)
    cid_hx, _ = ga.feed_string('テスト')
    assert cid_hx == '0637062a0639'
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_XREF))
    obj_stream = w.prepare_object_stream()
    font_ref = ga.embed_subset(w, obj_stream=obj_stream)
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


TEST_STRING = b'\x74\x77\x74\x84\x66'


def test_ascii_hex_decode():
    from pdf_utils import filters
    data = TEST_STRING * 20 + b'\0\0\0\0' + TEST_STRING * 20 + b'\x03\x02\x08'

    encoded = filters.ASCIIHexDecode.encode(data)
    assert filters.ASCIIHexDecode.decode(encoded) == data


def test_ascii85_decode():
    from pdf_utils import filters
    data = TEST_STRING * 20 + b'\0\0\0\0' + TEST_STRING * 20 + b'\x03\x02\x08'

    encoded = filters.ASCII85Decode.encode(data)
    # 50 normal groups of 4 * 5 -> 200,
    assert len(encoded) == 257
    assert filters.ASCII85Decode.decode(encoded) == data


def test_historical_read():
    reader = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    assert reader.total_revisions == 2

    # if this test file is ever replaced, the test will probably have to
    # be rewritten
    root_ref = generic.IndirectObject(1, 0, reader)
    acroform_ref = generic.IndirectObject(6, 0, reader)

    # current value
    current_root = reader.get_object(root_ref, revision=1)
    assert current_root == reader.root
    reader.get_object(acroform_ref, revision=1)

    previous_root = reader.get_object(root_ref, revision=0)
    assert '/AcroForm' not in previous_root
    with pytest.raises(misc.PdfReadError):
        reader.get_object(acroform_ref, revision=0)

    assert Reference(6, 0) in reader.xrefs.explicit_refs_in_revision(1)
    assert Reference(2, 0) in reader.xrefs.explicit_refs_in_revision(0)
    assert Reference(2, 0) not in reader.xrefs.explicit_refs_in_revision(1)


# TODO actually attempt to render the XObjects

@pytest.mark.parametrize('file_no, inherit_filters',
                         [[0, True], [0, False], [1, True], [1, False]])
def test_page_import(file_no, inherit_filters):
    fbytes = (VECTOR_IMAGE_PDF, VECTOR_IMAGE_PDF_DECOMP)[file_no]
    image_input = PdfFileReader(BytesIO(fbytes))
    w = writer.PdfFileWriter()
    xobj_ref = w.import_page_as_xobject(
        image_input, inherit_filters=inherit_filters
    )
    xobj: generic.StreamObject = xobj_ref.get_object()
    assert '/ExtGState' in xobj['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in xobj.data


@pytest.mark.parametrize('inherit_filters', [True, False])
def test_page_import_with_fonts(inherit_filters):
    image_input = PdfFileReader(BytesIO(FILE_WITH_EMBEDDED_FONT))
    w = writer.PdfFileWriter()
    xobj_ref = w.import_page_as_xobject(
        image_input, inherit_filters=inherit_filters
    )
    xobj: generic.StreamObject = xobj_ref.get_object()
    fonts = xobj['/Resources']['/Font']
    assert '/FEmb' in fonts
    df = fonts['/FEmb']['/DescendantFonts'][0].get_object()
    font_file = df['/FontDescriptor']['/FontFile3']
    assert len(font_file.data) == 1424


def test_deep_modify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    obj3 = generic.Reference(3, 0, w)
    deep_obj = w.get_object(obj3)['/Resources']['/Font']['/F1']['/Subtype']
    assert deep_obj.container_ref.idnum == obj3.idnum

    w.update_container(deep_obj)
    assert (0, 3) in w.objects


def test_box_constraint_over_underspecify():
    w = 1600
    h = 900
    ar = Fraction(16, 9)

    with pytest.raises(BoxSpecificationError):
        BoxConstraints(width=w, height=h, aspect_ratio=ar)

    bc = BoxConstraints(width=w)
    assert not bc.aspect_ratio_defined
    assert not bc.height_defined

    bc = BoxConstraints(width=w, height=h)
    assert bc.aspect_ratio == ar

    bc = BoxConstraints(width=w, aspect_ratio=ar)
    assert bc.height == h

    with pytest.raises(BoxSpecificationError):
        bc.height += 1

    bc = BoxConstraints(height=h, aspect_ratio=ar)
    assert bc.width == w

    with pytest.raises(BoxSpecificationError):
        bc.width += 1

    bc = BoxConstraints()
    bc.width = w
    assert bc.width_defined
    assert not bc.height_defined
    assert not bc.aspect_ratio_defined

    bc.height = h
    assert bc.aspect_ratio == ar


def test_box_constraint_recalc():
    w = 1600
    h = 900
    ar = Fraction(16, 9)

    bc = BoxConstraints(aspect_ratio=ar)
    assert bc.aspect_ratio == ar

    with pytest.raises(BoxSpecificationError):
        # noinspection PyStatementEffect
        bc.height

    with pytest.raises(BoxSpecificationError):
        # noinspection PyStatementEffect
        bc.width

    bc.width = w
    assert bc.height_defined
    assert bc.height == h

    bc = BoxConstraints(aspect_ratio=ar)
    bc.height = h
    assert bc.width_defined
    assert bc.width == w

    bc = BoxConstraints(width=w)
    with pytest.raises(BoxSpecificationError):
        # noinspection PyStatementEffect
        bc.aspect_ratio

    bc.height = h
    assert bc.aspect_ratio == ar


def test_trailer_update():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    dt = generic.pdf_date(datetime.datetime(2020, 10, 10, tzinfo=pytz.utc))

    info = generic.DictionaryObject({pdf_name('/CreationDate'): dt})
    w.trailer['/Info'] = w.add_object(info)
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.trailer['/Info']['/CreationDate'] == dt
