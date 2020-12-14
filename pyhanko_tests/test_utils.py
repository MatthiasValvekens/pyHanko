import datetime
from fractions import Fraction

import pytest
from io import BytesIO

import pytz

import pyhanko.pdf_utils.content
from pyhanko.pdf_utils.generic import Reference
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxSpecificationError, BoxConstraints
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils import writer, generic, misc
from fontTools import ttLib
from pyhanko.pdf_utils.font import GlyphAccumulator, pdf_name

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


NOTO_SERIF_JP = 'pyhanko_tests/data/fonts/NotoSerifJP-Regular.otf'


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
    from pyhanko.pdf_utils import filters
    data = TEST_STRING * 20 + b'\0\0\0\0' + TEST_STRING * 20 + b'\x03\x02\x08'

    encoded = filters.ASCIIHexDecode.encode(data)
    assert filters.ASCIIHexDecode.decode(encoded) == data


def test_ascii85_decode():
    from pyhanko.pdf_utils import filters
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
    current_root = reader.get_object(root_ref.reference, revision=1)
    assert current_root == reader.root
    reader.get_object(acroform_ref.reference, revision=1)

    previous_root = reader.get_object(root_ref.reference, revision=0)
    assert '/AcroForm' not in previous_root
    with pytest.raises(misc.PdfReadError):
        reader.get_object(acroform_ref.reference, revision=0)

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


def test_preallocate():
    w = writer.PdfFileWriter()
    with pytest.raises(misc.PdfWriteError):
        w.add_object(generic.NullObject(), idnum=20)

    alloc = w.allocate_placeholder()
    assert isinstance(alloc.get_object(), generic.NullObject)
    w.add_object(generic.TextStringObject("Test Test"), idnum=alloc.idnum)
    assert alloc.get_object() == "Test Test"


@pytest.mark.parametrize('stream_xrefs,with_objstreams',
                         [(False, False), (True, False), (True, True)])
def test_page_tree_import(stream_xrefs, with_objstreams):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter(stream_xrefs=stream_xrefs)
    if with_objstreams:
        objstream = w.prepare_object_stream()
    else:
        objstream = None
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'), obj_stream=objstream
    )
    if objstream is not None:
        w.add_object(objstream.as_pdf_object())
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data


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


def fmt_dummy_xrefs(xrefs, sep=b'\r\n'):
    dummy_hdr = b'%PDF-1.7\n%owqi'

    def _gen():
        xrefs_iter = iter(xrefs)
        yield dummy_hdr
        offset = len(dummy_hdr) + 1
        section_bytes = b'xref\n' + sep.join(next(xrefs_iter)) + sep + \
                        b'trailer<<>>'
        startxref = offset
        offset += len(section_bytes) + 1
        yield section_bytes
        for section in xrefs_iter:
            section_bytes = b'xref\n' + sep.join(section) + sep + \
                            b'trailer<</Prev %d>>' % startxref
            startxref = offset
            offset += len(section_bytes) + 1
            yield section_bytes
        yield b'startxref\n%d' % startxref
        yield b'%%EOF'
    return b'\n'.join(_gen())


def test_object_free():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000000 00001 f'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000300 00001 n']
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))
    assert r.xrefs.xref_sections == 3
    assert r.xrefs[generic.Reference(1, 0)] is None
    assert r.xrefs[generic.Reference(1, 1)] == 300


def test_object_free_no_override():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000000 00001 f'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000300 00001 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000000 00002 f']
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))
    assert r.xrefs.xref_sections == 4
    assert r.xrefs[generic.Reference(1, 0)] is None
    assert r.xrefs[generic.Reference(1, 1)] is None


def test_increase_gen_without_free():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000300 00001 n']
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_orphan_high_gen():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000300 00000 n'],
        [b'0 1',
         b'0000000000 65535 f',
         b'3 1',
         b'0000000500 00001 n']
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_generation_rollback():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000000 00001 f'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000300 00000 n']
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_free_nonexistent():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000000 00001 f'],
    ]

    # this is harmless
    PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))

    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000000 00001 f'],
        [b'0 1',
         b'0000000000 65535 f',
         b'2 1',
         b'0000000300 00000 n'],
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_free_unexpected_jump():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000200 00000 n',
         b'0000000000 00001 f'],
        [b'0 1',
         b'0000000000 65535 f',
         b'2 1',
         b'0000000300 00005 n'],
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_resource_add_test():
    res1 = pyhanko.pdf_utils.content.PdfResources()
    res2 = pyhanko.pdf_utils.content.PdfResources()
    res1[pyhanko.pdf_utils.content.ResourceType.XOBJECT][pdf_name('/Bleh')] = generic.NullObject()
    res1[pyhanko.pdf_utils.content.ResourceType.PATTERN][pdf_name('/Blih')] = generic.NullObject()
    res2[pyhanko.pdf_utils.content.ResourceType.XOBJECT][pdf_name('/Blah')] = generic.NullObject()
    res2[pyhanko.pdf_utils.content.ResourceType.FONT][pdf_name('/Bluh')] = generic.NullObject()

    res1 += res2
    res1_dict = res1.as_pdf_object()
    assert pdf_name('/XObject') in res1_dict
    assert pdf_name('/Pattern') in res1_dict
    assert pdf_name('/Font') in res1_dict
    assert pdf_name('/Bleh') in res1_dict['/XObject']
    assert pdf_name('/Blah') in res1_dict['/XObject']
    assert pdf_name('/Shading') not in res1_dict


def test_duplicate_resource():
    res1 = pyhanko.pdf_utils.content.PdfResources()
    res2 = pyhanko.pdf_utils.content.PdfResources()
    res1[pyhanko.pdf_utils.content.ResourceType.XOBJECT][pdf_name('/Bleh')] = generic.NullObject()
    res1[pyhanko.pdf_utils.content.ResourceType.PATTERN][pdf_name('/Blih')] = generic.NullObject()
    res2[pyhanko.pdf_utils.content.ResourceType.XOBJECT][pdf_name('/Bleh')] = generic.NullObject()
    res2[pyhanko.pdf_utils.content.ResourceType.FONT][pdf_name('/Bluh')] = generic.NullObject()

    with pytest.raises(pyhanko.pdf_utils.content.ResourceManagementError):
        res1 += res2


TESTDATE_CET = datetime.datetime(
    year=2008, month=2, day=3, hour=1, minute=5, second=59,
    tzinfo=pytz.timezone('CET')
)

TESTDATE_EST = datetime.datetime(
    year=2008, month=2, day=3, hour=1, minute=5, second=59,
    tzinfo=pytz.timezone('EST')
)


@pytest.mark.parametrize('date_str, expected_dt', [
    ('D:2008', datetime.datetime(year=2008, month=1, day=1)),
    ('D:200802', datetime.datetime(year=2008, month=2, day=1)),
    ('D:20080203', datetime.datetime(year=2008, month=2, day=3)),
    ('D:20080201', datetime.datetime(year=2008, month=2, day=1)),
    ('D:2008020301', datetime.datetime(year=2008, month=2, day=3, hour=1)),
    ('D:200802030105',
     datetime.datetime(year=2008, month=2, day=3, hour=1, minute=5)),
    ('D:20080203010559',
     datetime.datetime(year=2008, month=2, day=3, hour=1, minute=5, second=59)),
    ('D:20080203010559Z',
     datetime.datetime(year=2008, month=2, day=3, hour=1, minute=5, second=59,
                       tzinfo=pytz.utc)),
    ('D:20080203010559+01\'00', TESTDATE_CET),
    ('D:20080203010559+01', TESTDATE_CET),
    ('D:20080203010559+01\'', TESTDATE_CET),
    ('D:20080203010559+01\'00\'', TESTDATE_CET),
    ('D:20080203010559-05\'00', TESTDATE_EST),
    ('D:20080203010559-05', TESTDATE_EST),
    ('D:20080203010559-05\'', TESTDATE_EST),
    ('D:20080203010559-05\'00\'', TESTDATE_EST),
])
def test_date_parsing(date_str, expected_dt):
    assert generic.parse_pdf_date(date_str) == expected_dt


@pytest.mark.parametrize('date_str', [
    '2008', 'D:20', 'D:20080', 'D:20081301',
    'D:20030230', 'D:20080203010559Z00', 'D:20080203010559-05\'00\'11'
])
def test_date_parsing_errors(date_str):
    with pytest.raises(misc.PdfReadError):
        generic.parse_pdf_date(date_str)
