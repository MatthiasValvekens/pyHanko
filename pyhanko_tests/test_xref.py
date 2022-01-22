import os
from io import BytesIO

import pytest

from pyhanko.pdf_utils import generic, misc, writer
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_tests.samples import (
    MINIMAL,
    MINIMAL_AES256,
    MINIMAL_TWO_FIELDS_TAGGED,
    MINIMAL_XREF,
    PDF_DATA_DIR,
)
from pyhanko_tests.test_utils import NONEXISTENT_XREF_PATH


@pytest.mark.parametrize('fname', [
    # this file has an xref table starting at 1
    # and several badly aligned xref rows
    'minimal-badxref.pdf',
    # startxref table offset is off by one (but it's whitespace)
    'minimal-startxref-obo1.pdf',
    # startxref table offset is off by one (in the other direction)
    'minimal-startxref-obo2.pdf',
    # startxref stream offset is off by one (but it's whitespace)
    'minimal-startxref-obo3.pdf',
    # startxref stream offset is off by one (in the other direction)
    'minimal-startxref-obo4.pdf',
    # startxref stream offset is off by two (lands on a digit)
    'minimal-startxref-obo5.pdf',
    # startxref stream offset is off by some nonsense
    'minimal-startxref-obo6.pdf',
])
def test_mildly_malformed_xref_read(fname):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        reader = PdfFileReader(inf, strict=False)

        # try something
        root = reader.root
        assert '/Pages' in root


def test_hopelessly_malformed_xref_read():
    fname = 'minimal-startxref-hopeless.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match='Could not find xref'):
            PdfFileReader(inf, strict=False)


@pytest.mark.parametrize('fname', [
    # startxref table offset is off by one (but it's whitespace)
    # 'minimal-startxref-obo1.pdf',
    # startxref table offset is off by one (in the other direction)
    'minimal-startxref-obo2.pdf',
    # startxref stream offset is off by one (but it's whitespace)
    # 'minimal-startxref-obo3.pdf',
    # startxref stream offset is off by one (in the other direction)
    'minimal-startxref-obo4.pdf',
    # startxref stream offset is off by two (lands on a digit)
    'minimal-startxref-obo5.pdf',
    # startxref stream offset is off by some nonsense
    'minimal-startxref-obo6.pdf',
])
def test_xref_locate_fail_strict(fname):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match='Failed to locate xref'):
            PdfFileReader(inf, strict=True)


@pytest.mark.parametrize('fname,err,obj_to_get', [
    # object count is too low
    ('broken-objstream1.pdf', 'Object stream does not contain index', 4),
    # attempt to fetch object that has the wrong index
    ('broken-objstream2.pdf', 'Object is in wrong index.', 4),
    # attempt to fetch object that would require reading beyond the objstm
    # header section
    ('broken-objstream3.pdf', 'Object stream header possibly corrupted', 6),
    # attempt to fetch an object that isn't in the stream at all
    ('broken-objstream4.pdf', 'not found in stream', 6),
    # attempt to fetch a stream from an object stream
    ('broken-objstream5.pdf', 'forbidden object type', 9),
    # object stream ends prematurely
    ('broken-objstream6.pdf', 'Can\'t read', 4),
])
def test_broken_objstream(fname, err, obj_to_get):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match=err):
            r = PdfFileReader(inf, strict=True)
            r.get_object(generic.Reference(idnum=obj_to_get))


@pytest.mark.parametrize('fname,obj_to_get,expect_null', [
    # object count is too low
    ('broken-objstream1.pdf', 4, True),
    # attempt to fetch object that has the wrong index
    ('broken-objstream2.pdf', 4, False),
    # attempt to fetch object that would require reading beyond the objstm
    # header section
    ('broken-objstream3.pdf', 6, True),
    # attempt to fetch an object that isn't in the stream at all
    ('broken-objstream4.pdf', 6, True),
    # attempt to fetch a stream from an object stream
    ('broken-objstream5.pdf', 9, False),
    # object stream ends prematurely
    ('broken-objstream6.pdf', 4, True),
])
def test_broken_obj_stream_fallback(fname, obj_to_get, expect_null):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        r = PdfFileReader(inf, strict=False)
        obj = r.get_object(generic.Reference(idnum=obj_to_get))
        if expect_null:
            assert isinstance(obj, generic.NullObject)
        else:
            # we set up the tests to always point to dictionaries
            assert isinstance(obj, generic.DictionaryObject)


def test_preallocate():
    w = writer.PdfFileWriter()
    with pytest.raises(misc.PdfWriteError):
        w.add_object(generic.NullObject(), idnum=20)

    alloc = w.allocate_placeholder()
    assert isinstance(alloc.get_object(), generic.NullObject)
    w.add_object(generic.TextStringObject("Test Test"), idnum=alloc.idnum)
    assert alloc.get_object() == "Test Test"


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
    assert generic.Reference(1, 0) in r.xrefs.refs_freed_in_revision(1)
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
    assert generic.Reference(1, 0) in r.xrefs.refs_freed_in_revision(1)
    assert generic.Reference(1, 1) in r.xrefs.refs_freed_in_revision(3)


def test_refree_dead_object():
    # I've seen the pattern below in Acrobat output.
    # (minus the second update)
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000000 00000 f',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000000 00001 f'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000300 00001 n'],  # reintroduce as gen 1
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))
    assert r.xrefs.xref_sections == 3
    assert generic.Reference(1, 0) not in r.xrefs.refs_freed_in_revision(0)
    assert generic.Reference(1, 0) not in r.xrefs.refs_freed_in_revision(1)
    assert generic.Reference(1, 0) not in r.xrefs.explicit_refs_in_revision(1)
    assert generic.Reference(1, 1) in r.xrefs.explicit_refs_in_revision(2)


def test_forbid_obj_kill():
    xrefs = [
        [b'0 3',
         b'0000000000 65535 f',
         b'0000000100 00000 n',
         b'0000000200 00000 n'],
        [b'0 2',
         b'0000000000 65535 f',
         b'0000000000 00000 f'],  # this should be forbidden
    ]
    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


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


def test_tagged_path_count():

    r = PdfFileReader(BytesIO(MINIMAL_TWO_FIELDS_TAGGED))
    r = r.get_historical_resolver(0)
    r._load_reverse_xref_cache()
    # The path simplifier should eliminate all (pseudo-)duplicates refs except
    # these three:
    #  - one from the AcroForm hierarchy
    #  - one from the pages tree (through /Annots)
    #  - one from the structure tree
    paths_to = r._indirect_object_access_cache[generic.Reference(7, 0, r)]
    assert len(paths_to) == 3


def test_trailer_refs():
    # This is a corner case in the reference handler that shouldn't really
    # come up in real life. That said, it's easy to test for using a (somewhat
    # contrived) example, so let's do that.
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    # Note: the container of the catalog is the thing root_ref points to,
    # but root_ref, when viewed as a PDF object by itself (i.e. the indirect
    # object embedded in the trailer) should have a TrailerReference as its
    # container.
    root_ref = w.trailer.raw_get('/Root')
    assert isinstance(root_ref.container_ref, generic.TrailerReference)
    w.update_container(root_ref)


def test_xref_access_no_decrypt():
    r = PdfFileReader(BytesIO(MINIMAL_AES256))
    # attempt to access xref stream, turn off transparent decryption
    obj = r.get_object(ref=generic.Reference(7, 0), transparent_decrypt=False)
    assert not isinstance(obj, generic.DecryptedObjectProxy)


def test_xref_null_update():
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)
    w.write_in_place()
    r = PdfFileReader(buf)
    assert r.xrefs.total_revisions == 2
    assert r.xrefs.explicit_refs_in_revision(1) == set()


def test_xref_stream_null_update():
    buf = BytesIO(MINIMAL_XREF)
    w = IncrementalPdfFileWriter(buf)
    w.write_in_place()
    r = PdfFileReader(buf)
    assert r.xrefs.total_revisions == 2
    # The xref stream itself got added
    assert len(r.xrefs.explicit_refs_in_revision(1)) == 1


def test_nonexistent_xref_access():
    with open(NONEXISTENT_XREF_PATH, 'rb') as inf:
        r = PdfFileReader(inf)
        bad_ref = r.root['/Pages']['/Kids'][0].raw_get('/Bleh')
        with pytest.raises(misc.PdfReadError,
                           match='not found.*error in strict mode'):
            bad_ref.get_object()


def test_nonexistent_xref_access_nonstrict():
    with open(NONEXISTENT_XREF_PATH, 'rb') as inf:
        r = PdfFileReader(inf, strict=False)
        bad_ref = r.root['/Pages']['/Kids'][0].raw_get('/Bleh')
        assert isinstance(bad_ref.get_object(), generic.NullObject)


def test_historical_nonexistent_xref_access():
    out = BytesIO()
    with open(NONEXISTENT_XREF_PATH, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        pg_dict = w.root['/Pages']['/Kids'][0]
        del pg_dict['/Bleh']
        w.update_container(pg_dict)
        w.write(out)
    r = PdfFileReader(out)
    current_state = r.root['/Pages']['/Kids'][0]
    assert '/Bleh' not in current_state
    hist_root = r.get_historical_root(0)
    bad_ref = hist_root['/Pages']['/Kids'][0].raw_get('/Bleh')
    with pytest.raises(misc.PdfReadError,
                       match='not found.*error in strict mode'):
        bad_ref.get_object()


def test_historical_nonexistent_xref_access_nonstrict():
    out = BytesIO()
    with open(NONEXISTENT_XREF_PATH, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        pg_dict = w.root['/Pages']['/Kids'][0]
        del pg_dict['/Bleh']
        w.update_container(pg_dict)
        w.write(out)
    r = PdfFileReader(out, strict=False)
    hist_root = r.get_historical_root(0)
    bad_ref = hist_root['/Pages']['/Kids'][0].raw_get('/Bleh')
    assert isinstance(bad_ref.get_object(), generic.NullObject)


def test_no_objstms_without_xref_stm():
    w = writer.PdfFileWriter(stream_xrefs=False)
    with pytest.raises(misc.PdfWriteError, match='Obj'):
        w.prepare_object_stream()


def test_no_stms_in_obj_stm():
    w = writer.PdfFileWriter(stream_xrefs=True)
    obj_stm = w.prepare_object_stream()

    with pytest.raises(TypeError, match='Stream obj.*references'):
        w.add_object(
            generic.StreamObject(stream_data=b'Hello world!'),
            obj_stream=obj_stm
        )


def test_no_refs_in_obj_stm():
    w = writer.PdfFileWriter(stream_xrefs=True)
    obj_stm = w.prepare_object_stream()

    with pytest.raises(TypeError, match='Stream obj.*references'):
        w.add_object(
            generic.IndirectObject(2, 0, w),
            obj_stream=obj_stm
        )


def test_xref_orphaned_nonstrict():
    # higher-generation xref without matching free
    # should work in nonstrict mode
    fpath = os.path.join(PDF_DATA_DIR, 'minimal-with-orphaned-xrefs.pdf')
    with open(fpath, 'rb') as inf:
        r = PdfFileReader(inf, strict=False)
        assert r.root_ref.generation == 9


def test_xref_orphaned_strict():
    # higher-generation xref without matching free
    # should not work in strict mode
    fpath = os.path.join(PDF_DATA_DIR, 'minimal-with-orphaned-xrefs.pdf')
    with open(fpath, 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match="Xref.*orphaned.*1 9 obj"):
            PdfFileReader(inf, strict=True)