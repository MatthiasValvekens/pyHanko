import binascii
import os
from io import BytesIO

import pytest
from pyhanko.pdf_utils import generic, misc, writer
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.xref import (
    ObjStreamRef,
    XRefEntry,
    XRefSectionType,
    XRefType,
    parse_xref_stream,
    read_object_header,
)

from .samples import (
    MINIMAL,
    MINIMAL_AES256,
    MINIMAL_TWO_FIELDS_TAGGED,
    MINIMAL_XREF,
    PDF_DATA_DIR,
)
from .test_utils import NONEXISTENT_XREF_PATH


@pytest.mark.parametrize(
    'data',
    [
        b'1 0 obj\n<<>>',
        b'\n1 0 obj\n<<>>',
        b'\n1  0 obj\n<<>>',
        b'%this is a comment\n1  0 obj\n<<>>',
    ],
)
def test_object_header_whitespace(data):
    result = read_object_header(BytesIO(data), strict=True)
    assert result == (1, 0)


@pytest.mark.parametrize(
    'fname',
    [
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
    ],
)
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


@pytest.mark.parametrize(
    'fname',
    [
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
    ],
)
def test_xref_locate_fail_strict(fname):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match='Failed to locate xref'):
            PdfFileReader(inf, strict=True)


@pytest.mark.parametrize(
    'fname,err,obj_to_get',
    [
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
    ],
)
def test_broken_objstream(fname, err, obj_to_get):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match=err):
            r = PdfFileReader(inf, strict=True)
            r.get_object(generic.Reference(idnum=obj_to_get))


@pytest.mark.parametrize(
    'fname,obj_to_get,expect_null',
    [
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
    ],
)
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


def fmt_dummy_xrefs(xrefs, sep=b'\r\n', manual_size=None):
    dummy_hdr = b'%PDF-1.7\n%owqi'

    def _gen():
        xrefs_iter = iter(xrefs)
        yield dummy_hdr
        offset = len(dummy_hdr) + 1
        init_section_entries = next(xrefs_iter)
        sz = manual_size or len(init_section_entries)
        section_bytes = (
            b'xref\n'
            + sep.join(init_section_entries)
            + sep
            + b'trailer<</Size %d>>' % sz
        )
        startxref = offset
        offset += len(section_bytes) + 1
        yield section_bytes
        for section in xrefs_iter:
            section_bytes = (
                b'xref\n'
                + sep.join(section)
                + sep
                + b'trailer<</Prev %d/Size %d>>' % (startxref, sz)
            )
            startxref = offset
            offset += len(section_bytes) + 1
            yield section_bytes
        yield b'startxref\n%d' % startxref
        yield b'%%EOF'

    return b'\n'.join(_gen())


def test_illegal_generation():
    xrefs = [
        [b'0 2', b'0000000000 65535 f', b'0000000100 99999 n'],
    ]

    with pytest.raises(misc.PdfReadError, match='Illegal generation'):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_illegal_generation_nonstrict():
    xrefs = [
        [b'0 2', b'0000000000 65535 f', b'0000000100 99999 n'],
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)), strict=False)
    assert not r.xrefs.get_xref_data(0).explicit_refs_in_revision


def test_xref_table_too_many_entries():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
    ]

    with pytest.raises(misc.PdfReadError, match='table size mismatch'):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs, manual_size=2)))


def test_xref_wrong_preamble():
    xrefs = [
        [b'0 2', b'0000000000 65535 f', b'0000000100 00000 n'],
    ]

    fmtd = fmt_dummy_xrefs(xrefs)
    fmtd = fmtd.replace(b'\nxref', b'\nxzzz')
    with pytest.raises(misc.PdfReadError, match='table read error'):
        PdfFileReader(BytesIO(fmtd))


def test_object_free():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000000 00001 f'],
        [b'0 2', b'0000000000 65535 f', b'0000000300 00001 n'],
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))
    assert r.xrefs.total_revisions == 3
    assert r.xrefs[generic.Reference(1, 0)] is None
    assert generic.Reference(1, 0) in r.xrefs.refs_freed_in_revision(1)
    assert r.xrefs[generic.Reference(1, 1)] == 300


def test_object_free_no_override():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000000 00001 f'],
        [b'0 2', b'0000000000 65535 f', b'0000000300 00001 n'],
        [b'0 2', b'0000000000 65535 f', b'0000000000 00002 f'],
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))
    assert r.xrefs.total_revisions == 4
    assert r.xrefs[generic.Reference(1, 0)] is None
    assert r.xrefs[generic.Reference(1, 1)] is None
    assert generic.Reference(1, 0) in r.xrefs.refs_freed_in_revision(1)
    assert generic.Reference(1, 1) in r.xrefs.refs_freed_in_revision(3)


def test_refree_dead_object():
    # I've seen the pattern below in Acrobat output.
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000000 00000 f',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000000 00001 f'],
    ]

    r = PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))
    assert r.xrefs.total_revisions == 2
    assert generic.Reference(1, 0) not in r.xrefs.refs_freed_in_revision(0)
    assert generic.Reference(1, 0) in r.xrefs.refs_freed_in_revision(1)
    assert generic.Reference(1, 0) in r.xrefs.explicit_refs_in_revision(1)


def test_forbid_obj_kill():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [
            b'0 2',
            b'0000000000 65535 f',
            b'0000000000 00000 f',
        ],  # this should be forbidden
    ]
    with pytest.raises(
        misc.PdfReadError, match='free xref with next generation 0'
    ):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_no_resurrection_allowed():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000000 00000 f',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000300 00001 n'],
    ]

    with pytest.raises(misc.PdfReadError, match='listed as dead'):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_increase_gen_without_free():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000300 00001 n'],
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_orphan_high_gen():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000300 00000 n'],
        [b'0 1', b'0000000000 65535 f', b'3 1', b'0000000500 00001 n'],
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_generation_rollback():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [b'0 2', b'0000000000 65535 f', b'0000000000 00001 f'],
        [b'0 2', b'0000000000 65535 f', b'0000000300 00000 n'],
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_free_nonexistent():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000000 00001 f',
        ],
    ]

    # this is harmless
    PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))

    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000000 00001 f',
        ],
        [b'0 1', b'0000000000 65535 f', b'2 1', b'0000000300 00000 n'],
    ]

    with pytest.raises(misc.PdfReadError):
        PdfFileReader(BytesIO(fmt_dummy_xrefs(xrefs)))


def test_free_unexpected_jump():
    xrefs = [
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000100 00000 n',
            b'0000000200 00000 n',
        ],
        [
            b'0 3',
            b'0000000000 65535 f',
            b'0000000200 00000 n',
            b'0000000000 00001 f',
        ],
        [b'0 1', b'0000000000 65535 f', b'2 1', b'0000000300 00005 n'],
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
    w._update_meta = lambda: None
    w.write_in_place()
    r = PdfFileReader(buf)
    assert r.xrefs.total_revisions == 2
    assert r.xrefs.explicit_refs_in_revision(1) == set()


def test_xref_stream_null_update():
    buf = BytesIO(MINIMAL_XREF)
    w = IncrementalPdfFileWriter(buf)
    w._update_meta = lambda: None
    w.write_in_place()
    r = PdfFileReader(buf)
    assert r.xrefs.total_revisions == 2
    # The xref stream itself got added
    assert len(r.xrefs.explicit_refs_in_revision(1)) == 1


def test_no_clobbering_xref_streams():
    # Test witnessing the limitation on our reader implementation
    # that disallows references to the xref stream of a previous revision
    # from being overridden.
    # (this behaviour may change in the future, but for now, the test is in
    # place to deal with it)

    buf = BytesIO(MINIMAL_XREF)
    w = IncrementalPdfFileWriter(buf)
    # update the xref stream in the previous revision
    stream_ref = w.prev.xrefs.get_xref_container_info(0).stream_ref
    w.mark_update(stream_ref)
    w.write_in_place()
    with pytest.raises(misc.PdfReadError, match="XRef.*must not be clobbered"):
        PdfFileReader(buf)


def test_nonexistent_xref_access():
    with open(NONEXISTENT_XREF_PATH, 'rb') as inf:
        r = PdfFileReader(inf)
        bad_ref = r.root['/Pages']['/Kids'][0].raw_get('/Bleh')
        with pytest.raises(
            misc.PdfReadError, match='not found.*error in strict mode'
        ):
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
    with pytest.raises(
        misc.PdfReadError, match='not found.*error in strict mode'
    ):
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
            obj_stream=obj_stm,
        )


def test_no_refs_in_obj_stm():
    w = writer.PdfFileWriter(stream_xrefs=True)
    obj_stm = w.prepare_object_stream()

    with pytest.raises(TypeError, match='Stream obj.*references'):
        w.add_object(generic.IndirectObject(2, 0, w), obj_stream=obj_stm)


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
        with pytest.raises(
            misc.PdfReadError, match="Object with id 1.*orphaned.*generation 9"
        ):
            PdfFileReader(inf, strict=True)


def test_xref_stream_parse_entry_types():
    encoded_entries = [
        "0000000000ffff",  # free
        "01000000110000",  # regular objects
        "01000000840000",
        "01000000bc0005",
        "01000001b40000",
        "01000002990000",
        "02000000030001",  # object in stream
        "03deadbeef1337",  # undefined (should be ignored)
        "02000000030002",  # object in stream
        "ffcafebabe0007",  # another undefined one
    ]
    xref_data = b''.join(binascii.unhexlify(entr) for entr in encoded_entries)
    stream_obj = generic.StreamObject(
        dict_data={
            generic.pdf_name('/W'): generic.ArrayObject(
                list(map(generic.NumberObject, [1, 4, 2]))
            ),
            generic.pdf_name('/Size'): 10,
        },
        stream_data=xref_data,
    )

    expected_out = [
        XRefEntry(
            xref_type=XRefType.FREE, location=None, idnum=0, generation=0xFFFF
        ),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x11, idnum=1),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x84, idnum=2),
        XRefEntry(
            xref_type=XRefType.STANDARD, location=0xBC, idnum=3, generation=5
        ),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x1B4, idnum=4),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x299, idnum=5),
        XRefEntry(
            xref_type=XRefType.IN_OBJ_STREAM,
            location=ObjStreamRef(3, 1),
            idnum=6,
        ),
        XRefEntry(
            xref_type=XRefType.IN_OBJ_STREAM,
            location=ObjStreamRef(3, 2),
            idnum=8,  # idnum jump because of undefined entry
        ),
    ]

    actual_out = list(parse_xref_stream(stream_obj))
    assert actual_out == expected_out


def test_xref_stream_parse_width_value_default_ix0():
    encoded_entries = [
        "00000000ffff",
        "000000110000",
    ]
    xref_data = b''.join(binascii.unhexlify(entr) for entr in encoded_entries)
    stream_obj = generic.StreamObject(
        dict_data={
            generic.pdf_name('/W'): generic.ArrayObject(
                list(map(generic.NumberObject, [0, 4, 2]))
            ),
            generic.pdf_name('/Size'): 2,
        },
        stream_data=xref_data,
    )

    expected_out = [
        XRefEntry(
            xref_type=XRefType.STANDARD, location=0, idnum=0, generation=0xFFFF
        ),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x11, idnum=1),
    ]

    actual_out = list(parse_xref_stream(stream_obj))
    assert actual_out == expected_out


def test_xref_stream_parse_long_width_value():
    encoded_entries = [
        "0000000000000000000000ffff",
        "01000000000011000000110000",
    ]
    xref_data = b''.join(binascii.unhexlify(entr) for entr in encoded_entries)
    stream_obj = generic.StreamObject(
        dict_data={
            generic.pdf_name('/W'): generic.ArrayObject(
                list(map(generic.NumberObject, [1, 10, 2]))
            ),
            generic.pdf_name('/Size'): 2,
        },
        stream_data=xref_data,
    )

    expected_out = [
        XRefEntry(
            xref_type=XRefType.FREE, location=None, idnum=0, generation=0xFFFF
        ),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x1100000011, idnum=1),
    ]

    actual_out = list(parse_xref_stream(stream_obj))
    assert actual_out == expected_out


def test_xref_stream_parse_width_value_default_ix2():
    # no tail part
    encoded_entries = [
        "0000000000",
        "0100000011",
    ]
    xref_data = b''.join(binascii.unhexlify(entr) for entr in encoded_entries)
    stream_obj = generic.StreamObject(
        dict_data={
            generic.pdf_name('/W'): generic.ArrayObject(
                list(map(generic.NumberObject, [1, 4, 0]))
            ),
            generic.pdf_name('/Size'): 2,
        },
        stream_data=xref_data,
    )

    expected_out = [
        XRefEntry(
            xref_type=XRefType.FREE, location=None, idnum=0, generation=0
        ),
        XRefEntry(xref_type=XRefType.STANDARD, location=0x11, idnum=1),
    ]

    actual_out = list(parse_xref_stream(stream_obj))
    assert actual_out == expected_out


def test_premature_xref_stream_end():
    encoded_entries = ["000000ffff", "0100110000"]

    xref_data = b''.join(binascii.unhexlify(entr) for entr in encoded_entries)
    stream_obj = generic.StreamObject(
        dict_data={
            generic.pdf_name('/W'): generic.ArrayObject(
                list(map(generic.NumberObject, [1, 2, 2]))
            ),
            generic.pdf_name('/Size'): 3,  # one too many
        },
        stream_data=xref_data,
    )

    with pytest.raises(misc.PdfReadError, match='incomplete entry'):
        list(parse_xref_stream(stream_obj))


def test_xref_stream_trailing_data():
    encoded_entries = ["0000000000ffff", "01000000110000", "deadbeef"]  # free
    xref_data = b''.join(binascii.unhexlify(entr) for entr in encoded_entries)
    stream_obj = generic.StreamObject(
        dict_data={
            generic.pdf_name('/W'): generic.ArrayObject(
                list(map(generic.NumberObject, [1, 4, 2]))
            ),
            generic.pdf_name('/Size'): 2,
        },
        stream_data=xref_data,
    )

    with pytest.raises(misc.PdfReadError, match='Trailing'):
        list(parse_xref_stream(stream_obj))


@pytest.mark.parametrize(
    'fname',
    [
        # A very simple example of a hybrid reference file
        #  (constructed by hand, so doesn't actually use any object streams)
        # Object "6 0 R" is only defined in an xref stream and "hidden"
        # in the standard xref table(s)
        'minimal-hybrid-xref.pdf',
        # Same file as above, but the "hidden object" is given a generation
        # number of 1 to exercise the exemption on requiring generation-specific
        # freeing instructions for hybrid reference files
        'minimal-hybrid-xref-weirdgen.pdf',
        # Same principle, but in "MS Word style" with all xrefs mirrored in the
        # hybrid stream.
        'minimal-hybrid-xref-mswordstyle.pdf',
    ],
)
def test_hybrid_xref(fname):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        r = PdfFileReader(inf, strict=True)
        assert r.trailer['/Info']['/Title'] == 'TestTest'
        container_info = r.xrefs.get_xref_container_info(1)
        assert container_info.xref_section_type == XRefSectionType.HYBRID_MAIN


def test_xref_size_nondecreasing():
    fname = 'minimal-broken-xref-size.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        with pytest.raises(misc.PdfReadError, match='nondecreasing'):
            PdfFileReader(inf, strict=True)


@pytest.mark.parametrize(
    'fname', ['minimal-hybrid-xref.pdf', 'minimal-hybrid-xref-mswordstyle.pdf']
)
def test_update_hybrid(fname):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        t_obj = w.trailer['/Info'].raw_get('/Title')
        assert '/XRefStm' in w.trailer
        assert isinstance(t_obj, generic.IndirectObject)
        w.objects[(t_obj.generation, t_obj.idnum)] = generic.pdf_string(
            'Updated'
        )
        out = BytesIO()
        w.write(out)

    r = PdfFileReader(out)
    assert '/XRefStm' not in r.trailer
    assert '/XRefStm' not in r.trailer_view
    assert r.trailer['/Info']['/Title'] == 'Updated'
    container_info = r.xrefs.get_xref_container_info(1)
    assert container_info.xref_section_type == XRefSectionType.HYBRID_MAIN
    container_info = r.xrefs.get_xref_container_info(2)
    assert container_info.xref_section_type == XRefSectionType.STANDARD


def test_count_refs_in_hybrid():
    fname = 'minimal-hybrid-xref-mswordstyle.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        r = PdfFileReader(inf)
        container_info = r.xrefs.get_xref_container_info(1)
        assert container_info.xref_section_type == XRefSectionType.HYBRID_MAIN
        # xref table is empty
        assert len(r.xrefs.get_xref_data(1).explicit_refs_in_revision) == 0
        # ...but the stream content should be counted as well
        assert len(r.xrefs.explicit_refs_in_revision(1)) == 6


@pytest.mark.parametrize(
    'fname', ['minimal-hybrid-xref.pdf', 'minimal-hybrid-xref-mswordstyle.pdf']
)
def test_update_hybrid_twice(fname):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        t_obj = w.trailer['/Info'].raw_get('/Title')
        assert isinstance(t_obj, generic.IndirectObject)
        w.objects[(t_obj.generation, t_obj.idnum)] = generic.pdf_string(
            'Updated'
        )
        out = BytesIO()
        w.write(out)

    r = PdfFileReader(out)
    assert r.trailer['/Info']['/Title'] == 'Updated'
    container_info = r.xrefs.get_xref_container_info(1)
    assert container_info.xref_section_type == XRefSectionType.HYBRID_MAIN
    container_info = r.xrefs.get_xref_container_info(2)
    assert container_info.xref_section_type == XRefSectionType.STANDARD

    w = IncrementalPdfFileWriter(out)
    w.add_object(generic.pdf_string('This is an object'))
    w.write_in_place()

    r = PdfFileReader(out)
    assert '/XRefStm' not in r.trailer
    assert '/XRefStm' not in r.trailer_view
    assert r.trailer['/Info']['/Title'] == 'Updated'
    container_info = r.xrefs.get_xref_container_info(1)
    assert container_info.xref_section_type == XRefSectionType.HYBRID_MAIN
    container_info = r.xrefs.get_xref_container_info(2)
    assert container_info.xref_section_type == XRefSectionType.STANDARD
    container_info = r.xrefs.get_xref_container_info(3)
    assert container_info.xref_section_type == XRefSectionType.STANDARD
