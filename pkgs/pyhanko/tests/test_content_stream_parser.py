from io import BytesIO

import pytest
from pyhanko.pdf_utils.content_stream_parser import parse_content_stream
from pyhanko.pdf_utils.generic import NullObject, NumberObject, StreamObject
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError
from test_data.samples import MINIMAL


def _wrap_as_streams(w: IncrementalPdfFileWriter, *data):
    result = []
    for d in data:
        obj = StreamObject(stream_data=d)
        ref = w.add_object(obj)
        obj.container_ref = ref.reference
        result.append(obj)
    return result


def test_parse_simple_content_stream():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    d = b"q 1 0 0 -1 0 100 cm Q"
    streams = _wrap_as_streams(w, d)
    result = list(parse_content_stream(streams))
    push, cm, pop = result

    assert not push.args
    assert push.op == 'q'
    assert push.start[0] == streams[0].container_ref
    assert push.start[1] == 0
    assert push.end[0] == streams[0].container_ref
    assert push.end[1] == 1

    assert not pop.args
    assert pop.op == 'Q'
    assert pop.start[0] == streams[0].container_ref
    assert pop.start[1] == len(d) - 1
    assert pop.end[0] == streams[0].container_ref
    assert pop.end[1] == len(d)

    assert cm.args == [NumberObject(n) for n in (1, 0, 0, -1, 0, 100)]
    assert cm.op == 'cm'
    assert cm.start[1] == 2
    assert cm.end[1] == len(d) - 2


def test_inline_image_fail_gracefully():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    d = b"q 1 0 0 -1 0 100 cm BI ... EI"
    streams = _wrap_as_streams(w, d)
    with pytest.raises(PdfReadError, match="inline images"):
        list(parse_content_stream(streams))


def test_parse_split_content_stream():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    d1 = b"q"
    d2 = b"1 0 0 -1 0 100 cm"
    d3 = b"Q"
    streams = _wrap_as_streams(w, d1, d2, d3)
    result = list(parse_content_stream(streams))
    push, cm, pop = result

    assert not push.args
    assert push.op == 'q'
    assert push.start[0] == streams[0].container_ref
    assert push.start[1] == 0
    assert push.end[0] == streams[0].container_ref
    assert push.end[1] == 1

    assert not pop.args
    assert pop.op == 'Q'
    assert pop.start[0] == streams[2].container_ref
    assert pop.start[1] == 0
    assert pop.end[0] == streams[2].container_ref
    assert pop.end[1] == 1

    assert cm.args == [NumberObject(n) for n in (1, 0, 0, -1, 0, 100)]
    assert cm.op == 'cm'
    assert cm.start[0] == streams[1].container_ref
    assert cm.start[1] == 0
    assert cm.end[0] == streams[1].container_ref
    assert cm.end[1] == len(d2)


def test_parse_unnaturally_split_content_stream():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    d1 = b"q 1 0"
    d2 = b"0 -1 0 100 cm Q"
    streams = _wrap_as_streams(w, d1, d2)
    result = list(parse_content_stream(streams))
    push, cm, pop = result

    assert cm.args == [NumberObject(n) for n in (1, 0, 0, -1, 0, 100)]
    assert cm.op == 'cm'
    assert cm.start[0] == streams[0].container_ref
    assert cm.start[1] == 2
    assert cm.end[0] == streams[1].container_ref
    assert cm.end[1] == len(d2) - 2


@pytest.mark.parametrize(
    "ds,expected_cm_start",
    [
        ((b"q %blah\n1 0 0 -1 0 100 cm Q",), 8),
        ((b"q %blah\n%foo bar baz\n1 0 0 -1 0 100 cm\nQ",), 21),
        ((b"q 1 0 0 -1 0 100 cm Q\n%end of stream comment",), 2),
        ((b"q %blah\n\r%foo bar baz\r\n1 0 0 -1 0 100 cm\r\nQ",), 23),
        ((b"q %blah\n %foo bar baz\n 1 0 0 -1 0 100 cm\n Q",), 23),
        (
            (
                b"q %one",
                b"1 0 0 -1 0 100 cm %two",
                b"Q %three",
            ),
            0,
        ),
    ],
)
def test_parse_content_stream_with_comments(ds, expected_cm_start):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    streams = _wrap_as_streams(w, *ds)
    result = list(parse_content_stream(streams))
    push, cm, pop = result

    assert cm.args == [NumberObject(n) for n in (1, 0, 0, -1, 0, 100)]
    assert cm.op == 'cm'
    assert cm.start[1] == expected_cm_start


@pytest.mark.parametrize(
    "d,expected_content",
    [
        (b"<<>> BDC EMC", {}),
        (b"<</Foo /Bar>> BDC EMC", {'/Foo': '/Bar'}),
        (b"q <</Foo /Bar>> BDC EMC Q", {'/Foo': '/Bar'}),
        (
            b"q <</Foo <</Bar/Baz>> /Quux [1]>> BDC EMC Q",
            {'/Foo': {'/Bar': '/Baz'}, '/Quux': [1]},
        ),
        (
            b"q <</Foo<</Bar/Baz>>\n/Quux [1]>>\n BDC EMC Q",
            {'/Foo': {'/Bar': '/Baz'}, '/Quux': [1]},
        ),
        (
            b"q <</Foo<</Bar/Baz>> %with a comment\n/Quux [1]>>\n BDC EMC Q",
            {'/Foo': {'/Bar': '/Baz'}, '/Quux': [1]},
        ),
    ],
)
def test_parse_dict_args(d, expected_content):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    streams = _wrap_as_streams(w, d)
    result = list(parse_content_stream(streams))
    bdc = next(r for r in result if r.op == 'BDC')

    assert bdc.args == [expected_content]


@pytest.mark.parametrize(
    "d,expected_content",
    [
        (b"[] TJ", []),
        (b"[null null] TJ", [NullObject(), NullObject()]),
        (b"[(foo) 100 (bar) -20 (baz)] TJ", ["foo", 100, "bar", -20, "baz"]),
        (
            b"BT [(foo) 100 (bar) -20 (baz)] TJ ET",
            ["foo", 100, "bar", -20, "baz"],
        ),
        (b"[(foo)\n100\n(bar)\n-20 (baz)] TJ", ["foo", 100, "bar", -20, "baz"]),
        (
            b"[(foo) %with comment\n100\n(bar)\n-20 (baz)] TJ",
            ["foo", 100, "bar", -20, "baz"],
        ),
    ],
)
def test_parse_arr_args(d, expected_content):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    streams = _wrap_as_streams(w, d)
    result = list(parse_content_stream(streams))
    tj = next(r for r in result if r.op == 'TJ')

    assert tj.args == [expected_content]


@pytest.mark.parametrize(
    'd',
    [
        b"<</Foo 1 0 R /Bar 0>> BDC",
        b"<</Foo op /Bar 0>> BDC",
        b"[1 0 R] TJ",
        b"[op] TJ",
        b"1 0 R BDC",
        b"b\xe3\x83\x90\xe3\x82\xb0z BDC",
    ],
)
def test_bad_tokens_for_content_streams(d):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    streams = _wrap_as_streams(w, d)
    with pytest.raises(PdfReadError):
        list(parse_content_stream(streams))
