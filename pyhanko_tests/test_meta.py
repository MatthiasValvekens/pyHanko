import itertools
import os
from datetime import datetime
from io import BytesIO

import pytest
import pytz
import tzlocal
from freezegun import freeze_time

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.metadata import model, xmp_xml
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter, copy_into_new_writer
from pyhanko_tests.samples import MINIMAL, PDF_DATA_DIR, VECTOR_IMAGE_PDF


def test_no_meta_view_fails_gracefully():
    r = PdfFileReader(BytesIO(MINIMAL))
    assert r.document_meta_view == model.DocumentMetadata()


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
def test_copy_into_new_writer_sets_info():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = copy_into_new_writer(r)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    meta = r.document_meta_view
    assert meta.last_modified == datetime.now(tz=tzlocal.get_localzone())

    assert 'pyHanko' in r.trailer_view['/Info']['/Producer']


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
def test_incremental_update_meta_view():
    w = IncrementalPdfFileWriter(BytesIO(VECTOR_IMAGE_PDF))
    assert w.document_meta_view.created.year == 2020
    w.document_meta.created = datetime.now()
    assert w.document_meta_view.created.year == 2022


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
@pytest.mark.parametrize('writer_type', ('fresh', 'from_data', 'incremental'))
def test_writer_meta_view_does_not_persist_changes(writer_type):
    exp_value = datetime(2020, 9, 5, 19, 30, 57, tzinfo=pytz.FixedOffset(120))
    if writer_type == 'fresh':
        w = PdfFileWriter()
        exp_value = None
    elif writer_type == 'from_data':
        w = copy_into_new_writer(PdfFileReader(BytesIO(VECTOR_IMAGE_PDF)))
    else:
        w = IncrementalPdfFileWriter(BytesIO(VECTOR_IMAGE_PDF))
    assert w.document_meta_view.created == exp_value
    w.document_meta_view.created = datetime.now()
    assert w.document_meta_view.created == exp_value


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
@pytest.mark.parametrize('writer_type,meta_dict', list(itertools.product(
    ('fresh', 'from_data', 'incremental', 'in_place'),
    [
        {'title': 'Test test'},
        {'author': 'John Doe'},
        {'title': 'Test test', 'keywords': ['foo', 'bar', 'baz']},
        {'created': datetime(2022, 9, 7, tzinfo=pytz.utc)},
    ]
)))
def test_metadata_info_round_trip(writer_type, meta_dict: dict):
    out = BytesIO()
    if writer_type == 'fresh':
        w = PdfFileWriter()
    elif writer_type == 'from_data':
        w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    else:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    w.update_root()

    for k, v in meta_dict.items():
        setattr(w.document_meta, k, v)

    if writer_type == 'in_place':
        w.write_in_place()
        out = w.prev.stream
    else:
        w.write(out)

    r = PdfFileReader(out)
    meta_dict['last_modified'] = datetime.now(tz=tzlocal.get_localzone())
    assert r.document_meta_view == model.DocumentMetadata(**meta_dict)


# Example from ISO 16684-1:20121 7.9.2.3

XMP_WITH_PARSETYPE_RESOURCE = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xmpTPg="http://ns.adobe.com/xap/1.0/t/pg/"
         xmlns:stDim="http://ns.adobe.com/xap/1.0/sType/Dimensions#"
         xmlns:xmp="http://ns.adobe.com/xap/1.0/"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xmpTPg:MaxPageSize rdf:parseType="Resource">
            <stDim:h>11.0</stDim:h>
            <stDim:w>8.5</stDim:w>
            <stDim:unit>inch</stDim:unit>
        </xmpTPg:MaxPageSize>
        <xmp:BaseURL rdf:parseType="Resource">
            <rdf:value rdf:resource="https://www.adobe.com/"/>
            <xe:qualifier>artificial example</xe:qualifier>
        </xmp:BaseURL>
   </rdf:Description>
</rdf:RDF>
"""


def test_xmp_parsetype_resource():
    inp = BytesIO(XMP_WITH_PARSETYPE_RESOURCE.encode('utf8'))
    result = xmp_xml.parse_xmp(inp)[0]

    n_max_page_size = model.ExpandedName(
        ns="http://ns.adobe.com/xap/1.0/t/pg/", local_name="MaxPageSize"
    )
    n_unit = model.ExpandedName(
        ns="http://ns.adobe.com/xap/1.0/sType/Dimensions#", local_name="unit"
    )
    n_base_url = model.ExpandedName(ns=model.NS['xmp'], local_name="BaseURL")
    n_xe_qualifier = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="qualifier"
    )
    max_page_size = result[n_max_page_size].value
    assert max_page_size[n_unit].value == 'inch'

    base_url_val = result[n_base_url]
    assert base_url_val.qualifiers[n_xe_qualifier].value == 'artificial example'
    assert base_url_val.value == "https://www.adobe.com/"


def test_ensure_uri_is_rdf_resource():
    n_base_url = model.ExpandedName(ns=model.NS['xmp'], local_name="BaseURL")
    root = model.XmpStructure.of(
        (n_base_url, model.XmpValue("https://example.com"))
    )
    out = BytesIO()
    xmp_xml.serialise_xmp([root], out)
    assert b'rdf:resource="https://example.com"' in out.getvalue()


@freeze_time('2022-09-10')
def test_incremental_update_doc_with_xmp():
    with open(os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb') \
            as inf:
        w = IncrementalPdfFileWriter(inf)
        w.root['/Foo'] = generic.NameObject('/Bar')
        w.document_meta.subject = "Update test"
        out = BytesIO()
        w.write(out)
    r = PdfFileReader(out)
    xmp: model.XmpStructure = r.root['/Metadata'].xmp[0]
    assert xmp[model.DC_DESCRIPTION].value.entries[0].value == "Update test"
    pdfa_conformance = model.ExpandedName(
        "http://www.aiim.org/pdfa/ns/id/", "conformance"
    )
    assert xmp[pdfa_conformance].value == "B"


@freeze_time('2022-09-10')
def test_rewrite_update_doc_with_xmp():
    with open(os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb') \
            as inf:
        w = copy_into_new_writer(PdfFileReader(inf))
        w.document_meta.subject = "Update test"
        out = BytesIO()
        w.write(out)
    r = PdfFileReader(out)
    xmp: model.XmpStructure = r.root['/Metadata'].xmp[0]
    assert xmp[model.DC_DESCRIPTION].value.entries[0].value == "Update test"
    pdfa_conformance = model.ExpandedName(
        "http://www.aiim.org/pdfa/ns/id/", "conformance"
    )
    assert xmp[pdfa_conformance].value == "B"
