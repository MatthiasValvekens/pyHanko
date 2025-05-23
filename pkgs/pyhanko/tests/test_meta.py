import itertools
import os
from datetime import datetime, timezone
from io import BytesIO

import pytest
import tzlocal
from freezegun import freeze_time
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import EncryptedObjAccess
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.metadata import model, xmp_xml
from pyhanko.pdf_utils.misc import StringWithLanguage
from pyhanko.pdf_utils.reader import HistoricalResolver, PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter, copy_into_new_writer

from .samples import MINIMAL, PDF_DATA_DIR, VECTOR_IMAGE_PDF

try:
    import zoneinfo
except ImportError:
    # noinspection PyUnresolvedReferences
    from backports import zoneinfo


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


def test_date_parse_failure():
    r = PdfFileReader(BytesIO(MINIMAL))
    writer_kwargs = {
        'info': generic.DictionaryObject(
            {
                generic.pdf_name('/Title'): generic.pdf_string(
                    'a failure test'
                ),
                generic.pdf_name('/CreationDate'): generic.pdf_string(
                    'this makes no sense'
                ),
            }
        )
    }
    w = copy_into_new_writer(r, writer_kwargs=writer_kwargs)
    w._update_meta = lambda: None
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    meta = r.document_meta_view
    assert meta.created is None
    assert meta.title == "a failure test"


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
def test_incremental_update_meta_view():
    w = IncrementalPdfFileWriter(BytesIO(VECTOR_IMAGE_PDF))
    assert w.document_meta_view.created.year == 2020
    w.document_meta.created = datetime.now()
    assert w.document_meta_view.created.year == 2022


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
@pytest.mark.parametrize('writer_type', ('fresh', 'from_data', 'incremental'))
def test_writer_meta_view_does_not_persist_changes(writer_type):
    exp_value = datetime(
        2020, 9, 5, 19, 30, 57, tzinfo=zoneinfo.ZoneInfo('CET')
    )
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
@pytest.mark.parametrize(
    'writer_type,meta_dict,ver',
    list(
        itertools.product(
            ('fresh', 'from_data', 'incremental', 'in_place'),
            [
                {'title': 'Test test'},
                {'author': 'John Doe'},
                {'keywords': ['foo', 'bar', 'baz']},
                {'created': datetime(2022, 9, 7, tzinfo=timezone.utc)},
                {'author': 'John Doe', 'subject': 'Blah blah blah'},
            ],
            ("pdf1.7", "pdf2.0"),
        )
    ),
)
def test_metadata_info_round_trip(writer_type, meta_dict: dict, ver):
    out = BytesIO()
    if writer_type == 'fresh':
        w = PdfFileWriter()
    elif writer_type == 'from_data':
        w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    else:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    w.output_version = (1, 7) if ver == "pdf1.7" else (2, 0)

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
    if ver == "pdf2.0":
        assert '/Info' not in r.trailer_view
    else:
        assert r.document_meta_view == model.DocumentMetadata(**meta_dict)


@pytest.mark.parametrize(
    'writer_type,ver',
    list(
        itertools.product(
            ('fresh', 'from_data', 'incremental', 'in_place'), ((1, 7), (2, 0))
        )
    ),
)
def test_metadata_info_with_language_round_trip(writer_type, ver):
    title = StringWithLanguage('Test test', lang_code='en', country_code='US')
    out = BytesIO()
    if writer_type == 'fresh':
        w = PdfFileWriter()
    elif writer_type == 'from_data':
        w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    else:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    w.output_version = ver

    w.update_root()
    w.document_meta.title = title

    if writer_type == 'in_place':
        w.write_in_place()
        out = w.prev.stream
    else:
        w.write(out)

    r = PdfFileReader(out)
    if '/Metadata' in r.root:
        # language info preserved
        assert r.document_meta_view.title == title
    else:
        # language info not preserved
        assert r.document_meta_view.title == title.value


# Example from ISO 16684-1:20121 7.9.2.3

# noinspection HttpUrlsUsage
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


# noinspection HttpUrlsUsage
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
    assert base_url_val.value == model.XmpUri("https://www.adobe.com/")


def test_ensure_uri_is_rdf_resource():
    n_base_url = model.ExpandedName(ns=model.NS['xmp'], local_name="BaseURL")
    root = model.XmpStructure.of(
        (n_base_url, model.XmpValue(model.XmpUri("https://example.com")))
    )
    out = BytesIO()
    xmp_xml.serialise_xmp([root], out)
    assert b'rdf:resource="https://example.com"' in out.getvalue()


# noinspection HttpUrlsUsage
@freeze_time('2022-09-10')
def test_incremental_update_doc_with_xmp():
    with open(
        os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb'
    ) as inf:
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

    assert HistoricalResolver(r, 0).document_meta_view.subject is None


# noinspection HttpUrlsUsage
@freeze_time('2022-09-10')
def test_rewrite_update_doc_with_xmp():
    with open(
        os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb'
    ) as inf:
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


@freeze_time('2022-09-10')
def test_meta_view_from_xmp():
    with open(
        os.path.join(PDF_DATA_DIR, "minimal-pdf-ua-and-a.pdf"), 'rb'
    ) as inf:
        r = PdfFileReader(inf)
        # wipe out the info dict just because
        r.trailer['/Info'] = generic.DictionaryObject()
        assert r.document_meta_view.title == StringWithLanguage(
            value="Test document", lang_code="DEFAULT"
        )


def test_upgrade_pdf2_no_info_dict():
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)
    w.output_version = (2, 0)
    w.root['/Foo'] = generic.NameObject('/Bar')
    w.document_meta.title = "Test document"
    w.document_meta.author = "John Doe"
    w.document_meta.subject = "Test subject"
    w.document_meta.keywords = ["these", "are", "key", "words"]
    w.write_in_place()

    r = PdfFileReader(buf)
    assert '/Info' not in r.trailer_view
    assert r.document_meta_view.title.value == "Test document"
    assert r.document_meta_view.author == "John Doe"
    assert r.document_meta_view.subject.value == "Test subject"
    assert r.document_meta_view.keywords == ["these", "are", "key", "words"]

    # historical resolver only looks at info dict
    assert HistoricalResolver(r, 0).document_meta_view.subject is None


# noinspection HttpUrlsUsage
def test_add_extra_xmp():
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)
    w.root['/Foo'] = generic.NameObject('/Bar')
    w.document_meta.title = "Test document"

    n_base_url = model.ExpandedName(ns=model.NS['xmp'], local_name="BaseURL")
    n_xe_qualifier = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="qualifier"
    )
    extra = model.XmpStructure.of(
        (
            n_base_url,
            model.XmpValue(
                model.XmpUri("https://example.com/"),
                qualifiers=model.Qualifiers.of(
                    (n_xe_qualifier, model.XmpValue('artificial example'))
                ),
            ),
        ),
    )
    w.document_meta.xmp_extra = [extra]
    w.write_in_place()

    r = PdfFileReader(buf)
    assert '/Info' not in r.trailer_view
    assert r.document_meta_view.title.value == "Test document"

    base_url_val = r.root['/Metadata'].xmp[1][n_base_url]
    assert base_url_val.qualifiers[n_xe_qualifier].value == 'artificial example'
    assert base_url_val.value == model.XmpUri("https://example.com/")


# noinspection HttpUrlsUsage
def test_unmanaged_xmp():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = copy_into_new_writer(r)
    n_base_url = model.ExpandedName(ns=model.NS['xmp'], local_name="BaseURL")
    n_xe_qualifier = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="qualifier"
    )
    extra = model.XmpStructure.of(
        (
            n_base_url,
            model.XmpValue(
                model.XmpUri("https://example.com/"),
                qualifiers=model.Qualifiers.of(
                    (n_xe_qualifier, model.XmpValue('artificial example'))
                ),
            ),
        ),
    )
    w.document_meta.title = "This should not be written"
    w.document_meta.xmp_unmanaged = True
    w.document_meta.xmp_extra = [extra]
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert '/Info' not in r.trailer_view
    assert r.document_meta_view.title is None

    base_url_val = r.root['/Metadata'].xmp[1][n_base_url]
    assert base_url_val.qualifiers[n_xe_qualifier].value == 'artificial example'
    assert base_url_val.value == model.XmpUri("https://example.com/")


# noinspection HttpUrlsUsage
def test_unmanaged_xmp_does_not_affect_info():
    # use a PDF that already has an info dictionary
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = copy_into_new_writer(r)
    n_base_url = model.ExpandedName(ns=model.NS['xmp'], local_name="BaseURL")
    n_xe_qualifier = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="qualifier"
    )
    extra = model.XmpStructure.of(
        (
            n_base_url,
            model.XmpValue(
                model.XmpUri("https://example.com/"),
                qualifiers=model.Qualifiers.of(
                    (n_xe_qualifier, model.XmpValue('artificial example'))
                ),
            ),
        ),
    )
    w.document_meta.title = "This should not be written"
    w.document_meta.xmp_unmanaged = True
    w.document_meta.xmp_extra = [extra]
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    meta = r.document_meta_view
    assert meta.title is None
    # producer line should update
    assert 'pyHanko' in r.trailer_view['/Info']['/Producer']


# noinspection HttpUrlsUsage
XMP_WITH_RESOURCE_WITH_MULTIPLE_QUALS = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:dc="http://purl.org/dc/elements/1.1/"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <dc:title rdf:parseType="Resource" xml:lang="en">
            <!-- NOTE: this is actually not valid in the DC schema -->
            <rdf:value>This is a test</rdf:value>
            <xe:qualifier>artificial example</xe:qualifier>
        </dc:title>
   </rdf:Description>
</rdf:RDF>
"""


# noinspection HttpUrlsUsage
def test_xmp_with_resource_with_multiple_quals():
    inp = BytesIO(XMP_WITH_RESOURCE_WITH_MULTIPLE_QUALS.encode('utf8'))
    result = xmp_xml.parse_xmp(inp)[0]
    qual_ct = result[model.DC_TITLE].qualifiers.iter_quals(with_lang=True)
    assert len(list(qual_ct)) == 2

    n_xe_qualifier = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="qualifier"
    )

    assert result == model.XmpStructure.of(
        (
            model.DC_TITLE,
            model.XmpValue(
                "This is a test",
                model.Qualifiers.of(
                    (model.XML_LANG, model.XmpValue("en")),
                    (
                        n_xe_qualifier,
                        model.XmpValue(
                            "artificial example",
                            model.Qualifiers.lang_as_qual("en"),
                        ),
                    ),
                ),
            ),
        ),
        (model.RDF_ABOUT, model.XmpValue("")),
    )
    title_val = result[model.DC_TITLE]
    assert title_val.qualifiers[n_xe_qualifier].value == 'artificial example'
    assert xmp_xml.meta_from_xmp([result]).title == model.StringWithLanguage(
        "This is a test", lang_code="en"
    )


def test_xmp_str():
    inp = BytesIO(XMP_WITH_RESOURCE_WITH_MULTIPLE_QUALS.encode('utf8'))
    result = xmp_xml.parse_xmp(inp)[0]
    r = repr(result)
    assert "artificial" in r
    assert "lang': \'en\'" in r


# noinspection HttpUrlsUsage
XMP_WITH_BAG = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:keywords rdf:parseType="Resource">
            <rdf:value>
                <rdf:Bag>
                    <rdf:li>apple</rdf:li>
                    <rdf:li>pear</rdf:li>
                    <rdf:li>banana</rdf:li>
                </rdf:Bag>
            </rdf:value>
            <xml:lang>en</xml:lang>
            <xe:qualifier>artificial example</xe:qualifier>
        </xe:keywords>
   </rdf:Description>
</rdf:RDF>
"""


# noinspection HttpUrlsUsage
def test_xmp_with_bag():
    inp = BytesIO(XMP_WITH_BAG.encode('utf8'))
    result = xmp_xml.parse_xmp(inp)[0]

    n_xe_keywords = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="keywords"
    )
    n_xe_qualifier = model.ExpandedName(
        ns="http://ns.adobe.com/xmp-example/", local_name="qualifier"
    )

    keywords_val = result[n_xe_keywords]
    assert keywords_val.qualifiers[n_xe_qualifier].value == 'artificial example'

    assert keywords_val.value == model.XmpArray.unordered(
        map(model.XmpValue, ['apple', 'banana', 'pear'])
    )


def test_xmp_ord_arr_comparison():
    o1 = model.XmpArray.ordered(
        map(model.XmpValue, ['apple', 'pear', 'banana'])
    )
    o2 = model.XmpArray.ordered(
        map(model.XmpValue, ['apple', 'banana', 'pear'])
    )
    a = model.XmpArray.alternative(
        map(model.XmpValue, ['apple', 'pear', 'banana'])
    )
    assert o1 != o2
    assert o1 != a


def test_xmp_unord_arr_comparison():
    u1 = model.XmpArray.unordered(
        map(model.XmpValue, ['apple', 'pear', 'banana'])
    )
    u2 = model.XmpArray.unordered(
        map(model.XmpValue, ['apple', 'banana', 'pear'])
    )
    assert u1 == u2


# noinspection HttpUrlsUsage
XMP_WITH_PARSETYPE_LIT_INVALID = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title rdf:parseType="Literal">bleh</xe:title>
   </rdf:Description>
</rdf:RDF>
"""


def test_xmp_parsetype_lit_not_supported():
    with pytest.raises(xmp_xml.XmpXmlProcessingError, match="Literal"):
        xmp_xml.parse_xmp(
            BytesIO(XMP_WITH_PARSETYPE_LIT_INVALID.encode('utf8'))
        )


# noinspection HttpUrlsUsage
XMP_WITH_INVALID_VALUE_FORM = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title><xe:zzz/></xe:title>
   </rdf:Description>
</rdf:RDF>
"""


def test_xmp_with_invalid_form():
    with pytest.raises(xmp_xml.XmpXmlProcessingError, match="value form"):
        xmp_xml.parse_xmp(BytesIO(XMP_WITH_INVALID_VALUE_FORM.encode('utf8')))


# noinspection HttpUrlsUsage
XMP_VALUE_FORM_MULTIPLE_CHILDREN = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title><xe:foo/><xe:bar/></xe:title>
   </rdf:Description>
</rdf:RDF>
"""


def test_xmp_value_form_multiple_children():
    with pytest.raises(
        xmp_xml.XmpXmlProcessingError, match="more than one child"
    ):
        xmp_xml.parse_xmp(
            BytesIO(XMP_VALUE_FORM_MULTIPLE_CHILDREN.encode('utf8'))
        )


XMP_NO_RDF_IN_XMPMETA = """
<x:xmpmeta xmlns:x="adobe:ns:meta/">
</x:xmpmeta>
"""


def test_xmp_no_rdf_in_xmpmeta():
    with pytest.raises(
        xmp_xml.XmpXmlProcessingError, match="RDF node in x:xmpmeta"
    ):
        xmp_xml.parse_xmp(BytesIO(XMP_NO_RDF_IN_XMPMETA.encode('utf8')))


XMP_INVALID_ROOT = """
<xml:boo/>
"""


def test_xmp_invalid_root():
    with pytest.raises(xmp_xml.XmpXmlProcessingError, match="XMP root must be"):
        xmp_xml.parse_xmp(BytesIO(XMP_INVALID_ROOT.encode('utf8')))


# noinspection HttpUrlsUsage
XMP_WITH_DUPLICATE_STRUCT_FIELD = """
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:xe="http://ns.adobe.com/xmp-example/">
    <rdf:Description rdf:about="">
        <xe:title>bleh</xe:title>
        <xe:title>bleh</xe:title>
   </rdf:Description>
</rdf:RDF>
"""


def test_xmp_with_duplicate_struct_field():
    with pytest.raises(xmp_xml.XmpXmlProcessingError, match="Duplicate field"):
        xmp_xml.parse_xmp(
            BytesIO(XMP_WITH_DUPLICATE_STRUCT_FIELD.encode('utf8'))
        )


# noinspection HttpUrlsUsage
XMP_INVALID_DATE1 = """
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>1/1/2022</xmp:CreateDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
"""


def test_xmp_invalid_date1():
    with pytest.raises(
        xmp_xml.XmpXmlProcessingError, match="Failed to parse.*as a date"
    ):
        xmp_xml.meta_from_xmp(
            xmp_xml.parse_xmp(BytesIO(XMP_INVALID_DATE1.encode('utf8')))
        )


# noinspection HttpUrlsUsage
XMP_INVALID_DATE2 = """
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate rdf:parseType="Resource"></xmp:CreateDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
"""


def test_xmp_invalid_date2():
    with pytest.raises(xmp_xml.XmpXmlProcessingError, match="Wrong type"):
        xmp_xml.meta_from_xmp(
            xmp_xml.parse_xmp(BytesIO(XMP_INVALID_DATE2.encode('utf8')))
        )


# noinspection HttpUrlsUsage
PDFA_PLUS_UA_XMP_SAMPLE_WRONG_URI_TYPE = """
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.1.0-jc003">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:xmp="http://ns.adobe.com/xap/1.0/"
        xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
        xmlns:pdfuaid="http://www.aiim.org/pdfua/ns/id/"
        xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"
        xmlns:pdfaExtension="http://www.aiim.org/pdfa/ns/extension/"
        xmlns:pdfaSchema="http://www.aiim.org/pdfa/ns/schema#"
        xmlns:pdfaProperty="http://www.aiim.org/pdfa/ns/property#"
      dc:format="application/pdf"
      xmp:CreateDate="2022-07-07T01:26:05+02:00"
      xmp:ModifyDate="2022-07-07T01:26:05+02:00"
      pdfaid:part="2"
      pdfaid:conformance="A">
      <dc:creator>
        <rdf:Seq>
          <rdf:li>Matthias Valvekens</rdf:li>
        </rdf:Seq>
      </dc:creator>
      <dc:title>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">Curriculum Vitae</rdf:li>
        </rdf:Alt>
      </dc:title>
      <pdfuaid:part>1</pdfuaid:part>
      <pdfaExtension:schemas>
        <rdf:Bag>
          <rdf:li>
            <rdf:Description
              pdfaSchema:namespaceURI="http://www.aiim.org/pdfua/ns/id/"
              pdfaSchema:prefix="pdfuaid"
              pdfaSchema:schema="PDF/UA identification schema">
            <pdfaSchema:property>
              <rdf:Seq>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA version identifier"
                  pdfaProperty:name="part"
                  pdfaProperty:valueType="Integer"/>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA amendment identifier"
                  pdfaProperty:name="amd"
                  pdfaProperty:valueType="Text"/>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA corrigenda identifier"
                  pdfaProperty:name="corr"
                  pdfaProperty:valueType="Text"/>
              </rdf:Seq>
            </pdfaSchema:property>
            </rdf:Description>
          </rdf:li>
        </rdf:Bag>
      </pdfaExtension:schemas>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
"""


# noinspection HttpUrlsUsage
PDFA_PLUS_UA_XMP_SAMPLE_CORRECT_URI_TYPE = """
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.1.0-jc003">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:xmp="http://ns.adobe.com/xap/1.0/"
        xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
        xmlns:pdfuaid="http://www.aiim.org/pdfua/ns/id/"
        xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"
        xmlns:pdfaExtension="http://www.aiim.org/pdfa/ns/extension/"
        xmlns:pdfaSchema="http://www.aiim.org/pdfa/ns/schema#"
        xmlns:pdfaProperty="http://www.aiim.org/pdfa/ns/property#"
      dc:format="application/pdf"
      xmp:CreateDate="2022-07-07T01:26:05+02:00"
      xmp:ModifyDate="2022-07-07T01:26:05+02:00"
      pdfaid:part="2"
      pdfaid:conformance="A">
      <dc:creator>
        <rdf:Seq>
          <rdf:li>Matthias Valvekens</rdf:li>
        </rdf:Seq>
      </dc:creator>
      <dc:title>
        <rdf:Alt>
          <rdf:li xml:lang="x-default">Curriculum Vitae</rdf:li>
        </rdf:Alt>
      </dc:title>
      <pdfuaid:part>1</pdfuaid:part>
      <pdfaExtension:schemas>
        <rdf:Bag>
          <rdf:li>
            <rdf:Description
              pdfaSchema:prefix="pdfuaid"
              pdfaSchema:schema="PDF/UA identification schema">
            <pdfaSchema:namespaceURI
              rdf:resource="http://www.aiim.org/pdfua/ns/id/"/>
            <pdfaSchema:property>
              <rdf:Seq>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA version identifier"
                  pdfaProperty:name="part"
                  pdfaProperty:valueType="Integer"/>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA amendment identifier"
                  pdfaProperty:name="amd"
                  pdfaProperty:valueType="Text"/>
                <rdf:li
                  pdfaProperty:category="internal"
                  pdfaProperty:description="PDF/UA corrigenda identifier"
                  pdfaProperty:name="corr"
                  pdfaProperty:valueType="Text"/>
              </rdf:Seq>
            </pdfaSchema:property>
            </rdf:Description>
          </rdf:li>
        </rdf:Bag>
      </pdfaExtension:schemas>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
"""


@pytest.mark.parametrize('sample', ['ok', 'wrong uri type'])
def test_parse_pdfa_ext_schema(sample):
    xmp = (
        PDFA_PLUS_UA_XMP_SAMPLE_CORRECT_URI_TYPE
        if sample == 'ok'
        else PDFA_PLUS_UA_XMP_SAMPLE_WRONG_URI_TYPE
    )
    roots = xmp_xml.parse_xmp(BytesIO(xmp.encode('utf8')))
    root = roots[0]
    pdfa_ext = root[model.ExpandedName(model.NS['pdfaExtension'], 'schemas')]
    pdfua_ext_schema = pdfa_ext.value.entries[0]
    pfx = pdfua_ext_schema.value[
        model.ExpandedName(model.NS['pdfaSchema'], 'prefix')
    ].value
    assert pfx == "pdfuaid"
    property_seq = pdfua_ext_schema.value[
        model.ExpandedName(model.NS['pdfaSchema'], 'property')
    ].value
    desc_value = property_seq.entries[0].value[
        model.ExpandedName(model.NS['pdfaProperty'], 'description')
    ]
    assert desc_value.value == "PDF/UA version identifier"
    ns_uri = pdfua_ext_schema.value[
        model.ExpandedName(model.NS['pdfaSchema'], 'namespaceURI')
    ].value
    assert isinstance(ns_uri, model.XmpUri)
    assert ns_uri.value == model.NS['pdfuaid']


@pytest.mark.parametrize('sample', ['ok', 'wrong uri type'])
def test_reser_pdfa_ext_schema(sample):
    xmp = (
        PDFA_PLUS_UA_XMP_SAMPLE_CORRECT_URI_TYPE
        if sample == 'ok'
        else PDFA_PLUS_UA_XMP_SAMPLE_WRONG_URI_TYPE
    )
    roots = xmp_xml.parse_xmp(BytesIO(xmp.encode('utf8')))
    out = BytesIO()
    xmp_xml.serialise_xmp(roots, out)
    roots_redux = xmp_xml.parse_xmp(out)
    assert roots_redux[0] == roots[0]


XMP_WITH_EMPTY_STRING = """
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.1.0-jc003">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        dc:format="application/pdf">
      <dc:creator>
        <rdf:Seq>
          <rdf:li/>
        </rdf:Seq>
      </dc:creator>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
"""


def test_empty_string():
    roots = xmp_xml.parse_xmp(BytesIO(XMP_WITH_EMPTY_STRING.encode('utf8')))
    assert roots[0][model.DC_CREATOR].value.entries[0].value == ""


def test_xmp_lang_explicit_xdefault():
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    w.output_version = (2, 0)
    w.document_meta.subject = model.StringWithLanguage("Blah", "DEFAULT")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert (
        b"<rdf:li xml:lang=\"x-default\">Blah</rdf:li>"
        in r.root['/Metadata'].data
    )


def test_encrypt_skipping_managed_metadata():
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    w.encrypt("secret", "secret", encrypt_metadata=False)
    w.document_meta.title = "Metadata is unencrypted"
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    # do not decrypt anything (not that it would matter in this case)
    ref = r.root.raw_get("/Metadata", decrypt=EncryptedObjAccess.RAW)
    raw_md = r.get_object(ref, never_decrypt=True)
    assert raw_md['/DecodeParms']['/Name'] == '/Identity'
    assert b'Metadata is unencrypted' in raw_md.encoded_data

    r = PdfFileReader(out)
    r.decrypt("secret")
    assert r.document_meta_view.title.value == "Metadata is unencrypted"


def test_encrypt_with_managed_metadata():
    w = copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    w.encrypt("secret", "secret")
    w.document_meta.title = "Metadata is encrypted"
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    # do not decrypt at first
    ref = r.root.raw_get("/Metadata", decrypt=EncryptedObjAccess.RAW)
    raw_md = r.get_object(ref, never_decrypt=True)
    assert b'Metadata is encrypted' not in raw_md.encoded_data

    r = PdfFileReader(out)
    r.decrypt("secret")
    assert r.document_meta_view.title.value == "Metadata is encrypted"


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
def test_incremental_update_handle_binary_producer_string():
    # Check whether binary (nondecodable) producer strings are handled
    # gracefully in incremental updates

    fname = os.path.join(PDF_DATA_DIR, 'info-bin-producer-string.pdf')
    out = BytesIO()
    with open(fname, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        w.root['/Blah'] = generic.pdf_name('/Blah')
        w.update_root()
        w.write(out)

    r = PdfFileReader(out)
    assert r.trailer_view['/Info']['/Producer'].startswith('pyHanko')


@freeze_time(datetime(2022, 9, 7, tzinfo=tzlocal.get_localzone()))
def test_rewrite_handle_binary_producer_string():
    # Check whether binary (nondecodable) producer strings are handled
    # gracefully

    fname = os.path.join(PDF_DATA_DIR, 'info-bin-producer-string.pdf')
    out = BytesIO()
    with open(fname, 'rb') as inf:
        w = copy_into_new_writer(PdfFileReader(inf))
        w.root['/Blah'] = generic.pdf_name('/Blah')
        w.write(out)

    r = PdfFileReader(out)
    assert r.trailer_view['/Info']['/Producer'].startswith('pyHanko')


def test_bogus_metadata_key_value():
    out = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(out)
    w.root['/Metadata'] = generic.pdf_name('/Blah')
    w.update_root()
    w._update_meta = lambda: None
    w.write_in_place()

    r = PdfFileReader(out)
    assert r._xmp_meta_view() is None
