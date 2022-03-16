import datetime
import itertools
import os
from fractions import Fraction
from io import BytesIO
from itertools import product
from typing import Tuple

import pytest
import pytz

from pyhanko.pdf_utils import generic, misc, writer
from pyhanko.pdf_utils.content import (
    PdfResources,
    ResourceManagementError,
    ResourceType,
)
from pyhanko.pdf_utils.crypt import (
    DEFAULT_CRYPT_FILTER,
    STD_CF,
    AuthStatus,
    CryptFilterConfiguration,
    IdentityCryptFilter,
    PubKeyAdbeSubFilter,
    PubKeyAESCryptFilter,
    PubKeyRC4CryptFilter,
    PubKeySecurityHandler,
    SecurityHandler,
    SecurityHandlerVersion,
    StandardAESCryptFilter,
    StandardRC4CryptFilter,
    StandardSecurityHandler,
    StandardSecuritySettingsRevision,
    build_crypt_filter,
)
from pyhanko.pdf_utils.generic import Reference, pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints, BoxSpecificationError
from pyhanko.pdf_utils.reader import PdfFileReader, RawPdfPath
from pyhanko.pdf_utils.rw_common import PdfHandler
from pyhanko.sign.general import load_cert_from_pemder

from .samples import *


@pytest.mark.parametrize('zip1, zip2',
                         [[True, True], [True, False], [False, False]])
def test_create_fresh(zip1, zip2):
    pdf_out = writer.PdfFileWriter()
    p1 = simple_page(pdf_out, 'Hello world', compress=zip1)
    p2 = simple_page(pdf_out, 'Hello Page 2', compress=zip2)
    p1_ref = pdf_out.insert_page(p1)
    p2_ref = pdf_out.insert_page(p2)

    out = BytesIO()
    pdf_out.write(out)
    out.seek(0)

    r = PdfFileReader(out)
    pages = r.root['/Pages']
    assert pages['/Count'] == 2
    kids = pages['/Kids']
    assert b'world' in kids[0].get_object()['/Contents'].data
    assert b'Page 2' in kids[1].get_object()['/Contents'].data

    assert r.find_page_for_modification(0)[0].idnum == p1_ref.idnum
    assert r.find_page_for_modification(1)[0].idnum == p2_ref.idnum
    assert r.find_page_for_modification(-1)[0].idnum == p2_ref.idnum
    assert r.find_page_for_modification(-2)[0].idnum == p1_ref.idnum

    with pytest.raises(misc.PdfError):
        r.find_page_for_modification(2)
    with pytest.raises(misc.PdfError):
        r.find_page_for_modification(-3)


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
    page_obj_ref = r.root['/Pages']['/Kids'].raw_get(0)
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
    page_obj_ref = r.root['/Pages']['/Kids'].raw_get(0)
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
    page_obj_ref = r.root['/Pages']['/Kids'].raw_get(0)
    assert isinstance(page_obj_ref, generic.IndirectObject)
    page_obj = page_obj_ref.get_object()
    conts = page_obj['/Contents']
    assert len(conts) == 3
    assert stream_ref.idnum in (c.idnum for c in conts)
    # check if resource dictionary is still OK
    assert '/F1' in page_obj['/Resources']['/Font']


def test_read_rewrite():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = BytesIO()
    w.write(out)
    out.seek(0)
    assert out.getvalue() == MINIMAL


def test_whitespace_variants():
    snippet_to_replace = b' /Pages 2 0 R'
    assert snippet_to_replace in MINIMAL
    for whitespace in [b' ', b'\n', b'\r', b'\t', b'\f']:
        new_snippet = snippet_to_replace.replace(b' ', whitespace)
        r = PdfFileReader(BytesIO(MINIMAL.replace(snippet_to_replace, new_snippet)))
        assert r.root['/Pages']['/Count'] == 1


@pytest.mark.parametrize('data', [
    b'/Test\x00B',
    b'/Test  B',
    b'/Test\x00  B',
    b'/Test\x00 [',
    b'/Test/B',
    b'/Tes#74/B',
    b'/Tes#74\x00/B',
    b'/Tes#74 /B',
    b'/Tes#74 \x00 /B',
])
def test_name_delim(data):
    res = generic.NameObject.read_from_stream(BytesIO(data))
    assert res == '/Test'


TEST_STRING = b'\x74\x77\x74\x84\x66'


def test_ascii_hex_decode():
    from pyhanko.pdf_utils import filters
    data = TEST_STRING * 20 + b'\0\0\0\0' + TEST_STRING * 20 + b'\x03\x02\x08'

    encoded = filters.ASCIIHexDecode().encode(data)
    assert filters.ASCIIHexDecode().decode(encoded) == data


def test_ascii85_decode():
    from pyhanko.pdf_utils import filters
    data = TEST_STRING * 20 + b'\0\0\0\0' + TEST_STRING * 20 + b'\x03\x02\x08'

    encoded = filters.ASCII85Decode().encode(data)
    # 50 normal groups of 4 * 5 -> 200,
    assert len(encoded) == 257
    assert filters.ASCII85Decode().decode(encoded) == data


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

page_import_test_files = (
    VECTOR_IMAGE_PDF, VECTOR_IMAGE_PDF_DECOMP, VECTOR_IMAGE_VARIANT_PDF
)


@pytest.mark.parametrize('file_no, inherit_filters',
                         list(product([0, 1, 2], [True, False])))
def test_page_import(file_no, inherit_filters):
    fbytes = page_import_test_files[file_no]
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


@pytest.mark.parametrize('stream_xrefs,with_objstreams,encrypt',
                         [(False, False, True), (False, False, False),
                          (True, False, False), (True, True, False),
                          (True, True, True)])
def test_page_tree_import(stream_xrefs, with_objstreams, encrypt):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter(stream_xrefs=stream_xrefs)
    if encrypt:
        w.encrypt("secret")
    if with_objstreams:
        objstream = w.prepare_object_stream()
    else:
        objstream = None
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'), obj_stream=objstream
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    if encrypt:
        r.decrypt("secret")
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data
    if with_objstreams:
        assert len(r.xrefs.object_streams_used_in(0)) == 1


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


def test_incremental_trailer_operations():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    w.add_object(generic.NullObject())
    assert '/Root' in w.trailer
    w.set_custom_trailer_entry(
        pdf_name('/TEST.Test'), generic.TextStringObject('bleh')
    )

    assert '/TEST.Test' in w.trailer
    iter_result = set(iter(w.trailer))
    assert '/TEST.Test' in iter_result
    assert '/Root' in iter_result

    assert ('/TEST.Test', 'bleh') in w.trailer.items()

    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.trailer['/TEST.Test'] == 'bleh'


@pytest.mark.parametrize('incremental', [True, False])
def test_generic_trailer_write(incremental):
    if incremental:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    else:
        w = writer.copy_into_new_writer(PdfFileReader(BytesIO(MINIMAL)))
    w.add_object(generic.NullObject())
    w.set_custom_trailer_entry(
        pdf_name('/TEST.Test'), generic.TextStringObject('bleh')
    )
    assert '/TEST.Test' in w.trailer_view
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.trailer['/TEST.Test'] == 'bleh'


def test_resource_add_test():
    res1 = PdfResources()
    res2 = PdfResources()
    res1[ResourceType.XOBJECT][pdf_name('/Bleh')] = generic.NullObject()
    res1[ResourceType.PATTERN][pdf_name('/Blih')] = generic.NullObject()
    res2[ResourceType.XOBJECT][pdf_name('/Blah')] = generic.NullObject()
    res2[ResourceType.FONT][pdf_name('/Bluh')] = generic.NullObject()

    res1 += res2
    res1_dict = res1.as_pdf_object()
    assert pdf_name('/XObject') in res1_dict
    assert pdf_name('/Pattern') in res1_dict
    assert pdf_name('/Font') in res1_dict
    assert pdf_name('/Bleh') in res1_dict['/XObject']
    assert pdf_name('/Blah') in res1_dict['/XObject']
    assert pdf_name('/Shading') not in res1_dict


def test_duplicate_resource():
    res1 = PdfResources()
    res2 = PdfResources()
    res1[ResourceType.XOBJECT][pdf_name('/Bleh')] = generic.NullObject()
    res1[ResourceType.PATTERN][pdf_name('/Blih')] = generic.NullObject()
    res2[ResourceType.XOBJECT][pdf_name('/Bleh')] = generic.NullObject()
    res2[ResourceType.FONT][pdf_name('/Bluh')] = generic.NullObject()

    with pytest.raises(ResourceManagementError):
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


def test_info_delete():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    with pytest.raises(misc.PdfError):
        w.set_info(None)


@pytest.mark.parametrize("use_owner_pass,rev,keylen_bytes,use_aes", [
    (True, StandardSecuritySettingsRevision.RC4_BASIC, 5, False),
    (False, StandardSecuritySettingsRevision.RC4_BASIC, 5, False),
    (True, StandardSecuritySettingsRevision.RC4_EXTENDED, 5, False),
    (False, StandardSecuritySettingsRevision.RC4_EXTENDED, 5, False),
    (True, StandardSecuritySettingsRevision.RC4_EXTENDED, 16, False),
    (False, StandardSecuritySettingsRevision.RC4_EXTENDED, 16, False),
    (True, StandardSecuritySettingsRevision.RC4_OR_AES128, 5, False),
    (False, StandardSecuritySettingsRevision.RC4_OR_AES128, 5, False),
    (True, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, False),
    (False, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, False),
    (True, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, True),
    (False, StandardSecuritySettingsRevision.RC4_OR_AES128, 16, True),
])
def test_legacy_encryption(use_owner_pass, rev, keylen_bytes, use_aes):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()
    sh = StandardSecurityHandler.build_from_pw_legacy(
        rev, w._document_id[0].original_bytes, "ownersecret", "usersecret",
        keylen_bytes=keylen_bytes, use_aes128=use_aes,
        perms=-44
    )
    w.security_handler = sh
    w._encrypt = w.add_object(sh.as_pdf_object())
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt("ownersecret" if use_owner_pass else "usersecret")
    if use_owner_pass:
        assert result.status == AuthStatus.OWNER
        assert result.permission_flags is None
    else:
        assert result.status == AuthStatus.USER
        assert result.permission_flags == -44
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert r.trailer['/Encrypt']['/P'] == -44
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data


@pytest.mark.parametrize("legacy", [True, False])
def test_wrong_password(legacy):
    w = writer.PdfFileWriter()
    ref = w.add_object(generic.TextStringObject("Blah blah"))
    if legacy:
        sh = StandardSecurityHandler.build_from_pw_legacy(
            StandardSecuritySettingsRevision.RC4_OR_AES128,
            w._document_id[0].original_bytes, "ownersecret", "usersecret",
            keylen_bytes=16, use_aes128=True
        )
    else:
        sh = StandardSecurityHandler.build_from_pw("ownersecret", "usersecret")
    w.security_handler = sh
    w._encrypt = w.add_object(sh.as_pdf_object())
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    with pytest.raises(misc.PdfReadError):
        r.get_object(ref.reference)
    assert r.decrypt("thispasswordiswrong").status == AuthStatus.FAILED
    assert r.security_handler._auth_failed
    assert r.security_handler.get_string_filter()._auth_failed
    with pytest.raises(misc.PdfReadError):
        r.get_object(ref.reference)


def test_identity_crypt_filter_api():

    # confirm that the CryptFilter API of the identity filter doesn't do
    # anything unexpected, even though we typically don't invoke it explicitly.
    idf: IdentityCryptFilter = IdentityCryptFilter()
    idf._set_security_handler(None)
    assert not idf._auth_failed
    assert isinstance(idf.derive_shared_encryption_key(), bytes)
    assert isinstance(idf.derive_object_key(1, 2), bytes)
    assert isinstance(idf.method, generic.NameObject)
    assert isinstance(idf.keylen, int)
    assert idf.decrypt(None, b'abc') == b'abc'
    assert idf.encrypt(None, b'abc') == b'abc'

    # can't serialise /Identity
    with pytest.raises(misc.PdfError):
        idf.as_pdf_object()


@pytest.mark.parametrize("use_alias, with_never_decrypt", [
    (True, False), (False, True), (False, False)
])
def test_identity_crypt_filter(use_alias, with_never_decrypt):
    w = writer.PdfFileWriter()
    sh = StandardSecurityHandler.build_from_pw("secret")
    w.security_handler = sh
    idf: IdentityCryptFilter = IdentityCryptFilter()
    assert sh.crypt_filter_config[pdf_name("/Identity")] is idf
    if use_alias:
        sh.crypt_filter_config._crypt_filters[pdf_name("/IdentityAlias")] = idf
        assert sh.crypt_filter_config[pdf_name("/IdentityAlias")] is idf
    if use_alias:
        # identity filter can't be serialised, so this should throw an error
        with pytest.raises(misc.PdfError):
            w._assign_security_handler(sh)
        return
    else:
        w._assign_security_handler(sh)
    test_bytes = b'This is some test data that should remain unencrypted.'
    test_stream = generic.StreamObject(
        stream_data=test_bytes, handler=sh
    )
    test_stream.apply_filter(
        "/Crypt", params={pdf_name("/Name"): pdf_name("/Identity")}
    )
    ref = w.add_object(test_stream).reference
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    r.decrypt("secret")
    the_stream = r.get_object(ref, never_decrypt=with_never_decrypt)
    assert the_stream.encoded_data == test_bytes
    assert the_stream.data == test_bytes


@pytest.mark.parametrize("version, keylen, use_aes, use_crypt_filters", [
    (SecurityHandlerVersion.AES256, 32, True, True),
    (SecurityHandlerVersion.RC4_OR_AES128, 16, True, True),
    (SecurityHandlerVersion.RC4_OR_AES128, 16, False, True),
    (SecurityHandlerVersion.RC4_OR_AES128, 5, False, True),
    (SecurityHandlerVersion.RC4_40, 5, False, True),
    (SecurityHandlerVersion.RC4_40, 5, False, False),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, True),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, False),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, True),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, False),
])
def test_pubkey_encryption(version, keylen, use_aes, use_crypt_filters):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_TEST_DECRYPTER.cert], keylen_bytes=keylen,
        version=version, use_aes=use_aes, use_crypt_filters=use_crypt_filters,
        perms=-44
    )
    w.security_handler = sh
    w._encrypt = w.add_object(sh.as_pdf_object())
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    assert result.status == AuthStatus.USER
    assert result.permission_flags == -44
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data


def test_key_encipherment_requirement():
    with pytest.raises(misc.PdfWriteError):
        PubKeySecurityHandler.build_from_certs(
            [PUBKEY_SELFSIGNED_DECRYPTER.cert], keylen_bytes=32,
            version=SecurityHandlerVersion.AES256,
            use_aes=True, use_crypt_filters=True,
            perms=-44
        )


@pytest.mark.parametrize("version, keylen, use_aes, use_crypt_filters", [
    (SecurityHandlerVersion.AES256, 32, True, True),
    (SecurityHandlerVersion.RC4_OR_AES128, 16, True, True),
    (SecurityHandlerVersion.RC4_OR_AES128, 16, False, True),
    (SecurityHandlerVersion.RC4_OR_AES128, 5, False, True),
    (SecurityHandlerVersion.RC4_40, 5, False, True),
    (SecurityHandlerVersion.RC4_40, 5, False, False),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, True),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 5, False, False),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, True),
    (SecurityHandlerVersion.RC4_LONGER_KEYS, 16, False, False),
])
def test_key_encipherment_requirement_override(version, keylen, use_aes,
                                               use_crypt_filters):
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_SELFSIGNED_DECRYPTER.cert], keylen_bytes=keylen,
        version=version, use_aes=use_aes, use_crypt_filters=use_crypt_filters,
        perms=-44, ignore_key_usage=True
    )
    w.security_handler = sh
    w._encrypt = w.add_object(sh.as_pdf_object())
    new_page_tree = w.import_object(
        r.root.raw_get('/Pages'),
    )
    w.root['/Pages'] = new_page_tree
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(PUBKEY_SELFSIGNED_DECRYPTER)
    assert result.status == AuthStatus.USER
    assert result.permission_flags == -44
    page = r.root['/Pages']['/Kids'][0].get_object()
    assert '/ExtGState' in page['/Resources']
    # just a piece of data I know occurs in the decoded content stream
    # of the (only) page in VECTOR_IMAGE_PDF
    assert b'0 1 0 rg /a0 gs' in page['/Contents'].data


def test_pubkey_alternative_filter():
    w = writer.PdfFileWriter()

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    # subfilter should be picked up
    w._encrypt.get_object()['/Filter'] = pdf_name('/FooBar')
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert isinstance(r.security_handler, PubKeySecurityHandler)


@pytest.mark.parametrize('delete_subfilter', [True, False])
def test_pubkey_unsupported_filter(delete_subfilter):
    w = writer.PdfFileWriter()

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    encrypt = w._encrypt.get_object()
    encrypt['/Filter'] = pdf_name('/FooBar')
    if delete_subfilter:
        del encrypt['/SubFilter']
    else:
        encrypt['/SubFilter'] = pdf_name('/baz.quux')
    out = BytesIO()
    w.write(out)
    with pytest.raises(misc.PdfReadError):
        PdfFileReader(out)


def test_pubkey_encryption_block_cfs_s4():
    w = writer.PdfFileWriter()

    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    encrypt = w._encrypt.get_object()
    encrypt['/SubFilter'] = pdf_name('/adbe.pkcs7.s4')
    out = BytesIO()
    w.write(out)
    with pytest.raises(misc.PdfReadError):
        PdfFileReader(out)


def test_pubkey_encryption_s5_requires_cfs():
    w = writer.PdfFileWriter()

    sh = PubKeySecurityHandler.build_from_certs([PUBKEY_TEST_DECRYPTER.cert])
    w._assign_security_handler(sh)
    encrypt = w._encrypt.get_object()
    del encrypt['/CF']
    out = BytesIO()
    w.write(out)
    with pytest.raises(misc.PdfReadError):
        PdfFileReader(out)


def test_pubkey_encryption_dict_errors():
    sh = PubKeySecurityHandler.build_from_certs([PUBKEY_TEST_DECRYPTER.cert])

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    encrypt['/SubFilter'] = pdf_name('/asdflakdsjf')
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    encrypt['/Length'] = generic.NumberObject(13)
    with pytest.raises(misc.PdfError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    del encrypt['/CF']['/DefaultCryptFilter']['/CFM']
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    del encrypt['/CF']['/DefaultCryptFilter']['/Recipients']
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)

    encrypt = generic.DictionaryObject(sh.as_pdf_object())
    encrypt['/CF']['/DefaultCryptFilter']['/CFM'] = pdf_name('/None')
    with pytest.raises(misc.PdfReadError):
        PubKeySecurityHandler.build(encrypt)


@pytest.mark.parametrize('with_hex_filter, main_unencrypted', [
    (True, False), (True, True), (False, True), (False, False)
])
def test_custom_crypt_filter(with_hex_filter, main_unencrypted):
    w = writer.PdfFileWriter()
    custom = pdf_name('/Custom')
    crypt_filters = {
        custom: StandardRC4CryptFilter(keylen=16),
    }
    if main_unencrypted:
        # streams/strings are unencrypted by default
        cfc = CryptFilterConfiguration(crypt_filters=crypt_filters)
    else:
        crypt_filters[STD_CF] = StandardAESCryptFilter(keylen=16)
        cfc = CryptFilterConfiguration(
            crypt_filters=crypt_filters,
            default_string_filter=STD_CF, default_stream_filter=STD_CF
        )
    sh = StandardSecurityHandler.build_from_pw_legacy(
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        id1=w.document_id[0], desired_user_pass="usersecret",
        desired_owner_pass="ownersecret",
        keylen_bytes=16, crypt_filter_config=cfc
    )
    w._assign_security_handler(sh)
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    dummy_stream.add_crypt_filter(name=custom, handler=sh)
    ref = w.add_object(dummy_stream)
    dummy_stream2 = generic.StreamObject(stream_data=test_data)
    ref2 = w.add_object(dummy_stream2)

    if with_hex_filter:
        dummy_stream.apply_filter(pdf_name('/AHx'))
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    r.decrypt("ownersecret")
    obj: generic.StreamObject = r.get_object(ref.reference)
    assert obj.data == test_data
    if with_hex_filter:
        cf_dict = obj['/DecodeParms'][1]
    else:
        cf_dict = obj['/DecodeParms']

    assert cf_dict['/Name'] == pdf_name('/Custom')

    obj2: generic.DecryptedObjectProxy = r.get_object(
        ref2.reference, transparent_decrypt=False
    )
    raw = obj2.raw_object
    assert isinstance(raw, generic.StreamObject)
    if main_unencrypted:
        assert raw.encoded_data == test_data
    else:
        assert raw.encoded_data != test_data


@pytest.mark.parametrize('with_hex_filter, main_unencrypted', [
    (True, False), (True, True), (False, True), (False, False)
])
def test_custom_pubkey_crypt_filter(with_hex_filter, main_unencrypted):
    w = writer.PdfFileWriter()
    custom = pdf_name('/Custom')
    crypt_filters = {
        custom: PubKeyRC4CryptFilter(keylen=16),
    }
    if main_unencrypted:
        # streams/strings are unencrypted by default
        cfc = CryptFilterConfiguration(crypt_filters=crypt_filters)
    else:
        crypt_filters[DEFAULT_CRYPT_FILTER] = PubKeyAESCryptFilter(
            keylen=16, acts_as_default=True
        )
        cfc = CryptFilterConfiguration(
            crypt_filters=crypt_filters,
            default_string_filter=DEFAULT_CRYPT_FILTER,
            default_stream_filter=DEFAULT_CRYPT_FILTER
        )
    sh = PubKeySecurityHandler(
        version=SecurityHandlerVersion.RC4_OR_AES128,
        pubkey_handler_subfilter=PubKeyAdbeSubFilter.S5,
        legacy_keylen=16, crypt_filter_config=cfc
    )

    # if main_unencrypted, these should be no-ops
    sh.add_recipients([PUBKEY_TEST_DECRYPTER.cert])
    # (this is always pointless, but it should be allowed)
    sh.add_recipients([PUBKEY_TEST_DECRYPTER.cert])

    crypt_filters[custom].add_recipients([PUBKEY_TEST_DECRYPTER.cert])
    w._assign_security_handler(sh)

    encrypt_dict = w._encrypt.get_object()
    cfs = encrypt_dict['/CF']
    # no /Recipients in S5 mode
    assert '/Recipients' not in encrypt_dict
    assert isinstance(cfs[custom]['/Recipients'], generic.ByteStringObject)
    if main_unencrypted:
        assert DEFAULT_CRYPT_FILTER not in cfs
    else:
        default_rcpts = cfs[DEFAULT_CRYPT_FILTER]['/Recipients']
        assert isinstance(default_rcpts, generic.ArrayObject)
        assert len(default_rcpts) == 2

    # custom crypt filters can only have one set of recipients
    with pytest.raises(misc.PdfError):
        crypt_filters[custom].add_recipients([PUBKEY_TEST_DECRYPTER.cert])

    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    dummy_stream.add_crypt_filter(name=custom, handler=sh)
    ref = w.add_object(dummy_stream)
    dummy_stream2 = generic.StreamObject(stream_data=test_data)
    ref2 = w.add_object(dummy_stream2)

    if with_hex_filter:
        dummy_stream.apply_filter(pdf_name('/AHx'))
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)

    # the custom test filter shouldn't have been decrypted yet
    # so attempting to decode the stream should cause the crypt filter
    # to throw an error
    obj: generic.StreamObject = r.get_object(ref.reference)
    with pytest.raises(misc.PdfError):
        # noinspection PyStatementEffect
        obj.data

    r.security_handler.crypt_filter_config[custom].authenticate(
        PUBKEY_TEST_DECRYPTER
    )
    assert obj.data == test_data
    if with_hex_filter:
        cf_dict = obj['/DecodeParms'][1]
    else:
        cf_dict = obj['/DecodeParms']

    assert cf_dict['/Name'] == pdf_name('/Custom')

    obj2: generic.DecryptedObjectProxy = r.get_object(
        ref2.reference, transparent_decrypt=False
    )
    raw = obj2.raw_object
    assert isinstance(raw, generic.StreamObject)
    if main_unencrypted:
        assert raw.encoded_data == test_data
    else:
        assert raw.encoded_data != test_data


def test_custom_crypt_filter_errors():
    w = writer.PdfFileWriter()
    custom = pdf_name('/Custom')
    crypt_filters = {
        custom: StandardRC4CryptFilter(keylen=16),
        STD_CF: StandardAESCryptFilter(keylen=16)
    }
    cfc = CryptFilterConfiguration(
        crypt_filters=crypt_filters,
        default_string_filter=STD_CF, default_stream_filter=STD_CF
    )
    sh = StandardSecurityHandler.build_from_pw_legacy(
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        id1=w.document_id[0], desired_user_pass="usersecret",
        desired_owner_pass="ownersecret",
        keylen_bytes=16, crypt_filter_config=cfc
    )
    w._assign_security_handler(sh)
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    with pytest.raises(misc.PdfStreamError):
        dummy_stream.add_crypt_filter(name='/Idontexist', handler=sh)

    # no handler
    dummy_stream.add_crypt_filter(name=custom)
    dummy_stream._handler = None
    w.add_object(dummy_stream)

    out = BytesIO()
    with pytest.raises(misc.PdfStreamError):
        w.write(out)


def test_continue_encrypted_file_without_auth():
    w = writer.PdfFileWriter()
    w.root["/Test"] = generic.TextStringObject("Blah blah")
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    incr_w = IncrementalPdfFileWriter(out)
    incr_w.root["/Test"] = generic.TextStringObject("Bluh bluh")
    incr_w.update_root()
    with pytest.raises(misc.PdfWriteError):
        incr_w.write_in_place()


def test_continue_encrypted_file_from_reader():
    w = writer.PdfFileWriter()
    w.root["/Test"] = generic.TextStringObject("Blah blah")
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    # first decrypt, then extend
    r.decrypt("usersecret")
    incr_w = IncrementalPdfFileWriter.from_reader(r)
    incr_w.root["/Test"] = generic.TextStringObject("Bluh bluh")
    incr_w.update_root()
    incr_w.write_in_place()

    r = PdfFileReader(out)
    r.decrypt("usersecret")
    assert r.root['/Test'] == generic.TextStringObject("Bluh bluh")


def test_copy_file():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1


def test_aes256_perm_read():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_AES256))
    result = r.decrypt("ownersecret")
    assert result.permission_flags is None
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_AES256))
    result = r.decrypt("usersecret")
    assert result.permission_flags == -4

    assert r.trailer['/Encrypt']['/P'] == -4


def test_copy_encrypted_file():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_AES256))
    r.decrypt("ownersecret")
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1


def test_copy_to_encrypted_file():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    w.encrypt("ownersecret", "usersecret")
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt("ownersecret")
    assert result.status == AuthStatus.OWNER
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1


def test_empty_user_pass():
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    old_root_ref = w.root_ref
    w.encrypt('ownersecret', '')
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt('')
    assert result.status == AuthStatus.USER
    assert r.root_ref == old_root_ref
    assert len(r.root['/AcroForm']['/Fields']) == 1
    assert len(r.root['/Pages']['/Kids']) == 1
    assert r.trailer['/Info']['/Producer'].startswith('pyHanko')


def test_load_pkcs12():

    sedk = SimpleEnvelopeKeyDecrypter.load_pkcs12(
        "pyhanko_tests/data/crypto/selfsigned.pfx", b'exportsecret'
    )
    assert sedk.cert.subject == PUBKEY_SELFSIGNED_DECRYPTER.cert.subject


def test_pubkey_wrong_cert():
    r = PdfFileReader(BytesIO(VECTOR_IMAGE_PDF))
    w = writer.PdfFileWriter()

    recpt_cert = load_cert_from_pemder(
        TESTING_CA_DIR + '/interm/decrypter2.cert.pem'
    )
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    ref = w.add_object(dummy_stream)
    w.encrypt_pubkey([recpt_cert])
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    assert result.status == AuthStatus.FAILED

    with pytest.raises(misc.PdfError):
        r.get_object(ref.reference)


# noinspection PyMethodMayBeStatic
class PathMockHandler(PdfHandler):
    @property
    def trailer_view(self) -> generic.DictionaryObject:
        raise NotImplementedError

    @property
    def root_ref(self) -> generic.Reference:
        raise NotImplementedError

    @property
    def document_id(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def get_object(self, ref, *_args, **_kwargs):
        if ref.idnum == 0:
            return generic.TextStringObject('OK')
        else:
            return generic.ArrayObject([generic.NumberObject(7)])


path_test_obj = generic.DictionaryObject({
    pdf_name('/Blah'): generic.DictionaryObject({
        pdf_name('/Bleh'): generic.ArrayObject(
            [generic.NumberObject(5), pdf_name('/Foo')]
        ),
        pdf_name('/Null'): generic.NullObject(),
    }),
    pdf_name('/WithRefs'): generic.DictionaryObject({
        pdf_name('/Arr'): generic.IndirectObject(1, 0, PathMockHandler()),
        pdf_name('/String'): generic.IndirectObject(0, 0, PathMockHandler())
    })
})


@pytest.mark.parametrize('path, result', [
    (RawPdfPath('/Blah', '/Bleh', 1), '/Foo'),
    (RawPdfPath('/Blah', '/Bleh', 0), 5),
    (RawPdfPath('/Blah', '/Null'), generic.NullObject()),
    (RawPdfPath('/WithRefs', '/Arr', 0), 7),
    (RawPdfPath('/WithRefs', '/String'), 'OK')
])
def test_path_access(path, result):
    assert path.access_on(path_test_obj) == result


@pytest.mark.parametrize('path', [
    RawPdfPath(0), RawPdfPath('/Blah', '/Null', '/NothingLeft'),
    RawPdfPath('/Blah', '/Bleh', '/NotADictionary'),
    RawPdfPath('/TheresNoSuchKey'), RawPdfPath('/Blah', '/Bleh', 10000)
])
def test_path_access_failures(path):
    with pytest.raises(misc.PdfReadError):
        path.access_on(path_test_obj)


def test_path_access_reference():
    ref1 = RawPdfPath('/WithRefs', '/Arr').access_reference_on(path_test_obj)
    assert ref1.idnum == 1

    ref1 = RawPdfPath('/WithRefs', '/String').access_reference_on(path_test_obj)
    assert ref1.idnum == 0

    with pytest.raises(misc.IndirectObjectExpected):
        RawPdfPath('/Blah').access_reference_on(path_test_obj)


def test_bool_dunders():
    bool_true = generic.BooleanObject(True)
    bool_false = generic.BooleanObject(False)
    assert bool_true != bool_false
    assert bool_true != ''
    assert bool_false != ''
    assert bool_true
    assert not bool_false
    assert bool_true == bool(bool_true)
    assert bool_false == bool(bool_false)

    assert repr(bool_true) == str(bool_true) == 'True'
    assert repr(bool_false) == str(bool_false) == 'False'


def test_pdf_num_precision():
    assert repr(generic.FloatObject('32.00001')) == '32.00001'
    assert repr(generic.FloatObject('32.92001')) == '32.92001'
    assert repr(generic.FloatObject('32')) == '32'


@pytest.mark.parametrize('arr_str', [b'[1 1 1]', b'[1 1 1\x00\x00\x00]',
                                     b'[1\x00\x001 1 ]'])
def test_array_null_bytes(arr_str):
    stream = BytesIO(arr_str)
    parsed = generic.ArrayObject.read_from_stream(stream, generic.Reference(1))
    assert parsed == [1, 1, 1]


def test_crypt_filter_build_failures():
    cfdict = generic.DictionaryObject()
    assert build_crypt_filter({}, cfdict, False) is None
    cfdict['/CFM'] = generic.NameObject('/None')
    assert build_crypt_filter({}, cfdict, False) is None

    with pytest.raises(NotImplementedError):
        cfdict['/CFM'] = generic.NameObject('/NoSuchCF')
        build_crypt_filter({}, cfdict, False)


@pytest.mark.parametrize('on_subclass', [True, False])
def test_custom_crypt_filter_type(on_subclass):
    w = writer.PdfFileWriter()
    custom_cf_type = pdf_name('/CustomCFType')

    class CustomCFClass(StandardRC4CryptFilter):
        def __init__(self):
            super().__init__(keylen=16)
        method = custom_cf_type

    if on_subclass:
        class NewStandardSecurityHandler(StandardSecurityHandler):
            pass
        sh_class = NewStandardSecurityHandler
        assert sh_class._known_crypt_filters is \
               not StandardSecurityHandler._known_crypt_filters
        assert '/V2' in sh_class._known_crypt_filters
        SecurityHandler.register(sh_class)
    else:
        sh_class = StandardSecurityHandler

    sh_class.register_crypt_filter(
        custom_cf_type, lambda _, __: CustomCFClass(),
    )
    cfc = CryptFilterConfiguration(
        crypt_filters={STD_CF: CustomCFClass()},
        default_string_filter=STD_CF, default_stream_filter=STD_CF
    )
    sh = sh_class.build_from_pw_legacy(
        rev=StandardSecuritySettingsRevision.RC4_OR_AES128,
        id1=w.document_id[0], desired_user_pass="usersecret",
        desired_owner_pass="ownersecret",
        keylen_bytes=16, crypt_filter_config=cfc
    )
    assert isinstance(sh, sh_class)
    w._assign_security_handler(sh)
    test_data = b'This is test data!'
    dummy_stream = generic.StreamObject(stream_data=test_data)
    ref = w.add_object(dummy_stream)

    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    r.decrypt("ownersecret")

    cfc = r.security_handler.crypt_filter_config
    assert cfc.stream_filter_name == cfc.string_filter_name
    obj: generic.StreamObject = r.get_object(ref.reference)
    assert obj.data == test_data

    obj: generic.DecryptedObjectProxy = \
        r.get_object(ref.reference, transparent_decrypt=False)
    assert isinstance(obj.raw_object, generic.StreamObject)
    assert obj.raw_object.encoded_data != test_data

    # restore security handler registry state
    del sh_class._known_crypt_filters[custom_cf_type]
    if on_subclass:
        SecurityHandler.register(StandardSecurityHandler)


def test_security_handler_version_deser():
    assert SecurityHandlerVersion.from_number(5) \
           == SecurityHandlerVersion.AES256
    assert SecurityHandlerVersion.from_number(6) == SecurityHandlerVersion.OTHER
    assert SecurityHandlerVersion.from_number(None) \
           == SecurityHandlerVersion.OTHER

    assert StandardSecuritySettingsRevision.from_number(6) \
           == StandardSecuritySettingsRevision.AES256
    assert StandardSecuritySettingsRevision.from_number(7) \
           == StandardSecuritySettingsRevision.OTHER


def test_ordered_enum():

    class Version(misc.OrderedEnum):
        VER1 = 1
        VER2 = 2

    assert Version.VER2 > Version.VER1
    assert Version.VER2 >= Version.VER1
    assert not (Version.VER1 > Version.VER1)

    assert Version.VER1 < Version.VER2
    assert Version.VER1 <= Version.VER2
    assert not (Version.VER1 < Version.VER1)


def test_version_enum():

    class Version(misc.VersionEnum):
        VER1 = 1
        VER2 = 2
        FUTURE = None

    assert Version.VER2 > Version.VER1
    assert Version.VER2 >= Version.VER1
    assert Version.FUTURE > Version.VER1
    assert Version.FUTURE >= Version.VER1
    assert not (Version.FUTURE > Version.FUTURE)
    assert not (Version.VER2 >= Version.FUTURE)
    assert not (Version.VER2 > Version.FUTURE)

    assert Version.VER1 < Version.VER2
    assert Version.VER1 <= Version.VER2
    assert Version.VER1 < Version.FUTURE
    assert Version.VER1 <= Version.FUTURE
    assert not (Version.FUTURE < Version.FUTURE)
    assert not (Version.FUTURE <= Version.VER2)
    assert not (Version.FUTURE < Version.VER2)


def test_key_len():
    with pytest.raises(misc.PdfError):
        SecurityHandlerVersion.RC4_OR_AES128.check_key_length(20)
    assert SecurityHandlerVersion.RC4_OR_AES128.check_key_length(6) == 6
    assert SecurityHandlerVersion.AES256.check_key_length(6) == 32
    assert SecurityHandlerVersion.RC4_40.check_key_length(32) == 5
    assert SecurityHandlerVersion.RC4_LONGER_KEYS.check_key_length(16) == 16


def test_ensure_version_newfile():

    r = PdfFileReader(BytesIO(MINIMAL))

    w = writer.copy_into_new_writer(r)
    w.ensure_output_version(version=(2, 0))

    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.input_version == (2, 0)


def test_ensure_version_update_noop():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.input_version == (1, 7)


def test_ensure_version_update():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    w.ensure_output_version(version=(2, 0))
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.input_version == (2, 0)


def test_ensure_version_update_twice():
    out = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(out)
    w.ensure_output_version(version=(1, 8))
    w.write_in_place()
    r = PdfFileReader(out)
    assert r.input_version == (1, 8)
    w = IncrementalPdfFileWriter(out)
    w.ensure_output_version(version=(2, 0))
    w.write_in_place()
    r = PdfFileReader(out)
    assert r.input_version == (2, 0)


def test_ensure_version_update_twice_smaller():
    out = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(out)
    w.ensure_output_version(version=(2, 0))
    w.write_in_place()
    r = PdfFileReader(out)
    assert r.input_version == (2, 0)
    w = IncrementalPdfFileWriter(out)
    w.ensure_output_version(version=(1, 7))
    w.add_object(generic.pdf_string('Bleh'))
    w.write_in_place()
    r = PdfFileReader(out)
    assert r.input_version == (2, 0)


TEST_EXT2 = writer.DeveloperExtension(
    prefix_name=generic.NameObject('/TEST'),
    base_version=generic.NameObject('/1.7'),
    extension_level=2, url='https://example.com',
    extension_revision='No-frills test extension'
)

TEST_EXT_MULTI = writer.DeveloperExtension(
    prefix_name=generic.NameObject('/MULT'),
    base_version=generic.NameObject('/1.7'),
    extension_level=2, url='https://example.com',
    extension_revision='Test extension intended to be used as multivalue',
    multivalued=writer.DevExtensionMultivalued.ALWAYS
)


@pytest.mark.parametrize(
    'expected_lvl,new_ext', [
        (2, TEST_EXT2),
        (3, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, compare_by_level=True
        )),
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, compare_by_level=True
        )),
        (3, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, subsumes=(2,)
        )),
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, subsumed_by=(2,)
        )),
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1001,
            subsumed_by=(2,), subsumes=(1000, 1)
        )),
    ]
)
def test_single_extension_registration(expected_lvl, new_ext):
    w = writer.PdfFileWriter()
    w.register_extension(TEST_EXT2)
    assert w.root['/Extensions']['/TEST']['/ExtensionLevel'] == 2
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    w.register_extension(new_ext)

    assert w.root['/Extensions']['/TEST']['/ExtensionLevel'] == expected_lvl


@pytest.mark.parametrize(
    'expected_len,new_ext', [
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3,
        )),
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, compare_by_level=False
        )),
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, subsumed_by=(5,)
        )),
        (2, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1001,
            subsumed_by=(2000,), subsumes=(1000, 1)
        )),
        (1, writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, compare_by_level=True,
            multivalued=writer.DevExtensionMultivalued.ALWAYS
        )),
    ]
)
def test_extension_registration_create_array(expected_len, new_ext):
    w = writer.PdfFileWriter()
    w.register_extension(TEST_EXT2)
    out = BytesIO()
    w.write(out)

    w.register_extension(new_ext)

    ext_val = w.root['/Extensions']['/TEST']
    assert isinstance(ext_val, generic.ArrayObject)
    assert len(ext_val) == expected_len


@pytest.mark.parametrize(
    'expected_lvls,new_ext', [
        ((2,), TEST_EXT_MULTI),
        ((3,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, compare_by_level=True
        )),
        ((2,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, compare_by_level=True
        )),
        ((3,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, subsumes=(2,)
        )),
        ((2,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, subsumed_by=(2,)
        )),
        ((2,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1001,
            subsumed_by=(2,), subsumes=(1000, 1)
        )),
        ((2, 3,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3
        )),
        ((2, 3,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, compare_by_level=False
        )),
        ((2, 1,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, subsumed_by=(5,)
        )),
        ((2, 1001,), writer.DeveloperExtension(
            prefix_name=generic.NameObject('/MULT'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1001,
            subsumed_by=(2000,), subsumes=(1000, 1)
        )),
    ]
)
def test_multi_extension_registration(expected_lvls, new_ext):
    w = writer.PdfFileWriter()
    w.register_extension(TEST_EXT_MULTI)
    ext_val = w.root['/Extensions']['/MULT']
    assert isinstance(ext_val, generic.ArrayObject)
    assert len(ext_val) == 1
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    w.register_extension(new_ext)

    ext_val = w.root['/Extensions']['/MULT']
    actual_lvls = set(ext_dict['/ExtensionLevel'] for ext_dict in ext_val)
    assert actual_lvls == set(expected_lvls)


@pytest.mark.parametrize(
    'new_ext', [
        writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3,
            multivalued=writer.DevExtensionMultivalued.NEVER
        ),
        writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=3, compare_by_level=False,
            multivalued=writer.DevExtensionMultivalued.NEVER
        ),
        writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1, subsumed_by=(5,),
            multivalued=writer.DevExtensionMultivalued.NEVER
        ),
        writer.DeveloperExtension(
            prefix_name=generic.NameObject('/TEST'),
            base_version=generic.NameObject('/1.7'),
            extension_level=1001,
            subsumed_by=(2000,), subsumes=(1000, 1),
            multivalued=writer.DevExtensionMultivalued.NEVER
        ),
    ]
)
def test_extension_registration_unclear(new_ext):
    w = writer.PdfFileWriter()
    w.register_extension(TEST_EXT2)
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    with pytest.raises(misc.PdfWriteError, match="Could not register ext"):
        w.register_extension(new_ext)


def test_extension_registration_type_err():
    w = writer.PdfFileWriter()
    w.root['/Extensions'] = generic.DictionaryObject({
        TEST_EXT2.prefix_name: generic.NullObject()
    })
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    with pytest.raises(misc.PdfReadError, match="type.*NullObject"):
        w.register_extension(TEST_EXT2)


def test_extension_registration_type_err_arr():
    w = writer.PdfFileWriter()
    w.root['/Extensions'] = generic.DictionaryObject({
        TEST_EXT2.prefix_name: generic.ArrayObject([generic.NullObject()])
    })
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    with pytest.raises(misc.PdfReadError, match="type.*NullObject"):
        w.register_extension(TEST_EXT2)


def test_extension_registration_no_level():
    w = writer.PdfFileWriter()
    ext_dict = TEST_EXT2.as_pdf_object()
    del ext_dict['/ExtensionLevel']
    w.root['/Extensions'] = generic.DictionaryObject({
        TEST_EXT2.prefix_name: ext_dict
    })
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    with pytest.raises(misc.PdfReadError, match="Could not read developer ext"):
        w.register_extension(TEST_EXT2)


def test_extension_registration_bad_level():
    w = writer.PdfFileWriter()
    ext_dict = TEST_EXT2.as_pdf_object()
    ext_dict['/ExtensionLevel'] = generic.NullObject()
    w.root['/Extensions'] = generic.DictionaryObject({
        TEST_EXT2.prefix_name: ext_dict
    })
    out = BytesIO()
    w.write(out)

    w = writer.copy_into_new_writer(PdfFileReader(out))
    with pytest.raises(misc.PdfReadError, match="Could not read developer ext"):
        w.register_extension(TEST_EXT2)


@pytest.mark.parametrize(
    'name_bytes,expected', [
        # examples from the spec
        (b'/Name1', pdf_name('/Name1')),
        (b'/A;Name_With-Various***Characters',
         pdf_name('/A;Name_With-Various***Characters')),
        (b'/1.2', pdf_name('/1.2')),
        (b'/$$', pdf_name('/$$')),
        (b'/@pattern', pdf_name('/@pattern')),
        (b'/.notdef', pdf_name('/.notdef')),
        (b'/Lime#20Green', pdf_name('/Lime Green')),
        (b'/paired#28#29parentheses', pdf_name('/paired()parentheses')),
        (b'/The_Key_of_F#23_Minor', pdf_name('/The_Key_of_F#_Minor')),
        # check hex digit handling
        (b'/application#2Fpdf', pdf_name('/application/pdf')),
        (b'/application#2fpdf', pdf_name('/application/pdf'))
    ]
)
def test_name_decode(name_bytes, expected):
    result = generic.NameObject.read_from_stream(BytesIO(name_bytes))
    assert result == expected


@pytest.mark.parametrize(
    # examples from the spec
    'name_bytes,expected_error', [
        (b'Foo', 'Name object should start with /'),
        (b'/Foo#', 'Unterminated escape'),
        (b'/Foo#1', 'Unterminated escape'),
        (b'/Foo#z1', 'hexadecimal digit'),
        (b'/Foo\x7fbar', 'must be escaped'),
        (b'/Foo\xefbar', 'must be escaped'),
    ]
)
def test_name_decode_failure(name_bytes, expected_error):
    with pytest.raises(misc.PdfReadError, match=expected_error):
        generic.NameObject.read_from_stream(BytesIO(name_bytes))


@pytest.mark.parametrize(
    'name_str,expected_bytes', [
        ('/Foo', b'/Foo'),
        ('/application/pdf', b'/application#2Fpdf'),
        ('/Lime Green', b'/Lime#20Green'),
        ('/The_Key_of_F#_Minor', b'/The_Key_of_F#23_Minor'),
    ]
)
def test_name_encode(name_str, expected_bytes):
    out = BytesIO()
    pdf_name(name_str).write_to_stream(out)
    assert out.getvalue() == expected_bytes


def test_name_encode_fail():
    msg = "Could not serialise name object"
    with pytest.raises(misc.PdfWriteError, match=msg):
        pdf_name("NoSlashHere").write_to_stream(BytesIO())


def test_parse_name_invalid_utf8():
    result = generic.NameObject.read_from_stream(BytesIO(b'/Test#ae'))
    assert result == '/Test\u00ae'


@pytest.mark.parametrize('dt,dt_str', [
    (
        datetime.datetime(2020, 12, 26, 15, 5, 11, tzinfo=pytz.timezone('EST')),
        "D:20201226150511-05'00'",
    ),
    (
        datetime.datetime(2020, 12, 26, 15, 5, 11, tzinfo=pytz.utc),
        "D:20201226150511Z",
    ),
    (
        datetime.datetime(2020, 12, 26, 15, 5, 11, tzinfo=pytz.timezone('CET')),
        "D:20201226150511+01'00'",
    ),
])
def test_parse_datetime(dt, dt_str):
    assert generic.pdf_date(dt) == dt_str


def test_read_circular_page_tree():
    fname = os.path.join(PDF_DATA_DIR, 'circular-page-tree.pdf')
    with open(fname, 'rb') as inf:
        r = PdfFileReader(inf)
        # this should work
        page1, _ = r.find_page_for_modification(0)
        assert '/Contents' in page1.get_object()
        # this should raise an error
        with pytest.raises(misc.PdfReadError, match="Circular"):
            r.find_page_for_modification(1)


def test_read_broken_page_tree_direct_kids():
    fname = os.path.join(PDF_DATA_DIR, 'page-tree-direct-kid.pdf')
    with open(fname, 'rb') as inf:
        r = PdfFileReader(inf)
        # this should work
        page1, _ = r.find_page_for_modification(0)
        assert '/Contents' in page1.get_object()
        # this should raise an error
        with pytest.raises(misc.PdfReadError, match="must be indirect"):
            r.find_page_for_modification(1)


@pytest.mark.parametrize('input_str', [
    """
    <</A/B%bleh
    /C/D>>
    """,
    """
    <</A/B/C%bleh
    /D>>
    """,
    """
    <</A/B/C%bleh >>
    /D>>
    """,
    """
    <<%lkjadsf
    /A/B/C%bleh >>
    /D>>
    """,
    """
    <<%lkjadsf\r/A/B/C%bleh >>
    /D>>
    """,
    """
    <<%lkjadsf\r\n/A/B/C%bleh >>\r/D>>
    """,
])
def test_parse_comments(input_str):
    strm = BytesIO(input_str.strip().encode('utf8'))
    result = generic.DictionaryObject.read_from_stream(
        strm, container_ref=generic.Reference(1, 0, pdf=None)
    )
    assert len(result) == 2
    assert result['/A'] == '/B'
    assert result['/C'] == '/D'


NONEXISTENT_XREF_PATH = os.path.join(
    PDF_DATA_DIR, 'minimal-with-nonexistent-refs.pdf'
)


def test_producer_override():
    # file produced with cairo
    inf = BytesIO(VECTOR_IMAGE_PDF)
    w = writer.copy_into_new_writer(PdfFileReader(inf))
    outf = BytesIO()
    w.write(outf)
    r = PdfFileReader(outf)
    proc = r.trailer['/Info']['/Producer']
    assert proc.startswith('cairo')
    assert 'pyHanko' in proc

    w = writer.copy_into_new_writer(r)
    outf2 = BytesIO()
    w.write(outf2)
    r = PdfFileReader(outf)
    proc2 = r.trailer['/Info']['/Producer']

    # now it shouldn't have changed
    assert proc == proc2


def test_fresh_producer():
    inf = BytesIO(MINIMAL)
    w = writer.copy_into_new_writer(PdfFileReader(inf))
    outf = BytesIO()
    w.write(outf)
    r = PdfFileReader(outf)
    proc = r.trailer['/Info']['/Producer']
    assert proc.startswith('pyHanko')


def test_fresh_producer_existing_info():
    inf = BytesIO(MINIMAL)
    w = writer.copy_into_new_writer(PdfFileReader(inf))
    w.set_info(generic.DictionaryObject({'/Title': generic.pdf_string('test')}))
    outf = BytesIO()
    w.write(outf)
    r = PdfFileReader(outf)
    assert '/Producer' not in r.trailer['/Info']

    w = writer.copy_into_new_writer(r)
    outf2 = BytesIO()
    w.write(outf2)
    r = PdfFileReader(outf2)
    proc = r.trailer['/Info']['/Producer']
    assert proc.startswith('pyHanko')


def test_multi_def_dictionary():
    # need a reader for context
    r = PdfFileReader(BytesIO(MINIMAL))
    tst = BytesIO(b"<</Bleh /A /Bluh /B /Bleh /C>>")
    with pytest.raises(misc.PdfStrictReadError):
        generic.DictionaryObject.read_from_stream(
            tst, container_ref=generic.Reference(1, 0, pdf=r)
        )


def test_multi_def_dictionary_nonstrict():
    # need a reader for context
    r = PdfFileReader(BytesIO(MINIMAL), strict=False)
    tst = BytesIO(b"<</Bleh /A /Bluh /B /Bleh /C>>")
    res = generic.DictionaryObject.read_from_stream(
        tst, container_ref=generic.Reference(1, 0, pdf=r)
    )
    assert res['/Bleh'] == pdf_name('/A')


def test_compacted_syntax():
    # rudimentary test to see if we can parse SafeDocs' compacted syntax file
    path = os.path.join(PDF_DATA_DIR, "safedocs", "CompactedPDFSyntaxTest.pdf")
    with open(path, 'rb') as inf:
        r = PdfFileReader(inf)
        assert r.root['/MarkInfo']['/Marked']
        page = r.root['/Pages']['/Kids'][0]
        assert page['/MediaBox'] == [0, 0, 999, 999]
        pgcontents = page['/Contents'][0].data
        assert b'compacted syntax sequences' in pgcontents
        assert r.trailer_view['/Info']['/Subject'] == 'Compacted Syntax v3.0'


SIMPLE_STRING_ENC_SAMPLES = [
    (b'abcdef', generic.TextStringEncoding.PDF_DOC),
    (b'\xfe\xff\x00a\x00b\x00c\x00d\x00e\x00f',
     generic.TextStringEncoding.UTF16BE),
    (b'\xff\xfea\x00b\x00c\x00d\x00e\x00f\x00',
     generic.TextStringEncoding.UTF16LE),
    (b'\xef\xbb\xbfabcdef', generic.TextStringEncoding.UTF8),
]


@pytest.mark.parametrize('encoded, expected_enc', SIMPLE_STRING_ENC_SAMPLES)
def test_autodetect_string_encoding(encoded, expected_enc):
    result = generic.pdf_string(encoded)
    assert isinstance(result, generic.TextStringObject)

    assert result.autodetected_encoding == expected_enc
    assert result == 'abcdef'
    assert result.original_bytes == encoded


@pytest.mark.parametrize('encoded, expected_enc', SIMPLE_STRING_ENC_SAMPLES)
def test_string_encode(encoded, expected_enc):
    txt = generic.TextStringObject('abcdef')
    txt.force_output_encoding = expected_enc
    out = BytesIO()
    txt.write_to_stream(out)
    out.seek(0)
    out_bytes = generic._read_string_literal_bytes(out)
    assert out_bytes == encoded


# FIXME these should work with PDFDocEncoding as well

@pytest.mark.parametrize('encoded, decoded', [
    (b'(\xef\xbb\xbfHello\\nWorld)', 'Hello\nWorld'),
    (b'(\xef\xbb\xbfHello\\fWorld)', 'Hello\fWorld'),
    (b'(\xef\xbb\xbfHello\\tWorld)', 'Hello\tWorld'),
    (b'(\xef\xbb\xbfHello\\bWorld)', 'Hello\bWorld'),
    (b'(\xef\xbb\xbfHello\\rWorld)', 'Hello\rWorld'),
    (b'(\xef\xbb\xbfHello\\012World)', 'Hello\nWorld'),
    (b'(\xef\xbb\xbfHello\\12World)', 'Hello\nWorld'),
])
def test_decode_string_escapes(encoded, decoded):
    stream = BytesIO(encoded)
    stream.seek(0)
    read_back = generic._read_string_literal_bytes(stream)
    assert read_back == decoded.encode('utf-8-sig')

    stream.seek(0)
    read_back = generic.read_string_from_stream(stream)
    assert isinstance(read_back, generic.TextStringObject)
    assert read_back == decoded


def test_decode_string_illegal_escape_sequence():
    stream = BytesIO(b'(Hello World\\z)')
    stream.seek(0)
    with pytest.raises(misc.PdfReadError, match='Unexpected escape.*z'):
        generic.read_string_from_stream(stream)


def test_decode_string_premature_end():
    stream = BytesIO(b'(Hello World')
    stream.seek(0)
    with pytest.raises(misc.PdfReadError, match='ended unexpectedly'):
        generic.read_string_from_stream(stream)


def test_decode_hex_premature_end():
    stream = BytesIO(b'<deadbeef')
    stream.seek(0)
    with pytest.raises(misc.PdfReadError, match='ended prematurely'):
        generic.read_hex_string_from_stream(stream)


def test_decode_hex_invalid_token():
    stream = BytesIO(b'<deadbeefNonsense>')
    stream.seek(0)
    with pytest.raises(misc.PdfReadError, match='Unexpected.*N'):
        generic.read_hex_string_from_stream(stream)


def test_text_string_no_bytes_available():
    with pytest.raises(misc.PdfError, match='No information'):
        # noinspection PyStatementEffect
        generic.TextStringObject('generic text string').original_bytes


COMMENT_TEST_PAIRS = [
    (b'%Bleh<<>>\n<</A/B>>',
     generic.DictionaryObject({pdf_name('/A'): pdf_name('/B')})),
    (b'%Bleh\n[/A/B]',
     generic.ArrayObject([pdf_name('/A'), pdf_name('/B')])),
    (b'%Bleh\n/A', pdf_name('/A')),
    (b'%Bleh\n.123', generic.FloatObject(0.123)),
    (b'%Bleh\n1', generic.NumberObject(1)),
    (b'%Bleh\n(ABC)', generic.TextStringObject("ABC")),
]


@pytest.mark.parametrize('data,exp_result,linesep', [
    (x, y, z) for (x, y), z in
    itertools.product(COMMENT_TEST_PAIRS, [b'\n', b'\r', b'\r\n'])
])
def test_read_object_comment(data, exp_result, linesep):
    buf = BytesIO(data.replace(b'\n', linesep))
    # need something to give a reference
    r = PdfFileReader(BytesIO(MINIMAL))
    res = generic.read_object(buf, container_ref=generic.TrailerReference(r))
    assert res == exp_result


COMMENT_IN_DICT_DATA = [
    b'<<%Bleh\n/A/B>>',
    b'<</A%Bleh\n/B>>',
    b'<</A/B%Bleh\n>>',
    b'<< %Bleh\n/A/B>>',
    b'<</A %Bleh\n/B>>',
    b'<</A/B %Bleh\n>>',
    b'<<%Bleh\n /A/B>>',
    b'<</A%Bleh\n /B>>',
    b'<</A/B%Bleh\n >>',
]


@pytest.mark.parametrize('data,linesep,space', list(
    itertools.product(
        COMMENT_IN_DICT_DATA, [b'\n', b'\r', b'\r\n'], [b' ', b'\x00']
    )
))
def test_comment_in_dict(data, linesep, space):
    buf = BytesIO(data.replace(b'\n', linesep).replace(b' ', space))
    # need something to give a reference
    r = PdfFileReader(BytesIO(MINIMAL))
    res = generic.read_object(buf, container_ref=generic.TrailerReference(r))
    assert res == generic.DictionaryObject({pdf_name('/A'): pdf_name('/B')})


COMMENT_IN_HEX_STRING_DATA = [
    b'<%Bleh\ndeadbeef>',
    b'<dead%Bleh\nbeef>',
    b'<deadbeef%Bleh\n>',
    b'<d%Bleh\neadbeef>',
    b'<deadbee%Bleh\nf>',
    b'< %Bleh\ndeadbeef>',
    b'<dead %Bleh\nbeef>',
    b'<deadbeef %Bleh\n>',
    b'<d %Bleh\neadbeef>',
    b'<deadbee%Bleh\nf>',
    b'<%Bleh\n deadbeef>',
    b'<dead%Bleh\n beef>',
    b'<deadbeef%Bleh\n >',
    b'<d%Bleh\n eadbeef>',
    b'<deadbee%Bleh\n f>',
]


@pytest.mark.parametrize('data,linesep,space', list(
    itertools.product(
        COMMENT_IN_HEX_STRING_DATA, [b'\n', b'\r', b'\r\n'], [b' ', b'\x00']
    )
))
def test_comment_in_hex_string(data, linesep, space):
    buf = BytesIO(data.replace(b'\n', linesep).replace(b' ', space))
    # need something to give a reference
    r = PdfFileReader(BytesIO(MINIMAL))
    res = generic.read_object(buf, container_ref=generic.TrailerReference(r))
    assert res == b'\xde\xad\xbe\xef'
