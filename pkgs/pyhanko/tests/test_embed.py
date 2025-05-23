import binascii
from datetime import datetime, timedelta
from io import BytesIO

import pytest
import tzlocal
from freezegun import freeze_time
from pyhanko.pdf_utils import crypt, embed, generic, misc, writer
from pyhanko.pdf_utils.crypt import AuthStatus
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from .samples import *


def _embed_test(w, fname, ufname, data, created=None, modified=None):
    ef_obj = embed.EmbeddedFileObject.from_file_data(
        w,
        data=data,
        mime_type='application/pdf',
        params=embed.EmbeddedFileParams(
            creation_date=created, modification_date=modified
        ),
    )

    spec = embed.FileSpec(
        file_spec_string=fname,
        file_name=ufname,
        embedded_data=ef_obj,
        description='Embedding test',
    )
    embed.embed_file(w, spec)


@freeze_time('2020-11-01')
@pytest.mark.parametrize('incremental', [True, False])
def test_simple_embed(incremental):
    if incremental:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    else:
        r = PdfFileReader(BytesIO(MINIMAL))
        w = writer.copy_into_new_writer(r)

    modified = datetime.now(tz=tzlocal.get_localzone())
    created = modified - timedelta(days=1)
    _embed_test(
        w,
        fname='vector-test.pdf',
        ufname='テスト.pdf',
        data=VECTOR_IMAGE_PDF,
        created=created,
        modified=modified,
    )

    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert r.input_version == (1, 7)
    emb_lst = r.root['/Names']['/EmbeddedFiles']['/Names']
    assert len(emb_lst) == 2
    assert emb_lst[0] == 'vector-test.pdf'
    spec_obj = emb_lst[1]
    assert spec_obj['/Desc'] == 'Embedding test'
    assert spec_obj['/UF'] == 'テスト.pdf'
    stream = spec_obj['/EF']['/F']
    assert stream.data == VECTOR_IMAGE_PDF

    assert stream['/Subtype'] == '/application/pdf'

    assert stream['/Params']['/CheckSum'] == binascii.unhexlify(
        'caaf24354fd2e68c08826d65b309b404'
    )
    assert generic.parse_pdf_date(stream['/Params']['/ModDate']) == modified
    assert generic.parse_pdf_date(stream['/Params']['/CreationDate']) == created

    assert '/AF' not in r.root


@freeze_time('2020-11-01')
@pytest.mark.parametrize('incremental', [True, False])
def test_embed_twice(incremental):
    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r)

    modified = datetime.now(tz=tzlocal.get_localzone())
    created = modified - timedelta(days=1)
    _embed_test(
        w,
        fname='vector-test.pdf',
        ufname='テスト.pdf',
        data=VECTOR_IMAGE_PDF,
        created=created,
        modified=modified,
    )

    if incremental:
        out = BytesIO()
        w.write(out)
        w = IncrementalPdfFileWriter(out)

    _embed_test(
        w,
        fname='some-other-file.pdf',
        ufname='テスト2.pdf',
        data=MINIMAL_AES256,
        created=created,
        modified=modified,
    )

    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    emb_lst = r.root['/Names']['/EmbeddedFiles']['/Names']
    assert len(emb_lst) == 4
    assert emb_lst[0] == 'vector-test.pdf'
    spec_obj = emb_lst[1]
    assert spec_obj['/UF'] == 'テスト.pdf'
    stream = spec_obj['/EF']['/F']
    assert stream.data == VECTOR_IMAGE_PDF

    assert emb_lst[2] == 'some-other-file.pdf'
    spec_obj = emb_lst[3]
    assert spec_obj['/UF'] == 'テスト2.pdf'
    stream = spec_obj['/EF']['/F']
    assert stream.data == MINIMAL_AES256


@freeze_time('2020-11-01')
@pytest.mark.parametrize('incremental', [True, False])
def test_embed_with_af(incremental):
    if incremental:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    else:
        r = PdfFileReader(BytesIO(MINIMAL))
        w = writer.copy_into_new_writer(r)

    modified = datetime.now(tz=tzlocal.get_localzone())
    created = modified - timedelta(days=1)
    ef_obj = embed.EmbeddedFileObject.from_file_data(
        w,
        data=VECTOR_IMAGE_PDF,
        params=embed.EmbeddedFileParams(
            creation_date=created, modification_date=modified
        ),
    )

    spec = embed.FileSpec(
        file_spec_string='vector-test.pdf',
        embedded_data=ef_obj,
        description='Embedding test /w assoc file',
        af_relationship=generic.pdf_name('/Unspecified'),
    )
    embed.embed_file(w, spec)
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    assert r.input_version == (2, 0)
    emb_lst = r.root['/Names']['/EmbeddedFiles']['/Names']
    assert len(emb_lst) == 2
    assert emb_lst[0] == 'vector-test.pdf'
    spec_obj = emb_lst[1]
    assert '/UF' not in spec_obj
    assert spec_obj['/AFRelationship'] == '/Unspecified'
    stream = spec_obj['/EF']['/F']
    assert stream.data == VECTOR_IMAGE_PDF
    assert '/UF' not in spec_obj['/EF']

    assert r.root['/AF'].raw_get(0).reference == spec_obj.container_ref


def test_embed_without_ef_stream():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r)

    spec = embed.FileSpec(
        file_spec_string='vector-test.pdf',
        description='Embedding test /w assoc file',
        af_relationship=generic.pdf_name('/Unspecified'),
    )
    err_msg = "File spec does not have an embedded file stream"
    with pytest.raises(misc.PdfWriteError, match=err_msg):
        embed.embed_file(w, spec)


def test_encrypt_efs():
    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r)
    cf = crypt.StandardAESCryptFilter(keylen=32)
    cf.set_embedded_only()
    sh = crypt.StandardSecurityHandler.build_from_pw(
        'secret',
        crypt_filter_config=crypt.CryptFilterConfiguration(
            {crypt.STD_CF: cf},
            default_stream_filter=crypt.IDENTITY,
            default_string_filter=crypt.IDENTITY,
            default_file_filter=crypt.STD_CF,
        ),
        encrypt_metadata=False,
    )
    w._assign_security_handler(sh)
    modified = datetime.now(tz=tzlocal.get_localzone())
    created = modified - timedelta(days=1)
    _embed_test(
        w,
        fname='vector-test.pdf',
        ufname='テスト.pdf',
        data=VECTOR_IMAGE_PDF,
        created=created,
        modified=modified,
    )

    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    # should be able to access this without authenticating
    assert b'Hello' in r.root['/Pages']['/Kids'][0]['/Contents'].data
    ef_stm = r.root['/Names']['/EmbeddedFiles']['/Names'][1]['/EF'].raw_get(
        '/F'
    )

    result = r.decrypt('secret')
    assert result.status == AuthStatus.OWNER

    assert ef_stm.get_object()._has_crypt_filter
    assert ef_stm.get_object().data == VECTOR_IMAGE_PDF


def test_decrypt_ef_without_explicit_crypt_filter():
    # such files violate the spec, but since we can deal with them gracefully,
    # we certainly should

    with open(PDF_DATA_DIR + '/embedded-encrypted-nocf.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        ef_stm = r.root['/Names']['/EmbeddedFiles']['/Names'][1]['/EF'].raw_get(
            '/F'
        )
        r.decrypt('secret')
        assert not ef_stm.get_object()._has_crypt_filter
        assert ef_stm.get_object().data == VECTOR_IMAGE_PDF


def test_wrapper_doc_underspecified():
    with pytest.raises(ValueError, match='exactly one of.*must be'):
        embed.wrap_encrypted_payload(b'bacadsflkj')

    with pytest.raises(ValueError, match='exactly one of.*must be'):
        embed.wrap_encrypted_payload(b'bacadsflkj', password='a', certs=[])


def test_wrapper_doc():
    w = embed.wrap_encrypted_payload(VECTOR_IMAGE_PDF, password='secret')
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert b'attached file' in r.root['/Pages']['/Kids'][0]['/Contents'].data

    assert r.root['/Collection']['/D'] == 'attachment.pdf'
    assert r.root['/Collection']['/View'] == '/H'
    ef_stm = r.root['/Names']['/EmbeddedFiles']['/Names'][1]['/EF'].raw_get(
        '/F'
    )

    result = r.decrypt('secret')
    assert result.status == AuthStatus.OWNER

    assert ef_stm.get_object()._has_crypt_filter
    assert ef_stm.get_object().data == VECTOR_IMAGE_PDF


def test_wrapper_doc_pubkey():
    w = embed.wrap_encrypted_payload(
        VECTOR_IMAGE_PDF, certs=[PUBKEY_TEST_DECRYPTER.cert]
    )
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert b'attached file' in r.root['/Pages']['/Kids'][0]['/Contents'].data

    assert r.root['/Collection']['/D'] == 'attachment.pdf'
    assert r.root['/Collection']['/View'] == '/H'
    ef_stm = r.root['/Names']['/EmbeddedFiles']['/Names'][1]['/EF'].raw_get(
        '/F'
    )

    result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
    assert result.status == AuthStatus.USER

    assert ef_stm.get_object()._has_crypt_filter
    assert ef_stm.get_object().data == VECTOR_IMAGE_PDF
