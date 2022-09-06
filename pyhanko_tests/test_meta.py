import itertools
from datetime import datetime
from io import BytesIO

import pytest
import pytz
import tzlocal
from freezegun import freeze_time

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.metadata.model import DocumentMetadata
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter, copy_into_new_writer
from pyhanko_tests.samples import MINIMAL, VECTOR_IMAGE_PDF


def test_no_meta_view_fails_gracefully():
    r = PdfFileReader(BytesIO(MINIMAL))
    assert r.document_meta_view == DocumentMetadata()


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
    assert r.document_meta_view == DocumentMetadata(**meta_dict)
