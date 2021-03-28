from io import BytesIO

from freezegun import freeze_time

from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils import barcodes, generic
from pyhanko import stamp
from pyhanko_tests.samples import MINIMAL


@freeze_time('2020-11-01')
def test_qr_fixed_size():
    writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    w = 280
    h = 60
    qrss = stamp.QRStampStyle()
    box = BoxConstraints(width=w, height=h)
    qr = stamp.QRStamp(writer, 'https://example.com', qrss, box=box)
    qr.as_form_xobject()
    qr.apply(0, 10, 10)
    assert qr.text_box.box.width == 224


def test_qr_natural_size():
    writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    qrss = stamp.QRStampStyle()
    qr = stamp.QRStamp(writer, 'https://example.com', qrss)
    qr.as_form_xobject()
    qr.apply(0, 10, 10)

    assert qr.text_box_x() == qr.qr_default_width + 2 * qrss.innsep


def test_code128_render():
    writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    bb = barcodes.BarcodeBox("code128", "this is a test")
    xobj_ref = writer.add_object(bb.as_form_xobject())

    stamp_wrapper_stream = generic.StreamObject(
        stream_data=b'q 1 0 0 1 50 50 cm /Barcode Do Q'
    )
    resources = generic.DictionaryObject({
        pdf_name('/XObject'): generic.DictionaryObject({
            pdf_name('/Barcode'): xobj_ref
        })
    })
    writer.add_stream_to_page(
        0, writer.add_object(stamp_wrapper_stream), resources
    )

    # TODO try to read back the code using some kind of barcode scanning
    #  library, perhaps.
