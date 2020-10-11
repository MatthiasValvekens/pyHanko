from io import BytesIO

import pytest

from pdf_utils import text
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.misc import BoxConstraints

from pdfstamp import stamp
from .samples import *


@pytest.mark.parametrize('with_border, natural_size', [[True, True], [False, False], [True, False]])
def test_simple_textbox_render(with_border, natural_size):
    tbs = text.TextBoxStyle(border_width=1 if with_border else 0)
    bc = None if natural_size else BoxConstraints(width=1600, height=900)

    textbox = text.TextBox(parent=None, style=tbs, box=bc)
    textbox.content = 'This is a textbox with some text.\nAnd multiple lines'
    xobj = textbox.as_form_xobject()
    x1, y1, x2, y2 = xobj['/BBox']
    assert '/F1' in textbox._resources['/Font']

    if not natural_size:
        assert abs(x1 - x2) == 1600
        assert abs(y1 - y2) == 900


def test_qr_fixed_size():
    writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    w = 280
    h = 60
    qrss = stamp.QRStampStyle()
    box = BoxConstraints(width=w, height=h)
    qr = stamp.QRStamp(writer, 'https://example.com', qrss, box=box)
    qr.as_form_xobject()
    qr.apply(0, 10, 10)
    assert qr.text_box.box.width == 220


def test_qr_natural_size():
    writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    qrss = stamp.QRStampStyle()
    qr = stamp.QRStamp(writer, 'https://example.com', qrss)
    qr.as_form_xobject()
    qr.apply(0, 10, 10)

    assert qr.text_box_x() == qr.qr_default_width + 2 * qrss.innsep