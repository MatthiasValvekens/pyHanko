import pytest

from pyhanko.pdf_utils import text
from pyhanko.pdf_utils.misc import BoxConstraints


@pytest.mark.parametrize('with_border, natural_size', [[True, True], [False, False], [True, False]])
def test_simple_textbox_render(with_border, natural_size):
    tbs = text.TextBoxStyle(border_width=1 if with_border else 0)
    bc = None if natural_size else BoxConstraints(width=1600, height=900)

    textbox = text.TextBox(style=tbs, box=bc)
    textbox.content = 'This is a textbox with some text.\nAnd multiple lines'
    xobj = textbox.as_form_xobject()
    x1, y1, x2, y2 = xobj['/BBox']
    assert '/F1' in textbox.resources.font

    if not natural_size:
        assert abs(x1 - x2) == 1600
        assert abs(y1 - y2) == 900
