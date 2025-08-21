from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import tzlocal

from pyhanko.pdf_utils import layout
from pyhanko.pdf_utils.layout import LayoutError
from pyhanko.pdf_utils.text import DEFAULT_BOX_LAYOUT, TextBox, TextBoxStyle
from pyhanko.pdf_utils.writer import BasePdfFileWriter

from .base import BaseStamp, BaseStampStyle

__all__ = ['TextStampStyle', 'TextStamp']


@dataclass(frozen=True)
class TextStampStyle(BaseStampStyle):
    """
    Style for text-based stamps.

    Roughly speaking, this stamp type renders some predefined (but parametrised)
    piece of text inside a text box, and possibly applies a background to it.
    """

    text_box_style: TextBoxStyle = TextBoxStyle()
    """
    The text box style for the internal text box used.
    """

    inner_content_layout: Optional[layout.SimpleBoxLayoutRule] = None
    """
    Rule determining the position and alignment of the inner text box within
    the stamp.

    .. warning::
        This only affects the position of the box, not the alignment of the
        text within.
    """

    stamp_text: str = '%(ts)s'
    """
    Text template for the stamp. The template can contain an interpolation
    parameter ``ts`` that will be replaced by the stamping time.

    Additional parameters may be added if necessary. Values for these must be
    passed to the :meth:`~.TextStamp.__init__` method of the
    :class:`.TextStamp` class in the ``text_params`` argument.
    """

    timestamp_format: str = '%Y-%m-%d %H:%M:%S %Z'
    """
    Datetime format used to render the timestamp.
    """

    def create_stamp(
        self,
        writer: BasePdfFileWriter,
        box: layout.BoxConstraints,
        text_params: dict,
    ) -> 'TextStamp':
        return TextStamp(
            writer=writer, style=self, box=box, text_params=text_params
        )


class TextStamp(BaseStamp):
    """
    Class that renders a text stamp as specified by an instance
    of :class:`.TextStampStyle`.
    """

    def __init__(
        self,
        writer: BasePdfFileWriter,
        style,
        text_params=None,
        box: Optional[layout.BoxConstraints] = None,
    ):
        super().__init__(box=box, style=style, writer=writer)
        self.text_params = text_params

        self.text_box: Optional[TextBox] = None

    def get_default_text_params(self):
        """
        Compute values for the default string interpolation parameters
        to be applied to the template string specified in the stamp
        style. This method does not take into account the ``text_params``
        init parameter yet.

        :return:
            A dictionary containing the parameters and their values.
        """
        ts = datetime.now(tz=tzlocal.get_localzone())
        return {
            'ts': ts.strftime(self.style.timestamp_format),
        }

    def _text_layout(self):
        # Set the contents of the text box
        self.text_box = tb = TextBox(
            self.style.text_box_style,
            writer=self.writer,
            resources=self.resources,
            box=None,
        )
        _text_params = self.get_default_text_params()
        if self.text_params is not None:
            _text_params.update(self.text_params)
        try:
            text = self.style.stamp_text % _text_params
        except KeyError as e:
            raise LayoutError(f"Stamp text parameter '{e.args[0]}' is missing")
        tb.content = text

        # Render the text box in its natural size, we'll deal with
        # the minutiae later
        return tb.render()

    def _inner_layout_natural_size(self):
        # render text
        text_commands = self._text_layout()

        inn_box = self.text_box.box
        return [text_commands], (inn_box.width, inn_box.height)

    def _inner_content_layout_rule(self):
        return self.style.inner_content_layout or DEFAULT_BOX_LAYOUT

    def _render_inner_content(self):
        command_stream = [b'q']

        # compute the inner bounding box
        inn_commands, (
            inn_width,
            inn_height,
        ) = self._inner_layout_natural_size()

        inner_layout = self._inner_content_layout_rule()

        bbox = self.box

        # position the inner box
        inn_position = inner_layout.fit(bbox, inn_width, inn_height)

        command_stream.append(inn_position.as_cm())
        command_stream.extend(inn_commands)
        command_stream.append(b'Q')

        return command_stream
