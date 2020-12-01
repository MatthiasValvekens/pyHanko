"""Utilities related to text rendering & layout."""

import logging
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Union, Callable

from pyhanko.pdf_utils.font import (
    FontEngine, SimpleFontEngine, GlyphAccumulator, GlyphAccumulatorFactory
)
from pyhanko.pdf_utils.generic import (
    pdf_name,
)
from pyhanko.pdf_utils.content import ResourceType, PdfResources, PdfContent
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.config_utils import ConfigurableMixin, ConfigurationError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TextStyle(ConfigurableMixin):
    """Container for basic test styling settings."""

    font: Union[FontEngine, Callable[[], FontEngine]] \
        = field(default_factory=SimpleFontEngine.default_engine)
    """
    The :class:`.FontEngine` to be used for this text style.
    Defaults to Courier (as a non-embedded standard font).
    
    .. caution::
        Not all :class:`.FontEngine` implementations are reusable and/or 
        stateless! When reusability is a requirement, passing a no-argument 
        callable that produces :class:`.FontEngine` objects of the appropriate 
        type might help (see :class:`.GlyphAccumulatorFactory`).
    """

    font_size: int = 10
    """
    Font size to be used.
    """

    leading: int = None
    """
    Text leading. If ``None``, the :attr:`font_size` parameter is used instead.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            fc = config_dict['font']
            if not isinstance(fc, str) or \
                    not (fc.endswith('.otf') or fc.endswith('.ttf')):
                raise ConfigurationError(
                    "'font' must be a path to an OpenType font file."
                )

            config_dict['font'] = GlyphAccumulatorFactory(fc)
        except KeyError:
            pass


@dataclass(frozen=True)
class TextBoxStyle(TextStyle):
    """Extension of :class:`.TextStyle` for use in text boxes."""

    text_sep: int = 10
    """
    Separation of text from the box's border, in user units.
    """

    border_width: int = 0
    """
    Border width, if applicable.
    """

    vertical_center: bool = True
    """
    Attempt to vertically center text if the box's height is fixed.
    """


class TextBox(PdfContent):
    """Implementation of a text box that implements the :class:`.PdfContent`
    interface.

    .. note::
        Text boxes currently don't offer automatic word wrapping.
    """

    def __init__(self, style: TextBoxStyle,
                 resources: PdfResources = None,
                 box: BoxConstraints = None,
                 writer=None,
                 font_name='F1'):
        super().__init__(resources, writer=writer, box=box)
        self.style = style
        self._content = None
        self._scaling_factor = None
        self._content_lines = self._wrapped_lines = None
        self.font_name = font_name
        font_engine = style.font
        if callable(font_engine):
            font_engine = font_engine()
        self.font_engine = font_engine

    def wrap_string(self, txt):
        font_engine = self.font_engine
        wrapped = font_engine.render(txt)
        width_em = font_engine.measure(txt)
        return wrapped, width_em * self.style.font_size

    @property
    def content_lines(self):
        """
        :return:
            Text content of the text box, broken up into lines.
        """
        return self._content_lines

    @property
    def content(self):
        """
        :return:
            The actual text content of the text box.
            This is a modifiable property.

            In textboxes that don't have a fixed size, setting this property
            can cause the text box to be resized.
        """
        return self._content

    @content.setter
    def content(self, content):
        # TODO text reflowing logic goes here
        #  (with option to either scale things, or do word wrapping)
        self._content = content

        max_line_len = 0
        lines = []
        for line in content.split('\n'):
            wrapped_line, line_len = self.wrap_string(line)
            max_line_len = max(max_line_len, line_len)
            lines.append(wrapped_line)
        self._wrapped_lines = lines
        self._content_lines = content.split('\n')

        # we give precedence to the width if the box constraints specify
        #  a fixed aspect ratio
        natural_width = int(max_line_len) + 2 * self.style.text_sep
        if not self.box.width_defined:
            self.box.width = natural_width

        if not self.box.height_defined:
            self.box.height = self.get_text_height() + 2 * self.style.text_sep
        else:
            self._scaling_factor = Fraction(self.box.width, natural_width)

    @property
    def leading(self):
        """
        :return:
            The effective leading value, i.e. the
            :attr:`~.TextStyle.leading` attribute of the associated
            :class:`.TextBoxStyle`, or :attr:`~.TextStyle.font_size` if
            not specified.
        """
        style = self.style
        return style.font_size if style.leading is None else style.leading

    def get_text_height(self):
        """
        :return:
            The text height in user units.
        """
        return len(self.content_lines) * self.leading

    def text_x(self):
        """
        :return:
            The x-position where the text will be painted.
        """
        return self.style.text_sep

    def text_y(self):
        """
        :return:
            The y-position where the text will be painted.
        """
        bh = self.box.height
        if self.style.vertical_center and self.box.height_defined:
            th = self.get_text_height()
            if th <= bh:
                return (th + bh) // 2
            else:
                logger.warning(f"Text height {th} exceeds box height {bh}")
                return bh
        else:
            return bh - self.style.text_sep

    def render(self):

        style = self.style

        if isinstance(self.font_engine, GlyphAccumulator):
            assert self.writer is not None
            self.font_engine.embed_subset(self.writer)

        self.set_resource(
            category=ResourceType.FONT, name=pdf_name('/' + self.font_name),
            value=self.font_engine.as_resource()
        )
        leading = self.leading
        if not self.box.height_defined:
            self.box.height = self.get_text_height() + 2 * style.text_sep

        xstart = self.text_x()
        ystart = self.text_y() + leading

        command_stream = []
        sf = self._scaling_factor

        # draw border before scaling
        if style.border_width:
            command_stream.append(
                'q %g w 0 0 %g %g re S Q' % (
                    style.border_width, self.box.width, self.box.height
                )
            )

        if sf is not None:
            command_stream.append('%g 0 0 %g 0 0 cm' % (sf, sf))

        command_stream += [
            'BT', f'/{self.font_name} {style.font_size} Tf {leading} TL',
            f'{xstart} {ystart} Td'
        ]
        command_stream.extend(f"{wl} '" for wl in self._wrapped_lines)
        command_stream.append('ET')
        return ' '.join(command_stream).encode('latin-1')
