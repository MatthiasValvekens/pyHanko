import logging
from dataclasses import dataclass, field
from fractions import Fraction

from fontTools import ttLib

from pdf_utils.font import FontEngine, SimpleFontEngine, GlyphAccumulator
from pdf_utils.generic import PdfContent, pdf_name
from pdf_utils.misc import BoxConstraints
from pdfstamp.misc import ConfigurableMixin, ConfigurationError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TextStyle(ConfigurableMixin):
    font: FontEngine = field(default_factory=SimpleFontEngine.default_engine)
    font_size: int = 10
    leading: int = None

    @classmethod
    def process_entries(cls, config_dict):
        try:
            fc = config_dict['font']
            if not isinstance(fc, str) or \
                    not (fc.endswith('.otf') or fc.endswith('.ttf')):
                raise ConfigurationError(
                    "'font' must be a path to an OpenType font file."
                )

            ffile = ttLib.TTFont(fc)
            config_dict['font'] = GlyphAccumulator(ffile)
        except KeyError:
            pass


@dataclass(frozen=True)
class TextBoxStyle(TextStyle):
    text_sep: int = 10
    border_width: int = 0
    vertical_center: bool = True


class TextBox(PdfContent):

    def __init__(self, parent, style: TextBoxStyle, box: BoxConstraints = None,
                 font_name='F1'):
        super().__init__(parent=parent, box=box)
        self.style = style
        self._content = None
        self._scaling_factor = None
        self._content_lines = self._wrapped_lines = None
        self.font_name = font_name

    def wrap_string(self, txt):
        wrapped, width_em = self.style.font.render_and_measure(txt)
        return wrapped, width_em * self.style.font_size

    @property
    def content_lines(self):
        return self._content_lines

    @property
    def content(self):
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

        # we give precedence to the height if the box constraints specify
        #  a fixed aspect ratio
        if not self.box.height_defined:
            self.box.height = self.get_text_height() + 2 * self.style.text_sep

        natural_width = int(max_line_len) + 2 * self.style.text_sep
        if not self.box.width_defined:
            self.box.width = natural_width
        else:
            self._scaling_factor = Fraction(self.box.width, natural_width)


    @property
    def leading(self):
        style = self.style
        return style.font_size if style.leading is None else style.leading

    def get_text_height(self):
        return len(self.content_lines) * self.leading

    def text_x(self):
        return self.style.text_sep

    def text_y(self):
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
        self.set_resource(
            category=pdf_name('/Font'), name=pdf_name('/' + self.font_name),
            value=style.font.as_resource()
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
