from pyhanko.pdf_utils import generic

from ..writer import BasePdfFileWriter
from .api import FontEngine, FontEngineFactory, ShapeResult

pdf_name = generic.NameObject


class SimpleFontEngine(FontEngine):
    """
    Simplistic font engine that effectively only works with PDF standard fonts,
    and does not care about font metrics. Best used with monospaced fonts such
    as Courier.
    """

    @property
    def uses_complex_positioning(self):
        return False

    def __init__(self, writer, name, avg_width):
        self.avg_width = avg_width
        self.name = name
        super().__init__(writer, name, embedded_subset=False)

    def shape(self, txt) -> ShapeResult:
        ops = f'({txt}) Tj'.encode('latin1')
        total_len = len(txt) * self.avg_width

        return ShapeResult(
            graphics_ops=ops, x_advance=total_len,
            y_advance=0
        )

    def as_resource(self):
        font_dict = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/BaseFont'): pdf_name('/' + self.name),
            pdf_name('/Subtype'): pdf_name('/Type1'),
            pdf_name('/Encoding'): pdf_name('/WinAnsiEncoding')
        })
        return font_dict


class SimpleFontEngineFactory(FontEngineFactory):
    def __init__(self, name, avg_width):
        self.avg_width = avg_width
        self.name = name

    def create_font_engine(self, writer: 'BasePdfFileWriter', obj_stream=None):
        return SimpleFontEngine(writer, self.name, self.avg_width)

    @staticmethod
    def default_factory():
        """
        :return:
            A :class:`.FontEngineFactory` instance representing the Courier
            standard font.
        """
        return SimpleFontEngineFactory('Courier', 0.6)
