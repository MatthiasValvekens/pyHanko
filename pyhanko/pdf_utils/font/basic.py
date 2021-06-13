from pyhanko.pdf_utils import generic
from .api import FontEngine, ShapeResult

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

    @staticmethod
    def default_engine():
        """
        :return:
            A :class:`.FontEngine` instance representing the Courier
            standard font.
        """
        return SimpleFontEngine('Courier', 0.6)

    def __init__(self, name, avg_width):
        self.avg_width = avg_width
        self.name = name

    def shape(self, txt) -> ShapeResult:
        ops = f'({txt}) Tj'.encode('latin1')
        total_len = len(txt) * self.avg_width

        return ShapeResult(
            graphics_ops=ops, x_advance=total_len,
            y_advance=0
        )

    def as_resource(self):
        # assume that self.font is the name of a PDF standard font
        # TODO enforce that
        font_dict = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/BaseFont'): pdf_name('/' + self.name),
            pdf_name('/Subtype'): pdf_name('/Type1'),
            pdf_name('/Encoding'): pdf_name('/WinAnsiEncoding')
        })
        return font_dict
