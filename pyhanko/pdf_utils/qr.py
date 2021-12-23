from qrcode.image.base import BaseImage

from pyhanko.pdf_utils.misc import rd


class PdfStreamQRImage(BaseImage):
    """
    Quick-and-dirty implementation of the Image interface required
    by the qrcode package.
    """

    kind = "PDF"
    allowed_kinds = ("PDF",)

    def new_image(self, **kwargs):
        return []

    def drawrect(self, row, col):
        self._img.append((row, col))

    def render_command_stream(self):
        # start a command stream with fill colour set to black
        command_stream = ['0 0 0 rg']
        for row, col in self._img:
            (x, y), _ = self.pixel_box(row, col)
            # paint a rectangle
            command_stream.append(
                '%g %g %g %g re f' % (
                    rd(x), rd(y), rd(self.box_size), rd(self.box_size)
                )
            )
        return ' '.join(command_stream).encode('ascii')

    def save(self, stream, kind=None):
        raise NotImplementedError

    def process(self):
        raise NotImplementedError

    def drawrect_context(self, row, col, active, context):
        return self.drawrect(row, col)  # pragma: nocover
