import fpdf
import qrcode
from PyPDF2 import PdfFileReader, PdfFileWriter
from io import BytesIO
from dataclasses import dataclass
from datetime import datetime


class FPDFImage(qrcode.image.base.BaseImage):
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

    def save(self, stream, kind=None):
        """
        Assume that "stream" is a FPDF object.

        WARNING: this will set the fill_color setting to black,
        and since FPDF has no API to retrieve the current value
        of that setting, there is no "official" way to restore
        it to the caller's value. We make no attempt to do so.
        """
        base_x = stream.get_x()
        base_y = stream.get_y()
        stream.set_fill_color(0,0,0)
        for row, col in self._img:
            (x,y), _ = self.pixel_box(row, col)
            stream.set_xy(
                base_x + x, base_y + y
            )
            stream.cell(self.box_size, self.box_size, fill=True)


@dataclass(frozen=True)
class StampStyle:
    font_size: int = 10
    font_family: str = 'Courier'
    # TODO fix bogus defaults
    stamp_width: int = 340
    stamp_innsep: int = 3
    stamp_textsep: int = 3

    stamp_qrsize: int = 100

    timestamp_format = '%Y-%m-%d %H:%M:%S'


class Stamper:

    def __init__(self, style=None):
        self.style: StampStyle = style or StampStyle()
    
    def stamp(self, input_handle, dest_page, x, y, url, output_handle=None):
        style = self.style
        input_pdf = PdfFileReader(input_handle)
        dest_page_data = input_pdf.getPage(dest_page)
        page_geo = dest_page_data.mediaBox
        (width, height) = (int(page_geo.getWidth()), int(page_geo.getHeight()))

        # TODO make sure to handle portrait/landscape correctly
        overlay = fpdf.FPDF(format=(width, height), unit='pt')
        overlay.add_page()
        overlay.set_font(style.font_family, size=style.font_size)

        text_x = x + 2 * style.stamp_innsep + style.stamp_qrsize
        overlay.set_xy(text_x, y + style.stamp_innsep + style.stamp_textsep)
        # TODO support local timezone output, linkify
        # TODO set width by measuring string widths
        stamp_text = (
            "Digital version available at\n"
            "%(url)s\n\n"
            "Timestamp: %(ts)s UTC"
        ) % {
            'url': url, 
            'ts': datetime.utcnow().strftime(style.timestamp_format)
        }
        overlay.multi_cell(
            w=style.stamp_width - style.stamp_qrsize - 3 * style.stamp_innsep,
            h=style.font_size + 2,
            txt=stamp_text
        )

        # height is determined by the height of the text,
        # or the QR code, whichever is greater
        stamp_height = max(
            overlay.get_y() + style.stamp_innsep - y,
            style.stamp_qrsize + 2 * style.stamp_innsep
        )
        overlay.set_xy(x, y)
        overlay.cell(style.stamp_width, stamp_height, border=1)


        qr_y_sep = (stamp_height - style.stamp_qrsize) // 2
        overlay.set_xy(
            x + style.stamp_innsep,
            y + max(style.stamp_innsep, qr_y_sep)
        )
        self._draw_qr(overlay, url)

        # output(...) returns a string, not a bytestring,
        # so we have to call encode().
        # FPDF is weird like that
        overlay_bytes = overlay.output(dest='S').encode('latin-1')

        overlay_page = PdfFileReader(BytesIO(overlay_bytes)).getPage(0)
        result = PdfFileWriter()
        for p in range(input_pdf.getNumPages()):
            current_page = input_pdf.getPage(p)
            if p == dest_page:
                current_page.mergePage(overlay_page)
            result.addPage(current_page)

        output_handle = output_handle or BytesIO()
        result.write(output_handle)
        return output_handle

    def _draw_qr(self, overlay, url):
        qr = qrcode.QRCode(box_size=4)
        qr.add_data(url)
        qr.make()

        # fit the QR code in a square of the requested size
        qr_num_boxes = len(qr.modules) + 2 * qr.border
        qr.box_size = int(round(self.style.stamp_qrsize / qr_num_boxes))
        qr.make_image(image_factory=FPDFImage).save(overlay)

    def stamp_file(self, input_name, output_name, **kwargs):

        with open(input_name, 'rb') as fin:
            output_stream = self.stamp(fin, **kwargs)

        with open(output_name, 'wb') as out:
            output_stream.seek(0)
            out.write(output_stream.getbuffer())
