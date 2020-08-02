import fpdf
from PyPDF2 import PdfFileReader, PdfFileWriter
from io import BytesIO
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class StampStyle:
    font_size: int = 10
    font_family: str = 'Courier'
    # TODO fix bogus defaults
    stamp_width: int = 440
    stamp_height: int = 100
    stamp_innsep: int = 5

    stamp_qrsize: int = 80

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
        overlay.set_xy(x, y)
        overlay.cell(style.stamp_width, style.stamp_height, border=1)

        # FIXME: x-align doesn't seem to be working as intended
        text_x = x + 2 * style.stamp_innsep + style.stamp_qrsize
        overlay.set_xy(x, y + style.stamp_innsep)
        # TODO support local timezone output
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

    def stamp_file(self, input_name, output_name, **kwargs):

        with open(input_name, 'rb') as fin:
            output_stream = self.stamp(fin, **kwargs)

        with open(output_name, 'wb') as out:
            output_stream.seek(0)
            out.write(output_stream.getbuffer())
