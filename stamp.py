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
            stream.rect(
                base_x + x, base_y + y, self.box_size, self.box_size, style='F'
            )



@dataclass(frozen=True)
class StampStyle:
    font_size: int = 10
    font_family: str = 'Courier'
    innsep: int = 3
    textsep: int = 10
    max_text_width = 300

    stamp_qrsize: int = 100

    # TODO support local timezone output
    timestamp_format = '%Y-%m-%d %H:%M:%S UTC'

    url_placeholder = '@@@'
    stamp_text = (
        "Digital version available at\n"
        "this url: @@@\n\n"
        "Timestamp: %(ts)s"
    )




class Stamper:

    def __init__(self, style=None):
        self.style: StampStyle = style or StampStyle()
    
    def stamp(self, input_handle, dest_page, x, y, url, text_params=None, 
              output_handle=None):
        style = self.style
        input_pdf = PdfFileReader(input_handle)
        dest_page_data = input_pdf.getPage(dest_page)
        page_geo = dest_page_data.mediaBox
        (width, height) = (int(page_geo.getWidth()), int(page_geo.getHeight()))

        # TODO make sure to handle portrait/landscape correctly
        overlay = fpdf.FPDF(format=(width, height), unit='pt')
        overlay.add_page()
        overlay.set_font(style.font_family, size=style.font_size)

        # inner text area geometry
        total_text_sep = style.innsep + style.textsep
        until_text_start = 2 * style.innsep + style.stamp_qrsize
        text_min_x = x + until_text_start
        # line count * font size -> text height
        # (TODO is this reliable with non-monospaced typefaces?)
        text_height = len(style.stamp_text.split('\n')) * style.font_size

        # height is determined by the height of the text,
        # or the QR code, whichever is greater
        # The width depends on the width of the inner text box
        #  => compute later

        stamp_height = max(
            text_height + 2 * total_text_sep,
            style.stamp_qrsize + 2 * style.innsep
        )
        text_y_sep = (stamp_height - text_height) // 2

        # text rendering
        l_margin_old, r_margin_old = overlay.l_margin, overlay.r_margin
        overlay.set_left_margin(text_min_x)
        overlay.set_right_margin(text_min_x + style.max_text_width)
        overlay.set_xy(text_min_x, y + text_y_sep)
        max_line_len = self._render_text(overlay, url, text_params)

        # restore margins
        overlay.set_left_margin(l_margin_old)
        overlay.set_right_margin(r_margin_old)

        stamp_width = (
            until_text_start 
            + min(style.max_text_width, max_line_len)
            + total_text_sep
        )

        # draw border around stamp
        overlay.rect(x, y, stamp_width, stamp_height)

        qr_y_sep = (stamp_height - style.stamp_qrsize) // 2
        overlay.set_xy(
            x + style.innsep,
            y + max(style.innsep, qr_y_sep)
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

    def _render_text(self, overlay, url, text_params=None):
        style = self.style
        line_height = style.font_size

        # render text
        max_line_len = 0
        _text_params = {
            'ts': datetime.utcnow().strftime(style.timestamp_format),
        }
        if text_params is not None:
            _text_params.update(text_params)
        text = style.stamp_text % _text_params

        # TODO Auto word-wrap is probably too much trouble, but
        #  perhaps it's worth experimenting a little
        for line in text.split('\n'):
            line_len = 0
            # replace any URL placeholders with links
            # in most sane cases, the URL placeholder will only occur once,
            # but why not do it robustly, eh
            parts = iter(line.split('@@@'))

            # first part always makes sense
            part = next(parts) 
            w = overlay.get_string_width(part)
            line_len += w
            overlay.cell(w, h=line_height, txt=part)
            # handle any remaining parts, and insert links
            # where appropriate
            for part in parts:
                w = overlay.get_string_width(url)
                overlay.cell(w, h=line_height, txt=url, link=url)
                line_len += w
                w = overlay.get_string_width(part)
                overlay.cell(w, h=line_height, txt=part)
                line_len += w
            overlay.ln()
            max_line_len = max(max_line_len, line_len)
            
        return max_line_len

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
