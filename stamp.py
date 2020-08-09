import os
from typing import Optional, Union

import qrcode
import tzlocal
from fontTools.ttLib import TTFont
from pdf_utils.font import GlyphAccumulator

from pdf_utils.incremental_writer import (
    IncrementalPdfFileWriter, init_xobject_dictionary
)
from PyPDF2 import generic
from dataclasses import dataclass
from datetime import datetime

from qrcode.image.base import BaseImage


pdf_name = generic.NameObject
pdf_string = generic.createStringObject
rd = lambda x: round(x, 4)


class PdfStreamImage(BaseImage):
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
                '%f %f %f %f re f' % (
                    rd(x), rd(y), rd(self.box_size), rd(self.box_size)
                )
            )
        return ' '.join(command_stream).encode('ascii')

    def save(self, stream, kind=None): 
        stream.write(self.render_command_stream())


@dataclass(frozen=True)
class StampStyle:
    font: Optional[Union[str, TTFont]] = None
    font_size: int = 10
    innsep: int = 3
    textsep: int = 10
    max_text_width: int = 300
    avg_char_width: int = None

    stamp_qrsize: int = 100

    timestamp_format: str = '%Y-%m-%d %H:%M:%S %Z'

    stamp_text: str = (
        "Digital version available at\n"
        "this url: %(url)s\n"
        "Timestamp: %(ts)s"
    )


class QRStamp(generic.StreamObject):

    def __init__(self, writer: IncrementalPdfFileWriter, url: str, 
                 style: StampStyle, text_params=None):
        super().__init__()
        self.writer = writer
        self.url = url
        self.style = style
        self.text_params = None
        self.update({
            pdf_name('/Type'): pdf_name('/XObject'),
            pdf_name('/Subtype'): pdf_name('/Form')
        })
        self._resources_ready = False
        self.text_params = text_params
        self.font = font = self.style.font or 'Courier'

        if isinstance(font, TTFont):
            self.glyph_accumulator = GlyphAccumulator(font)
        elif isinstance(font, str):
            self.glyph_accumulator = None
        else:
            raise ValueError(
                "Invalid type '%s' for font parameter" % type(font)
            )

    def wrap_string(self, txt):
        if self.glyph_accumulator is not None:
            hex_str, width = self.glyph_accumulator.feed_string(txt)
            return '<%s>' % hex_str, width
        else:
            # FIXME This is a very crappy estimate for non-monospaced fonts
            char_width = self.style.avg_char_width or 0.6 * self.style.font_size
            return '(%s)' % txt, len(txt) * char_width

    def _format_resources(self):
        if self._resources_ready:
            return
        if self.glyph_accumulator is None:
            # assume that self.font is the name of a PDF standard font
            # TODO enforce that
            font_dict = generic.DictionaryObject({
                pdf_name('/Type'): pdf_name('/Font'),
                pdf_name('/BaseFont'): pdf_name('/' + self.font),
                pdf_name('/Subtype'): pdf_name('/Type1'),
                pdf_name('/Encoding'): pdf_name('/WinAnsiEncoding')
            })
            font_ref = self.writer.add_object(font_dict)
        else:
            font_ref = self.glyph_accumulator.embed_subset(self.writer)

        resources = generic.DictionaryObject({
            pdf_name('/Font'): generic.DictionaryObject({
                pdf_name('/F1'): font_ref
            }),
            pdf_name('/XObject'): generic.DictionaryObject({
                pdf_name('/QR'): self._qr_xobject()
            })
        })
        self[pdf_name('/Resources')] = self.writer.add_object(resources)
        self._resouces_ready = True

    def _qr_xobject(self):
        qr = qrcode.QRCode(box_size=4)
        qr.add_data(self.url)
        qr.make()

        # fit the QR code in a square of the requested size
        qr_num_boxes = len(qr.modules) + 2 * qr.border
        qr.box_size = int(round(self.style.stamp_qrsize / qr_num_boxes))

        img = qr.make_image(image_factory=PdfStreamImage)
        command_stream = img.render_command_stream()

        box_size = self.style.stamp_qrsize
        qr_xobj = init_xobject_dictionary(
            command_stream, box_size, box_size
        )
        return self.writer.add_object(qr_xobj)

    def _render_stream(self):
        style = self.style

        # inner text area geometry
        total_text_sep = style.innsep + style.textsep
        text_min_x = 2 * style.innsep + style.stamp_qrsize
        # roughly estimate text height
        text_height = len(style.stamp_text.split('\n')) * style.font_size

        command_stream = ['q']

        # height is determined by the height of the text,
        # or the QR code, whichever is greater
        # The width depends on the width of the inner text box
        #  => compute later

        stamp_height = max(
            text_height + 2 * total_text_sep,
            style.stamp_qrsize + 2 * style.innsep
        )
        self._height = stamp_height
        text_y_sep = (stamp_height - text_height) // 2

        # text rendering
        max_line_len, text_commands = self._text_stream(
            text_min_x, stamp_height - text_y_sep
        )

        stamp_width = (
            text_min_x + min(style.max_text_width, max_line_len)
            + total_text_sep
        )
        self._width = stamp_width

        qr_y_sep = (stamp_height - style.stamp_qrsize) // 2

        command_stream.append(text_commands)
        # paint the QR code, translated and with y axis inverted
        command_stream.append(
            'q 1 0 0 -1 %f %f cm /QR Do Q' % (
                rd(style.innsep),
                rd(stamp_height - max(style.innsep, qr_y_sep)),
            )
        )

        # draw border around stamp and set bounding box
        self[pdf_name('/BBox')] = generic.ArrayObject(list(
            map(generic.FloatObject, [0, 0, stamp_width, stamp_height])
        ))
        command_stream.append(
            '3 w 0 0 %f %f re S' % (stamp_width, stamp_height)
        )
        command_stream.append('Q')
        self._data = ' '.join(command_stream).encode('latin-1')

    def _text_stream(self, xstart, ystart):
        style = self.style
        line_height = style.font_size

        # render text
        max_line_len = 0
        ts = datetime.now(tz=tzlocal.get_localzone())
        _text_params = {
            'ts': ts.strftime(style.timestamp_format),
            'url': self.url
        }
        if self.text_params is not None:
            _text_params.update(self.text_params)
        text = style.stamp_text % _text_params

        # TODO Auto word-wrap is probably too much trouble, but
        #  perhaps it's worth experimenting a little
        self.glyph_accumulator.feed_string(text)
        command_stream = [
            'BT', '/F1 %d Tf' % self.style.font_size,
            '%d TL' % line_height, '%d %d Td' % (xstart, ystart)
        ]
        for line in text.split('\n'):
            wrapped_line, line_len = self.wrap_string(line)
            max_line_len = max(max_line_len, line_len)
            command_stream.append('%s Tj T*' % wrapped_line)
        command_stream.append('ET')
        return max_line_len, ' '.join(command_stream)

    def render_all(self):
        self._render_stream()
        self._format_resources()

    def writeToStream(self, stream, key):
        if self._data is None:
            raise ValueError(
                'Stamp stream needs to be rendered before calling .write()'
            )
        return super().writeToStream(stream, key)

    @classmethod
    def apply(cls, writer: IncrementalPdfFileWriter, style, dest_page,
              x, y, url, text_params=None):

        stamp = cls(writer, url, style, text_params)
        stamp_ref = writer.add_object(stamp)
        # randomise resource name to avoid conflicts
        resource_name = '/QRStamp' + os.urandom(16).hex()
        stamp_paint = 'q 1 0 0 1 %f %f cm %s Do Q' % (
            rd(x), rd(y), resource_name
        )
        stamp_wrapper_stream = generic.StreamObject.initializeFromDictionary({
            '__streamdata__': stamp_paint.encode('ascii'),
            pdf_name('/Length'): len(stamp_paint)
        })
        resources = generic.DictionaryObject({
            pdf_name('/XObject'): generic.DictionaryObject({
                pdf_name(resource_name): stamp_ref
            })
        })
        page_ref = writer.add_stream_to_page(
            dest_page, writer.add_object(stamp_wrapper_stream), resources
        )
        stamp.render_all()

        link_rect = (x, y, x + stamp._width, y + stamp._height)
        link_annot = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Annot'),
            pdf_name('/Subtype'): pdf_name('/Link'),
            pdf_name('/Rect'): generic.ArrayObject(list(
                map(generic.FloatObject, link_rect)
            )),
            pdf_name('/A'): generic.DictionaryObject({
                pdf_name('/S'): pdf_name('/URI'),
                pdf_name('/URI'): pdf_string(url)
            })
        })
        writer.register_annotation(page_ref, writer.add_object(link_annot))
        return stamp_ref


def stamp_file(input_name, output_name, style, dest_page,
               x, y, url, text_params=None):

    with open(input_name, 'rb') as fin:
        pdf_out = IncrementalPdfFileWriter(fin)
        QRStamp.apply(pdf_out, style, dest_page, x, y, url, text_params)

        with open(output_name, 'wb') as out:
            pdf_out.write(out)
