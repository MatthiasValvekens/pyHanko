import os

import qrcode
import tzlocal

from pdf_utils.incremental_writer import (
    IncrementalPdfFileWriter,
)
from pdf_utils.misc import BoxConstraints, BoxSpecificationError
from pdf_utils.text import TextStyle
from pdf_utils.writer import init_xobject_dictionary
from dataclasses import dataclass
from datetime import datetime

from qrcode.image.base import BaseImage
from pdf_utils import generic
from pdf_utils.generic import pdf_name, pdf_string


rd = lambda x: round(x, 4)


class AnnotAppearances:

    def __init__(self, normal, rollover=None, down=None):
        self.normal = normal
        self.rollover = rollover
        self.down = down

    def as_pdf_object(self):
        res = generic.DictionaryObject({pdf_name('/N'): self.normal})
        if self.rollover is not None:
            res[pdf_name('/R')] = self.rollover
        if self.down is not None:
            res[pdf_name('/D')] = self.down
        return res


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
                '%g %g %g %g re f' % (
                    rd(x), rd(y), rd(self.box_size), rd(self.box_size)
                )
            )
        return ' '.join(command_stream).encode('ascii')

    def save(self, stream, kind=None): 
        stream.write(self.render_command_stream())


@dataclass(frozen=True)
class TextStampStyle(TextStyle):
    stamp_text: str = '%(ts)s'
    text_box_constraints: BoxConstraints = None
    timestamp_format: str = '%Y-%m-%d %H:%M:%S %Z'


@dataclass(frozen=True)
class QRStampStyle(TextStampStyle):
    innsep: int = 3
    stamp_text: str = (
        "Digital version available at\n"
        "this url: %(url)s\n"
        "Timestamp: %(ts)s"
    )
    stamp_qrsize: int = 100


class TextStamp(generic.StreamObject):
    def __init__(self, writer: IncrementalPdfFileWriter, style,
                 text_params=None):
        super().__init__()
        self.writer = writer
        self.style = style
        self.text_params = text_params
        self.update({
            pdf_name('/Type'): pdf_name('/XObject'),
            pdf_name('/Subtype'): pdf_name('/Form')
        })
        self._resources_ready = False
        self._wrapped_lines = None
        self._max_line_len = None
        self._stamp_ref = None

    def wrap_string(self, txt):
        wrapped, width_em = self.style.font.render_and_measure(txt)
        return wrapped, width_em * self.style.font_size

    def add_resources(self, resources):
        pass

    def extra_commands(self):
        return []

    def _format_resources(self):
        if self._resources_ready:
            return
        font_ref = self.style.font.as_resource(self.writer)
        raw_resource_dict = {
            pdf_name('/Font'): generic.DictionaryObject({
                pdf_name('/F1'): font_ref
            }),
        }
        self.add_resources(raw_resource_dict)
        resources = generic.DictionaryObject(raw_resource_dict)
        self[pdf_name('/Resources')] = self.writer.add_object(resources)
        self._resouces_ready = True

    def get_text_sep(self):
        return self.style.textsep

    def get_leading(self):
        style = self.style
        return style.font_size if style.leading is None else style.leading

    def get_text_height(self):
        return len(self.style.stamp_text.split('\n')) * self.get_leading()

    def get_stamp_width(self):
        if self._max_line_len is None:
            self._preprocess_text()

        return self.get_text_xstart() + self._max_line_len + self.get_text_sep()

    def get_stamp_height(self):
        try:
            height = self.style.text_box_constraints.height
        except BoxSpecificationError:
            try:
                ar = self.style.text_box_constraints.aspect_ratio
                stamp_width = self.get_stamp_width()
                height = int(stamp_width / ar)
            except BoxSpecificationError:
                height = self.get_text_height() + 2 * self.get_text_sep()
            self.style.text_box_constraints.height = height
        return height

    def get_text_xstart(self):
        return self.get_text_sep()

    def get_text_ystart(self):
        th = self.get_text_height()
        sh = self.get_stamp_height()
        if th < sh:
            return (th + sh) // 2
        else:
            return sh

    def get_default_text_params(self):
        ts = datetime.now(tz=tzlocal.get_localzone())
        return {
            'ts': ts.strftime(self.style.timestamp_format),
        }

    def _render_stream(self):
        command_stream = ['q']

        stamp_height = self.get_stamp_height()
        stamp_width = self.get_stamp_width()
        # text rendering
        text_commands = self._text_stream()
        command_stream.append(text_commands)

        # append additional drawing commands
        command_stream.extend(self.extra_commands())

        # draw border around stamp and set bounding box
        self[pdf_name('/BBox')] = generic.ArrayObject(list(
            map(generic.FloatObject, [0, 0, stamp_width, stamp_height])
        ))
        command_stream.append(
            '3 w 0 0 %g %g re S' % (stamp_width, stamp_height)
        )
        command_stream.append('Q')
        self._data = ' '.join(command_stream).encode('latin-1')
        return stamp_width, stamp_height

    def _preprocess_text(self):
        # compute line lengths, wrap strings
        max_line_len = 0
        _text_params = self.get_default_text_params()
        if self.text_params is not None:
            _text_params.update(self.text_params)
        text = self.style.stamp_text % _text_params

        lines = []
        for line in text.split('\n'):
            wrapped_line, line_len = self.wrap_string(line)
            max_line_len = max(max_line_len, line_len)
            lines.append(wrapped_line)
        self._wrapped_lines = lines
        self._max_line_len = max_line_len

    def _text_stream(self):
        style = self.style
        leading = style.font_size if style.leading is None else style.leading
        xstart = self.get_text_xstart()
        ystart = self.get_text_ystart()

        # TODO Auto word-wrap is probably too much trouble, but
        #  perhaps it's worth experimenting a little
        command_stream = [
            'BT', '/F1 %d Tf' % self.style.font_size,
            '%d TL' % leading, '%d %d Td' % (xstart, ystart)
        ]
        if self._wrapped_lines is None:
            self._preprocess_text()
        command_stream.extend("%s '" % wl for wl in self._wrapped_lines)
        command_stream.append('ET')
        return ' '.join(command_stream)

    def render_all(self):
        w, h = self._render_stream()
        self._format_resources()
        return w, h

    def write_to_stream(self, stream, key):
        if self._data is None:
            raise ValueError(
                'Stamp stream needs to be rendered before calling .write()'
            )
        return super().write_to_stream(stream, key)

    def register(self):
        stamp_ref = self._stamp_ref
        if stamp_ref is None:
            self._stamp_ref = stamp_ref = self.writer.add_object(self)
        return stamp_ref

    def apply(self, dest_page, x, y):
        stamp_ref = self.register()
        # randomise resource name to avoid conflicts
        resource_name = '/Stamp' + os.urandom(16).hex()
        stamp_paint = 'q 1 0 0 1 %g %g cm %s Do Q' % (
            rd(x), rd(y), resource_name
        )
        stamp_wrapper_stream = generic.StreamObject(
            stream_data=stamp_paint.encode('ascii')
        )
        resources = generic.DictionaryObject({
            pdf_name('/XObject'): generic.DictionaryObject({
                pdf_name(resource_name): stamp_ref
            })
        })
        wr = self.writer
        page_ref = wr.add_stream_to_page(
            dest_page, wr.add_object(stamp_wrapper_stream), resources
        )
        return page_ref, self.render_all()

    def as_appearances(self) -> AnnotAppearances:
        # TODO support defining overrides/extra's for the rollover/down
        #  appearances in some form
        stamp_ref = self.register()
        self.render_all()
        return AnnotAppearances(normal=stamp_ref)


class QRStamp(TextStamp):

    def __init__(self, writer: IncrementalPdfFileWriter, url: str,
                 style: QRStampStyle, text_params=None):
        super().__init__(writer, style, text_params=text_params)
        self.url = url

    def add_resources(self, raw_resource_dict):
        raw_resource_dict[pdf_name('/XObject')] = generic.DictionaryObject({
            pdf_name('/QR'): self._qr_xobject()
        })

    def extra_commands(self):
        height = self.get_stamp_height()
        qr_y_sep = (height - self.style.stamp_qrsize) // 2
        # paint the QR code, translated and with y axis inverted
        draw_qr_command = 'q 1 0 0 -1 %g %g cm /QR Do Q' % (
            rd(self.style.innsep),
            rd(height - max(self.style.innsep, qr_y_sep)),
        )
        return [draw_qr_command]

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
        qr_xobj.compress()
        return self.writer.add_object(qr_xobj)

    def get_text_xstart(self):
        return 2 * self.style.innsep + self.style.stamp_qrsize

    def get_stamp_height(self):
        # height is determined by the height of the text,
        # or the QR code, whichever is greater
        # This potentially breaks the fixed AR logic, but since QR codes
        # should have a certain minimal size anyway, I think I'm
        # willing to pay that price
        sh = super().get_stamp_height()
        return max(sh, self.style.stamp_qrsize + 2 * self.style.innsep)

    def get_default_text_params(self):
        tp = super().get_default_text_params()
        tp['url'] = self.url
        return tp

    def apply(self, dest_page, x, y):
        page_ref, (w, h) = super().apply(dest_page, x, y)
        link_rect = (x, y, x + w, y + h)
        link_annot = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Annot'),
            pdf_name('/Subtype'): pdf_name('/Link'),
            pdf_name('/Rect'): generic.ArrayObject(list(
                map(generic.FloatObject, link_rect)
            )),
            pdf_name('/A'): generic.DictionaryObject({
                pdf_name('/S'): pdf_name('/URI'),
                pdf_name('/URI'): pdf_string(self.url)
            })
        })
        wr = self.writer
        wr.register_annotation(page_ref, wr.add_object(link_annot))
        return page_ref, (w, h)


def stamp_file(input_name, output_name, style, dest_page,
               x, y, url, text_params=None):

    with open(input_name, 'rb') as fin:
        pdf_out = IncrementalPdfFileWriter(fin)
        stamp = QRStamp(pdf_out, url, style, text_params=text_params)
        stamp.apply(dest_page, x, y)

        with open(output_name, 'wb') as out:
            pdf_out.write(out)
