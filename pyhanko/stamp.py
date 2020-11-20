import os
from binascii import hexlify

import qrcode
import tzlocal

from pyhanko.pdf_utils.barcodes import PdfStreamQRImage
from pyhanko.pdf_utils.font import GlyphAccumulator
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import BoxConstraints, BoxSpecificationError, rd
from pyhanko.pdf_utils.text import TextBoxStyle, TextBox
from pyhanko.pdf_utils.writer import init_xobject_dictionary
from dataclasses import dataclass
from datetime import datetime

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name, pdf_string, PdfContent
from pyhanko.misc import ConfigurableMixin


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


@dataclass(frozen=True)
class TextStampStyle(ConfigurableMixin):
    text_box_style: TextBoxStyle = TextBoxStyle()
    border_width: int = 3
    stamp_text: str = '%(ts)s'
    timestamp_format: str = '%Y-%m-%d %H:%M:%S %Z'
    background: PdfContent = None
    background_opacity: float = 0.6

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            tbs = config_dict['text_box_style']
            config_dict['text_box_style'] \
                = TextBoxStyle.from_config(tbs)
        except KeyError:
            pass

        try:
            bg_spec = config_dict['background']
            # 'special' value to use the stamp vector image baked into
            # the module
            # TODO allow loading backgrounds from images (after I deal with the
            #  issues surrounding relationships between PdfContent objects)
            if bg_spec == '__stamp__':
                config_dict['background'] = STAMP_ART_CONTENT
            else:  # pragma: nocover
                raise NotImplementedError(
                    "Backgrounds other than __stamp__ haven't been implemented."
                )
        except KeyError:
            pass


@dataclass(frozen=True)
class QRStampStyle(TextStampStyle):
    innsep: int = 3
    stamp_text: str = (
        "Digital version available at\n"
        "this url: %(url)s\n"
        "Timestamp: %(ts)s"
    )
    stamp_qrsize: float = 0.25


class TextStamp(PdfContent):
    def __init__(self, writer: IncrementalPdfFileWriter, style,
                 text_params=None, box: BoxConstraints = None):
        super().__init__(parent=None, box=box)
        self.writer = writer
        self.style = style
        self.text_params = text_params
        self._resources_ready = False
        self._stamp_ref = None

        self.text_box = None

    def init_text_box(self):
        # if necessary, try to adjust the text box's bounding box
        #  to the stamp's

        box = self.box
        expected_h = None
        if box.height_defined:
            expected_h = box.height - self.text_box_y()
        self.text_box = TextBox(
            self, self.style.text_box_style,
            box=BoxConstraints(height=expected_h)
        )

    def extra_commands(self):
        return []

    def get_stamp_width(self):
        try:
            return self.box.width
        except BoxSpecificationError:
            width = self.text_box_x() + self.text_box.box.width
            self.box.width = width
            return width

    def get_stamp_height(self):
        try:
            return self.box.height
        except BoxSpecificationError:
            height = self.box.height \
                = self.text_box_y() + self.text_box.box.height
            return height

    def text_box_x(self):
        return 0

    def text_box_y(self):
        return 0

    def get_default_text_params(self):
        ts = datetime.now(tz=tzlocal.get_localzone())
        return {
            'ts': ts.strftime(self.style.timestamp_format),
        }

    def render(self):
        command_stream = [b'q']

        # text rendering
        self.init_text_box()
        _text_params = self.get_default_text_params()
        if self.text_params is not None:
            _text_params.update(self.text_params)
        text = self.style.stamp_text % _text_params
        self.text_box.content = text

        # FIXME this is another instance where the decoupling between
        #  PdfContent and the writer is undesirable: we cannot delegate
        #  font embedding to the text box since it doesn't know about
        #  the writer.
        if isinstance(self.text_box.style.font, GlyphAccumulator):
            self.text_box.style.font.embed_subset(self.writer)

        stamp_height = self.get_stamp_height()
        stamp_width = self.get_stamp_width()

        bg = self.style.background
        if bg is not None:
            # TODO this is one of the places where some more clever layout
            #  engine would really help, since all of this is pretty ad hoc and
            #  makes a number of non-obvious choices that would be better off
            #  delegated to somewhere else.

            # scale the background
            bg_height = 0.9 * stamp_height
            sf = bg_height / bg.box.height
            bg_y = 0.05 * stamp_height
            bg_width = bg.box.width * sf
            bg_x = 0
            if bg_width <= stamp_width:
                bg_x = (stamp_width - bg_width) // 2

            # encapsulate resources by using XObjects
            # TODO what about background reuse? We should take advantage of
            #  the fact that we're using XObjects here.
            self.set_resource(
                pdf_name('/XObject'), pdf_name('/Background'),
                value=self.writer.add_object(bg.as_form_xobject())
            )

            # set opacity in graphics state
            opacity = generic.FloatObject(self.style.background_opacity)
            self.set_resource(
                category=pdf_name('/ExtGState'),
                name=pdf_name('/BackgroundGS'),
                value=generic.DictionaryObject({
                    pdf_name('/CA'): opacity, pdf_name('/ca'): opacity
                })
            )
            command_stream.append(
                b'q /BackgroundGS gs %g 0 0 %g %g %g cm /Background Do Q' % (
                    sf, sf, bg_x, bg_y
                )
            )

        text_commands = self.text_box.render()
        command_stream.append(
            b'q 1 0 0 1 %g %g cm' % (self.text_box_x(), self.text_box_y())
        )
        command_stream.append(text_commands)
        command_stream.append(b'Q')

        # append additional drawing commands
        command_stream.extend(self.extra_commands())

        # draw border around stamp
        command_stream.append(
            b'%g w 0 0 %g %g re S' % (
                self.style.border_width, stamp_width, stamp_height
            )
        )
        command_stream.append(b'Q')
        return b' '.join(command_stream)

    def register(self):
        stamp_ref = self._stamp_ref
        if stamp_ref is None:
            form_xobj = self.as_form_xobject()
            self._stamp_ref = stamp_ref = self.writer.add_object(form_xobj)
        return stamp_ref

    def apply(self, dest_page, x, y):
        stamp_ref = self.register()
        # randomise resource name to avoid conflicts
        # TODO handle this properly
        resource_name = b'/Stamp' + hexlify(os.urandom(16))
        stamp_paint = b'q 1 0 0 1 %g %g cm %s Do Q' % (
            rd(x), rd(y), resource_name
        )
        stamp_wrapper_stream = generic.StreamObject(stream_data=stamp_paint)
        resources = generic.DictionaryObject({
            pdf_name('/XObject'): generic.DictionaryObject({
                pdf_name(resource_name): stamp_ref
            })
        })
        wr = self.writer
        page_ref = wr.add_stream_to_page(
            dest_page, wr.add_object(stamp_wrapper_stream), resources
        )
        dims = (self.box.width, self.box.height)
        return page_ref, dims

    def as_appearances(self) -> AnnotAppearances:
        # TODO support defining overrides/extra's for the rollover/down
        #  appearances in some form
        stamp_ref = self.register()
        return AnnotAppearances(normal=stamp_ref)


class QRStamp(TextStamp):
    qr_default_width = 30

    def __init__(self, writer: IncrementalPdfFileWriter, url: str,
                 style: QRStampStyle, text_params=None,
                 box: BoxConstraints = None):
        super().__init__(writer, style, text_params=text_params, box=box)
        self.url = url
        self._qr_size = None

    @property
    def qr_size(self):
        if self._qr_size is None:
            style = self.style
            if self.box.width_defined:
                width = style.stamp_qrsize * self.box.width
            else:
                width = self.qr_default_width

            if self.box.height_defined:
                # in this case, the box might not be high enough to contain
                # the full QR code
                height = self.box.height
                size = min(width,  height - 2 * style.innsep)
            else:
                size = width
            self._qr_size = size
        return self._qr_size

    def extra_commands(self):
        qr_ref, natural_qr_size = self._qr_xobject()
        self.set_resource(
            category=pdf_name('/XObject'), name=pdf_name('/QR'),
            value=qr_ref
        )
        height = self.get_stamp_height()
        qr_y_sep = (height - self.qr_size) // 2
        qr_scale = self.qr_size / natural_qr_size
        # paint the QR code, translated and with y axis inverted
        draw_qr_command = b'q %g 0 0 -%g %g %g cm /QR Do Q' % (
            rd(qr_scale), rd(qr_scale), rd(self.style.innsep),
            rd(height - qr_y_sep),
        )
        return [draw_qr_command]

    def _qr_xobject(self):
        qr = qrcode.QRCode()
        qr.add_data(self.url)
        qr.make()

        img = qr.make_image(image_factory=PdfStreamQRImage)
        command_stream = img.render_command_stream()

        bbox_size = (qr.modules_count + 2 * qr.border) * qr.box_size
        qr_xobj = init_xobject_dictionary(
            command_stream, bbox_size, bbox_size
        )
        qr_xobj.compress()
        return self.writer.add_object(qr_xobj), bbox_size

    def text_box_x(self):
        return 2 * self.style.innsep + self.qr_size

    def get_stamp_height(self):
        try:
            return self.box.height
        except BoxSpecificationError:
            style = self.style
            # if the box does not define a height
            # height is determined by the height of the text,
            # or the QR code, whichever is greater
            text_height = self.text_box.box.height
            height = max(text_height, self.qr_size + 2 * style.innsep)
            self.box.height = height
            return height

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


STAMP_ART_CONTENT = generic.RawContent(
    None, box=BoxConstraints(width=100, height=100),
    data=b'''
q 1 0 0 -1 0 100 cm 
0.603922 0.345098 0.54902 rg
3.699 65.215 m 3.699 65.215 2.375 57.277 7.668 51.984 c 12.957 46.695 27.512
 49.34 39.418 41.402 c 39.418 41.402 31.48 40.078 32.801 33.465 c 34.125
 26.852 39.418 28.172 39.418 24.203 c 39.418 20.234 30.156 17.59 30.156
14.945 c 30.156 12.297 28.465 1.715 50 1.715 c 71.535 1.715 69.844 12.297
 69.844 14.945 c 69.844 17.59 60.582 20.234 60.582 24.203 c 60.582 28.172
 65.875 26.852 67.199 33.465 c 68.52 40.078 60.582 41.402 60.582 41.402
c 72.488 49.34 87.043 46.695 92.332 51.984 c 97.625 57.277 96.301 65.215
 96.301 65.215 c h f
3.801 68.734 92.398 7.391 re f
3.801 79.512 92.398 7.391 re f
3.801 90.289 92.398 7.391 re f
Q
''')
