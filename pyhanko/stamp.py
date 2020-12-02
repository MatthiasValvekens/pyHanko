"""
Utilities for stamping PDF files.

Here 'stamping' loosely refers to adding small overlays (QR codes, text boxes,
etc.) on top of already existing content in PDF files.

The code in this module is also used by the :mod:`.sign` module to render
signature appearances.
"""

import uuid
from binascii import hexlify
from fractions import Fraction
from typing import Optional

import qrcode
import tzlocal

from pyhanko.pdf_utils.barcodes import PdfStreamQRImage
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import rd
from pyhanko.pdf_utils.layout import BoxSpecificationError, BoxConstraints
from pyhanko.pdf_utils.text import TextBoxStyle, TextBox
from pyhanko.pdf_utils.writer import init_xobject_dictionary
from dataclasses import dataclass
from datetime import datetime

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import (
    pdf_name, pdf_string,
)
from pyhanko.pdf_utils.content import ResourceType, PdfContent, RawContent
from pyhanko.pdf_utils.config_utils import ConfigurableMixin


__all__ = [
    "AnnotAppearances", "TextStampStyle", "QRStampStyle", "STAMP_ART_CONTENT",
    "TextStamp", "QRStamp", "text_stamp_file", "qr_stamp_file",
]


class AnnotAppearances:
    """
    Convenience abstraction to set up an appearance dictionary for a PDF
    annotation.

    Annotations can have three appearance streams, which can be roughly
    characterised as follows:

    * *normal*: the only required one, and the default one;
    * *rollover*: used when mousing over the annotation;
    * *down*: used when clicking the annotation.

    These are given as references to form XObjects.

    .. note::
        This class only covers the simple case of an appearance dictionary
        for an annotation with only one appearance state.

    See § 12.5.5 in ISO 32000-1 for further information.
    """

    def __init__(self, normal: generic.IndirectObject,
                 rollover: Optional[generic.IndirectObject] = None,
                 down: Optional[generic.IndirectObject] = None):
        self.normal = normal
        self.rollover = rollover
        self.down = down

    def as_pdf_object(self) -> generic.DictionaryObject:
        """
        Convert the :class:`.AnnotationAppearances` instance to a PDF
        dictionary.

        :return:
            A :class:`~.pdf_utils.generic.DictionaryObject` that can be plugged
            into the ``/AP`` entry of an annotation dictionary.
        """

        res = generic.DictionaryObject({pdf_name('/N'): self.normal})
        if self.rollover is not None:
            res[pdf_name('/R')] = self.rollover
        if self.down is not None:
            res[pdf_name('/D')] = self.down
        return res


@dataclass(frozen=True)
class TextStampStyle(ConfigurableMixin):
    """
    Style for text-based stamps.

    Roughly speaking, this stamp type renders some predefined (but parametrised)
    piece of text inside a text box, and possibly applies a background to it.
    """

    text_box_style: TextBoxStyle = TextBoxStyle()
    """
    The text box style for the internal text box used.
    """

    border_width: int = 3
    """
    Border width in user units (for the stamp, not the text box).
    """

    stamp_text: str = '%(ts)s'
    """
    Text template for the stamp. The template can contain an interpolation
    parameter ``ts`` that will be replaced by the stamping time.
    
    Additional parameters may be added if necessary. Values for these must be
    passed to the :meth:`~.TextStamp.__init__` method of the 
    :class:`.TextStamp` class in the ``text_params`` argument.
    """

    timestamp_format: str = '%Y-%m-%d %H:%M:%S %Z'
    """
    Datetime format used to render the timestamp.
    """

    background: PdfContent = None
    """
    :class:`~.pdf_utils.content.PdfContent` instance that will be used to render
    the stamp's background.
    """

    background_opacity: float = 0.6
    """
    Opacity value to render the background at. This should be a floating-point
    number between `0` and `1`.
    """

    @classmethod
    def process_entries(cls, config_dict):
        """
        The implementation of :meth:`process_entries` calls
        :meth:`.TextBoxStyle.from_config` to parse the ``text_box_style``
        configuration entry, if present.

        Then, it processes the background specified.
        This can either be a path to an image file, in which case it will
        be turned into an instance of :class:`~.pdf_utils.images.PdfImage`,
        or the special value ``__stamp__``, which is an alias for
        :const:`~pyhanko.stamp.STAMP_ART_CONTENT`.

        See :meth:`.ConfigurableMixin.process_entries` for general
        documentation about this method.
        """

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
            if bg_spec == '__stamp__':
                config_dict['background'] = STAMP_ART_CONTENT
            elif isinstance(bg_spec, str):
                from PIL import Image
                img = Image.open(bg_spec)
                # Setting the writer can be delayed
                config_dict['background'] = PdfImage(img, writer=None)
        except KeyError:
            pass


@dataclass(frozen=True)
class QRStampStyle(TextStampStyle):
    """
    Style for text-based stamps together with a QR code.

    This is exactly the same as a text stamp, except that the text box
    is rendered with a QR code to the left of it.
    """

    innsep: int = 3
    """
    Inner separation inside the stamp.
    """

    stamp_text: str = (
        "Digital version available at\n"
        "this url: %(url)s\n"
        "Timestamp: %(ts)s"
    )
    """
    Text template for the stamp.
    The description of :attr:`.TextStampStyle.stamp_text` still applies, but
    an additional default interpolation parameter ``url`` is available.
    This parameter will be replaced with the URL that the QR code points to.
    """

    stamp_qrsize: float = 0.25
    """
    Indicates the proportion of the width of the stamp that should be taken up
    by the QR code.
    """


class TextStamp(PdfContent):
    """
    Class that renders a text stamp as specified by an instance
    of :class:`.TextStampStyle`.
    """

    def __init__(self, writer: IncrementalPdfFileWriter, style,
                 text_params=None, box: BoxConstraints = None):
        super().__init__(box=box, writer=writer)
        self.style = style
        self.text_params = text_params
        self._resources_ready = False
        self._stamp_ref = None

        self.text_box = None
        self.expected_text_width = None

    def _init_text_box(self):
        # if necessary, try to adjust the text box's bounding box
        #  to the stamp's

        box = self.box
        expected_w = None
        if box.width_defined:
            expected_w = box.width - self.text_box_x()
            self.expected_text_width = expected_w

        expected_h = None
        if box.height_defined:
            expected_h = box.height - self.text_box_y()

        box = None
        if expected_h and expected_w:
            # text boxes do not auto-scale their font size, so
            # we have to take care of that
            box = BoxConstraints(
                aspect_ratio=Fraction(expected_w, expected_h)
            )

        self.text_box = TextBox(
            self.style.text_box_style, writer=self.writer,
            resources=self.resources, box=box
        )

    def extra_commands(self) -> list:
        """
        Render extra graphics commands to be used after painting the
        inner text box, but before drawing the border.

        :return:
            A list of :class:`bytes` objects.
        """
        return []

    def get_stamp_width(self) -> int:
        """Compute the stamp's total width.

        :return:
            The width of the stamp in user units.
        """

        try:
            return self.box.width
        except BoxSpecificationError:
            width = self.text_box_x() + self.text_box.box.width
            self.box.width = width
            return width

    def get_stamp_height(self) -> int:
        """Compute the stamp's total height.

        :return:
            The height of the stamp in user units.
        """

        try:
            return self.box.height
        except BoxSpecificationError:
            height = self.box.height \
                = self.text_box_y() + self.text_box.box.height
            return height

    def text_box_x(self) -> int:
        """Text box x-coordinate.

        :return:
            The horizontal position of the internal text box's lower left
            corner inside the stamp's bounding box.
        """
        return 0

    def text_box_y(self):
        """Text box y-coordinate.

        :return:
            The horizontal position of the internal text box's lower left
            corner inside the stamp's bounding box.
        """
        return 0

    def get_default_text_params(self):
        """
        Compute values for the default string interpolation parameters
        to be applied to the template string string specified in the he stamp
        style. This method does not take into account the ``text_params``
        init parameter yet.

        :return:
            A dictionary containing the parameters and their values.
        """
        ts = datetime.now(tz=tzlocal.get_localzone())
        return {
            'ts': ts.strftime(self.style.timestamp_format),
        }

    def render(self):
        command_stream = [b'q']

        # text rendering
        self._init_text_box()
        _text_params = self.get_default_text_params()
        if self.text_params is not None:
            _text_params.update(self.text_params)
        text = self.style.stamp_text % _text_params
        self.text_box.content = text

        stamp_height = self.get_stamp_height()
        stamp_width = self.get_stamp_width()

        bg = self.style.background
        if bg is not None:
            # TODO this is one of the places where some more clever layout
            #  engine would really help, since all of this is pretty ad hoc and
            #  makes a number of non-obvious choices that would be better off
            #  delegated to somewhere else.
            bg.set_writer(self.writer)

            # scale the background
            bg_height = 0.9 * stamp_height
            if bg.box.height_defined:
                sf = bg_height / bg.box.height
            else:
                bg.box.height = bg_height
                sf = 1
            bg_y = 0.05 * stamp_height
            bg_width = bg.box.width * sf
            bg_x = 0
            if bg_width <= stamp_width:
                bg_x = (stamp_width - bg_width) // 2

            # set opacity in graphics state
            opacity = generic.FloatObject(self.style.background_opacity)
            self.set_resource(
                category=ResourceType.EXT_G_STATE,
                name=pdf_name('/BackgroundGS'),
                value=generic.DictionaryObject({
                    pdf_name('/CA'): opacity, pdf_name('/ca'): opacity
                })
            )
            command_stream.append(
                b'q /BackgroundGS gs %g 0 0 %g %g %g cm %s Q' % (
                    sf, sf, bg_x, bg_y, bg.render()
                )
            )
            self.import_resources(bg.resources)

        tb = self.text_box
        text_commands = tb.render()

        text_scale = 1
        if self.expected_text_width is not None and tb.box.width_defined:
            text_scale = self.expected_text_width / tb.box.width

        command_stream.append(
            b'q %g 0 0 %g %g %g cm' % (
                text_scale, text_scale,
                self.text_box_x(), self.text_box_y()
            )
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

    def register(self) -> generic.IndirectObject:
        """
        Register the stamp with the writer coupled to this instance, and
        cache the returned reference.

        This works by calling :meth:`.PdfContent.as_form_xobject`.

        :return:
            An indirect reference to the form XObject containing the stamp.
        """
        stamp_ref = self._stamp_ref
        if stamp_ref is None:
            form_xobj = self.as_form_xobject()
            self._stamp_ref = stamp_ref = self.writer.add_object(form_xobj)
        return stamp_ref

    def apply(self, dest_page: int, x: int, y: int):
        """
        Apply a stamp to a particular page in the PDF writer attached to this
        :class:`.TextStamp` instance.

        :param dest_page:
            Index of the page to which the stamp is to be applied
            (starting at `0`).
        :param x:
            Horizontal position of the stamp's lower left corner on the page.
        :param y:
            Vertical position of the stamp's lower left corner on the page.
        :return:
            A reference to the affected page object, together with
            a ``(width, height)`` tuple describing the dimensions of the stamp.
        """
        stamp_ref = self.register()
        resource_name = b'/Stamp' + hexlify(uuid.uuid4().bytes)
        stamp_paint = b'q 1 0 0 1 %g %g cm %s Do Q' % (
            rd(x), rd(y), resource_name
        )
        stamp_wrapper_stream = generic.StreamObject(stream_data=stamp_paint)
        resources = generic.DictionaryObject({
            pdf_name('/XObject'): generic.DictionaryObject({
                pdf_name(resource_name.decode('ascii')): stamp_ref
            })
        })
        wr = self.writer
        page_ref = wr.add_stream_to_page(
            dest_page, wr.add_object(stamp_wrapper_stream), resources
        )
        dims = (self.box.width, self.box.height)
        return page_ref, dims

    def as_appearances(self) -> AnnotAppearances:
        """
        Turn this stamp into an appearance dictionary for an annotation
        (or a form field widget), after rendering it.
        Only the normal appearance will be defined.

        :return:
            An instance of :class:`.AnnotAppearances`.
        """
        # TODO support defining overrides/extra's for the rollover/down
        #  appearances in some form
        stamp_ref = self.register()
        return AnnotAppearances(normal=stamp_ref)


class QRStamp(TextStamp):
    qr_default_width = 30
    """
    Default value for the QR code's width in user units.
    This value is only used if the stamp's bounding box does not have a
    defined width, in which case the :attr:`.QRStampStyle.stamp_qrsize`
    attribute is unusable.
    
    You can safely override this attribute if you so desire.
    """

    def __init__(self, writer: IncrementalPdfFileWriter, url: str,
                 style: QRStampStyle, text_params=None,
                 box: BoxConstraints = None):
        super().__init__(writer, style, text_params=text_params, box=box)
        self.url = url
        self._qr_size = None

    @property
    def qr_size(self):
        """
        Compute the effective size of the QR code.

        :return:
            The size of the QR code in user units.
        """
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
            category=ResourceType.XOBJECT, name=pdf_name('/QR'),
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


def _stamp_file(input_name: str, output_name: str, style: TextStampStyle,
                stamp_class, dest_page: int, x: int, y: int, **stamp_kwargs):

    with open(input_name, 'rb') as fin:
        pdf_out = IncrementalPdfFileWriter(fin)
        stamp = stamp_class(writer=pdf_out, style=style, **stamp_kwargs)
        stamp.apply(dest_page, x, y)

        with open(output_name, 'wb') as out:
            pdf_out.write(out)


def text_stamp_file(input_name: str, output_name: str, style: TextStampStyle,
                    dest_page: int, x: int, y: int, text_params=None):
    """
    Add a text stamp to a file.

    :param input_name:
        Path to the input file.
    :param output_name:
        Path to the output file.
    :param style:
        Text stamp style to use.
    :param dest_page:
        Index of the page to which the stamp is to be applied (starting at `0`).
    :param x:
        Horizontal position of the stamp's lower left corner on the page.
    :param y:
        Vertical position of the stamp's lower left corner on the page.
    :param text_params:
        Additional parameters for text template interpolation.
    """
    _stamp_file(
        input_name, output_name, style, TextStamp, dest_page, x, y,
        text_params=text_params
    )


def qr_stamp_file(input_name: str, output_name: str, style: QRStampStyle,
                  dest_page: int, x: int, y: int, url: str,
                  text_params=None):
    """
    Add a QR stamp to a file.

    :param input_name:
        Path to the input file.
    :param output_name:
        Path to the output file.
    :param style:
        QR stamp style to use.
    :param dest_page:
        Index of the page to which the stamp is to be applied (starting at `0`).
    :param x:
        Horizontal position of the stamp's lower left corner on the page.
    :param y:
        Vertical position of the stamp's lower left corner on the page.
    :param url:
        URL for the QR code to point to.
    :param text_params:
        Additional parameters for text template interpolation.
    """

    _stamp_file(
        input_name, output_name, style, QRStamp, dest_page, x, y,
        url=url, text_params=text_params
    )


STAMP_ART_CONTENT = RawContent(
    box=BoxConstraints(width=100, height=100),
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
"""
Hardcoded stamp background that will render a stylised image of a stamp using 
PDF graphics operators (see below).

.. image:: images/stamp-background.svg
   :alt: Standard stamp background
   :align: center
   
"""
