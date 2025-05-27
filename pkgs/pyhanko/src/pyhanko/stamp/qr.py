import enum
from dataclasses import dataclass
from typing import List, Optional, Tuple

from pyhanko.config.errors import ConfigurationError
from pyhanko.pdf_utils import content, generic, layout
from pyhanko.pdf_utils.generic import pdf_name, pdf_string
from pyhanko.pdf_utils.writer import BasePdfFileWriter, init_xobject_dictionary

from .appearances import CoordinateSystem
from .text import TextStamp, TextStampStyle

__all__ = ["QRPosition", "QRStampStyle", "QRStamp", "DEFAULT_QR_SCALE"]


class QRPosition(enum.Enum):
    """
    QR positioning constants, with the corresponding default content layout
    rule.
    """

    LEFT_OF_TEXT = layout.SimpleBoxLayoutRule(
        x_align=layout.AxisAlignment.ALIGN_MIN,
        y_align=layout.AxisAlignment.ALIGN_MID,
    )
    RIGHT_OF_TEXT = layout.SimpleBoxLayoutRule(
        x_align=layout.AxisAlignment.ALIGN_MAX,
        y_align=layout.AxisAlignment.ALIGN_MID,
    )
    ABOVE_TEXT = layout.SimpleBoxLayoutRule(
        y_align=layout.AxisAlignment.ALIGN_MAX,
        x_align=layout.AxisAlignment.ALIGN_MID,
    )
    BELOW_TEXT = layout.SimpleBoxLayoutRule(
        y_align=layout.AxisAlignment.ALIGN_MIN,
        x_align=layout.AxisAlignment.ALIGN_MID,
    )

    @property
    def horizontal_flow(self):
        return self in (QRPosition.LEFT_OF_TEXT, QRPosition.RIGHT_OF_TEXT)

    @classmethod
    def from_config(cls, config_str) -> 'QRPosition':
        """
        Convert from a configuration string.

        :param config_str:
            A string: 'left', 'right', 'top', 'bottom'
        :return:
            An :class:`.QRPosition` value.
        :raise ConfigurationError: on unexpected string inputs.
        """
        try:
            return {
                'left': QRPosition.LEFT_OF_TEXT,
                'right': QRPosition.RIGHT_OF_TEXT,
                'top': QRPosition.ABOVE_TEXT,
                'bottom': QRPosition.BELOW_TEXT,
            }[config_str.lower()]
        except KeyError:
            raise ConfigurationError(
                f"'{config_str}' is not a valid QR position setting; valid "
                f"values are 'left', 'right', 'top', 'bottom'"
            )


DEFAULT_QR_SCALE = 0.2
"""
If the layout & other bounding boxes don't impose another size requirement,
render QR codes at ~20% of their natural size in QR canvas units. At scale 1,
this produces codes of about 2cm x 2cm for a 25-module QR code, which is
probably OK.
"""


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

    qr_inner_size: Optional[int] = None
    """
    Size of the QR code in the inner layout. By default, this is in user units,
    but if the stamp has a fully defined bounding box, it may be rescaled
    depending on :attr:`inner_content_layout`.

    If unspecified, a reasonable default will be used.
    """

    qr_position: QRPosition = QRPosition.LEFT_OF_TEXT
    """
    Position of the QR code relative to the text box.
    """

    qr_inner_content: Optional[content.PdfContent] = None
    """
    Inner graphics content to be included in the QR code (experimental).
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)

        try:
            qr_pos = config_dict['qr_position']
            config_dict['qr_position'] = QRPosition.from_config(qr_pos)
        except KeyError:
            pass

    def create_stamp(
        self,
        writer: BasePdfFileWriter,
        box: layout.BoxConstraints,
        text_params: dict,
    ) -> 'QRStamp':
        # extract the URL parameter
        try:
            url = text_params.pop('url')
        except KeyError:
            raise layout.LayoutError(
                "Using a QR stamp style requires a 'url' text parameter."
            )
        return QRStamp(
            writer, style=self, url=url, text_params=text_params, box=box
        )


class QRStamp(TextStamp):
    def __init__(
        self,
        writer: BasePdfFileWriter,
        url: str,
        style: QRStampStyle,
        text_params=None,
        box: Optional[layout.BoxConstraints] = None,
    ):
        super().__init__(writer, style, text_params=text_params, box=box)
        self.url = url
        self._qr_size = None

    def _inner_content_layout_rule(self):
        style = self.style
        if style.inner_content_layout is not None:
            return style.inner_content_layout

        # choose a reasonable default based on the QR code's relative position
        return style.qr_position.value

    def _inner_layout_natural_size(self) -> Tuple[List[bytes], Tuple[int, int]]:
        text_commands, (
            text_width,
            text_height,
        ) = super()._inner_layout_natural_size()

        qr_ref, natural_qr_size = self._qr_xobject()
        self.set_resource(
            category=content.ResourceType.XOBJECT,
            name=pdf_name('/QR'),
            value=qr_ref,
        )

        style = self.style
        stamp_box = self.box

        # To size the QR code, we proceed as follows:
        #  - If qr_inner_size is not None, use it
        #  - If the stamp has a fully defined bbox already,
        #    make sure it fits within the innseps, and it's not too much smaller
        #    than the text box
        #  - Else, scale down by DEFAULT_QR_SCALE and use that value
        #
        # Note: if qr_inner_size is defined AND the stamp bbox is available
        # already, scaling might still take effect depending on the inner layout
        # rule.
        innsep = style.innsep
        if style.qr_inner_size is not None:
            qr_size = style.qr_inner_size
        elif stamp_box.width_defined and stamp_box.height_defined:
            # ensure that the QR code doesn't shrink too much if the text
            # box is too tall.
            min_dim = min(
                max(stamp_box.height, text_height),
                max(stamp_box.width, text_width),
            )
            qr_size = min_dim - 2 * innsep
        else:
            qr_size = int(round(DEFAULT_QR_SCALE * natural_qr_size))

        qr_innunits_scale = qr_size / natural_qr_size
        qr_padded = qr_size + 2 * innsep
        # Next up: put the QR code and the text box together to get the
        # inner layout bounding box
        if style.qr_position.horizontal_flow:
            inn_width = qr_padded + text_width
            inn_height = max(qr_padded, text_height)
        else:
            inn_width = max(qr_padded, text_width)
            inn_height = qr_padded + text_height
        # grab the base layout rule from the QR position setting
        default_layout: layout.SimpleBoxLayoutRule = style.qr_position.value

        # Fill in the margins
        qr_layout_rule = layout.SimpleBoxLayoutRule(
            x_align=default_layout.x_align,
            y_align=default_layout.y_align,
            margins=layout.Margins.uniform(innsep),
            # There's no point in scaling here, the inner content canvas
            # is always big enough
            inner_content_scaling=layout.InnerScaling.NO_SCALING,
        )

        inner_box = layout.BoxConstraints(inn_width, inn_height)
        qr_inn_pos = qr_layout_rule.fit(inner_box, qr_size, qr_size)

        # we still need to take the axis reversal into account
        # (which also implies an adjustment in the y displacement)
        draw_qr_command = b'q %g 0 0 %g %g %g cm /QR Do Q' % (
            qr_inn_pos.x_scale * qr_innunits_scale,
            qr_inn_pos.y_scale * qr_innunits_scale,
            qr_inn_pos.x_pos,
            qr_inn_pos.y_pos,
        )

        # Time to put in the text box now
        if style.qr_position == QRPosition.LEFT_OF_TEXT:
            tb_margins = layout.Margins(
                left=qr_padded, right=0, top=0, bottom=0
            )
        elif style.qr_position == QRPosition.RIGHT_OF_TEXT:
            tb_margins = layout.Margins(
                right=qr_padded, left=0, top=0, bottom=0
            )
        elif style.qr_position == QRPosition.BELOW_TEXT:
            tb_margins = layout.Margins(
                bottom=qr_padded, right=0, left=0, top=0
            )
        else:
            tb_margins = layout.Margins(
                top=qr_padded, right=0, left=0, bottom=0
            )

        tb_layout_rule = layout.SimpleBoxLayoutRule(
            # flip around the alignment conventions of the default layout
            # to position the text box on the other side
            x_align=default_layout.x_align.flipped,
            y_align=default_layout.y_align.flipped,
            margins=tb_margins,
            inner_content_scaling=layout.InnerScaling.NO_SCALING,
        )

        # position the text box
        text_inn_pos = tb_layout_rule.fit(inner_box, text_width, text_height)

        commands = [draw_qr_command, b'q', text_inn_pos.as_cm()]
        commands.extend(text_commands)
        commands.append(b'Q')
        return commands, (inn_width, inn_height)

    def _qr_xobject(self):
        import qrcode
        from pyhanko.pdf_utils.qr import PdfFancyQRImage, PdfStreamQRImage

        is_fancy = self.style.qr_inner_content is not None
        err_corr = (
            qrcode.constants.ERROR_CORRECT_H
            if is_fancy
            else qrcode.constants.ERROR_CORRECT_M
        )
        qr = qrcode.QRCode(error_correction=err_corr)
        qr.add_data(self.url)
        qr.make()

        if is_fancy:
            img = qr.make_image(
                image_factory=PdfFancyQRImage,
                version=qr.version,
                center_image=self.style.qr_inner_content,
            )
        else:
            img = qr.make_image(image_factory=PdfStreamQRImage)
        command_stream = img.render_command_stream()

        bbox_size = (qr.modules_count + 2 * qr.border) * qr.box_size
        qr_xobj = init_xobject_dictionary(command_stream, bbox_size, bbox_size)
        qr_xobj.compress()
        return self.writer.add_object(qr_xobj), bbox_size

    def get_default_text_params(self):
        tp = super().get_default_text_params()
        tp['url'] = self.url
        return tp

    def apply(
        self,
        dest_page,
        x,
        y,
        *,
        coords: CoordinateSystem = CoordinateSystem.PAGE_DEFAULT,
    ):
        page_ref, (w, h) = super().apply(dest_page, x, y, coords=coords)
        link_rect = (x, y, x + w, y + h)
        link_annot = generic.DictionaryObject(
            {
                pdf_name('/Type'): pdf_name('/Annot'),
                pdf_name('/Subtype'): pdf_name('/Link'),
                pdf_name('/Rect'): generic.ArrayObject(
                    list(map(generic.FloatObject, link_rect))
                ),
                pdf_name('/A'): generic.DictionaryObject(
                    {
                        pdf_name('/S'): pdf_name('/URI'),
                        pdf_name('/URI'): pdf_string(self.url),
                    }
                ),
            }
        )
        wr = self.writer
        assert wr is not None
        wr.register_annotation(page_ref, wr.add_object(link_annot))
        return page_ref, (w, h)
