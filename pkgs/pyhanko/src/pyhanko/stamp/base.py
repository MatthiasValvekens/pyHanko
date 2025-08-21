import uuid
from binascii import hexlify
from dataclasses import dataclass
from typing import Optional, Tuple

from pyhanko.config.api import ConfigurableMixin
from pyhanko.config.errors import ConfigurationError
from pyhanko.pdf_utils import content, generic, layout
from pyhanko.pdf_utils.generic import IndirectObject, pdf_name
from pyhanko.pdf_utils.misc import rd
from pyhanko.pdf_utils.writer import BasePdfFileWriter

from .appearances import AnnotAppearances, CoordinateSystem
from .art import STAMP_ART_CONTENT


def _get_background_content(bg_spec) -> content.PdfContent:
    if not isinstance(bg_spec, str):
        raise ConfigurationError("Background specification must be a string")
    # 'special' value to use the stamp vector image baked into
    # the module
    if bg_spec == '__stamp__':
        return STAMP_ART_CONTENT
    elif bg_spec.endswith('.pdf'):
        # import first page of PDF as background
        return content.ImportedPdfPage(bg_spec)
    else:
        from PIL import Image

        from pyhanko.pdf_utils.images import PdfImage

        img = Image.open(bg_spec)
        # Setting the writer can be delayed
        return PdfImage(img, writer=None)


@dataclass(frozen=True)
class BaseStampStyle(ConfigurableMixin):
    """
    Base class for stamp styles.
    """

    border_width: int = 3
    """
    Border width in user units (for the stamp, not the text box).
    """

    border_color: Optional[Tuple[float, float, float]] = None
    """
    Border color specified as an RGB tuple taking values between 0.0 and 1.0.

    .. warning::
        There is currently no direct support for non-RGB color spaces.
    """

    background: Optional[content.PdfContent] = None
    """
    :class:`~.pdf_utils.content.PdfContent` instance that will be used to render
    the stamp's background.
    """

    background_layout: layout.SimpleBoxLayoutRule = layout.SimpleBoxLayoutRule(
        x_align=layout.AxisAlignment.ALIGN_MID,
        y_align=layout.AxisAlignment.ALIGN_MID,
        margins=layout.Margins.uniform(5),
    )
    """
    Layout rule to render the background inside the stamp's bounding box.
    Only used if the background has a fully specified :attr:`PdfContent.box`.

    Otherwise, the renderer will position the cursor at
    ``(left_margin, bottom_margin)`` and render the content as-is.
    """

    background_opacity: float = 0.6
    """
    Opacity value to render the background at. This should be a floating-point
    number between `0` and `1`.
    """

    @classmethod
    def process_entries(cls, config_dict):
        """
        This implementation of :meth:`process_entries` processes the
        :attr:`background` configuration value.
        This can either be a path to an image file, in which case it will
        be turned into an instance of :class:`~.pdf_utils.images.PdfImage`,
        or the special value ``__stamp__``, which is an alias for
        :const:`~pyhanko.stamp.STAMP_ART_CONTENT`.
        """

        super().process_entries(config_dict)
        bg_spec = None
        try:
            bg_spec = config_dict['background']
        except KeyError:
            pass
        if bg_spec is not None:
            config_dict['background'] = _get_background_content(bg_spec)

    def create_stamp(
        self,
        writer: BasePdfFileWriter,
        box: layout.BoxConstraints,
        text_params: dict,
    ) -> 'BaseStamp':
        raise NotImplementedError


class BaseStamp(content.PdfContent):
    def __init__(
        self,
        writer: BasePdfFileWriter,
        style,
        box: Optional[layout.BoxConstraints] = None,
    ):
        super().__init__(box=box, writer=writer)
        self.style = style
        self._resources_ready = False
        self._stamp_ref: Optional[IndirectObject] = None

    def _render_background(self):
        bg = self.style.background
        bg.set_writer(self.writer)
        bg_content = bg.render()  # render first, in case the BBox is lazy

        bg_box = bg.box
        if bg_box.width_defined and bg_box.height_defined:
            # apply layout rule
            positioning = self.style.background_layout.fit(
                self.box, bg_box.width, bg_box.height
            )
        else:
            # No idea about the background dimensions, so just use
            # the left/bottom margins and hope for the best
            margins = self.style.background_layout.margins
            positioning = layout.Positioning(
                x_scale=1, y_scale=1, x_pos=margins.left, y_pos=margins.bottom
            )

        # set opacity in graphics state
        opacity = generic.FloatObject(self.style.background_opacity)
        self.set_resource(
            category=content.ResourceType.EXT_G_STATE,
            name=pdf_name('/BackgroundGS'),
            value=generic.DictionaryObject(
                {pdf_name('/CA'): opacity, pdf_name('/ca'): opacity}
            ),
        )

        # Position & render the background
        command = b'q /BackgroundGS gs %s %s Q' % (
            positioning.as_cm(),
            bg_content,
        )
        # we do this after render(), just in case our background resource
        # decides to pull in extra stuff during rendering
        self.import_resources(bg.resources)
        return command

    def _render_inner_content(self):
        raise NotImplementedError

    def render(self):
        command_stream = [b'q']

        inner_content = self._render_inner_content()

        # Now that the inner layout is done, the dimensions of our bounding
        # box should all have been reified. Let's put in the background,
        # if there is one
        if self.style.background:
            command_stream.append(self._render_background())

        # put in the inner content
        if inner_content:
            command_stream.extend(inner_content)

        # draw the border around the stamp
        bbox = self.box
        border_width = self.style.border_width
        border_color = self.style.border_color
        if border_width:
            if border_color:
                command_stream.append(b'%g %g %g RG' % border_color)

            command_stream.append(
                b'%g w 0 0 %g %g re S'
                % (border_width, bbox.width, bbox.height),
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
            wr = self._ensure_writer
            form_xobj = self.as_form_xobject()
            self._stamp_ref = stamp_ref = wr.add_object(form_xobj)
        return stamp_ref

    def apply(
        self,
        dest_page: int,
        x: int,
        y: int,
        *,
        coords: CoordinateSystem = CoordinateSystem.PAGE_DEFAULT,
    ):
        """
        Apply a stamp to a particular page in the PDF writer attached to this
        :class:`.BaseStamp` instance.

        :param dest_page:
            Index of the page to which the stamp is to be applied
            (starting at `0`).
        :param x:
            Horizontal position of the stamp's lower left corner on the page.
        :param y:
            Vertical position of the stamp's lower left corner on the page.
        :param coords:
            The coordinate convention to use.
        :return:
            A reference to the affected page object, together with
            a ``(width, height)`` tuple describing the dimensions of the stamp.
        """
        stamp_ref = self.register()
        resource_name = b'/Stamp' + hexlify(uuid.uuid4().bytes)
        stamp_paint = b'q 1 0 0 1 %g %g cm %s Do Q' % (
            rd(x),
            rd(y),
            resource_name,
        )
        stamp_wrapper_stream = generic.StreamObject(stream_data=stamp_paint)
        resources = generic.DictionaryObject(
            {
                pdf_name('/XObject'): generic.DictionaryObject(
                    {pdf_name(resource_name.decode('ascii')): stamp_ref}
                )
            }
        )
        wr = self.writer
        assert wr is not None
        if coords == CoordinateSystem.PAGE_DEFAULT:
            # wrap the existing content in q / Q
            wr.add_stream_to_page(
                dest_page,
                wr.add_object(
                    generic.StreamObject(stream_data=b"q"),
                ),
                prepend=True,
            )
            wr.add_stream_to_page(
                dest_page,
                wr.add_object(
                    generic.StreamObject(stream_data=b"Q"),
                ),
            )
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
