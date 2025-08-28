from dataclasses import dataclass

from pyhanko.pdf_utils import content, layout
from pyhanko.pdf_utils.writer import BasePdfFileWriter

from .base import BaseStamp, BaseStampStyle

__all__ = ['StaticContentStamp', 'StaticStampStyle']


@dataclass(frozen=True)
class StaticStampStyle(BaseStampStyle):
    """
    Stamp style that does not include any custom parts; it only renders
    the background.
    """

    background_opacity: float = 1.0
    """
    Opacity value to render the background at. This should be a floating-point
    number between `0` and `1`.
    """

    @classmethod
    def from_pdf_file(
        cls, file_name, page_ix=0, **kwargs
    ) -> 'StaticStampStyle':
        """
        Create a :class:`StaticStampStyle` from a page from an external PDF
        document. This is a convenience wrapper around
        :class:`~content.ImportedPdfContent`.

        The remaining keyword arguments are passed to
        :class:`StaticStampStyle`'s init method.

        :param file_name:
            File name of the external PDF document.
        :param page_ix:
            Page index to import. The default is ``0``, i.e. the first page.
        """
        return StaticStampStyle(
            background=content.ImportedPdfPage(file_name, page_ix=page_ix),
            **kwargs,
        )

    def create_stamp(
        self,
        writer: BasePdfFileWriter,
        box: layout.BoxConstraints,
        text_params: dict,
    ) -> 'StaticContentStamp':
        return StaticContentStamp(writer=writer, style=self, box=box)


class StaticContentStamp(BaseStamp):
    """Class representing stamps with static content."""

    def __init__(
        self,
        writer: BasePdfFileWriter,
        style: StaticStampStyle,
        box: layout.BoxConstraints,
    ):
        if not (box and box.height_defined and box.width_defined):
            raise layout.LayoutError(
                "StaticContentStamp requires a predetermined bounding box."
            )
        super().__init__(box=box, style=style, writer=writer)

    def _render_inner_content(self):
        return []
