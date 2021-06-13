from dataclasses import dataclass

from pyhanko.pdf_utils import generic

__all__ = ['ShapeResult', 'FontEngine']


@dataclass(frozen=True)
class ShapeResult:
    """Result of shaping a Unicode string."""
    graphics_ops: bytes
    """
    PDF graphics operators to render the glyphs.
    """

    x_advance: float
    """Total horizontal advance in em units."""

    y_advance: float
    """Total vertical advance in em units."""


class FontEngine:
    """General interface for text shaping and font metrics."""

    @property
    def uses_complex_positioning(self):
        """
        If ``True``, this font engine expects the line matrix to always be equal
        to the text matrix when exiting and entering :meth:`shape`.
        In other words, the current text position is where ``0 0 Td`` would
        move to.

        If ``False``, this method does not use any text positioning operators,
        and therefore uses the PDF standard's 'natural' positioning rules
        for text showing operators.

        The default is ``True`` unless overridden.
        """
        return True

    def shape(self, txt: str) -> ShapeResult:
        """Render a string to a format suitable for inclusion in a content
        stream and measure its total cursor advancement vector in em units.

        :param txt:
            String to shape.
        :return:
            A shaping result.
        """
        raise NotImplementedError

    def as_resource(self) -> generic.DictionaryObject:
        """Convert a :class:`.FontEngine` to a PDF object suitable for embedding
        inside a resource dictionary.

        :return:
            A PDF dictionary.
        """
        raise NotImplementedError
