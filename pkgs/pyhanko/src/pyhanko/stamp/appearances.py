import enum
from typing import Optional

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name

__all__ = ['AnnotAppearances', 'CoordinateSystem']


class CoordinateSystem(enum.Enum):
    """
    Positioning convention for stamps.
    """

    PAGE_DEFAULT = 1
    """
    Always treat the stamp's position in the page's default coordinate system,
    by defensively forcing a restore to the original graphics state.

    .. note::
        This is the default behaviour since ``0.27.0``.
    """

    AMBIENT = 2
    """
    Apply the stamp in the ambient frame of reference set by the existing
    page content.
    This may yield unpredictable results depending on the input document.

    .. note::
        This was the default behaviour prior to ``0.27.0``.
    """


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

    def __init__(
        self,
        normal: generic.IndirectObject,
        rollover: Optional[generic.IndirectObject] = None,
        down: Optional[generic.IndirectObject] = None,
    ):
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
