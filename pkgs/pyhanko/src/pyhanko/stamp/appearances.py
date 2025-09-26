import enum

__all__ = ['CoordinateSystem']


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
