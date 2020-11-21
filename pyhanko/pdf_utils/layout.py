from fractions import Fraction
from typing import Optional


class BoxSpecificationError(ValueError):
    pass


class BoxConstraints:
    _width: Optional[int]
    _height: Optional[int]
    _ar: Optional[Fraction]
    _fully_specified: bool

    def __init__(self, width=None, height=None, aspect_ratio: Fraction = None):
        self._width = int(width) if width is not None else None
        self._height = int(height) if height is not None else None

        fully_specified = False

        self._ar = None
        if width is None and height is None and aspect_ratio is None:
            return
        elif width is not None and height is not None:
            if aspect_ratio is not None:
                raise BoxSpecificationError  # overspecified
            self._ar = Fraction(self._width, self._height)
            fully_specified = True
        elif aspect_ratio is not None:
            self._ar = aspect_ratio
            if height is not None:
                self._width = height * aspect_ratio
            elif width is not None:
                self._height = width / aspect_ratio

        self._fully_specified = fully_specified

    def _recalculate(self):
        if self._width is not None and self._height is not None:
            self._ar = Fraction(self._width, self._height)
            self._fully_specified = True
        elif self._ar is not None:
            if self._height is not None:
                self._width = int(self._height * self._ar)
                self._fully_specified = True
            elif self._width is not None:
                self._height = int(self._width / self._ar)
                self._fully_specified = True

    @property
    def width(self) -> int:
        if self._width is not None:
            return self._width
        else:
            raise BoxSpecificationError

    @width.setter
    def width(self, width):
        if self._width is None:
            self._width = width
            self._recalculate()
        else:
            raise BoxSpecificationError

    @property
    def width_defined(self) -> bool:
        return self._width is not None

    @property
    def height(self) -> int:
        if self._height is not None:
            return self._height
        else:
            raise BoxSpecificationError

    @height.setter
    def height(self, height):
        if self._height is None:
            self._height = height
            self._recalculate()
        else:
            raise BoxSpecificationError

    @property
    def height_defined(self) -> bool:
        return self._height is not None

    @property
    def aspect_ratio(self) -> Fraction:
        if self._ar is not None:
            return self._ar
        else:
            raise BoxSpecificationError

    @property
    def aspect_ratio_defined(self) -> bool:
        return self._ar is not None