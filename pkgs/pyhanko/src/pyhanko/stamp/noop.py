from dataclasses import dataclass

from pyhanko.pdf_utils import layout
from pyhanko.pdf_utils.writer import BasePdfFileWriter

from .base import BaseStampStyle

__all__ = ['NoOpStampStyle']


@dataclass(frozen=True)
class NoOpStampStyle(BaseStampStyle):
    """
    Stamp style that generates no stamp (preserves existing signature appearance)
    """

    def create_stamp(
        self,
        writer: BasePdfFileWriter,
        box: layout.BoxConstraints,
        text_params: dict,
    ) -> None:
        return None
