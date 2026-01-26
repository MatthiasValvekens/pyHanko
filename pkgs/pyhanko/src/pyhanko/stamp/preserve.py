from dataclasses import dataclass

from pyhanko.pdf_utils import content, layout
from pyhanko.pdf_utils.writer import BasePdfFileWriter

from .base import BaseStamp, BaseStampStyle

__all__ = ['PreserveStampStyle']


@dataclass(frozen=True)
class PreserveStampStyle(BaseStampStyle):
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
