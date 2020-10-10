from dataclasses import dataclass

from pdf_utils.font import FontEngine, SimpleFontEngine


@dataclass(frozen=True)
class TextStyle:
    font: FontEngine = SimpleFontEngine.default_engine()
    font_size: int = 10
    leading: int = None
    textsep: int = 10


# TODO implement generic textbox with text reflowing etc.
