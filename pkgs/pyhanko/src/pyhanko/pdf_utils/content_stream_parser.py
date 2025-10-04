from dataclasses import dataclass
from io import BytesIO
from typing import List, Tuple

from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.generic import (
    ContentOpReading,
    OperatorLiteral,
    PdfObject,
    Reference,
    StreamObject,
    read_object,
)
from pyhanko.pdf_utils.misc import skip_over_comments, skip_over_whitespace


@dataclass(frozen=True)
class GraphicsOperator:
    op: str
    args: List[PdfObject]
    start: Tuple[Reference, int]
    end: Tuple[Reference, int]


def parse_content_stream(stream_parts: List[StreamObject]):
    start_ref = None
    start_pos = 0
    args_collected: List[PdfObject] = []
    for pdf_stream in stream_parts:
        current_ref = pdf_stream.container_ref
        assert isinstance(current_ref, Reference)
        stream_data = pdf_stream.data
        stream = BytesIO(stream_data)
        total = len(stream_data)
        skip_over_whitespace(stream, error_on_end_of_stream=False)
        skip_over_comments(stream, error_on_end_of_stream=False)
        while (pos := stream.tell()) < total:
            obj = read_object(
                stream,
                current_ref,
                in_content_stream=ContentOpReading.GRAPHIC_OPS,
            )
            if start_ref is None:
                args_collected = []
                start_ref = current_ref
                start_pos = pos
            if isinstance(obj, OperatorLiteral):
                # TODO try to skip over inline images? Is annoying to do
                #  in pre-2.0 files.
                if obj.literal == 'BI':
                    raise misc.PdfReadError(
                        "Content streams with inline images are not supported"
                    )
                yield GraphicsOperator(
                    obj.literal,
                    args_collected,
                    (start_ref, start_pos),
                    (current_ref, pos + len(obj.literal)),
                )
                start_ref = None
            else:
                args_collected.append(obj)
            skip_over_whitespace(stream, error_on_end_of_stream=False)
            skip_over_comments(stream, error_on_end_of_stream=False)
