from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

from .qr import QRStamp, QRStampStyle
from .text import TextStamp, TextStampStyle

__all__ = ["qr_stamp_file", "text_stamp_file"]


def _stamp_file(
    input_name: str,
    output_name: str,
    style: TextStampStyle,
    stamp_class,
    dest_page: int,
    x: int,
    y: int,
    **stamp_kwargs,
):
    with open(input_name, 'rb') as fin:
        pdf_out = IncrementalPdfFileWriter(fin, strict=False)
        stamp = stamp_class(writer=pdf_out, style=style, **stamp_kwargs)
        stamp.apply(dest_page, x, y)

        with open(output_name, 'wb') as out:
            pdf_out.write(out)


def text_stamp_file(
    input_name: str,
    output_name: str,
    style: TextStampStyle,
    dest_page: int,
    x: int,
    y: int,
    text_params=None,
):
    """
    Add a text stamp to a file.

    :param input_name:
        Path to the input file.
    :param output_name:
        Path to the output file.
    :param style:
        Text stamp style to use.
    :param dest_page:
        Index of the page to which the stamp is to be applied (starting at `0`).
    :param x:
        Horizontal position of the stamp's lower left corner on the page.
    :param y:
        Vertical position of the stamp's lower left corner on the page.
    :param text_params:
        Additional parameters for text template interpolation.
    """
    _stamp_file(
        input_name,
        output_name,
        style,
        TextStamp,
        dest_page,
        x,
        y,
        text_params=text_params,
    )


def qr_stamp_file(
    input_name: str,
    output_name: str,
    style: QRStampStyle,
    dest_page: int,
    x: int,
    y: int,
    url: str,
    text_params=None,
):
    """
    Add a QR stamp to a file.

    :param input_name:
        Path to the input file.
    :param output_name:
        Path to the output file.
    :param style:
        QR stamp style to use.
    :param dest_page:
        Index of the page to which the stamp is to be applied (starting at `0`).
    :param x:
        Horizontal position of the stamp's lower left corner on the page.
    :param y:
        Vertical position of the stamp's lower left corner on the page.
    :param url:
        URL for the QR code to point to.
    :param text_params:
        Additional parameters for text template interpolation.
    """

    _stamp_file(
        input_name,
        output_name,
        style,
        QRStamp,
        dest_page,
        x,
        y,
        url=url,
        text_params=text_params,
    )
