from PIL.ImagePalette import ImagePalette

from .generic import pdf_name
from . import generic
from .writer import BasePdfFileWriter

from PIL import Image

__all__ = ['pil_image']


def pil_image(img, writer: BasePdfFileWriter):
    assert isinstance(img, Image.Image)
    # TODO would PA be hard to support?

    if img.mode not in ('RGB', 'RGBA', 'P', 'L', 'LA'):  # pragma: nocover
        raise NotImplementedError

    dict_data = {
        pdf_name('/Type'): pdf_name('/XObject'),
        pdf_name('/Subtype'): pdf_name('/Image'),
        pdf_name('/Width'): generic.NumberObject(img.width),
        pdf_name('/Height'): generic.NumberObject(img.height),
    }

    bpc = generic.NumberObject(8)

    smask_image = None
    if img.mode.endswith('A'):
        # extract the alpha channel, and save it as a separate image object
        smask_pil_image = img.split()[-1]
        assert smask_pil_image.mode == 'L'
        smask_image = pil_image(smask_pil_image, writer)
        # finally, convert to RBG or L as appropriate
        img = img.convert(img.mode[:-1])

    clr_space = \
        pdf_name('/DeviceGray') if img.mode == 'L' else pdf_name('/DeviceRGB')
    if img.mode == 'P':
        palette: ImagePalette = img.palette
        palette_arr = palette.palette
        if palette.mode != 'RGB':  # pragma: nocover
            raise NotImplementedError
        palette_size = len(palette_arr) // 3
        # declare an indexed colour space based on /DeviceRGB
        # with 'palette_size' colours, with mapping defined as
        # a byte string
        clr_space = generic.ArrayObject([
            pdf_name('/Indexed'), pdf_name('/DeviceRGB'),
            generic.NumberObject(palette_size - 1),
            generic.ByteStringObject(palette_arr)
        ])

    if smask_image is not None:
        dict_data[pdf_name('/SMask')] = smask_image

    dict_data[pdf_name('/ColorSpace')] = clr_space
    dict_data[pdf_name('/BitsPerComponent')] = bpc
    # TODO nice to have: I'd like to pack everything into minimal space here
    #   (but the flate compression should deal with it pretty nicely)
    #  NOTE the BPC values allowed by the standard are limited to 1, 2, 4, 8
    #   (and 12, 16, but those aren't allowed by PIL anyway in this context)
    image_bytes = img.tobytes()

    stream = generic.StreamObject(
        dict_data, stream_data=image_bytes
    )
    stream.compress()
    return writer.add_object(stream)
