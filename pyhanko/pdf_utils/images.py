import uuid
from fractions import Fraction

from PIL.ImagePalette import ImagePalette
from typing import Union

from pyhanko.pdf_utils.misc import BoxConstraints
from .generic import pdf_name, PdfContent, ResourceType, PdfResources
from . import generic
from .writer import BasePdfFileWriter

from PIL import Image

__all__ = ['pil_image', 'PdfImage']


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


class PdfImage(PdfContent):

    def __init__(self, image: Union[Image.Image, str],
                 writer: BasePdfFileWriter,
                 resources: PdfResources = None,
                 name: str = None,
                 opacity=None, box: BoxConstraints = None):

        if isinstance(image, str):
            image = Image.open(image)

        self.image: Image.Image = image
        self.name = name or str(uuid.uuid4())
        self.opacity = opacity

        if box is None:
            # assume square pixels
            box = BoxConstraints(
                aspect_ratio=Fraction(self.image.width, self.image.height)
            )
        super().__init__(resources, writer=writer, box=box)
        self._image_ref = None

    @property
    def image_ref(self):
        assert self.writer is not None
        if self._image_ref is None:
            self._image_ref = pil_image(self.image, self.writer)
        return self._image_ref

    def render(self) -> bytes:
        img_ref_name = '/Img' + self.name
        self.set_resource(
            category=ResourceType.XOBJECT, name=pdf_name(img_ref_name),
            value=self.image_ref
        )

        opacity = b''
        if self.opacity is not None:
            gs_name = '/GS' + str(uuid.uuid4())
            self.set_resource(
                category=ResourceType.EXT_G_STATE, name=pdf_name(gs_name),
                value=generic.DictionaryObject({
                    pdf_name('/ca'): generic.FloatObject(self.opacity)
                })
            )
            opacity = gs_name.encode('ascii') + b' gs'

        # Internally, the image is mapped to the unit square in
        # user coordinates, irrespective of width/height.
        # In particular, we might have to scale the x and y axes differently.
        if not self.box.height_defined:
            self.box.height = self.image.height
        if not self.box.width_defined:
            self.box.width = self.image.width

        draw = b'%g 0 0 %g 0 0 cm %s Do' % (
            self.box.width, self.box.height, img_ref_name.encode('ascii')
        )
        return b'q %s %s Q' % (opacity, draw)
