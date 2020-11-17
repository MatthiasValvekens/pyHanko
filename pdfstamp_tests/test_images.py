from io import BytesIO

import pytest
import os
from PIL import Image
from .samples import *
from pdf_utils import images
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils import generic
from pdf_utils.generic import pdf_name

IMG_DIR = 'pdfstamp_tests/data/img'


@pytest.mark.parametrize('infile', ['stamp.png', 'stamp-indexed.png'])
def test_image_embed(infile):
    img = Image.open(os.path.join(IMG_DIR, infile))

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    image_ref = images.pil_image(img, w)
    page_ref, resources = w.find_page_for_modification(0)
    resources[pdf_name('/XObject')] = generic.DictionaryObject({
        pdf_name('/Img'): image_ref
    })
    w.update_container(resources)
    content_stream: generic.StreamObject = page_ref.get_object()['/Contents']
    content_stream._data = content_stream.data \
                           + b' q 50 0 0 50 5 5 cm /Img Do Q'
    content_stream._encoded_data = None
    w.update_container(content_stream)
    w.write_in_place()

    # TODO flatten and do a visual comparison

    image_obj = image_ref.get_object()
    if 'indexed' in infile:
        assert '/SMask' not in image_obj
    else:
        assert '/SMask' in image_obj
