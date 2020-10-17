def read_all(fname):
    with open(fname, 'rb') as f:
        return f.read()


CRYPTO_DATA_DIR = 'tests/data/crypto'
TESTING_CA_DIR = CRYPTO_DATA_DIR + '/testing-ca'
PDF_DATA_DIR = 'tests/data/pdf'
MINIMAL = read_all(PDF_DATA_DIR + '/minimal.pdf')
MINIMAL_XREF = read_all(PDF_DATA_DIR + '/minimal-xref.pdf')
MINIMAL_ONE_FIELD = read_all(PDF_DATA_DIR + '/minimal-with-field.pdf')
MINIMAL_TWO_FIELDS = read_all(PDF_DATA_DIR + '/minimal-two-fields.pdf')

# user/owner passwords are 'usersecret' and 'ownersecret' respectively
MINIMAL_RC4 = read_all(PDF_DATA_DIR + '/minimal-rc4.pdf')
MINIMAL_ONE_FIELD_RC4 = read_all(PDF_DATA_DIR + '/minimal-with-field-rc4.pdf')

VECTOR_IMAGE_PDF = read_all(PDF_DATA_DIR + '/scribble.pdf')
VECTOR_IMAGE_PDF_DECOMP = read_all(PDF_DATA_DIR + '/scribble-decomp.pdf')

FILE_WITH_EMBEDDED_FONT = read_all(PDF_DATA_DIR + '/fontembed.pdf')


def simple_page(pdf_out, ascii_text, compress=False, extra_stream=False):
    # based on the minimal pdf file of
    # https://brendanzagaeski.appspot.com/0004.html
    from pdf_utils import writer, generic
    from pdf_utils.generic import pdf_name
    resources = generic.DictionaryObject({
        pdf_name('/Font'): generic.DictionaryObject({
            pdf_name('/F1'): generic.DictionaryObject({
                pdf_name('/Type'): pdf_name('/Font'),
                pdf_name('/Subtype'): pdf_name('/Type1'),
                pdf_name('/BaseFont'): pdf_name('/Courier')
            })
        })
    })
    media_box = generic.ArrayObject(
        map(generic.NumberObject, (0, 0, 300, 144))
    )

    def stream_data(txt, y):
        return f'BT /F1 18 Tf 0 {y} Td ({txt}) Tj ET'.encode('ascii')

    stream = generic.StreamObject(
        stream_data=stream_data(ascii_text, 0)
    )
    if compress:
        stream.compress()

    if extra_stream:
        stream2 = generic.StreamObject(stream_data=stream_data(ascii_text, 100))
        if compress:
            stream2.compress()
        contents = generic.ArrayObject(
            [pdf_out.add_object(stream), pdf_out.add_object(stream2)]
        )
    else:
        contents = pdf_out.add_object(stream)
    return writer.PageObject(
        contents=contents, media_box=media_box, resources=resources
    )
