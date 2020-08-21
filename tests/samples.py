def read_all(fname):
    with open(fname, 'rb') as f:
        return f.read()


CRYPTO_DATA_DIR = 'tests/data/crypto'
PDF_DATA_DIR = 'tests/data/pdf'
MINIMAL = read_all(PDF_DATA_DIR + '/minimal.pdf')
MINIMAL_ONE_FIELD = read_all(PDF_DATA_DIR + '/minimal-with-field.pdf')
MINIMAL_TWO_FIELDS = read_all(PDF_DATA_DIR + '/minimal-two-fields.pdf')

# user/owner passwords are 'usersecret' and 'ownersecret' respectively
MINIMAL_RC4 = read_all(PDF_DATA_DIR + '/minimal-rc4.pdf')
MINIMAL_ONE_FIELD_RC4 = read_all(PDF_DATA_DIR + '/minimal-with-field-rc4.pdf')


def simple_page(pdf_out, ascii_text, compress=False):
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
    stream = generic.StreamObject(
        stream_data=f'BT /F1 18 Tf 0 0 Td ({ascii_text}) Tj ET'.encode('ascii')
    )
    if compress:
        stream.compress()
    return writer.PageObject(
        contents=pdf_out.add_object(stream), media_box=media_box,
        resources=resources
    )
