from io import BytesIO

import pytest
from pyhanko.cli import cli_root
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfSignatureMetadata, sign_pdf
from test_data.samples import MINIMAL, MINIMAL_TWO_FIELDS, MINIMAL_TWO_PAGES
from test_utils.signing_commons import FROM_CA

from .conftest import INPUT_PATH


def test_list_empty_fields_with_status(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_TWO_FIELDS)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'list',
            INPUT_PATH,
        ],
    )

    assert not result.exception, result.output
    assert result.output == 'Sig1:EMPTY\nSig2:EMPTY\n'


def test_list_mixed_fields_with_status(cli_runner):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    with open(INPUT_PATH, 'wb') as inf:
        sign_pdf(
            w,
            signature_meta=PdfSignatureMetadata(field_name="Sig1"),
            signer=FROM_CA,
            output=inf,
        )

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'list',
            INPUT_PATH,
        ],
    )

    assert not result.exception, result.output
    assert result.output == 'Sig1:FILLED\nSig2:EMPTY\n'


def test_list_empty_fields_without_status(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_TWO_FIELDS)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'list',
            '--skip-status',
            INPUT_PATH,
        ],
    )

    assert not result.exception, result.output
    assert result.output == 'Sig1\nSig2\n'


def test_cli_add_field_incremental_update_by_default(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL)

    output_path = 'presign.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            '--field',
            '1/0,0,100,100/Sig1',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output

    with open(output_path, 'rb') as inf:
        r = PdfFileReader(inf)
        name = r.root['/AcroForm']['/Fields'][0]['/T']
        assert name == 'Sig1'
        assert r.xrefs.total_revisions == 2


def test_cli_add_field_with_resave(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL)

    output_path = 'presign.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            '--resave',
            '--field',
            '1/0,0,100,100/Sig1',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output

    with open(output_path, 'rb') as inf:
        r = PdfFileReader(inf)
        name = r.root['/AcroForm']['/Fields'][0]['/T']
        assert name == 'Sig1'
        assert r.xrefs.total_revisions == 1


def test_cli_add_field_to_last_page(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_TWO_PAGES)

    output_path = 'presign.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            '--field',
            '-1/0,0,100,100/Sig1',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output

    with open(output_path, 'rb') as inf:
        r = PdfFileReader(inf)
        second_page = r.root['/Pages']['/Kids'][1].container_ref
        field_pointer = r.root['/AcroForm']['/Fields'][0]['/P'].container_ref
        assert second_page.idnum == field_pointer.idnum


@pytest.mark.parametrize(
    'field_spec,expected_error_msg',
    [
        ('0/0,0,100,100/Sig1', "nonzero integer"),
        ('zzz/0,0,100,100/Sig1', "nonzero integer"),
        ('Sig1', "should be of the form"),
        ('1/0,z,100,100/Sig1', "should be four integers"),
    ],
)
def test_cli_field_spec_errors(cli_runner, field_spec, expected_error_msg):
    output_path = 'presign.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            '--field',
            field_spec,
            INPUT_PATH,
            output_path,
        ],
    )
    assert result.exit_code == 1, result.output
    assert expected_error_msg in result.output
