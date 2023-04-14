import click

from pyhanko.cli.commands.signing import signing
from pyhanko.cli.runtime import pyhanko_exception_manager
from pyhanko.cli.utils import parse_field_location_spec
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields

__all__ = ['list_sigfields', 'add_sig_field']


@signing.command(name='list', help='list signature fields')
@click.argument('infile', type=click.File('rb'))
@click.option(
    '--skip-status',
    help='do not print status',
    required=False,
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
def list_sigfields(infile, skip_status):
    with pyhanko_exception_manager():
        r = PdfFileReader(infile)
        field_info = fields.enumerate_sig_fields(r)
        for ix, (name, value, field_ref) in enumerate(field_info):
            if skip_status:
                print(name)
                continue
            print(f"{name}:{'EMPTY' if value is None else 'FILLED'}")


@signing.command(
    name='addfields', help='add empty signature fields to a PDF field'
)
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.option(
    '--field', metavar='PAGE/X1,Y1,X2,Y2/NAME', multiple=True, required=True
)
def add_sig_field(infile, outfile, field):
    with pyhanko_exception_manager():
        writer = IncrementalPdfFileWriter(infile)

        for s in field:
            name, spec = parse_field_location_spec(s)
            assert spec is not None
            fields.append_signature_field(writer, spec)

        writer.write(outfile)
        infile.close()
        outfile.close()