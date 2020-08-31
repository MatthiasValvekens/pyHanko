import click
import getpass

from certvalidator import ValidationContext

from pdfstamp.sign import signers
from pdfstamp.sign.timestamps import HTTPTimeStamper
from pdfstamp.sign import validation, beid, fields
from pdf_utils.reader import PdfFileReader
from pdf_utils.incremental_writer import IncrementalPdfFileWriter

__all__ = ['cli']


# group everything under this entry point for easy exporting
@click.group()
def cli():
    pass


@cli.group(help='sign PDF files', name='sign')
def signing():
    pass


SIG_META = 'SIG_META'
EXISTING_ONLY = 'EXISTING_ONLY'
TIMESTAMP_URL = 'TIMESTAMP_URL'

readable_file = click.Path(exists=True, readable=True, dir_okay=False)


@signing.command(name='list', help='list signature fields')
@click.argument('infile', type=click.File('rb'))
@click.option('--skip-status', help='do not print status', required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--validate', help='validate signatures', required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--trust-replace',
              help='listed trust roots supersede OS-provided trust store',
              required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--trust', help='list trust roots (multiple allowed)',
              required=False, multiple=True, type=readable_file)
def list_sigfields(infile, skip_status, validate, trust, trust_replace):
    r = PdfFileReader(infile)
    for name, value, _ in fields.enumerate_sig_fields(r):
        if skip_status:
            print(name)
            continue
        status = 'EMPTY'
        if value is not None:
            if validate:
                v_context = None
                if trust:
                    # add trust roots to the validation context, or replace them
                    trust_certs = list(
                        signers.load_ca_chain(trust))
                    if trust_replace:
                        v_context = ValidationContext(trust_roots=trust_certs)
                    else:
                        v_context = ValidationContext(
                            extra_trust_roots=trust_certs
                        )
                try:
                    status = validation.validate_pdf_signature(
                        r, value, signer_validation_context=v_context
                    ).summary()
                except ValueError:
                    status = 'MALFORMED'
            else:
                status = 'FILLED'
        print('%s:%s' % (name, status))


@signing.group(name='addsig', help='add a signature')
@click.option('--field', help='name of the signature field', required=False)
@click.option('--name', help='explicitly specify signer name', required=False)
@click.option('--reason', help='reason for signing', required=False)
@click.option('--location', help='location of signing', required=False)
@click.option('--certify', help='add certification signature', required=False, 
              default=False, is_flag=True, type=bool, show_default=True)
@click.option('--existing-only', help='never create signature fields', 
              required=False, default=False, is_flag=True, type=bool, 
              show_default=True)
@click.option('--timestamp-url', help='URL for timestamp server',
              required=False, type=str, default=None)
@click.pass_context
def addsig(ctx, field, name, reason, location, certify, existing_only,
           timestamp_url):
    ctx.ensure_object(dict)
    ctx.obj[EXISTING_ONLY] = existing_only or field is None
    ctx.obj[TIMESTAMP_URL] = timestamp_url
    ctx.obj[SIG_META] = signers.PdfSignatureMetadata(
        field_name=field, location=location, reason=reason, name=name,
        certify=certify
    )


def addsig_simple_signer(signer: signers.SimpleSigner, infile, outfile,
                         timestamp_url, signature_meta, existing_fields_only):
    if timestamp_url is not None:
        signer.timestamper = HTTPTimeStamper(timestamp_url)
    writer = IncrementalPdfFileWriter(infile)

    # TODO make this an option higher up the tree
    # TODO mention filename in prompt
    if writer.prev.encrypted:
        pdf_pass = getpass.getpass(
            prompt=f'Password for encrypted file: '
        ).encode('utf-8')
        writer.encrypt(pdf_pass)

    result = signers.sign_pdf(
        writer, signature_meta, signer,
        existing_fields_only=existing_fields_only
    )
    buf = result.getbuffer()
    outfile.write(buf)
    buf.release()

    infile.close()
    outfile.close()


@addsig.command(name='pemder', help='read key material from PEM/DER files')
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.option('--key', help='file containing the private key (PEM/DER)', 
              type=readable_file, required=True)
@click.option('--cert', help='file containing the signer\'s certificate '
              '(PEM/DER)', type=readable_file, required=True)
@click.option('--chain', type=readable_file, multiple=True,
              help='file(s) containing the chain of trust for the '
                   'signer\'s certificate (PEM/DER). May be '
                   'passed multiple times.')
# TODO allow reading the passphrase from a specific file descriptor
#  (for advanced scripting setups)
@click.option('--passfile', help='file containing the passphrase '
              'for the private key', required=False, type=click.File('rb'),
              show_default='stdin')
@click.pass_context
def addsig_pemder(ctx, infile, outfile, key, cert, chain, passfile):
    signature_meta = ctx.obj[SIG_META]
    existing_fields_only = ctx.obj[EXISTING_ONLY]
    timestamp_url = ctx.obj[TIMESTAMP_URL]

    if passfile is None:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
    else:
        passphrase = passfile.read()
        passfile.close()
    
    signer = signers.SimpleSigner.load(
        cert_file=cert, key_file=key, key_passphrase=passphrase,
        ca_chain_files=chain
    )
    return addsig_simple_signer(
        signer, infile, outfile, timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only
    )


@addsig.command(name='pkcs12', help='read key material from a PKCS#12 file')
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.argument('pfx', type=readable_file)
@click.option('--chain', type=readable_file, multiple=True,
              help='PEM/DER file(s) containing extra certificates to embed '
                   '(e.g. chain of trust not embedded in the PKCS#12 file)'
                   'May be passed multiple times.')
@click.option('--passfile', help='file containing the passphrase '
                                 'for the PKCS#12 file.', required=False,
              type=click.File('rb'),
              show_default='stdin')
@click.pass_context
def addsig_pkcs12(ctx, infile, outfile, pfx, chain, passfile):
    # TODO add sanity check in case the user gets the arg order wrong
    #  (now it fails with a gnarly DER decoding error, which is not very
    #  user-friendly)
    signature_meta = ctx.obj[SIG_META]
    existing_fields_only = ctx.obj[EXISTING_ONLY]
    timestamp_url = ctx.obj[TIMESTAMP_URL]

    if passfile is None:
        passphrase = getpass.getpass(prompt='Export passphrase: ')\
                        .encode('utf-8')
    else:
        passphrase = passfile.read()
        passfile.close()

    signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=pfx, passphrase=passphrase, ca_chain_files=chain
    )
    return addsig_simple_signer(
        signer, infile, outfile, timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only
    )


@addsig.command(name='beid', help='use Belgian eID to sign')
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.option('--lib', help='path to libbeidpkcs11 library file',
              type=readable_file, required=True)
@click.option('--use-auth-cert', type=bool, show_default=True,
              default=False, required=False, is_flag=True,
              help='use Authentication cert instead')
@click.option('--slot-no', help='specify PKCS#11 slot to use', 
              required=False, type=int, default=None)
@click.pass_context
def addsig_beid(ctx, infile, outfile, lib, use_auth_cert, slot_no):
    signature_meta = ctx.obj[SIG_META]
    existing_fields_only = ctx.obj[EXISTING_ONLY]
    timestamp_url = ctx.obj[TIMESTAMP_URL]
    session = beid.open_beid_session(lib, slot_no=slot_no)
    label = 'Authentication' if use_auth_cert else 'Signature'
    if timestamp_url is not None:
        timestamper = HTTPTimeStamper(timestamp_url)
    else:
        timestamper = None
    signer = beid.BEIDSigner(session, label, timestamper=timestamper)

    result = signers.sign_pdf(
        IncrementalPdfFileWriter(infile), signature_meta, signer,
        existing_fields_only=existing_fields_only
    )
    buf = result.getbuffer()
    outfile.write(buf)
    buf.release()

    infile.close()
    outfile.close()


@signing.command(name='addfields')
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.argument('specs', metavar='PAGE/X1,Y1,X2,Y2/NAME [...]', nargs=-1)
def add_sig_field(infile, outfile, specs):
    def _parse_specs():
        for spec in specs:
            try:
                page, box, name = spec.split('/')
            except ValueError:
                raise click.ClickException(
                    "Sig field should be of the form PAGE/X1,Y1,X2,Y2/NAME."
                )
            try:
                page_ix = int(page) - 1
                if page_ix < 0:
                    raise ValueError
            except ValueError:
                raise click.ClickException(
                    "Sig field parameter PAGE should be a nonnegative integer, "
                    "not %s." % page
                )
            try:
                x1, y1, x2, y2 = map(int, box.split(','))
            except ValueError:
                raise click.ClickException(
                    "Sig field parameters X1,Y1,X2,Y2 should be four integers."
                )
            yield fields.SigFieldSpec(
                sig_field_name=name, on_page=page_ix, box=(x1, y1, x2, y2)
            )

    writer = IncrementalPdfFileWriter(infile)
    fields.append_signature_fields(writer, list(_parse_specs()))
    writer.write(outfile)
    infile.close()
    outfile.close()
