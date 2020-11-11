from datetime import timedelta

import click
import logging
import getpass

from certvalidator import ValidationContext

from pdfstamp.sign import signers
from pdfstamp.sign.timestamps import HTTPTimeStamper
from pdfstamp.sign import validation, beid, fields
from pdf_utils.reader import PdfFileReader
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdfstamp.sign.validation import SignatureValidationError

__all__ = ['cli']

# noinspection PyTypeChecker
root_logger = logging.getLogger(None)
root_logger.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
sh.setFormatter(formatter)
root_logger.addHandler(sh)


# group everything under this entry point for easy exporting
@click.group()
def cli():
    pass


@cli.group(help='sign PDF files', name='sign')
def signing():
    pass


readable_file = click.Path(exists=True, readable=True, dir_okay=False)


def init_validation_context_kwargs(trust, trust_replace, other_certs,
                                   allow_fetching=None):
    vc_kwargs = {'time_tolerance': timedelta(seconds=10)}
    if allow_fetching is not None:
        vc_kwargs['allow_fetching'] = allow_fetching
    if trust:
        # add trust roots to the validation context, or replace them
        trust_certs = list(
            signers.load_ca_chain(trust)
        )
        if trust_replace:
            vc_kwargs['trust_roots'] = trust_certs
        else:
            vc_kwargs['extra_trust_roots'] = trust_certs
    if other_certs:
        vc_kwargs['other_certs'] = list(signers.load_ca_chain(other_certs))
    return vc_kwargs


# TODO add an option to do LTV, but guess the profile
@signing.command(name='list', help='list signature fields')
@click.argument('infile', type=click.File('rb'))
@click.option('--skip-status', help='do not print status', required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--validate', help='validate signatures', required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--executive-summary',
              help='only print final judgment on signature validity',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--trust-replace',
              help='listed trust roots supersede OS-provided trust store',
              required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--trust', help='list trust roots (multiple allowed)',
              required=False, multiple=True, type=readable_file)
@click.option('--other-certs',
              help='other certs relevant for validation',
              required=False, multiple=True, type=readable_file)
@click.option('--ltv-profile',
              help='LTV signature validation profile',
              type=click.Choice(('pades', 'adobe')), required=False)
@click.option('--ltv-obsessive',
              help='Fail trust validation if a certificate has no known CRL '
                   'or OCSP endpoints.',
              type=bool, is_flag=True, default=False, show_default=True)
def list_sigfields(infile, skip_status, validate, executive_summary, trust,
                   trust_replace, other_certs, ltv_profile, ltv_obsessive):
    r = PdfFileReader(infile)
    if validate and ltv_profile is not None:
        if ltv_profile == 'pades':
            ltv_profile = validation.RevocationInfoValidationType.PADES_LT
        else:
            ltv_profile = validation.RevocationInfoValidationType.ADOBE_STYLE
    vc_kwargs = init_validation_context_kwargs(
        trust, trust_replace, other_certs
    )
    for name, value, field_ref in fields.enumerate_sig_fields(r):
        if skip_status:
            print(name)
            continue
        status_str = 'EMPTY'
        if value is not None:
            if validate:
                try:
                    if ltv_profile is None:
                        vc = ValidationContext(**vc_kwargs)
                        status = validation.validate_pdf_signature(
                            r, field_ref, signer_validation_context=vc
                        )
                    else:
                        status = validation.validate_pdf_ltv_signature(
                            r, field_ref, ltv_profile,
                            force_revinfo=ltv_obsessive,
                            validation_context_kwargs=vc_kwargs
                        )
                    if executive_summary:
                        status_str = (
                            'VALID' if status.bottom_line else 'INVALID'
                        )
                    else:
                        status_str = status.summary()
                except SignatureValidationError:
                    status_str = 'INVALID'
                except ValueError:
                    status_str = 'MALFORMED'
            else:
                status_str = 'FILLED'
        print('%s:%s' % (name, status_str))


SIG_META = 'SIG_META'
EXISTING_ONLY = 'EXISTING_ONLY'
TIMESTAMP_URL = 'TIMESTAMP_URL'


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
@click.option('--use-pades', help='sign PAdES-style [level B/B-T/B-LT]',
              required=False, default=False, is_flag=True, type=bool,
              show_default=True)
@click.option('--with-validation-info', help='embed revocation info',
              required=False, default=False, is_flag=True, type=bool,
              show_default=True)
@click.option('--trust-replace',
              help='listed trust roots supersede OS-provided trust store',
              required=False,
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--trust', help='list trust roots (multiple allowed)',
              required=False, multiple=True, type=readable_file)
@click.option('--other-certs',
              help='other certs relevant for validation',
              required=False, multiple=True, type=readable_file)
@click.pass_context
def addsig(ctx, field, name, reason, location, certify, existing_only,
           timestamp_url, use_pades, with_validation_info, trust_replace, trust,
           other_certs):
    ctx.ensure_object(dict)
    ctx.obj[EXISTING_ONLY] = existing_only or field is None
    ctx.obj[TIMESTAMP_URL] = timestamp_url

    if use_pades:
        subfilter = fields.SigSeedSubFilter.PADES
    else:
        subfilter = fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED

    if with_validation_info:
        vc_kwargs = init_validation_context_kwargs(
            trust, trust_replace, other_certs, allow_fetching=True
        )
        vc = ValidationContext(**vc_kwargs)
    else:
        vc = None
    ctx.obj[SIG_META] = signers.PdfSignatureMetadata(
        field_name=field, location=location, reason=reason, name=name,
        certify=certify, subfilter=subfilter,
        embed_validation_info=with_validation_info,
        validation_context=vc
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
            prompt='Password for encrypted file: '
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
    signer = beid.BEIDSigner(
        session, label, timestamper=timestamper
    )

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
