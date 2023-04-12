import click
from pyhanko_certvalidator import ValidationContext

from pyhanko import __version__
from pyhanko.cli._ctx import CLIContext
from pyhanko.cli._root import cli_root
from pyhanko.cli._trust import (
    _build_vc_kwargs,
    _get_key_usage_settings,
    trust_options,
)
from pyhanko.cli.commands.signing.pkcs11_cli import process_pkcs11_commands
from pyhanko.cli.commands.signing.simple import addsig_pemder, addsig_pkcs12
from pyhanko.cli.commands.stamp import select_style
from pyhanko.cli.utils import parse_field_location_spec
from pyhanko.sign import DEFAULT_SIGNER_KEY_USAGE, fields, signers
from pyhanko.sign.signers.pdf_byterange import BuildProps

__all__ = ['signing']


@cli_root.group(help='sign PDFs and other files', name='sign')
def signing():
    pass


@signing.group(name='addsig', help='add a signature')
@click.option('--field', help='name of the signature field', required=False)
@click.option('--name', help='explicitly specify signer name', required=False)
@click.option('--reason', help='reason for signing', required=False)
@click.option('--location', help='location of signing', required=False)
@click.option(
    '--certify',
    help='add certification signature',
    required=False,
    default=False,
    is_flag=True,
    type=bool,
    show_default=True,
)
@click.option(
    '--existing-only',
    help='never create signature fields',
    required=False,
    default=False,
    is_flag=True,
    type=bool,
    show_default=True,
)
@click.option(
    '--timestamp-url',
    help='URL for timestamp server',
    required=False,
    type=str,
    default=None,
)
@click.option(
    '--use-pades',
    help='sign PAdES-style [level B/B-T/B-LT/B-LTA]',
    required=False,
    default=False,
    is_flag=True,
    type=bool,
    show_default=True,
)
@click.option(
    '--use-pades-lta',
    help='produce PAdES-B-LTA signature',
    required=False,
    default=False,
    is_flag=True,
    type=bool,
    show_default=True,
)
@click.option(
    '--prefer-pss',
    is_flag=True,
    default=False,
    type=bool,
    help='prefer RSASSA-PSS to PKCS#1 v1.5 padding, if available',
)
@click.option(
    '--with-validation-info',
    help='embed revocation info',
    required=False,
    default=False,
    is_flag=True,
    type=bool,
    show_default=True,
)
@click.option(
    '--style-name',
    help='stamp style name for signature appearance',
    required=False,
    type=str,
)
@click.option(
    '--stamp-url',
    help='QR code URL to use in QR stamp style',
    required=False,
    type=str,
)
@trust_options
@click.option(
    '--detach',
    type=bool,
    is_flag=True,
    default=False,
    help=(
        'write only the signature CMS object to the output file; '
        'this can be used to sign non-PDF files'
    ),
)
@click.option(
    '--detach-pem',
    help='output PEM data instead of DER when using --detach',
    type=bool,
    is_flag=True,
    default=False,
)
@click.option(
    '--retroactive-revinfo',
    help='Treat revocation info as retroactively valid '
    '(i.e. ignore thisUpdate timestamp)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--no-strict-syntax',
    help='Attempt to ignore syntactical problems in the input file '
    'and enable signature creation in hybrid-reference files.'
    '(warning: such documents may behave in unexpected ways)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def addsig(
    ctx: click.Context,
    field,
    name,
    reason,
    location,
    certify,
    existing_only,
    timestamp_url,
    use_pades,
    use_pades_lta,
    with_validation_info,
    validation_context,
    trust_replace,
    trust,
    other_certs,
    style_name,
    stamp_url,
    prefer_pss,
    retroactive_revinfo,
    detach,
    detach_pem,
    no_strict_syntax,
):
    ctx_obj: CLIContext = ctx.obj
    ctx_obj.existing_fields_only = existing_only or field is None
    ctx_obj.timestamp_url = timestamp_url
    ctx_obj.prefer_pss = prefer_pss

    if detach:
        ctx_obj.detach_pem = detach_pem
        ctx_obj.sig_settings = None
        return  # everything else doesn't apply

    if use_pades_lta:
        use_pades = with_validation_info = True
        if not timestamp_url:
            raise click.ClickException(
                "--timestamp-url is required for --use-pades-lta"
            )
    if use_pades:
        subfilter = fields.SigSeedSubFilter.PADES
    else:
        subfilter = fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED

    key_usage = DEFAULT_SIGNER_KEY_USAGE
    if with_validation_info:
        vc_kwargs = _build_vc_kwargs(
            ctx,
            validation_context,
            trust,
            trust_replace,
            other_certs,
            retroactive_revinfo,
            allow_fetching=True,
        )
        vc = ValidationContext(**vc_kwargs)
        key_usage_sett = _get_key_usage_settings(ctx, validation_context)
        if key_usage_sett is not None and key_usage_sett.key_usage is not None:
            key_usage = key_usage_sett.key_usage
    else:
        vc = None
    field_name, new_field_spec = parse_field_location_spec(
        field, require_full_spec=False
    )
    ctx_obj.sig_settings = signers.PdfSignatureMetadata(
        field_name=field_name,
        location=location,
        reason=reason,
        name=name,
        certify=certify,
        subfilter=subfilter,
        embed_validation_info=with_validation_info,
        validation_context=vc,
        signer_key_usage=key_usage,
        use_pades_lta=use_pades_lta,
        app_build_props=BuildProps(name='pyHanko CLI', revision=__version__),
    )
    ctx_obj.new_field_spec = new_field_spec
    ctx_obj.stamp_style = select_style(ctx, style_name, stamp_url)
    ctx_obj.stamp_url = stamp_url
    ctx_obj.lenient = no_strict_syntax


def _register():
    addsig.command(name='pemder', help='read key material from PEM/DER files')(
        addsig_pemder
    )
    addsig.command(name='pkcs12', help='read key material from a PKCS#12 file')(
        addsig_pkcs12
    )
    process_pkcs11_commands(addsig)


_register()
