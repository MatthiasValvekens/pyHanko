import getpass
from typing import Optional

import click

from pyhanko.cli._ctx import CLIContext
from pyhanko.cli._trust import grab_certs
from pyhanko.cli.commands.signing.utils import (
    _open_for_signing,
    detached_sig,
    generic_sign_pdf,
    get_text_params,
)
from pyhanko.cli.config import CLIConfig
from pyhanko.cli.runtime import pyhanko_exception_manager
from pyhanko.cli.utils import _warn_empty_passphrase, logger, readable_file
from pyhanko.config.errors import ConfigurationError
from pyhanko.config.local_keys import (
    PemDerSignatureConfig,
    PKCS12SignatureConfig,
)
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_cms import (
    signer_from_p12_config,
    signer_from_pemder_config,
)
from pyhanko.sign.timestamps import HTTPTimeStamper


def addsig_simple_signer(
    signer: signers.SimpleSigner,
    infile_path,
    outfile,
    timestamp_url,
    signature_meta,
    existing_fields_only,
    style,
    text_params,
    new_field_spec,
    lenient,
):
    with pyhanko_exception_manager():
        if timestamp_url is not None:
            timestamper = HTTPTimeStamper(timestamp_url)
        else:
            timestamper = None
        writer = _open_for_signing(
            infile_path,
            signer_cert=signer.signing_cert,
            signer_key=signer.signing_key,
            lenient=lenient,
        )

        generic_sign_pdf(
            writer=writer,
            outfile=outfile,
            signature_meta=signature_meta,
            signer=signer,
            timestamper=timestamper,
            style=style,
            new_field_spec=new_field_spec,
            existing_fields_only=existing_fields_only,
            text_params=text_params,
        )


@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option(
    '--key',
    help='file containing the private key (PEM/DER)',
    type=readable_file,
    required=False,
)
@click.option(
    '--cert',
    help='file containing the signer\'s certificate ' '(PEM/DER)',
    type=readable_file,
    required=False,
)
@click.option(
    '--chain',
    type=readable_file,
    multiple=True,
    help='file(s) containing the chain of trust for the '
    'signer\'s certificate (PEM/DER). May be '
    'passed multiple times.',
)
@click.option(
    '--pemder-setup',
    type=str,
    required=False,
    help='name of preconfigured PEM/DER profile (overrides all '
    'other options)',
)
# TODO allow reading the passphrase from a specific file descriptor
#  (for advanced scripting setups)
@click.option(
    '--passfile',
    help='file containing the passphrase ' 'for the private key',
    required=False,
    type=click.File('r'),
    show_default='stdin',
)
@click.option(
    '--no-pass',
    help='assume the private key file is unencrypted',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def addsig_pemder(
    ctx: click.Context,
    infile,
    outfile,
    key,
    cert,
    chain,
    pemder_setup,
    passfile,
    no_pass,
):
    ctx_obj: CLIContext = ctx.obj
    signature_meta = ctx_obj.sig_settings
    existing_fields_only = ctx_obj.existing_fields_only
    timestamp_url = ctx_obj.timestamp_url

    if pemder_setup:
        cli_config: Optional[CLIConfig] = ctx_obj.config
        if cli_config is None:
            raise click.ClickException(
                "The --pemder-setup option requires a configuration file"
            )
        try:
            pemder_config = cli_config.get_pemder_config(pemder_setup)
        except ConfigurationError as e:
            msg = f"Error while reading PEM/DER setup {pemder_setup}"
            logger.error(msg, exc_info=e)
            raise click.ClickException(msg)
    elif not (key and cert):
        raise click.ClickException(
            "Either both the --key and --cert options, or the --pemder-setup "
            "option must be provided."
        )
    else:
        pemder_config = PemDerSignatureConfig(
            key_file=key,
            cert_file=cert,
            other_certs=grab_certs(chain),
            prefer_pss=ctx_obj.prefer_pss,
        )

    if pemder_config.key_passphrase is not None:
        passphrase = pemder_config.key_passphrase
    elif passfile is not None:
        passphrase = passfile.readline().strip().encode('utf-8')
        passfile.close()
    elif pemder_config.prompt_passphrase and not no_pass:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
        if not passphrase:
            _warn_empty_passphrase()
    else:
        passphrase = None

    signer = signer_from_pemder_config(
        pemder_config, provided_key_passphrase=passphrase
    )
    if ctx_obj.sig_settings is None:
        detached_sig(
            signer,
            infile,
            outfile,
            timestamp_url=timestamp_url,
            use_pem=ctx_obj.detach_pem,
        )
    addsig_simple_signer(
        signer,
        infile,
        outfile,
        timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only,
        style=ctx_obj.stamp_style,
        text_params=get_text_params(ctx),
        new_field_spec=ctx_obj.new_field_spec,
        lenient=ctx_obj.lenient,
    )


@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.argument('pfx', type=readable_file, required=False)
@click.option(
    '--p12-setup',
    type=str,
    required=False,
    help='name of preconfigured PKCS#12 profile (overrides all '
    'other options)',
)
@click.option(
    '--chain',
    type=readable_file,
    multiple=True,
    help='PEM/DER file(s) containing extra certificates to embed '
    '(e.g. chain of trust not embedded in the PKCS#12 file)'
    'May be passed multiple times.',
)
@click.option(
    '--passfile',
    help='file containing the passphrase ' 'for the PKCS#12 file.',
    required=False,
    type=click.File('r'),
    show_default='stdin',
)
@click.pass_context
def addsig_pkcs12(
    ctx: click.Context, infile, outfile, pfx, chain, passfile, p12_setup
):
    # TODO add sanity check in case the user gets the arg order wrong
    #  (now it fails with a gnarly DER decoding error, which is not very
    #  user-friendly)
    ctx_obj: CLIContext = ctx.obj
    signature_meta = ctx_obj.sig_settings
    existing_fields_only = ctx_obj.existing_fields_only
    timestamp_url = ctx_obj.timestamp_url

    if p12_setup:
        cli_config: Optional[CLIConfig] = ctx_obj.config
        if cli_config is None:
            raise click.ClickException(
                "The --p12-setup option requires a configuration file"
            )
        try:
            pkcs12_config = cli_config.get_pkcs12_config(p12_setup)
        except ConfigurationError as e:
            msg = f"Error while reading PKCS#12 config {p12_setup}"
            logger.error(msg, exc_info=e)
            raise click.ClickException(msg)
    elif not pfx:
        raise click.ClickException(
            "Either the PFX argument or the --p12-setup option "
            "must be provided."
        )
    else:
        pkcs12_config = PKCS12SignatureConfig(
            pfx_file=pfx,
            other_certs=grab_certs(chain),
            prefer_pss=ctx_obj.prefer_pss,
        )

    if pkcs12_config.pfx_passphrase is not None:
        passphrase = pkcs12_config.pfx_passphrase
    elif passfile is not None:
        passphrase = passfile.readline().strip().encode('utf-8')
        passfile.close()
    elif pkcs12_config.prompt_passphrase:
        passphrase = getpass.getpass(prompt='PKCS#12 passphrase: ').encode(
            'utf-8'
        )
    else:
        passphrase = None

    signer = signer_from_p12_config(
        pkcs12_config, provided_pfx_passphrase=passphrase
    )
    if ctx_obj.sig_settings is None:
        detached_sig(
            signer,
            infile,
            outfile,
            timestamp_url=timestamp_url,
            use_pem=ctx_obj.detach_pem,
        )
    addsig_simple_signer(
        signer,
        infile,
        outfile,
        timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only,
        style=ctx_obj.stamp_style,
        text_params=get_text_params(ctx),
        new_field_spec=ctx_obj.new_field_spec,
        lenient=ctx_obj.lenient,
    )
