import getpass
import os
from typing import Optional

import click

from pyhanko.cli._ctx import CLIContext
from pyhanko.cli.commands.signing.utils import (
    _open_for_signing,
    detached_sig,
    generic_sign_pdf,
    get_text_params,
)
from pyhanko.cli.config import CLIConfig
from pyhanko.cli.runtime import pyhanko_exception_manager
from pyhanko.cli.utils import logger, readable_file
from pyhanko.config.errors import ConfigurationError
from pyhanko.config.pkcs11 import (
    PKCS11PinEntryMode,
    PKCS11SignatureConfig,
    TokenCriteria,
)
from pyhanko.sign.timestamps import HTTPTimeStamper

try:
    import pkcs11  # lgtm [py/unused-import]

    pkcs11_available = True
except ImportError:
    pkcs11 = None
    pkcs11_available = False


P11_PIN_ENV_VAR = "PYHANKO_PKCS11_PIN"


def _sign_pkcs11(ctx: click.Context, signer, infile, outfile, timestamp_url):
    ctx_obj: CLIContext = ctx.obj
    with pyhanko_exception_manager():
        if ctx_obj.sig_settings is None:
            return detached_sig(
                signer,
                infile,
                outfile,
                timestamp_url=timestamp_url,
                use_pem=ctx_obj.detach_pem,
            )

        if timestamp_url is not None:
            timestamper = HTTPTimeStamper(timestamp_url)
        else:
            timestamper = None

        generic_sign_pdf(
            writer=_open_for_signing(infile, ctx_obj.lenient),
            outfile=outfile,
            signature_meta=ctx_obj.sig_settings,
            signer=signer,
            timestamper=timestamper,
            style=ctx_obj.stamp_style,
            new_field_spec=ctx_obj.new_field_spec,
            existing_fields_only=ctx_obj.existing_fields_only,
            text_params=get_text_params(ctx),
        )


@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option(
    '--lib', help='path to PKCS#11 module', type=readable_file, required=False
)
@click.option(
    '--token-label', help='PKCS#11 token label', type=str, required=False
)
@click.option(
    '--cert-label', help='certificate label', type=str, required=False
)
@click.option(
    '--raw-mechanism',
    help='invoke raw PKCS#11 mechanism',
    type=bool,
    is_flag=True,
    required=False,
)
@click.option('--key-label', help='key label', type=str, required=False)
@click.option(
    '--slot-no',
    help='specify PKCS#11 slot to use',
    required=False,
    type=int,
    default=None,
)
@click.option(
    '--skip-user-pin',
    type=bool,
    show_default=True,
    default=False,
    required=False,
    is_flag=True,
    help='do not prompt for PIN (e.g. if the token has a PIN pad)',
)
@click.option(
    '--p11-setup',
    type=str,
    required=False,
    help='name of preconfigured PKCS#11 profile (overrides all '
    'other options)',
)
@click.pass_context
def addsig_pkcs11(
    ctx: click.Context,
    infile,
    outfile,
    lib,
    token_label,
    cert_label,
    key_label,
    slot_no,
    skip_user_pin,
    p11_setup,
    raw_mechanism,
):
    from pyhanko.sign import pkcs11

    ctx_obj: CLIContext = ctx.obj
    timestamp_url = ctx_obj.timestamp_url

    if p11_setup:
        cli_config: Optional[CLIConfig] = ctx_obj.config
        if cli_config is None:
            raise click.ClickException(
                "The --p11-setup option requires a configuration file"
            )
        try:
            pkcs11_config = cli_config.get_pkcs11_config(p11_setup)
        except ConfigurationError as e:
            msg = f"Error while reading PKCS#11 config {p11_setup}"
            logger.error(msg, exc_info=e)
            raise click.ClickException(msg)
    else:
        if not (lib and cert_label):
            raise click.ClickException(
                "The parameters --lib and --cert-label are required."
            )

        pinentry_mode = (
            PKCS11PinEntryMode.SKIP
            if skip_user_pin
            else PKCS11PinEntryMode.PROMPT
        )

        pkcs11_config = PKCS11SignatureConfig(
            module_path=lib,
            cert_label=cert_label,
            key_label=key_label,
            slot_no=slot_no,
            token_criteria=TokenCriteria(token_label),
            # for now, DEFER requires a config file
            prompt_pin=pinentry_mode,
            raw_mechanism=raw_mechanism,
        )

    pin = pkcs11_config.user_pin

    # try to fetch the PIN from an env var
    if pin is None:
        pin_env = os.environ.get(P11_PIN_ENV_VAR, None)
        if pin_env:
            pin = pin_env.strip()

    if (
        pkcs11_config.prompt_pin == PKCS11PinEntryMode.PROMPT and pin is None
    ):  # pragma: nocover
        pin = getpass.getpass(prompt='PKCS#11 user PIN: ')
    try:
        with pkcs11.PKCS11SigningContext(pkcs11_config, user_pin=pin) as signer:
            _sign_pkcs11(ctx, signer, infile, outfile, timestamp_url)
    except pkcs11.PKCS11Error as e:
        # This will catch errors that happen during PKCS#11 setup
        # TODO make sure PKCS11Signer doesn't leak PCKS11Errors in its
        #  generic signing API
        logger.error("PKCS#11 error", exc_info=e)
        raise click.ClickException(f"PKCS#11 error: [{type(e).__name__}] {e}")


@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option(
    '--lib',
    help='path to libbeidpkcs11 library file',
    type=readable_file,
    required=False,
)
@click.option(
    '--use-auth-cert',
    type=bool,
    show_default=True,
    default=False,
    required=False,
    is_flag=True,
    help='use Authentication cert instead',
)
@click.option(
    '--slot-no',
    help='specify PKCS#11 slot to use',
    required=False,
    type=int,
    default=None,
)
@click.pass_context
def addsig_beid(
    ctx: click.Context, infile, outfile, lib, use_auth_cert, slot_no
):
    import pkcs11

    from pyhanko.sign import beid

    ctx_obj: CLIContext = ctx.obj
    if not lib:
        cli_config: Optional[CLIConfig] = ctx_obj.config
        if cli_config is None or cli_config.beid_module_path is None:
            raise click.ClickException(
                "The --lib option is mandatory unless beid-module-path is "
                "provided in the configuration file."
            )
        lib = cli_config.beid_module_path

    timestamp_url = ctx_obj.timestamp_url

    try:
        session = beid.open_beid_session(lib, slot_no=slot_no)
    except pkcs11.PKCS11Error as e:
        logger.error("PKCS#11 error", exc_info=e)
        raise click.ClickException(f"PKCS#11 error: [{type(e).__name__}] {e}")
    with session:
        signer = beid.BEIDSigner(session, use_auth_cert=use_auth_cert)
        _sign_pkcs11(ctx, signer, infile, outfile, timestamp_url)


def _pkcs11_cmd(name, hlp, fun, *, group):
    group.command(name=name, help=hlp)(fun)


def process_pkcs11_commands(group):
    if pkcs11_available:
        for args in PKCS11_COMMANDS:
            _pkcs11_cmd(*args, group=group)
    else:

        def _unavailable():
            raise click.ClickException(
                "This subcommand requires python-pkcs11 to be installed."
            )

        for name, hlp, fun in PKCS11_COMMANDS:
            _pkcs11_cmd(
                name, hlp + ' [dependencies missing]', _unavailable, group=group
            )


PKCS11_COMMANDS = [
    ('pkcs11', 'use generic PKCS#11 device to sign', addsig_pkcs11),
    ('beid', 'use Belgian eID to sign', addsig_beid),
]
