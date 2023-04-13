import contextlib
import getpass
import os
from typing import ContextManager, List, Optional

import click

from pyhanko.cli._ctx import CLIContext
from pyhanko.cli.commands.signing.plugin import (
    SigningCommandPlugin,
    register_plugin,
)
from pyhanko.cli.config import CLIConfig
from pyhanko.cli.utils import logger, readable_file
from pyhanko.config.errors import ConfigurationError
from pyhanko.config.pkcs11 import (
    PKCS11PinEntryMode,
    PKCS11SignatureConfig,
    TokenCriteria,
)
from pyhanko.sign import Signer

__all__ = ['PKCS11Plugin', 'BEIDPlugin']


try:
    import pkcs11  # lgtm [py/unused-import]

    pkcs11_available = True
except ImportError:
    pkcs11 = None
    pkcs11_available = False


P11_PIN_ENV_VAR = "PYHANKO_PKCS11_PIN"
UNAVAIL_MSG = "This subcommand requires python-pkcs11 to be installed."


@register_plugin
class PKCS11Plugin(SigningCommandPlugin):
    subcommand_name = 'pkcs11'
    help_summary = 'use generic PKCS#11 device to sign'
    unavailable_message = UNAVAIL_MSG

    def is_available(self) -> bool:
        return pkcs11_available

    def click_options(self) -> List[click.Option]:
        return [
            click.Option(
                ('--lib',),
                help='path to PKCS#11 module',
                type=readable_file,
                required=False,
            ),
            click.Option(
                ('--token-label',),
                help='PKCS#11 token label',
                type=str,
                required=False,
            ),
            click.Option(
                ('--cert-label',),
                help='certificate label',
                type=str,
                required=False,
            ),
            click.Option(
                ('--raw-mechanism',),
                help='invoke raw PKCS#11 mechanism',
                type=bool,
                is_flag=True,
                required=False,
            ),
            click.Option(
                ('--key-label',), help='key label', type=str, required=False
            ),
            click.Option(
                ('--slot-no',),
                help='specify PKCS#11 slot to use',
                required=False,
                type=int,
                default=None,
            ),
            click.Option(
                ('--skip-user-pin',),
                type=bool,
                show_default=True,
                default=False,
                required=False,
                is_flag=True,
                help='do not prompt for PIN (e.g. if the token has a PIN pad)',
            ),
            click.Option(
                ('--p11-setup',),
                type=str,
                required=False,
                help='name of preconfigured PKCS#11 profile (overrides all '
                'other options)',
            ),
        ]

    def create_signer(
        self, context: CLIContext, **kwargs
    ) -> ContextManager[Signer]:
        return _pkcs11_signer_context(context, **kwargs)


def _pkcs11_signer_context(
    ctx: CLIContext,
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

    if p11_setup:
        cli_config: Optional[CLIConfig] = ctx.config
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
    return pkcs11.PKCS11SigningContext(pkcs11_config, user_pin=pin)


@register_plugin
class BEIDPlugin(SigningCommandPlugin):
    subcommand_name = 'beid'
    help_summary = 'use Belgian eID to sign'
    unavailable_message = UNAVAIL_MSG

    def is_available(self) -> bool:
        return pkcs11_available

    def click_options(self) -> List[click.Option]:
        return [
            click.Option(
                ('--lib',),
                help='path to libbeidpkcs11 library file',
                type=readable_file,
                required=False,
            ),
            click.Option(
                ('--use-auth-cert',),
                type=bool,
                show_default=True,
                default=False,
                required=False,
                is_flag=True,
                help='use Authentication cert instead',
            ),
            click.Option(
                ('--slot-no',),
                help='specify PKCS#11 slot to use',
                required=False,
                type=int,
                default=None,
            ),
        ]

    def create_signer(
        self, context: CLIContext, **kwargs
    ) -> ContextManager[Signer]:
        return _beid_signer_context(context, **kwargs)


def _beid_signer_context(ctx: CLIContext, lib, use_auth_cert, slot_no):
    import pkcs11

    from pyhanko.sign import beid

    if not lib:
        cli_config: Optional[CLIConfig] = ctx.config
        if cli_config is None or cli_config.beid_module_path is None:
            raise click.ClickException(
                "The --lib option is mandatory unless beid-module-path is "
                "provided in the configuration file."
            )
        lib = cli_config.beid_module_path

    @contextlib.contextmanager
    def manager():
        try:
            session = beid.open_beid_session(lib, slot_no=slot_no)
        except pkcs11.PKCS11Error as e:
            logger.error("PKCS#11 error", exc_info=e)
            raise click.ClickException(
                f"PKCS#11 error: [{type(e).__name__}] {e}"
            )

        with session:
            yield beid.BEIDSigner(session, use_auth_cert=use_auth_cert)

    return manager()
