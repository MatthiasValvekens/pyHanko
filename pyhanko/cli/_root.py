import importlib
import logging

import click

from pyhanko import __version__
from pyhanko.cli._ctx import CLIContext
from pyhanko.cli.config import parse_cli_config
from pyhanko.cli.runtime import DEFAULT_CONFIG_FILE, logging_setup
from pyhanko.config.logging import LogConfig, parse_logging_config

__all__ = ['cli_root']


@click.group()
@click.version_option(prog_name='pyHanko', version=__version__)
@click.option(
    '--config',
    help=(
        'YAML file to load configuration from'
        f'[default: {DEFAULT_CONFIG_FILE}]'
    ),
    required=False,
    type=click.File('r'),
)
@click.option(
    '--verbose',
    help='Run in verbose mode',
    required=False,
    default=False,
    type=bool,
    is_flag=True,
)
@click.option(
    '--no-plugins',
    help='Disable non-builtin plugin loading',
    type=bool,
    is_flag=True,
)
@click.pass_context
def cli_root(ctx: click.Context, config, verbose, no_plugins):
    config_text = None
    if config is None:
        try:
            with open(DEFAULT_CONFIG_FILE, 'r') as f:
                config_text = f.read()
            config = DEFAULT_CONFIG_FILE
        except FileNotFoundError:
            pass
        except IOError as e:
            raise click.ClickException(
                f"Failed to read {DEFAULT_CONFIG_FILE}: {str(e)}"
            )
    else:
        try:
            config_text = config.read()
        except IOError as e:
            raise click.ClickException(
                f"Failed to read configuration: {str(e)}",
            )

    ctx.ensure_object(CLIContext)
    ctx_obj: CLIContext = ctx.obj
    if config_text is not None:
        ctx_obj.config = cfg = parse_cli_config(config_text)
        log_config = cfg.log_config
    else:
        # grab the default
        log_config = parse_logging_config({})

    from .commands.signing import register

    _load_plugins(ctx_obj, plugins_enabled=not no_plugins)
    register()

    if verbose:
        # override the root logger's logging level, but preserve the output
        root_logger_config = log_config[None]
        log_config[None] = LogConfig(
            level=logging.DEBUG, output=root_logger_config.output
        )
    else:
        # use the root logger's output settings to populate the default
        log_output = log_config[None].output
        # Revinfo fetch logs -> filter by default
        log_config['pyhanko_certvalidator.fetchers'] = LogConfig(
            level=logging.WARNING, output=log_output
        )
        if 'fontTools.subset' not in log_config:
            # the fontTools subsetter has a very noisy INFO log, so
            # set that one to WARNING by default
            log_config['fontTools.subset'] = LogConfig(
                level=logging.WARNING, output=log_output
            )

    logging_setup(log_config, verbose)

    if verbose:
        logging.debug("Running with --verbose")
    if config_text is not None:
        logging.debug(f'Finished reading configuration from {config}.')
    else:
        logging.debug('There was no configuration to parse.')


def _load_plugins(ctx_obj: CLIContext, plugins_enabled: bool):
    # we always load the default ones
    to_load = [
        'pyhanko.cli.commands.signing.pkcs11_cli',
        'pyhanko.cli.commands.signing.simple',
    ]
    if plugins_enabled and ctx_obj.config is not None:
        to_load += [str(mod) for mod in ctx_obj.config.plugin_modules]

    for path in to_load:
        importlib.import_module(path)
