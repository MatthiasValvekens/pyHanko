import re
from typing import Optional

import click
from pyhanko.cli._root import cli_root
from pyhanko.cli.config import CLIConfig
from pyhanko.cli.runtime import DEFAULT_CONFIG_FILE, pyhanko_exception_manager
from pyhanko.cli.utils import _index_page, logger, readable_file
from pyhanko.config.errors import ConfigurationError
from pyhanko.stamp import QRStampStyle, qr_stamp_file, text_stamp_file

__all__ = ['select_style', 'stamp']

_CONFIG_REQUIRED_MSG = (
    "Using stamp styles requires a configuration file "
    f"({DEFAULT_CONFIG_FILE} by default)."
)


def select_style(ctx: click.Context, style_name: str, url: str):
    cli_config: Optional[CLIConfig] = ctx.obj.config
    if not cli_config:
        if not style_name:
            return None
        raise click.ClickException(_CONFIG_REQUIRED_MSG)
    try:
        style = cli_config.get_stamp_style(style_name)
    except ConfigurationError as e:
        logger.error(e.msg, exc_info=e)
        raise click.ClickException(e.msg)
    if url and not isinstance(style, QRStampStyle):
        raise click.ClickException(
            "The --stamp-url parameter is only meaningful for QR stamp styles."
        )
    elif not url and isinstance(style, QRStampStyle):
        raise click.ClickException(
            "QR stamp styles require the --stamp-url option."
        )

    return style


PARAM_REGEX = re.compile("([a-zA-Z0-9_]+):(.*)")


@cli_root.command(help='stamp PDF files', name='stamp')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.argument('x', type=int)
@click.argument('y', type=int)
@click.option(
    '--style-name',
    help='stamp style name for stamp appearance',
    required=False,
    type=str,
)
@click.option(
    '--page',
    help='page on which the stamp should be applied',
    required=False,
    type=int,
    default=1,
    show_default=True,
)
@click.option(
    '--stamp-url',
    help='QR code URL to use in QR stamp style',
    required=False,
    type=str,
)
@click.option(
    '--text-param',
    help='parameter to interpolate in the stamp text (multiple allowed)',
    required=False,
    multiple=True,
    type=str,
)
@click.pass_context
def stamp(
    ctx,
    infile: str,
    outfile: str,
    x: int,
    y: int,
    style_name: str,
    page: int,
    stamp_url: str,
    text_param: list,
):
    cli_config: Optional[CLIConfig] = ctx.obj.config
    if cli_config is None:
        raise click.ClickException(_CONFIG_REQUIRED_MSG)
    text_params = {}
    for param in text_param:
        m = PARAM_REGEX.match(param)
        if not m:
            raise click.ClickException(
                f"--text-param must be of the form "
                f"<name>:<value>, not f{param!r}"
            )
        text_params[m.group(1)] = m.group(2)
    with pyhanko_exception_manager():
        stamp_style = select_style(ctx, style_name, stamp_url)
        page_ix = _index_page(page)
        if stamp_url:
            qr_stamp_file(
                infile,
                outfile,
                stamp_style,
                dest_page=page_ix,
                x=x,
                y=y,
                url=stamp_url,
                text_params=text_params,
            )
        else:
            text_stamp_file(
                infile,
                outfile,
                stamp_style,
                dest_page=page_ix,
                x=x,
                y=y,
                text_params=text_params,
            )
