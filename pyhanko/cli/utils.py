import logging

import click

logger = logging.getLogger("cli")


def _warn_empty_passphrase():
    click.echo(
        click.style(
            "WARNING: passphrase is empty. If you intended to sign with an "
            "unencrypted private key, use --no-pass instead.",
            bold=True,
        )
    )
