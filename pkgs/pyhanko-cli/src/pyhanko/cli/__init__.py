from pyhanko.cli._root import cli_root
from pyhanko.cli.commands.crypt import *  # noqa: F403
from pyhanko.cli.commands.fields import *  # noqa: F403
from pyhanko.cli.commands.signing import *  # noqa: F403
from pyhanko.cli.commands.stamp import *  # noqa: F403
from pyhanko.cli.commands.validation import *  # noqa: F403

__all__ = ['cli_root', 'launch']


def launch():
    cli_root(prog_name='pyhanko')  # pragma: nocover
