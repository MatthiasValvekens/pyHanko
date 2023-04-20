import abc
from typing import ClassVar, ContextManager, List, Optional

import click

from pyhanko.cli._ctx import CLIContext
from pyhanko.sign import Signer

__all__ = ['SigningCommandPlugin', 'register_plugin', 'SIGNING_PLUGIN_REGISTRY']


class SigningCommandPlugin(abc.ABC):
    subcommand_name: ClassVar[str]

    help_summary: ClassVar[str]
    unavailable_message: ClassVar[Optional[str]]

    def click_options(self) -> List[click.Option]:
        raise NotImplementedError

    def click_extra_arguments(self) -> List[click.Argument]:
        return []

    def is_available(self) -> bool:
        return True

    def create_signer(
        self, context: CLIContext, **kwargs
    ) -> ContextManager[Signer]:
        raise NotImplementedError


SIGNING_PLUGIN_REGISTRY: List[SigningCommandPlugin] = []


def register_plugin(cls):
    SIGNING_PLUGIN_REGISTRY.append(cls())
    return cls
