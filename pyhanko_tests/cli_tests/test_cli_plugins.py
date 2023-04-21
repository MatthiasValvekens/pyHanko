import sys

import pytest

from pyhanko.cli import cli_root
from pyhanko.cli.commands.signing.simple import PKCS12Plugin
from pyhanko.cli.plugin_api import register_signing_plugin
from pyhanko_tests.cli_tests.conftest import _write_config

if sys.version_info < (3, 8):
    pytest.skip(
        allow_module_level=True,
        reason="Plugins are only supported on Python 3.8+",
    )


class DummyTestPlugin(PKCS12Plugin):
    subcommand_name = 'test-dummy'
    help_summary = 'this is a test plugin'


@register_signing_plugin
class ManuallyRegisteredTestPlugin(PKCS12Plugin):
    subcommand_name = 'manual-dummy'
    help_summary = 'manual test plugin'


class UnavailablePlugin(PKCS12Plugin):
    subcommand_name = 'unavailable-plugin'
    help_summary = 'unavailable plugin'

    def is_available(self) -> bool:
        return False


def test_load_plugins_from_config(cli_runner):
    _write_config(
        {
            'plugins': [
                'pyhanko_tests.cli_tests.test_cli_plugins:DummyTestPlugin'
            ]
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--help',
        ],
    )
    output = result.output
    assert 'test-dummy' in output
    assert 'manual-dummy' in output

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            'test-dummy',
            '--help',
        ],
    )
    assert not result.exception


def test_plugin_must_be_class(cli_runner):
    _write_config(
        {
            'plugins': [
                'pyhanko_tests.cli_tests',
            ]
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--help',
        ],
    )
    assert not result.exception
    output = result.output
    assert 'Plugins must be defined as' in output
    assert not ('test-dummy' in output)


def test_disable_non_default_plugins(cli_runner):
    _write_config(
        {
            'plugins': [
                'pyhanko_tests.cli_tests.test_cli_plugins:DummyTestPlugin',
            ]
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            '--no-plugins',
            'sign',
            'addsig',
            '--help',
        ],
    )
    assert not result.exception
    output = result.output
    assert not ('test-dummy' in output)
    assert 'manual-dummy' in output


def test_show_unavailable_plugins(cli_runner):
    _write_config(
        {
            'plugins': [
                'pyhanko_tests.cli_tests.test_cli_plugins:UnavailablePlugin',
            ]
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--help',
        ],
    )
    assert not result.exception
    assert '[unavailable]' in result.output


def test_trigger_unavailable_plugin(cli_runner):
    _write_config(
        {
            'plugins': [
                'pyhanko_tests.cli_tests.test_cli_plugins:UnavailablePlugin',
            ]
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            'unavailable-plugin',
        ],
    )
    assert result.exit_code == 1
    assert 'This subcommand is not available' in result.output
