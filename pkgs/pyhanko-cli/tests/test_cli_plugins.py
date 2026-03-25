from pyhanko.cli import cli_root
from pyhanko.cli.commands.signing.simple import PKCS12Plugin
from pyhanko.cli.plugin_api import register_signing_plugin

from .conftest import _write_config


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
    unavailable_message = 'plugin always unavailable'

    def is_available(self) -> bool:
        return False


def test_load_plugins_from_config(cli_runner):
    _write_config({'plugins': ['tests.test_cli_plugins:DummyTestPlugin']})
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


def test_gracefully_handle_dupe_plugins(cli_runner):
    _write_config(
        {
            'plugins': [
                'tests.test_cli_plugins:DummyTestPlugin',
                'tests.test_cli_plugins:DummyTestPlugin',
            ]
        }
    )

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
                'tests',
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
    assert 'test-dummy' not in output


def test_disable_non_default_plugins(cli_runner):
    _write_config(
        {
            'plugins': [
                'tests.test_cli_plugins:DummyTestPlugin',
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
    assert 'test-dummy' not in output
    assert 'manual-dummy' in output


def test_show_unavailable_plugins(cli_runner):
    _write_config(
        {
            'plugins': [
                'tests.test_cli_plugins:UnavailablePlugin',
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
                'tests.test_cli_plugins:UnavailablePlugin',
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
    assert 'plugin always unavailable' in result.output


def test_identity_setup_with_too_few_parameters(cli_runner):
    cfg = {'identities': {'test': {'plugin': 'pemder', 'parameters': {}}}}
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'identity',
            'test',
            'input.pdf',
            'output.pdf',
        ],
    )
    assert result.exit_code == 1, result.output
    assert 'option must be provided' in result.output


def test_identity_setup_with_unknown_parameters(cli_runner):
    cfg = {
        'identities': {
            'test': {
                'plugin': 'pemder',
                'parameters': {
                    'key': "blah.key",
                    'cert': "blah.cert",
                    'no-pass': True,
                    'zzz': 'blah',
                },
            }
        }
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'identity',
            'test',
            'input.pdf',
            'output.pdf',
        ],
    )
    assert result.exit_code == 1, result.output
    assert "Parameter 'zzz' defined by 'test' not known" in result.output


def test_identity_setup_with_unknown_plugin(cli_runner):
    cfg = {'identities': {'test': {'plugin': 'zzz', 'parameters': {}}}}
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'identity',
            'test',
            'input.pdf',
            'output.pdf',
        ],
    )
    assert result.exit_code == 1, result.output
    assert "Plugin 'zzz'" in result.output


def test_unknown_identity(cli_runner):
    cfg = {'identities': {}}
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'identity',
            'test',
            'input.pdf',
            'output.pdf',
        ],
    )
    assert result.exit_code == 1, result.output
    assert "Identity 'test' not found" in result.output


def test_identity_without_config(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'identity',
            'test',
            'input.pdf',
            'output.pdf',
        ],
    )
    assert result.exit_code == 1, result.output
    assert "Identity command requires a config file" in result.output
