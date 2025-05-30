import pytest
from pyhanko.cli import cli_root

from .conftest import (
    INPUT_PATH,
    SIGNED_OUTPUT_PATH,
    _write_config,
)


def test_cli_stamp_with_style(cli_runner):
    cfg = {
        'stamp-styles': {'test': {'type': 'text', 'background': '__stamp__'}}
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--style-name',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert not result.exception, result.output
    # TODO make this a layout test


@pytest.mark.nosmoke
def test_cli_stamp_with_qr_style(cli_runner):
    cfg = {'stamp-styles': {'test': {'type': 'qr', 'background': '__stamp__'}}}
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--style-name',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
            '--stamp-url',
            'https://example.com',
        ],
    )
    assert not result.exception, result.output
    # TODO make this a layout test


def test_cli_stamp_style_no_config(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--style-name',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "requires a configuration file" in result.output


def test_cli_stamp_style_stamp_url_unnecessary(cli_runner):
    cfg = {
        'stamp-styles': {'test': {'type': 'text', 'background': '__stamp__'}}
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--style-name',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
            '--stamp-url',
            'blah',
        ],
    )
    assert result.exit_code == 1
    assert "only meaningful for QR" in result.output


@pytest.mark.nosmoke
def test_cli_stamp_style_stamp_url_mandatory(cli_runner):
    cfg = {'stamp-styles': {'test': {'type': 'qr', 'background': '__stamp__'}}}
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--style-name',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "require the --stamp-url option" in result.output


def test_cli_stamp_style_undefined(cli_runner):
    cfg = {
        'stamp-styles': {'test': {'type': 'text', 'background': '__stamp__'}}
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--style-name',
            'undefined',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "no stamp style named" in result.output


def test_cli_stamp_text_param_missing(cli_runner):
    cfg = {
        'stamp-styles': {
            'default': {
                'type': 'text',
                'stamp_text': '%(nonexistent)s',
                'background': '__stamp__',
            }
        }
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "Error raised while producing signature layout" in result.output
    assert "'nonexistent' is missing" in result.output


@pytest.mark.parametrize("param", ["nonsense", "---:blah", "%:blah"])
def test_cli_stamp_text_param_formatting_wrong(cli_runner, param):
    _write_config({})
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            '--text-param',
            param,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "must be of the form" in result.output
    assert param in result.output


def test_cli_stamp_text_param_multiple_substitution(cli_runner):
    cfg = {
        'stamp-styles': {
            'default': {
                'type': 'text',
                'stamp_text': 'Signing as %(my_name)s\n%(something_else)s',
                'background': '__stamp__',
            }
        }
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            "--text-param",
            "my_name:John Doe",
            "--text-param",
            "something_else:Who knows",
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 0


def test_cli_stamp_text_param_fail_partial_substitution(cli_runner):
    cfg = {
        'stamp-styles': {
            'default': {
                'type': 'text',
                'stamp_text': 'Signing as %(my_name)s\n%(something_else)s',
                'background': '__stamp__',
            }
        }
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            "--text-param",
            "my_name:John Doe",
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "Error raised while producing signature layout" in result.output
    assert "'something_else' is missing" in result.output


@pytest.mark.nosmoke
def test_cli_stamp_style_unspecified(cli_runner):
    cfg = {
        'stamp-styles': {
            'default': {
                'type': 'qr',
                'background': '__stamp__',
                'stamp-text': 'Blah',
            }
        }
    }
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
            '--stamp-url',
            'https://example.com',
        ],
    )
    assert result.exit_code == 0


def test_cli_stamp_style_malformed(cli_runner):
    cfg = {'stamp-styles': {'default': 'nonsense'}}
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'stamp',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            '0',
            '0',
        ],
    )
    assert result.exit_code == 1
    assert "Could not process" in result.output
