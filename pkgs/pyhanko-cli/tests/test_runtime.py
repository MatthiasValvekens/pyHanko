import pytest
from click import __version__ as click_version
from pyhanko.cli import cli_root
from test_data.samples import MINIMAL_AES256, MINIMAL_SLIGHTLY_BROKEN

from .conftest import INPUT_PATH, _write_config


def test_fail_read(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            '--field',
            '1/0,0,100,100/Sig1',
            INPUT_PATH,
            "out.pdf",
        ],
    )
    assert result.exit_code == 1
    assert "Failed to read" in result.output


def test_fail_strict_mildly_broken(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_SLIGHTLY_BROKEN)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "in strict mode; rerun" in result.output


def test_succeed_strict_mildly_broken_nonstrict(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_SLIGHTLY_BROKEN)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--no-strict-syntax',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 0


def test_log_stdout(cli_runner):
    cfg = {
        "logging": {
            "root-level": "DEBUG",
            "root-output": "stdout",
        }
    }
    _write_config(cfg)
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_SLIGHTLY_BROKEN)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "in strict mode; rerun" in result.stdout


@pytest.mark.skipif(
    click_version < "8.2.0",
    reason="skipping due to CLIRunner differences on older click versions",
)
def test_log_stderr_default(cli_runner):
    # Stderr capture in tests works differently on older Click versions
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_SLIGHTLY_BROKEN)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "in strict mode; rerun" in result.stderr


def test_log_file(cli_runner):
    cfg = {
        "logging": {
            "root-level": "DEBUG",
            "root-output": "pyhanko.log",
        }
    }
    _write_config(cfg)
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_SLIGHTLY_BROKEN)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    with open("pyhanko.log", "r") as log:
        log_content = log.read()
    assert "in strict mode; rerun" in log_content
