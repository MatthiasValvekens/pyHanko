from pyhanko.cli import cli_root
from tests.cli_tests.conftest import INPUT_PATH
from tests.samples import MINIMAL_AES256, MINIMAL_SLIGHTLY_BROKEN


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
