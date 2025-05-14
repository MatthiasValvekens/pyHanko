import pytest
from certomancer.registry import CertLabel
from tests.cli_tests.conftest import (
    DUMMY_PASSPHRASE,
    INPUT_PATH,
    SIGNED_OUTPUT_PATH,
    _write_cert,
    _write_config,
)
from tests.samples import TESTING_CA

from pyhanko.cli import cli_root


def test_cli_lta_update(
    pki_arch_name, timestamp_url, cli_runner, root_cert, p12_keys
):
    if pki_arch_name == 'ed448':
        # FIXME deal with this bug on the Certomancer end
        pytest.skip("ed448 timestamping in Certomancer doesn't work")
    cfg = {
        'pkcs12-setups': {
            'test': {'pfx-file': p12_keys, 'pfx-passphrase': DUMMY_PASSPHRASE}
        },
        'validation-contexts': {
            'test': {
                'trust': root_cert,
            }
        },
    }

    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            '--validation-context',
            'test',
            '--with-validation-info',
            '--use-pades',
            '--timestamp-url',
            timestamp_url,
            'pkcs12',
            '--p12-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'ltaupdate',
            '--validation-context',
            'test',
            '--timestamp-url',
            timestamp_url,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_ltvfix(
    pki_arch_name, timestamp_url, cli_runner, root_cert, p12_keys
):
    if pki_arch_name == 'ed448':
        # FIXME deal with this bug on the Certomancer end
        pytest.skip("ed448 timestamping in Certomancer doesn't work")
    cfg = {
        'pkcs12-setups': {
            'test': {'pfx-file': p12_keys, 'pfx-passphrase': DUMMY_PASSPHRASE}
        },
        'validation-contexts': {
            'test': {
                'trust': root_cert,
            }
        },
    }

    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            '--use-pades',
            '--timestamp-url',
            timestamp_url,
            'pkcs12',
            '--p12-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'ltvfix',
            '--field',
            'Sig1',
            '--validation-context',
            'test',
            '--apply-lta-timestamp',
            '--timestamp-url',
            timestamp_url,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_ltvfix_require_timestamp(cli_runner):
    cfg = {
        'validation-contexts': {
            'test': {
                'trust': _write_cert(TESTING_CA, CertLabel('root'), 'root.crt'),
            }
        },
    }

    _write_config(cfg)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'ltvfix',
            '--field',
            'Sig1',
            '--validation-context',
            'test',
            '--apply-lta-timestamp',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Please specify a timestamp server" in result.output


def test_cli_ltvfix_require_signed_field(cli_runner):
    cfg = {
        'validation-contexts': {
            'test': {
                'trust': _write_cert(TESTING_CA, CertLabel('root'), 'root.crt'),
            }
        },
    }

    _write_config(cfg)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'ltvfix',
            '--field',
            'Sig1',
            '--validation-context',
            'test',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Could not find a PDF signature labelled Sig1" in result.output
