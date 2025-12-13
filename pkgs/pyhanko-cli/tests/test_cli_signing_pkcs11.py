import getpass

import pytest
from pyhanko.cli import cli_root
from pyhanko.cli.commands.signing.pkcs11_cli import P11_PIN_ENV_VAR
from test_utils.pkcs11_utils.config import P11TestConfig

from .conftest import (
    INPUT_PATH,
    SIGNED_OUTPUT_PATH,
    _const,
    _write_config,
)


@pytest.fixture(
    params=[
        pytest.param(k, marks=pytest.mark.algo(k))
        for k in ('rsa', 'ecdsa', 'ed25519', 'ed448')
    ]
)
def root_cert_data(p11_config, any_algo):
    return p11_config.cert_chain[0]


@pytest.mark.hsm(platform='softhsm')
def test_cli_pkcs11_args_required(cli_runner, p11_config):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "--lib and --cert-label are required" in result.output


@pytest.mark.hsm(platform='softhsm')
def test_cli_pkcs11_setup_requires_config(cli_runner, p11_config):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            '--p11-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "requires a configuration file" in result.output


@pytest.mark.nosmoke
def test_cli_pkcs11_setup_config_unreadable(cli_runner):
    _write_config({'pkcs11-setups': {}})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            '--p11-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Error while reading PKCS#11 config" in result.output


def _pkcs11_setup_config(p11_test_config: P11TestConfig):
    cfg = {
        'pkcs11-setups': {
            'test': {
                'module-path': p11_test_config.module,
                'token-criteria': {
                    'label': p11_test_config.token_label,
                },
                'cert-label': p11_test_config.key_label,
                'other-certs-to-pull': p11_test_config.cert_chain_labels[1],
            }
        }
    }
    return cfg


@pytest.mark.hsm(platform='all')
def test_cli_addsig_pkcs11(
    cli_runner, post_validate, monkeypatch, p11_config, platform
):
    args = [
        '--lib',
        p11_config.module,
        '--token-label',
        p11_config.token_label,
        '--cert-label',
        p11_config.key_label,
        '--other-cert',
        p11_config.cert_chain_labels[1],
    ]
    if platform == "softhsm" and p11_config.algo == 'ecdsa':
        args += ['--raw-mechanism']
    monkeypatch.setattr(getpass, 'getpass', value=_const(p11_config.user_pin))
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            *args,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


@pytest.mark.hsm(platform='all')
def test_cli_addsig_pkcs11_with_setup(
    cli_runner, p11_config, post_validate, platform
):
    cfg = _pkcs11_setup_config(p11_config)
    if platform == 'softhsm' and p11_config.algo == 'ecdsa':
        cfg['pkcs11-setups']['test']['raw-mechanism'] = True
    cfg['pkcs11-setups']['test']['user-pin'] = p11_config.user_pin
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            '--p11-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


@pytest.mark.hsm(platform='softhsm')
def test_cli_addsig_pkcs11_with_setup_and_env_pin(
    cli_runner, p11_config, post_validate
):
    cli_runner.env[P11_PIN_ENV_VAR] = p11_config.user_pin
    cfg = _pkcs11_setup_config(p11_config)
    if p11_config.algo == 'ecdsa':
        cfg['pkcs11-setups']['test']['raw-mechanism'] = True
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            '--p11-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


@pytest.mark.hsm(platform='softhsm')
def test_cli_addsig_pkcs11_with_setup_and_pin_prompt(
    cli_runner,
    post_validate,
    monkeypatch,
    p11_config,
):
    cfg = _pkcs11_setup_config(p11_config)
    if p11_config.algo == 'ecdsa':
        cfg['pkcs11-setups']['test']['raw-mechanism'] = True
    _write_config(cfg)

    monkeypatch.setattr(getpass, 'getpass', value=_const(p11_config.user_pin))
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs11',
            '--p11-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output
