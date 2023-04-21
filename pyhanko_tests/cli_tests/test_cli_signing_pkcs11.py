import getpass

import requests_mock
from certomancer.integrations.illusionist import Illusionist
from freezegun import freeze_time

from pyhanko.cli import cli_root
from pyhanko.cli.commands.signing.pkcs11_cli import P11_PIN_ENV_VAR
from pyhanko.sign import beid
from pyhanko_tests.cli_tests.conftest import (
    FREEZE_DT,
    INPUT_PATH,
    SIGNED_OUTPUT_PATH,
    _const,
    _DummyManager,
    _validate_last_sig_in,
    _write_config,
)
from pyhanko_tests.samples import TESTING_CA
from pyhanko_tests.signing_commons import FROM_CA
from pyhanko_tests.test_pkcs11 import SOFTHSM, pkcs11_only, pkcs11_test_module


def test_cli_pkcs11_args_required(cli_runner):
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


def test_cli_pkcs11_setup_requires_config(cli_runner):
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


def _pkcs11_setup_config(pki_arch_name):
    cfg = {
        'pkcs11-setups': {
            'test': {
                'module-path': pkcs11_test_module,
                'token-criteria': {
                    'label': 'test' + pki_arch_name,
                },
                'cert-label': 'signer1',
                'other-certs-to-pull': 'interm',
            }
        }
    }
    return cfg


@pkcs11_only
def test_cli_addsig_pkcs11(
    cli_runner, pki_arch_name, post_validate, monkeypatch
):
    args = [
        '--lib',
        pkcs11_test_module,
        '--token-label',
        'test' + pki_arch_name,
        '--cert-label',
        'signer1',
        '--other-cert',
        'interm',
    ]
    if SOFTHSM and pki_arch_name == 'ecdsa':
        args += ['--raw-mechanism']
    monkeypatch.setattr(getpass, 'getpass', value=_const('1234'))
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


@pkcs11_only
def test_cli_addsig_pkcs11_with_setup(cli_runner, pki_arch_name, post_validate):
    cfg = _pkcs11_setup_config(pki_arch_name)
    if SOFTHSM and pki_arch_name == 'ecdsa':
        cfg['pkcs11-setups']['test']['raw-mechanism'] = True
    cfg['pkcs11-setups']['test']['user-pin'] = 1234
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


@pkcs11_only
def test_cli_addsig_pkcs11_with_setup_and_env_pin(
    cli_runner, pki_arch_name, post_validate
):
    cli_runner.env[P11_PIN_ENV_VAR] = '1234'
    cfg = _pkcs11_setup_config(pki_arch_name)
    if SOFTHSM and pki_arch_name == 'ecdsa':
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


@pkcs11_only
def test_cli_addsig_pkcs11_with_setup_and_pin_prompt(
    cli_runner, pki_arch_name, post_validate, monkeypatch
):
    cfg = _pkcs11_setup_config(pki_arch_name)
    if SOFTHSM and pki_arch_name == 'ecdsa':
        cfg['pkcs11-setups']['test']['raw-mechanism'] = True
    _write_config(cfg)

    monkeypatch.setattr(getpass, 'getpass', value=_const('1234'))
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


@freeze_time(FREEZE_DT)
def test_cli_addsig_beid(cli_runner, monkeypatch):
    monkeypatch.setattr(
        beid, 'open_beid_session', value=_const(_DummyManager())
    )
    monkeypatch.setattr(beid, 'BEIDSigner', value=_const(FROM_CA))
    with open('libbeidpkcs11-mock', 'wb') as mocklib:
        mocklib.write(b"\x00")
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            '--lib',
            'libbeidpkcs11-mock',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output

    with requests_mock.Mocker() as m:
        Illusionist(TESTING_CA).register(m)
        _validate_last_sig_in(TESTING_CA, SIGNED_OUTPUT_PATH)


@freeze_time(FREEZE_DT)
def test_cli_addsig_beid_with_setup(cli_runner, monkeypatch):
    monkeypatch.setattr(
        beid, 'open_beid_session', value=_const(_DummyManager())
    )
    monkeypatch.setattr(beid, 'BEIDSigner', value=_const(FROM_CA))

    _write_config({'beid-module-path': 'libbeidpkcs11-mock'})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output

    with requests_mock.Mocker() as m:
        Illusionist(TESTING_CA).register(m)
        _validate_last_sig_in(TESTING_CA, SIGNED_OUTPUT_PATH)


def test_cli_beid_lib_mandatory(cli_runner, monkeypatch):
    monkeypatch.setattr(
        beid, 'open_beid_session', value=_const(_DummyManager())
    )
    monkeypatch.setattr(beid, 'BEIDSigner', value=_const(FROM_CA))

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert '--lib option is mandatory' in result.output


def test_cli_beid_pkcs11_error(cli_runner, monkeypatch):
    from pkcs11 import PKCS11Error

    def _throw(*_args, **_kwargs):
        raise PKCS11Error

    monkeypatch.setattr(beid, 'open_beid_session', value=_throw)

    _write_config({'beid-module-path': 'blah'})

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert 'PKCS#11 error' in result.output
