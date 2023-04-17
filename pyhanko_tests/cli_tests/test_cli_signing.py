import asyncio
import getpass
import logging
import os

import pytest
import requests_mock
from asn1crypto import pem
from asn1crypto.cms import ContentInfo
from certomancer import PKIArchitecture
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import CertLabel, KeyLabel
from cryptography.hazmat.primitives import serialization
from freezegun import freeze_time
from pyhanko_certvalidator import ValidationContext

from pyhanko.cli import cli_root
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import beid
from pyhanko.sign.validation import (
    async_validate_detached_cms,
    validate_pdf_signature,
)
from pyhanko_tests.cli_tests.conftest import (
    FREEZE_DT,
    INPUT_PATH,
    _const,
    _DummyManager,
    _write_cert,
    _write_config,
)
from pyhanko_tests.samples import MINIMAL_ONE_FIELD, TESTING_CA
from pyhanko_tests.signing_commons import FROM_CA
from pyhanko_tests.test_pkcs11 import SOFTHSM, pkcs11_only, pkcs11_test_module

logger = logging.getLogger(__name__)
SIGNED_OUTPUT_PATH = 'output.pdf'


@pytest.fixture
def p12_keys(pki_arch, post_validate):
    p12_bytes = pki_arch.package_pkcs12(
        CertLabel("signer1"), password=b"secret"
    )
    fname = 'signer.p12'
    with open(fname, 'wb') as outf:
        outf.write(p12_bytes)
    return fname


def _validate_last_sig_in(arch: PKIArchitecture, pdf_file):
    vc = ValidationContext(
        trust_roots=[arch.get_cert(CertLabel('root'))], allow_fetching=True
    )
    with open(pdf_file, 'rb') as result:
        logger.info(f"Validating last signature in {pdf_file}...")
        r = PdfFileReader(result)
        last_sig = r.embedded_signatures[-1]
        status = validate_pdf_signature(last_sig, signer_validation_context=vc)
        assert status.bottom_line, status.pretty_print_details()
        logger.info(f"Validation successful")


@pytest.fixture
def post_validate(pki_arch):
    yield
    if os.path.isfile(SIGNED_OUTPUT_PATH):
        _validate_last_sig_in(pki_arch, SIGNED_OUTPUT_PATH)


def _write_user_key(pki_arch: PKIArchitecture):
    key = pki_arch.key_set.get_private_key(KeyLabel('signer1'))
    key_handle = serialization.load_der_private_key(key.dump(), password=None)
    pem_bytes = key_handle.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    fname = 'signer.key.pem'
    with open(fname, 'wb') as outf:
        outf.write(pem_bytes)
    return fname


@pytest.fixture
def user_key(pki_arch, post_validate):
    return _write_user_key(pki_arch)


def test_cli_addsig_pemder(cli_runner, cert_chain, user_key):
    root_cert, interm_cert, user_cert = cert_chain
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pemder',
            '--no-pass',
            '--cert',
            user_cert,
            '--chain',
            interm_cert,
            '--key',
            user_key,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def _pemder_setup_config(user_key, cert_chain) -> dict:
    root_cert, interm_cert, user_cert = cert_chain
    return {
        'pemder-setups': {
            'test': {
                'key-file': user_key,
                'cert-file': user_cert,
                'other-certs': [interm_cert, root_cert],
            }
        }
    }


def test_cli_addsig_pemder_with_setup(cli_runner, cert_chain, user_key):
    cfg = _pemder_setup_config(user_key, cert_chain)
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pemder',
            '--no-pass',
            '--pemder-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_addsig_pemder_with_unreadable_additional_certs(cli_runner):
    with open("bad-cert.pem", "w") as outf:
        outf.write("blah")
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pemder',
            '--no-pass',
            '--key',
            _write_user_key(TESTING_CA),
            '--cert',
            _write_cert(TESTING_CA, CertLabel('signer1'), "cert.pem"),
            '--chain',
            'bad-cert.pem',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Could not load certificates" in result.output


def test_cli_addsig_pemder_detached(cli_runner, pki_arch, cert_chain, user_key):
    cfg = _pemder_setup_config(user_key, cert_chain)
    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--detach-pem',
            '--field',
            'Sig1',
            'pemder',
            '--no-pass',
            '--pemder-setup',
            'test',
            INPUT_PATH,
            'output.sig.pem',
        ],
    )
    assert not result.exception, result.output
    with open(INPUT_PATH, 'rb') as in_data:
        with open('output.sig.pem', 'rb') as sig_data:
            sig_pem_bytes = sig_data.read()
            sd = ContentInfo.load(pem.unarmor(sig_pem_bytes)[2])['content']
            status = asyncio.run(
                async_validate_detached_cms(
                    in_data,
                    sd,
                    signer_validation_context=ValidationContext(
                        trust_roots=[pki_arch.get_cert(CertLabel('root'))],
                        allow_fetching=True,
                    ),
                )
            )
            assert status.bottom_line, status.pretty_print_details()


def test_cli_addsig_p12(cli_runner, p12_keys, monkeypatch):
    monkeypatch.setattr(getpass, 'getpass', value=_const('secret'))
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs12',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            p12_keys,
        ],
    )
    assert not result.exception, result.output


@pytest.mark.parametrize('passphrase_loc', ['config', 'prompt', 'file'])
def test_cli_addsig_p12_with_setup(
    cli_runner, p12_keys, monkeypatch, passphrase_loc
):
    cfg = {
        'pkcs12-setups': {
            'test': {
                'pfx-file': p12_keys,
            }
        }
    }
    args = []
    if passphrase_loc == 'config':
        cfg['pkcs12-setups']['test']['pfx_passphrase'] = 'secret'
    elif passphrase_loc == 'prompt':
        monkeypatch.setattr(getpass, 'getpass', value=_const('secret'))
    elif passphrase_loc == 'file':
        args = ['--passfile', 'passfile']
        with open('passfile', 'w') as pf:
            pf.write("secret")

    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs12',
            '--p12-setup',
            'test',
            *args,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_addsig_p12_passfile(cli_runner, p12_keys):
    with open('passfile', 'w') as pf:
        pf.write("secret")

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs12',
            '--passfile',
            'passfile',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            p12_keys,
        ],
    )
    assert not result.exception, result.output


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
def test_cli_addsig_pkcs11_with_pin_prompt(
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
    with freeze_time(FREEZE_DT):
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


def test_cli_sign_visible_no_style(cli_runner, cert_chain, user_key):
    root_cert, interm_cert, user_cert = cert_chain
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            '1/0,0,100,100/Sig1',
            'pemder',
            '--no-pass',
            '--cert',
            user_cert,
            '--chain',
            interm_cert,
            '--key',
            user_key,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_sign_visible_with_style(cli_runner, cert_chain, user_key):
    cfg = {
        'stamp-styles': {'test': {'type': 'text', 'background': '__stamp__'}}
    }
    _write_config(cfg)
    root_cert, interm_cert, user_cert = cert_chain
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--style-name',
            'test',
            '--field',
            '1/0,0,100,100/Sig1',
            'pemder',
            '--no-pass',
            '--cert',
            user_cert,
            '--chain',
            interm_cert,
            '--key',
            user_key,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_add_field_then_sign(cli_runner, cert_chain, user_key):
    root_cert, interm_cert, user_cert = cert_chain
    intermediate_file_path = 'presign.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            '--field',
            '1/0,0,100,100/Sig1',
            INPUT_PATH,
            intermediate_file_path,
        ],
    )
    assert not result.exception, result.output
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            '--existing-only',
            'pemder',
            '--no-pass',
            '--cert',
            user_cert,
            '--chain',
            interm_cert,
            '--key',
            user_key,
            intermediate_file_path,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_sign_implied_field(cli_runner, cert_chain, user_key):
    root_cert, interm_cert, user_cert = cert_chain
    with open(INPUT_PATH, 'wb') as f:
        f.write(MINIMAL_ONE_FIELD)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--existing-only',
            'pemder',
            '--no-pass',
            '--cert',
            user_cert,
            '--chain',
            interm_cert,
            '--key',
            user_key,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_sign_field_param_required(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--existing-only',
            'pemder',
            '--no-pass',
            '--key',
            _write_user_key(TESTING_CA),
            '--cert',
            _write_cert(TESTING_CA, CertLabel('signer1'), "cert.pem"),
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "There are no empty signature fields" in result.output
