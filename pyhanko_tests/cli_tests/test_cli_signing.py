import asyncio
import getpass
from typing import Optional

import pytest
from asn1crypto import pem
from asn1crypto.cms import ContentInfo
from certomancer import PKIArchitecture
from certomancer.registry import CertLabel, KeyLabel
from cryptography.hazmat.primitives import serialization
from pyhanko_certvalidator import ValidationContext

from pyhanko.cli import cli_root
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_detached_cms
from pyhanko_tests.cli_tests.conftest import (
    DUMMY_PASSPHRASE,
    INPUT_PATH,
    SIGNED_OUTPUT_PATH,
    _const,
    _write_cert,
    _write_config,
)
from pyhanko_tests.samples import (
    MINIMAL_AES256,
    MINIMAL_ONE_FIELD,
    MINIMAL_PUBKEY_AES256,
    TESTING_CA,
)


@pytest.fixture
def unencrypted_p12(pki_arch, post_validate):
    p12_bytes = pki_arch.package_pkcs12(CertLabel("signer1"))
    fname = 'signer.p12'
    with open(fname, 'wb') as outf:
        outf.write(p12_bytes)
    return fname


def _write_user_key(
    pki_arch: PKIArchitecture, passphrase: Optional[bytes] = None
):
    key = pki_arch.key_set.get_private_key(KeyLabel('signer1'))
    key_handle = serialization.load_der_private_key(key.dump(), password=None)
    pem_bytes = key_handle.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption(),
    )

    fname = 'signer.key.pem'
    with open(fname, 'wb') as outf:
        outf.write(pem_bytes)
    return fname


@pytest.fixture
def user_key(pki_arch, post_validate):
    return _write_user_key(pki_arch)


@pytest.fixture
def encrypted_user_key(pki_arch, post_validate):
    return _write_user_key(pki_arch, passphrase=DUMMY_PASSPHRASE.encode("utf8"))


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


def test_cli_addsig_pemder_without_nopass(
    cli_runner, cert_chain, user_key, monkeypatch
):
    # expect a warning, but no errors
    monkeypatch.setattr(getpass, 'getpass', _const(""))

    root_cert, interm_cert, user_cert = cert_chain
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pemder',
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


@pytest.mark.parametrize('loc', ['config', 'passfile', 'prompt'])
def test_cli_addsig_pemder_with_setup_encrypted_key(
    cli_runner, cert_chain, encrypted_user_key, monkeypatch, loc
):
    cfg = _pemder_setup_config(encrypted_user_key, cert_chain)
    if loc == 'config':
        cfg['pemder-setups']['test']['key-passphrase'] = DUMMY_PASSPHRASE
        args = []
    elif loc == 'passfile':
        with open('passfile', 'w') as passf:
            passf.write(DUMMY_PASSPHRASE)
        args = ['--passfile', 'passfile']
    else:
        args = []
        monkeypatch.setattr(getpass, 'getpass', _const(DUMMY_PASSPHRASE))

    _write_config(cfg)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pemder',
            '--pemder-setup',
            'test',
            *args,
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_addsig_pemder_setup_requires_config(cli_runner):
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
    assert result.exit_code == 1
    assert "requires a configuration file" in result.output


def test_cli_addsig_pemder_some_args_required(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pemder',
            '--no-pass',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "option must be provided" in result.output


def test_cli_addsig_pemder_setup_does_not_exist(cli_runner):
    cfg = {'pemder-setups': {}}
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
    assert result.exit_code == 1
    assert "Error while reading PEM/DER setup" in result.output


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
    monkeypatch.setattr(getpass, 'getpass', value=_const(DUMMY_PASSPHRASE))
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


def test_cli_addsig_unencrypted_p12(cli_runner, unencrypted_p12):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs12',
            '--no-pass',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
            unencrypted_p12,
        ],
    )
    assert not result.exception, result.output


def test_cli_addsig_unencrypted_p12_without_nopass(
    cli_runner, unencrypted_p12, monkeypatch
):
    # expect a warning, but no errors
    monkeypatch.setattr(getpass, 'getpass', _const(""))

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
            unencrypted_p12,
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
        cfg['pkcs12-setups']['test']['pfx_passphrase'] = DUMMY_PASSPHRASE
    elif passphrase_loc == 'prompt':
        monkeypatch.setattr(getpass, 'getpass', value=_const(DUMMY_PASSPHRASE))
    elif passphrase_loc == 'file':
        args = ['--passfile', 'passfile']
        with open('passfile', 'w') as pf:
            pf.write(DUMMY_PASSPHRASE)

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


def test_cli_addsig_p12_setup_requires_config(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs12',
            '--p12-setup',
            'blah',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "requires a configuration file" in result.output


def test_cli_addsig_p12_setup_unreadable(cli_runner):
    _write_config({'p12-setup': {}})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'pkcs12',
            '--p12-setup',
            'blah',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Error while reading PKCS#12 config" in result.output


def test_cli_addsig_p12_setup_or_pfx_argument_required(cli_runner):
    _write_config({'p12-setup': {}})
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
        ],
    )
    assert result.exit_code == 1
    assert "argument or the --p12-setup" in result.output


def test_cli_addsig_p12_passfile(cli_runner, p12_keys):
    with open('passfile', 'w') as pf:
        pf.write(DUMMY_PASSPHRASE)

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


def test_cli_pades_lta(
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
            '--use-pades-lta',
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


def test_cli_addsig_pemder_encrypted_file(
    cli_runner, cert_chain, user_key, monkeypatch
):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    monkeypatch.setattr(getpass, 'getpass', _const("ownersecret"))
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


def test_cli_addsig_no_pubkey_encryption(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)
    cfg = {
        'pemder-setups': {
            'test': {
                'key-file': _write_user_key(TESTING_CA),
                'cert-file': _write_cert(
                    TESTING_CA, CertLabel('signer1'), fname='cert.pem'
                ),
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
            'pemder',
            '--no-pass',
            '--pemder-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Public-key document encryption is not supported" in result.output


def test_cli_addsig_wrong_password(cli_runner, monkeypatch):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    monkeypatch.setattr(getpass, 'getpass', _const("wrong"))
    cfg = {
        'pemder-setups': {
            'test': {
                'key-file': _write_user_key(TESTING_CA),
                'cert-file': _write_cert(
                    TESTING_CA, CertLabel('signer1'), fname='cert.pem'
                ),
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
            'pemder',
            '--no-pass',
            '--pemder-setup',
            'test',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "Invalid password" in result.output


def test_cli_sign_visible_with_custom_default_style(
    cli_runner, cert_chain, user_key
):
    cfg = {
        'default-stamp-style': 'test',
        'stamp-styles': {
            'test': {
                'type': 'text',
                'background': '__stamp__',
                'stamp_text': 'Blah',
            }
        },
    }
    _write_config(cfg)
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
    with open(SIGNED_OUTPUT_PATH, 'rb') as outf:
        r = PdfFileReader(outf)
        page = r.root['/Pages']['/Kids'][0]
        assert b'Blah' in page['/Annots'][0]['/AP']['/N'].data
    assert not result.exception, result.output


def test_cli_sign_visible_with_default_style_and_others_in_config(
    cli_runner, cert_chain, user_key
):
    cfg = {
        'stamp-styles': {
            'test': {
                'type': 'text',
                'background': '__stamp__',
                'stamp_text': 'Blah',
            }
        },
    }
    _write_config(cfg)
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
    with open(SIGNED_OUTPUT_PATH, 'rb') as outf:
        r = PdfFileReader(outf)
        page = r.root['/Pages']['/Kids'][0]
        assert b'Digitally signed by' in page['/Annots'][0]['/AP']['/N'].data
    assert not result.exception, result.output


def test_cli_sign_visible_with_undefined_default_style(
    cli_runner, cert_chain, user_key
):
    cfg = {
        'default-stamp-style': 'undefined',
        'stamp-styles': {
            'test': {'type': 'text', 'background': '__stamp__'},
        },
    }
    _write_config(cfg)
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
    assert result.exit_code == 1
    assert "There is no stamp style named \'undefined\'" in result.output
