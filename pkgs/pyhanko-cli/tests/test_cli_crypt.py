import getpass
from io import BytesIO

import pytest
from cryptography import x509 as pyca_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.cli import cli_root

from pyhanko.pdf_utils import writer
from pyhanko.pdf_utils.crypt import (
    AuthStatus,
    PubKeySecurityHandler,
    SecurityHandlerVersion,
)
from pyhanko.pdf_utils.crypt.permissions import PubKeyPermissions
from pyhanko.pdf_utils.crypt.pubkey import RecipientEncryptionPolicy
from pyhanko.pdf_utils.reader import PdfFileReader
from test_data.samples import (
    MINIMAL,
    MINIMAL_AES256,
    MINIMAL_PUBKEY_AES256,
    PUBKEY_SELFSIGNED_DECRYPTER,
    PUBKEY_TEST_DECRYPTER,
)

from .conftest import INPUT_PATH, _const


def _test_password(fname, password, expected_status=AuthStatus.OWNER):
    with open(fname, 'rb') as inf:
        r = PdfFileReader(inf)
        auth_result = r.decrypt(password)
        assert auth_result.status == expected_status


def test_encrypt_file(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['encrypt', '--password', 'secret', INPUT_PATH, 'out.pdf'],
    )
    assert not result.exception, result.output

    _test_password('out.pdf', 'secret')


def test_encrypt_file_with_stdin_pass(cli_runner, monkeypatch):
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))
    result = cli_runner.invoke(
        cli_root,
        ['encrypt', INPUT_PATH, 'out.pdf'],
    )
    assert not result.exception, result.output

    _test_password('out.pdf', 'secret')


def test_encrypt_file_with_recipient_cert(cli_runner):
    cert_file = 'recipient.crt'
    with open(cert_file, 'wb') as certf:
        certf.write(PUBKEY_TEST_DECRYPTER.cert.dump())
    result = cli_runner.invoke(
        cli_root,
        [
            'encrypt',
            '--recipient',
            cert_file,
            INPUT_PATH,
            'out.pdf',
        ],
    )
    assert not result.exception, result.output

    with open('out.pdf', 'rb') as inf:
        r = PdfFileReader(inf)
        auth_result = r.decrypt_pubkey(PUBKEY_TEST_DECRYPTER)
        assert auth_result.status == AuthStatus.USER


def test_encrypt_not_both_pubkey_and_password(cli_runner):
    cert_file = 'recipient.crt'
    with open(cert_file, 'wb') as certf:
        certf.write(PUBKEY_SELFSIGNED_DECRYPTER.cert.dump())
    result = cli_runner.invoke(
        cli_root,
        [
            'encrypt',
            '--recipient',
            cert_file,
            '--password',
            'blah',
            INPUT_PATH,
            'out.pdf',
        ],
    )
    assert result.exit_code == 1
    assert 'Specify either' in result.output


def _check_first_page(decrypted_out):
    with open(decrypted_out, 'rb') as inf:
        r = PdfFileReader(inf)
        page_content = r.root['/Pages']['/Kids'][0]['/Contents'].data
        assert b'Hello' in page_content


def test_decrypt_with_owner_password(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            '--password',
            'ownersecret',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_decrypt_with_owner_password_on_stdin(cli_runner, monkeypatch):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    monkeypatch.setattr(getpass, 'getpass', _const('ownersecret'))
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_force_decrypt_with_user_password(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            '--password',
            'usersecret',
            '--force',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_decrypt_with_user_password_no_force(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            '--password',
            'usersecret',
            INPUT_PATH,
            output_path,
        ],
    )
    assert result.exit_code == 1
    assert "Pass --force" in result.output


def test_attempt_decrypt_unencrypted_file(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL)
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            '--password',
            'ownersecret',
            INPUT_PATH,
            output_path,
        ],
    )
    assert result.exit_code == 1
    assert "File is not encrypted" in result.output


def test_attempt_decrypt_wrong_sh_type(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            '--password',
            'ownersecret',
            INPUT_PATH,
            output_path,
        ],
    )
    assert result.exit_code == 1
    assert "File is not encrypted with" in result.output


def test_decrypt_with_wrong_password(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'password',
            '--password',
            'wrong_password',
            INPUT_PATH,
            output_path,
        ],
    )
    assert result.exit_code == 1
    assert "didn't match" in result.output


def _pubkey_decryption_pemder(
    decrypter,
    enc: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(
        b"secret"
    ),
):
    cert_file = 'recipient.crt'
    with open(cert_file, 'wb') as certf:
        certf.write(decrypter.cert.dump())

    key_file = 'recipient.key'

    key = decrypter.private_key
    key_handle = serialization.load_der_private_key(key.dump(), password=None)
    pem_bytes = key_handle.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )

    with open(key_file, 'wb') as outf:
        outf.write(pem_bytes)

    return key_file, cert_file


def _pubkey_decryption_pkcs12(decrypter):
    key = decrypter.private_key
    key_handle = serialization.load_der_private_key(key.dump(), password=None)

    cert = decrypter.cert
    cert_handle = pyca_x509.load_der_x509_certificate(cert.dump())

    out = 'recipient.p12'
    with open(out, 'wb') as outf:
        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=None,
            key=key_handle,
            cert=cert_handle,
            cas=[],
            encryption_algorithm=serialization.BestAvailableEncryption(
                b"secret"
            ),
        )
        outf.write(p12_bytes)
    return out


@pytest.fixture(params=['pkcs12', 'pemder'])
def pubkey_decryption(request):
    if request.param == 'pemder':
        key_file, cert_file = _pubkey_decryption_pemder(
            PUBKEY_SELFSIGNED_DECRYPTER
        )
        return ('pemder', ['--key', key_file, '--cert', cert_file])
    else:
        p12_file = _pubkey_decryption_pkcs12(PUBKEY_SELFSIGNED_DECRYPTER)
        return ('pkcs12', [p12_file])


def _sample_with_forbidden_encryption_change(h):

    r = PdfFileReader(BytesIO(MINIMAL))
    w = writer.copy_into_new_writer(r)

    sh = PubKeySecurityHandler.build_from_certs(
        [PUBKEY_SELFSIGNED_DECRYPTER.cert],
        version=SecurityHandlerVersion.AES256,
        keylen_bytes=32,
        use_aes=True,
        use_crypt_filters=True,
        perms=~PubKeyPermissions.ALLOW_ENCRYPTION_CHANGE,
        policy=RecipientEncryptionPolicy(ignore_key_usage=True),
    )
    w._assign_security_handler(sh)
    w.write(h)


@pytest.mark.parametrize('force', [True, False])
def test_decrypt_with_private_key(
    cli_runner, pubkey_decryption, monkeypatch, force
):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            *(('--force',) if force else ()),
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_decrypt_with_private_key_no_force_change_of_encryption_forbidden(
    cli_runner, pubkey_decryption, monkeypatch
):
    with open(INPUT_PATH, 'wb') as inf:
        _sample_with_forbidden_encryption_change(inf)
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert result.exit_code == 1
    assert "Pass --force" in result.output


def test_decrypt_with_private_key_force_change_of_encryption_forbidden(
    cli_runner, pubkey_decryption, monkeypatch
):
    with open(INPUT_PATH, 'wb') as inf:
        _sample_with_forbidden_encryption_change(inf)
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            '--force',
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_decrypt_with_private_key_and_passfile(cli_runner, pubkey_decryption):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)

    with open('passfile', 'w') as passf:
        passf.write("secret")

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            '--force',
            '--passfile',
            'passfile',
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_attempt_decrypt_with_private_key_unencrypted_file(
    cli_runner, pubkey_decryption, monkeypatch
):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL)
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            '--force',
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert result.exit_code == 1
    assert "File is not encrypted" in result.output


def test_attempt_decrypt_with_private_key_sh_type_mismatch(
    cli_runner, pubkey_decryption, monkeypatch
):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_AES256)
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            '--force',
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert result.exit_code == 1
    assert "File was not encrypted with" in result.output


def test_attempt_decrypt_with_non_matching_key(cli_runner, monkeypatch):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)
    p12_file = _pubkey_decryption_pkcs12(PUBKEY_TEST_DECRYPTER)
    monkeypatch.setattr(getpass, 'getpass', _const('secret'))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'pkcs12',
            '--force',
            INPUT_PATH,
            output_path,
            p12_file,
        ],
    )
    assert result.exit_code == 1
    assert "Failed to decrypt" in result.output


def test_decrypt_with_private_key_no_pass(cli_runner):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)
    key_file, cert_file = _pubkey_decryption_pemder(
        PUBKEY_SELFSIGNED_DECRYPTER, enc=serialization.NoEncryption()
    )

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            'pemder',
            '--key',
            key_file,
            '--cert',
            cert_file,
            '--no-pass',
            '--force',
            INPUT_PATH,
            output_path,
        ],
    )
    assert not result.exception, result.output
    _check_first_page(output_path)


def test_decrypt_with_private_key_empty_pass_on_stdin(
    cli_runner, pubkey_decryption, monkeypatch
):
    with open(INPUT_PATH, 'wb') as inf:
        inf.write(MINIMAL_PUBKEY_AES256)
    monkeypatch.setattr(getpass, 'getpass', _const(''))

    output_path = 'out.pdf'
    result = cli_runner.invoke(
        cli_root,
        [
            'decrypt',
            pubkey_decryption[0],
            '--force',
            INPUT_PATH,
            output_path,
            *pubkey_decryption[1],
        ],
    )
    assert result.exit_code == 1
