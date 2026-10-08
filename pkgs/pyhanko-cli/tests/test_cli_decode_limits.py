from io import BytesIO

import pytest
from pyhanko.cli import cli_root
from pyhanko.pdf_utils.decode_limits import DecodeLimits
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_testing_commons.test_data.samples import (
    PUBKEY_TEST_DECRYPTER,
    minimal_with_oversized_objstm,
)

from .conftest import (
    DUMMY_PASSPHRASE,
    INPUT_PATH,
    SIGNED_OUTPUT_PATH,
    _write_config,
)
from .test_cli_crypt import (
    _pubkey_decryption_pemder,
    _pubkey_decryption_pkcs12,
)

FLAG = '--no-decode-limits'
OUTPUT_PATH = 'out.pdf'


@pytest.fixture(scope="module")
def pki_arch_name():
    return "rsa"


@pytest.fixture
def oversized_input():
    with open(INPUT_PATH, 'wb') as f:
        minimal_with_oversized_objstm().write(f)


def _check_flag(cli_runner, args):
    result = cli_runner.invoke(cli_root, [a for a in args if a != FLAG])
    assert result.exit_code == 1, result.output
    assert f"rerun with {FLAG}" in result.output

    result = cli_runner.invoke(cli_root, args)
    assert not result.exception, result.output


def _read_output(path: str) -> PdfFileReader:
    with open(path, 'rb') as f:
        data = f.read()
    return PdfFileReader(
        BytesIO(data), decode_limits=DecodeLimits.for_trusted_input()
    )


@pytest.mark.parametrize(
    'args',
    [
        ['encrypt', FLAG, '--password', 'secret', INPUT_PATH, OUTPUT_PATH],
        ['sign', 'list', FLAG, INPUT_PATH],
        [
            'sign',
            'addfields',
            FLAG,
            '--field',
            '1/0,0,100,100/Sig1',
            INPUT_PATH,
            OUTPUT_PATH,
        ],
        [
            'sign',
            'addfields',
            FLAG,
            '--resave',
            '--field',
            '1/0,0,100,100/Sig1',
            INPUT_PATH,
            OUTPUT_PATH,
        ],
    ],
    ids=['encrypt', 'list', 'addfields', 'addfields-resave'],
)
def test_simple_commands(cli_runner, oversized_input, args):
    _check_flag(cli_runner, args)


def test_text_stamp(cli_runner, oversized_input):
    _write_config({'stamp-styles': {'test': {'type': 'text'}}})
    _check_flag(
        cli_runner,
        [
            'stamp',
            FLAG,
            '--style-name',
            'test',
            INPUT_PATH,
            OUTPUT_PATH,
            '0',
            '0',
        ],
    )


@pytest.mark.nosmoke
def test_qr_stamp(cli_runner, oversized_input):
    _write_config({'stamp-styles': {'test': {'type': 'qr'}}})
    _check_flag(
        cli_runner,
        [
            'stamp',
            FLAG,
            '--style-name',
            'test',
            '--stamp-url',
            'https://example.com',
            INPUT_PATH,
            OUTPUT_PATH,
            '0',
            '0',
        ],
    )


def test_decrypt_password(cli_runner):
    w = minimal_with_oversized_objstm()
    w.encrypt('ownersecret', 'usersecret')
    with open(INPUT_PATH, 'wb') as f:
        w.write(f)
    _check_flag(
        cli_runner,
        [
            'decrypt',
            'password',
            FLAG,
            '--password',
            'ownersecret',
            INPUT_PATH,
            OUTPUT_PATH,
        ],
    )
    assert _read_output(OUTPUT_PATH).security_handler is None


@pytest.mark.parametrize('method', ['pemder', 'pkcs12'])
def test_decrypt_pubkey(cli_runner, method):
    w = minimal_with_oversized_objstm()
    w.encrypt_pubkey([PUBKEY_TEST_DECRYPTER.cert])
    with open(INPUT_PATH, 'wb') as f:
        w.write(f)
    if method == 'pemder':
        key_file, cert_file = _pubkey_decryption_pemder(PUBKEY_TEST_DECRYPTER)
        method_args = ['--key', key_file, '--cert', cert_file]
    else:
        method_args = [_pubkey_decryption_pkcs12(PUBKEY_TEST_DECRYPTER)]
    with open('passfile.txt', 'w', encoding='utf-8') as passf:
        passf.write('secret')
    _check_flag(
        cli_runner,
        [
            'decrypt',
            method,
            FLAG,
            '--force',
            '--passfile',
            'passfile.txt',
            INPUT_PATH,
            OUTPUT_PATH,
            *method_args,
        ],
    )
    assert _read_output(OUTPUT_PATH).security_handler is None


@pytest.fixture
def signing_config(p12_keys, root_cert):
    _write_config(
        {
            'pkcs12-setups': {
                'test': {
                    'pfx-file': p12_keys,
                    'pfx-passphrase': DUMMY_PASSPHRASE,
                }
            },
            'validation-contexts': {
                'test': {'trust': root_cert, 'trust-replace': True}
            },
        }
    )


def _addsig_args(timestamp_url, *extra_group_args):
    return [
        'sign',
        'addsig',
        FLAG,
        '--field',
        'Sig1',
        '--use-pades',
        '--timestamp-url',
        timestamp_url,
        *extra_group_args,
        'pkcs12',
        '--p12-setup',
        'test',
        INPUT_PATH,
        SIGNED_OUTPUT_PATH,
    ]


@pytest.mark.parametrize(
    'extra_group_args,expected_timestamps',
    [
        ((), 0),
        (('--validation-context', 'test', '--use-pades-lta'), 1),
    ],
    ids=['pades', 'pades-lta'],
)
def test_addsig(
    cli_runner,
    oversized_input,
    signing_config,
    timestamp_url,
    extra_group_args,
    expected_timestamps,
):
    _check_flag(cli_runner, _addsig_args(timestamp_url, *extra_group_args))
    r = _read_output(SIGNED_OUTPUT_PATH)
    assert len(r.embedded_regular_signatures) == 1
    assert len(r.embedded_timestamp_signatures) == expected_timestamps


def test_timestamp(cli_runner, oversized_input, signing_config, timestamp_url):
    _check_flag(
        cli_runner,
        [
            'sign',
            'timestamp',
            FLAG,
            '--validation-context',
            'test',
            '--timestamp-url',
            timestamp_url,
            INPUT_PATH,
            OUTPUT_PATH,
        ],
    )


@pytest.fixture
def signed_oversized_input(
    cli_runner, oversized_input, signing_config, timestamp_url
):
    result = cli_runner.invoke(cli_root, _addsig_args(timestamp_url))
    assert not result.exception, result.output


@pytest.mark.parametrize('command', ['validate', 'adesverify'])
def test_validate(cli_runner, signed_oversized_input, command):
    # an extra revision forces diff analysis to read the signed revision
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addfields',
            FLAG,
            '--field',
            '1/0,0,100,100/Sig2',
            SIGNED_OUTPUT_PATH,
            OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output
    _check_flag(
        cli_runner,
        [
            'sign',
            command,
            FLAG,
            '--validation-context',
            'test',
            '--no-revocation-check',
            OUTPUT_PATH,
        ],
    )


def test_ltaupdate(cli_runner, signed_oversized_input, timestamp_url):
    _check_flag(
        cli_runner,
        [
            'sign',
            'ltaupdate',
            FLAG,
            '--validation-context',
            'test',
            '--timestamp-url',
            timestamp_url,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert len(_read_output(SIGNED_OUTPUT_PATH).embedded_timestamp_signatures)


def test_ltvfix(cli_runner, signed_oversized_input, timestamp_url):
    _check_flag(
        cli_runner,
        [
            'sign',
            'ltvfix',
            FLAG,
            '--field',
            'Sig1',
            '--validation-context',
            'test',
            '--timestamp-url',
            timestamp_url,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert len(_read_output(SIGNED_OUTPUT_PATH).embedded_timestamp_signatures)
