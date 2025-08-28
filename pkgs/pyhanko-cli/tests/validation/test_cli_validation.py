import datetime
import getpass
import re
from io import BytesIO

import pytest
from asn1crypto import pem
from certomancer import PKIArchitecture
from certomancer.registry import CertLabel
from freezegun import freeze_time
from pyhanko.cli import cli_root
from pyhanko.pdf_utils import writer
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from test_data.samples import (
    MINIMAL,
    MINIMAL_AES256,
    MINIMAL_ONE_FIELD,
    MINIMAL_PUBKEY_AES256,
    TESTING_CA,
)

from ..conftest import (
    FREEZE_DT,
    INPUT_PATH,
    _const,
    _write_cert,
    _write_config,
)
from .conftest import write_input_to_validate


def test_basic_validate(cli_runner, root_cert, input_to_validate):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_validate_encrypted_wrong_password(
    cli_runner, pki_arch, root_cert, monkeypatch
):
    fname = 'encrypted.pdf'
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_AES256))
    w.encrypt("ownersecret")
    write_input_to_validate(pki_arch, fname, w)

    monkeypatch.setattr(getpass, 'getpass', _const("badpassword"))
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert result.exit_code == 1
    assert "Password didn't match." in result.output


def test_validate_encrypted_empty_user_password(
    cli_runner, pki_arch, root_cert, monkeypatch
):
    fname = 'encrypted.pdf'
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    w.encrypt('ownersecret', '')
    write_input_to_validate(pki_arch, fname, w)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_validate_encrypted_empty_user_password_wrong_explicit_password(
    cli_runner, pki_arch, root_cert, monkeypatch
):
    fname = 'encrypted.pdf'
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    w.encrypt('ownersecret', '')
    write_input_to_validate(pki_arch, fname, w)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--password',
            'bogus',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert result.exit_code == 1
    assert "Password didn't match." in result.output


def test_validate_encrypted_explicit_empty_password(
    cli_runner, pki_arch, root_cert, monkeypatch
):
    fname = 'encrypted.pdf'
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    w.encrypt('ownersecret', '')
    write_input_to_validate(pki_arch, fname, w)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--password',
            '',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_validate_encrypted_wrong_explicit_empty_password(
    cli_runner, pki_arch, root_cert, monkeypatch
):
    fname = 'encrypted.pdf'
    r = PdfFileReader(BytesIO(MINIMAL_ONE_FIELD))
    w = writer.copy_into_new_writer(r)
    w.encrypt('ownersecret', 'usersecret')
    write_input_to_validate(pki_arch, fname, w)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--password',
            '',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert result.exit_code == 1
    assert "Password didn't match." in result.output


def test_validate_unsupported_handler(
    cli_runner, pki_arch, root_cert, monkeypatch
):
    fname = 'encrypted.pdf'

    with open(fname, 'wb') as outf:
        outf.write(MINIMAL_PUBKEY_AES256)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert result.exit_code == 1
    assert "only password-based encryption" in result.output


def test_basic_validate_summary(cli_runner, root_cert, input_to_validate):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--executive-summary',
            '--trust',
            root_cert,
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    pattern = re.compile("Sig1:.*:VALID$")
    assert pattern.match(result.output)


def test_basic_validate_pretty_print(cli_runner, root_cert, input_to_validate):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--trust',
            root_cert,
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


def test_basic_validate_with_validation_time(
    cli_runner, root_cert, input_to_validate
):
    with freeze_time(FREEZE_DT + datetime.timedelta(days=3650)):
        result = cli_runner.invoke(
            cli_root,
            [
                'sign',
                'validate',
                '--validation-time',
                f"{FREEZE_DT.date().isoformat()}",
                '--trust',
                root_cert,
                input_to_validate,
            ],
        )
        assert not result.exception, result.output
        assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_basic_validate_with_claimed_time(
    cli_runner, root_cert, input_to_validate
):
    with freeze_time(FREEZE_DT + datetime.timedelta(days=3650)):
        result = cli_runner.invoke(
            cli_root,
            [
                'sign',
                'validate',
                '--validation-time',
                'claimed',
                '--trust',
                root_cert,
                input_to_validate,
            ],
        )
        assert not result.exception, result.output
        assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_basic_validate_untrusted(cli_runner, root_cert, input_to_validate):
    with freeze_time(FREEZE_DT + datetime.timedelta(days=3650)):
        result = cli_runner.invoke(
            cli_root,
            [
                'sign',
                'validate',
                '--trust',
                root_cert,
                input_to_validate,
            ],
        )
        assert result.exit_code == 1


def test_basic_validate_with_weak_hash(cli_runner):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fname = write_input_to_validate(
        TESTING_CA, 'to_validate.pdf', w, weakened=True
    )
    root_cert = _write_cert(TESTING_CA, CertLabel('root'), 'root.cert.pem')
    _write_config({'validation-contexts': {'default': {'trust': root_cert}}})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            fname,
        ],
    )
    assert result.exit_code == 1
    assert 'sha1_rsa is not allowed' in result.output


@pytest.mark.parametrize('verbosity', ['default', 'verbose', 'pretty'])
def test_basic_validate_signed_with_wrong_key(cli_runner, verbosity):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fname = write_input_to_validate(
        TESTING_CA, 'to_validate.pdf', w, wrong_key=True
    )
    root_cert = _write_cert(TESTING_CA, CertLabel('root'), 'root.cert.pem')
    _write_config({'validation-contexts': {'default': {'trust': root_cert}}})
    result = cli_runner.invoke(
        cli_root,
        [
            *(('--verbose',) if verbosity == 'verbose' else ()),
            'sign',
            'validate',
            *(('--pretty-print',) if verbosity == 'pretty' else ()),
            fname,
        ],
    )
    assert result.exit_code == 1
    assert 'INVALID' in result.output
    if verbosity == 'pretty':
        assert 'unsound' in result.output
    else:
        assert 'unsound' not in result.output
    if verbosity == 'verbose':
        assert 'Running with --verbose' in result.output


def test_basic_validate_with_default_context(
    cli_runner, root_cert, input_to_validate
):
    _write_config({'validation-contexts': {'default': {'trust': root_cert}}})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_basic_validate_with_system_trust(cli_runner, input_to_validate):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1


def test_basic_validate_with_explicit_context(
    cli_runner, root_cert, input_to_validate
):
    _write_config({'validation-contexts': {'test': {'trust': root_cert}}})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--validation-context',
            'test',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


@pytest.mark.parametrize('setup_type', ['default', 'explicit'])
def test_basic_validate_context_config_wrong(cli_runner, setup_type):
    _write_config(
        {'validation-contexts': {setup_type: {'thismakesnosense': "blah"}}}
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            *(
                ()
                if setup_type == 'default'
                else ('--validation-context', setup_type)
            ),
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "validation context" in result.output


def test_basic_validate_context_without_config_file(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--validation-context',
            'test',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "No config file" in result.output


def test_basic_validate_context_incompatible_args(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--validation-context',
            'test',
            '--trust',
            INPUT_PATH,
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "--validation-context is incompatible with" in result.output


def test_basic_validate_context_file_not_found(cli_runner):
    _write_config(
        {'validation-contexts': {'test': {'trust': 'no-such-cert.crt'}}}
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--validation-context',
            'test',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "I/O problem" in result.output


def test_basic_validate_context_malformed_cert(cli_runner):
    with open('cert.crt', 'wb') as outf:
        outf.write(b"\xde\xad\xbe\xef")

    _write_config({'validation-contexts': {'test': {'trust': 'cert.crt'}}})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--validation-context',
            'test',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert "processing problem" in result.output


@pytest.fixture(params=['pem', 'der'])
def detached_input_to_validate(pki_arch: PKIArchitecture, request):
    outf = write_input_to_validate(pki_arch, 'detached.sig', w=None)
    if request.param == 'pem':
        with open(outf, 'rb') as derf:
            sig = derf.read()
        with open(outf, 'wb') as pemf:
            pemf.write(pem.armor('PKCS7', sig))
    return outf


def test_basic_detached_validate(
    cli_runner, root_cert, detached_input_to_validate
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--detached',
            detached_input_to_validate,
            '--trust',
            root_cert,
            INPUT_PATH,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED' in result.output
