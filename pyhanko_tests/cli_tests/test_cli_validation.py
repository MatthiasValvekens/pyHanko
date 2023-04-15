import datetime
import getpass
import re
from io import BytesIO

import pytest
from certomancer import PKIArchitecture
from certomancer.registry import CertLabel, KeyLabel
from freezegun import freeze_time
from pyhanko_certvalidator.registry import SimpleCertificateStore

from pyhanko.cli import cli_root
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.sign import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko_tests.cli_tests.conftest import (
    FREEZE_DT,
    INPUT_PATH,
    _const,
    _write_config,
)
from pyhanko_tests.samples import MINIMAL, MINIMAL_AES256, MINIMAL_PUBKEY_AES256


def _write_input_to_validate(
    pki_arch: PKIArchitecture, fname: str, w: BasePdfFileWriter
):
    registry = SimpleCertificateStore()
    registry.register(pki_arch.get_cert(CertLabel('interm')))
    registry.register(pki_arch.get_cert(CertLabel('root')))
    signer = SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        cert_registry=registry,
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
    )
    with open(fname, 'wb') as outf:
        sign_pdf(
            pdf_out=w,
            signature_meta=PdfSignatureMetadata(field_name='Sig1'),
            signer=signer,
            output=outf,
        )
    return fname


@pytest.fixture(params=["regular", "encrypted"])
def input_to_validate(pki_arch: PKIArchitecture, monkeypatch, request):
    if request.param == "encrypted":
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_AES256))
        monkeypatch.setattr(getpass, 'getpass', value=_const('ownersecret'))
        w.encrypt(b"ownersecret")
    else:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    return _write_input_to_validate(pki_arch, 'to-validate.pdf', w)


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
    _write_input_to_validate(pki_arch, fname, w)

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
