import datetime
import getpass
import re
from io import BytesIO

import pytest
from asn1crypto import cms, pem
from certomancer import PKIArchitecture
from certomancer.registry import CertLabel, KeyLabel
from freezegun import freeze_time
from pyhanko.cli import cli_root
from pyhanko.pdf_utils import writer
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko_certvalidator.registry import SimpleCertificateStore
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


@pytest.mark.parametrize('pki_mocks_enabled', [False])
def test_basic_validate_fail_without_revinfo(
    cli_runner, root_cert, input_to_validate, pki_mocks_enabled
):
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
    assert 'INTACT:UNTRUSTED' in result.output


@pytest.mark.parametrize('pki_mocks_enabled', [True, False])
def test_basic_validate_with_soft_revocation(
    cli_runner, root_cert, input_to_validate, pki_mocks_enabled
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            '--soft-revocation-check',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_basic_validate_with_required_revinfo(
    cli_runner, root_cert, input_to_validate
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            '--force-revinfo',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


@pytest.mark.parametrize('pki_mocks_enabled', [False])
def test_basic_validate_fail_without_required_revinfo(
    cli_runner, root_cert, input_to_validate, pki_mocks_enabled
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            '--force-revinfo',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1, result.output
    assert 'UNTRUSTED' in result.output


@pytest.mark.parametrize('pki_mocks_enabled', [False])
def test_basic_validate_without_revinfo_check(
    cli_runner, root_cert, input_to_validate, pki_mocks_enabled
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            '--no-revocation-check',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


@pytest.mark.parametrize('pki_mocks_enabled', [False])
def test_inconsistent_revo_settings(
    cli_runner, root_cert, input_to_validate, pki_mocks_enabled
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            '--no-revocation-check',
            '--soft-revocation-check',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'incompatible' in result.output


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


def test_validate_inconsistent_print_settings(cli_runner):
    with open('file.pdf', 'wb') as inf:
        inf.write(MINIMAL)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--executive-summary',
            '--pretty-print',
            'file.pdf',
        ],
    )
    assert result.exit_code == 1
    assert 'incompatible' in result.output


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


def test_validation_time_syntax_error(
    cli_runner,
):
    with open('file.pdf', 'wb') as inf:
        inf.write(MINIMAL_ONE_FIELD)

    with freeze_time(FREEZE_DT + datetime.timedelta(days=3650)):
        result = cli_runner.invoke(
            cli_root,
            [
                'sign',
                'validate',
                '--validation-time',
                '2020-99-99T99:99:99Z',
                'file.pdf',
            ],
        )
        assert result.exit_code == 1
        assert 'could not be parsed'


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


@pytest.mark.parametrize('pretty', [True, False])
def test_basic_validate_with_weak_hash(cli_runner, pretty):
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
            *(('--pretty-print',) if pretty else ()),
            fname,
        ],
    )
    assert result.exit_code == 1
    assert 'An error occurred while' in result.output
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


def _write_input_to_validate_with_missing_intermediate(pki_arch):
    fname = 'to-validate.pdf'
    registry = SimpleCertificateStore()
    registry.register(pki_arch.get_cert(CertLabel('root')))
    signer = SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        cert_registry=registry,
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
    )

    out = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(out)
    sign_pdf(
        pdf_out=w,
        signature_meta=PdfSignatureMetadata(field_name='Sig1'),
        signer=signer,
        in_place=True,
    )
    with open(fname, 'wb') as outf:
        outf.write(out.getvalue())
    return fname


def test_basic_validate_lacking_intermediate(
    cli_runner,
    root_cert,
    pki_arch,
):
    fname = _write_input_to_validate_with_missing_intermediate(pki_arch)
    with open('interm.crt', 'wb') as outf:
        outf.write(pki_arch.get_cert(CertLabel('interm')).dump())
    _write_config(
        {
            'validation-contexts': {
                'default': {'trust': root_cert, 'other-certs': 'interm.crt'}
            }
        }
    )

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED,UNTOUCHED' in result.output


def test_basic_validate_lacking_intermediate_with_trust_arg(
    cli_runner,
    root_cert,
    pki_arch,
):
    fname = _write_input_to_validate_with_missing_intermediate(pki_arch)
    with open('interm.crt', 'wb') as outf:
        outf.write(pki_arch.get_cert(CertLabel('interm')).dump())
    _write_config({'validation-contexts': {'default': {}}})

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--trust',
            root_cert,
            '--other-certs',
            'interm.crt',
            fname,
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


@pytest.mark.parametrize('setup_type', ['default', 'explicit'])
def test_basic_validate_context_config_nonsensical_other_certs(
    cli_runner, setup_type
):
    _write_config({'validation-contexts': {setup_type: {'other-certs': 1234}}})
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
def detached_input_type(request):
    return request.param


@pytest.fixture
def detached_input_to_validate(pki_arch: PKIArchitecture, detached_input_type):
    outf = write_input_to_validate(pki_arch, 'detached.sig', w=None)
    if detached_input_type == 'pem':
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


@pytest.mark.parametrize('detached_input_type', ['der'])
def test_fail_detached_validate(
    cli_runner, root_cert, detached_input_to_validate, detached_input_type
):
    with open(detached_input_to_validate, 'rb') as inf:
        d = inf.read()
    d = d[:-4] + b"\xde\xad\xbe\xef"
    with open(detached_input_to_validate, 'wb') as inf:
        inf.write(d)

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
    assert result.exit_code == 1
    assert 'Error: INVALID' in result.output


def test_detached_validate_malformed_input(
    cli_runner,
):
    with open('data.pem', 'wb') as f:
        f.write(b"\xde\xad\xbe\xef")

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--detached',
            'data.pem',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert 'Could not parse CMS object' in result.output


def test_detached_validate_bad_cms_type(
    cli_runner,
):
    with open('data.der', 'wb') as f:
        f.write(cms.ContentInfo({'content_type': 'data'}).dump())

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--detached',
            'data.der',
            INPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert 'CMS content type is not signedData' in result.output
