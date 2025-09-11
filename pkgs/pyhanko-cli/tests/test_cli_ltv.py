import pytest
from certomancer.registry import CertLabel
from pyhanko.cli import cli_root
from pyhanko.pdf_utils.reader import PdfFileReader
from test_data.samples import TESTING_CA

from .conftest import (
    DUMMY_PASSPHRASE,
    INPUT_PATH,
    LTV_CERTOMANCER_ARCHITECTURES,
    SIGNED_OUTPUT_PATH,
    _write_cert,
    _write_config,
)


@pytest.fixture(scope="module", params=LTV_CERTOMANCER_ARCHITECTURES)
def pki_arch_name(request):
    return request.param


def test_cli_lta_update(
    pki_arch_name, timestamp_url, cli_runner, root_cert, p12_keys
):
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


@pytest.mark.parametrize('with_lta_timestamp', [True, False])
def test_cli_ltvfix(
    pki_arch_name,
    timestamp_url,
    cli_runner,
    root_cert,
    p12_keys,
    with_lta_timestamp,
):
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
            *(('--timestamp-url', timestamp_url) if with_lta_timestamp else ()),
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output

    with open(SIGNED_OUTPUT_PATH, 'rb') as f:
        r = PdfFileReader(f)
        if with_lta_timestamp:
            assert len(r.embedded_timestamp_signatures) == 1
        else:
            assert not r.embedded_timestamp_signatures


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
