from datetime import timedelta
from io import BytesIO

import pytest
from certomancer.registry import CertLabel, KeyLabel
from pyhanko.cli import cli_root
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore
from test_data.samples import MINIMAL, TESTING_CA

from .conftest import (
    DUMMY_PASSPHRASE,
    FREEZE_DT,
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


@pytest.mark.parametrize('pki_arch_name', ['rsa'])
def test_cli_ltvfix_validation(
    pki_arch, timestamp_url, cli_runner, root_cert, p12_keys, pki_arch_name
):
    cfg = {
        'retroactive-revinfo': True,
        'time-tolerance': 1,
        'pkcs12-setups': {
            'test': {
                'pfx-file': p12_keys,
                'pfx-passphrase': DUMMY_PASSPHRASE,
            }
        },
        'validation-contexts': {
            'test': {
                'trust': root_cert,
            }
        },
    }

    _write_config(cfg)
    # sign an hour before the standard time
    registry = SimpleCertificateStore()
    signing_cert_spec = pki_arch.get_cert_spec(CertLabel('signer1'))
    registry.register(
        pki_arch.get_cert(signing_cert_spec.resolve_issuer_cert(pki_arch))
    )
    root_cert = pki_arch.get_cert(CertLabel('root'))
    registry.register(root_cert)
    signer = SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel('signer1')),
        cert_registry=registry,
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
    )
    timestamper = DummyTimeStamper(
        tsa_cert=pki_arch.get_cert(CertLabel('tsa')),
        tsa_key=pki_arch.key_set.get_private_key(KeyLabel('tsa')),
        fixed_dt=FREEZE_DT - timedelta(hours=1),
    )

    with open(SIGNED_OUTPUT_PATH, 'wb') as outf:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
        sign_pdf(
            pdf_out=w,
            signature_meta=PdfSignatureMetadata(field_name='Sig1'),
            signer=signer,
            timestamper=timestamper,
            output=outf,
        )

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'ltvfix',
            '--field',
            'Sig1',
            '--validation-context',
            'test',
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output

    with pytest.warns(UserWarning, match="adesverify instead"):
        result = cli_runner.invoke(
            cli_root,
            [
                'sign',
                'validate',
                '--ltv-profile',
                'pades',
                '--validation-context',
                'test',
                SIGNED_OUTPUT_PATH,
            ],
        )
        assert not result.exception, result.output
