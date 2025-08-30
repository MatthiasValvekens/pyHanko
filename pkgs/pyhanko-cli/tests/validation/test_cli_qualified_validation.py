from datetime import timedelta
from io import BytesIO
from pathlib import Path

import pytest
from asn1crypto import pem
from certomancer.registry import CertLabel, EntityLabel, ServiceLabel
from pyhanko.cli import cli_root
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from test_data.samples import (
    CERTOMANCER,
    MINIMAL,
    MINIMAL_ONE_FIELD,
    TESTING_CA_ECDSA,
)

from ..conftest import (
    _write_config,
)
from .conftest import write_input_to_validate, write_ltv_input_to_validate

CACHE_DIR = "./cache"
TL_URL_SUFFIX = 'testing-ca-qualified/tl/root.xml'
LOTL_URL_SUFFIX = 'testing-ca-qualified/lotl.xml'
LOTL_TLSO_CERT_PATH = 'tlso.cert.pem'
TL_URL = f'{CERTOMANCER.external_url_prefix}/{TL_URL_SUFFIX}'
LOTL_URL = f'{CERTOMANCER.external_url_prefix}/{LOTL_URL_SUFFIX}'


@pytest.fixture(scope="module")
def pki_arch_name():
    return "qualified"


@pytest.fixture()
def signer_cert_label():
    return CertLabel("esig-qualified")


@pytest.fixture
def tl_cache(pki_arch):
    from pyhanko.sign.validation.qualified.eutl_fetch import FileSystemTLCache
    from test_data.certomancer_trust_lists import (
        certomancer_lotl,
        certomancer_pki_as_trusted_list,
    )

    tl_xml = certomancer_pki_as_trusted_list(pki_arch, EntityLabel('root'))

    lotl_xml = certomancer_lotl(
        pki_arch,
        EntityLabel('root'),
        [(CertLabel('root'), 'be', TL_URL)],
    )

    fs_cache = FileSystemTLCache(Path(CACHE_DIR) / 'eutl', timedelta(days=3650))
    fs_cache[TL_URL] = tl_xml
    fs_cache[LOTL_URL] = lotl_xml

    with open(LOTL_TLSO_CERT_PATH, 'wb') as tlso:
        tlso.write(
            pem.armor(
                "CERTIFICATE", pki_arch.get_cert(CertLabel('root')).dump()
            )
        )
    return fs_cache


@pytest.mark.nosmoke
def test_validate_eutl(cli_runner, input_to_validate, tl_cache):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_bogus_tl(cli_runner, input_to_validate, tl_cache):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    tl_cache[TL_URL] = '<bogus/>'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'judged INVALID' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_bogus_lotl(cli_runner, input_to_validate, tl_cache):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    tl_cache[LOTL_URL] = '<bogus/>'
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'Trust list processing failed' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_with_extra_roots_ca_is_extra(cli_runner, tl_cache):
    fname = 'to-validate.pdf'
    writer = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    write_input_to_validate(
        TESTING_CA_ECDSA,
        fname,
        writer,
    )
    with open('extra-root.cert.pem', 'wb') as tlso:
        tlso.write(
            pem.armor(
                "CERTIFICATE",
                TESTING_CA_ECDSA.get_cert(CertLabel('root')).dump(),
            )
        )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'trust': 'extra-root.cert.pem',
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            # Test plumbing doesn't easily allow setting up mocks for more
            # than one PKI architecture, so we disable revocation here.
            '--no-revocation-check',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_with_extra_roots_ca_on_tl(
    cli_runner, input_to_validate, tl_cache
):
    with open('extra-root.cert.pem', 'wb') as tlso:
        tlso.write(
            pem.armor(
                "CERTIFICATE",
                TESTING_CA_ECDSA.get_cert(CertLabel('root')).dump(),
            )
        )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'trust': 'extra-root.cert.pem',
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
@pytest.mark.parametrize('territories', ['be,fr', 'be', ['be', 'fr'], ['be']])
def test_validate_config_eutl_limited_territories(
    cli_runner, input_to_validate, tl_cache, territories
):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                    'eutl-territories': territories,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
@pytest.mark.parametrize('territories', ['de,fr', 'de', ['de', 'fr'], [], ''])
def test_validate_eutl_config_limited_territories_not_included(
    cli_runner, input_to_validate, tl_cache, territories
):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                    'eutl-territories': territories,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'judged INVALID' in result.output


@pytest.mark.nosmoke
@pytest.mark.parametrize('territories', ['de,fr', 'de', ['de', 'fr'], [], ''])
def test_validate_eutl_config_limited_territories_overridden_in_cli(
    cli_runner, input_to_validate, tl_cache, territories
):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                    'eutl-territories': territories,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
@pytest.mark.parametrize('territories', ['be,fr', 'be'])
def test_validate_arg_eutl_limited_territories(
    cli_runner, input_to_validate, tl_cache, territories
):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-territories',
            territories,
            input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
def test_validate_territories_arg_empty(cli_runner):
    with open('file.pdf', 'wb') as outf:
        outf.write(MINIMAL)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-territories',
            '',
            'file.pdf',
        ],
    )
    assert result.exit_code == 1
    assert 'must be non-empty' in result.output


@pytest.mark.nosmoke
def test_validate_inconsistent_eutl_args(cli_runner):
    with open('file.pdf', 'wb') as outf:
        outf.write(MINIMAL)

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            '--eutl-territories',
            'be',
            'file.pdf',
        ],
    )
    assert result.exit_code == 1
    assert 'mutually exclusive' in result.output


@pytest.mark.nosmoke
@pytest.mark.parametrize('territories', ['de,fr', 'de'])
def test_validate_eutl_arg_limited_territories_not_included(
    cli_runner, input_to_validate, tl_cache, territories
):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-territories',
            territories,
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'judged INVALID' in result.output


@pytest.mark.nosmoke
def test_force_attempt_eutl_download(
    cli_runner, input_to_validate, tl_cache, monkeypatch
):
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    from pyhanko.sign.validation.qualified import eutl_fetch

    monkeypatch.setattr(eutl_fetch, 'FETCH_TRIES', 1)
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--eutl-all',
            '--eutl-force-redownload',
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'Trust list processing failed' in result.output


@pytest.mark.nosmoke
@pytest.mark.parametrize('overloaded_trust', [True, False])
def test_validate_eutl_ades(
    cli_runner, pki_arch, tl_cache, root_cert, overloaded_trust
):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('esig-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    vc_settings = {
        'eutl-lotl-url': LOTL_URL,
        'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
    }
    if overloaded_trust:
        # Regression scenario against issue where registering
        # a CA on the TL independently via trust=[] would cause it
        # to be considered non-qualified (since non-listed roots
        # are registered as unqualified)
        vc_settings['trust'] = root_cert
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {'default': vc_settings},
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--pretty-print',
            '--eutl-all',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'The signer\'s certificate is qualified' in result.output
    assert 'qualified for electronic signatures' in result.output
    assert 'directly identified as a QTST' in result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_qual_required(
    cli_runner, pki_arch, tl_cache, root_cert
):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('esig-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--eutl-all',
            '--require-qualified',
            fname,
        ],
    )
    assert 'INTACT:TRUSTED' in result.output
    assert 'UNTRUSTED' not in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_not_qualified(cli_runner, pki_arch, tl_cache):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('not-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--pretty-print',
            '--eutl-all',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'The signer\'s certificate is not qualified' in result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_not_qualified_summary(
    cli_runner, pki_arch, tl_cache
):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('not-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--eutl-all',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'NOT_QUALIFIED' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_qualified_summary(cli_runner, pki_arch, tl_cache):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('esig-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--eutl-all',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'QUALIFIED' in result.output
    assert 'NOT_QUALIFIED' not in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_not_qualified_required(
    cli_runner, pki_arch, tl_cache
):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('not-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--eutl-all',
            '--require-qualified',
            fname,
        ],
    )
    assert result.exit_code == 1
    assert 'UNTRUSTED' in result.output
    assert 'NOT_QUALIFIED' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_tsa_not_qualified(cli_runner, pki_arch, tl_cache):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('esig-qualified'),
        tsa_label=ServiceLabel('tsa-not-qualified'),
    )
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {
                'default': {
                    'eutl-lotl-url': LOTL_URL,
                    'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
                }
            },
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--pretty-print',
            '--eutl-all',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'The signer\'s certificate is qualified' in result.output
    assert 'The time stamping authority is not qualified' in result.output
    assert 'judged VALID' in result.output


@pytest.mark.nosmoke
def test_validate_eutl_ades_point_in_time_no_revinfo(
    cli_runner, pki_arch, tl_cache, root_cert
):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('esig-qualified'),
        tsa_label=ServiceLabel('tsa-qualified'),
    )
    vc_settings = {
        'eutl-lotl-url': LOTL_URL,
        'lotl-tlso-certs': LOTL_TLSO_CERT_PATH,
    }
    _write_config(
        {
            'cache-dir': CACHE_DIR,
            'validation-contexts': {'default': vc_settings},
        }
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'adesverify',
            '--pretty-print',
            '--validation-time',
            '2025-03-01T22:00:00Z',
            '--no-revocation-check',
            '--eutl-all',
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'The signer\'s certificate is qualified' in result.output
    assert 'qualified for electronic signatures' in result.output
    assert 'directly identified as a QTST' in result.output
    assert 'judged VALID' in result.output
