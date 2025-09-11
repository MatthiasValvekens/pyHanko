import pytest
from certomancer.registry import CertLabel, ServiceLabel
from pyhanko.cli import cli_root

from .conftest import write_ltv_input_to_validate

# no ed448 timestamping in Certomancer
# FIXME deal with the bug on the Certomancer end
LTV_CERTOMANCER_ARCHITECTURES = ["rsa", "ecdsa", "ed25519"]


@pytest.fixture(scope="module", params=LTV_CERTOMANCER_ARCHITECTURES)
def pki_arch_name(request):
    return request.param


@pytest.fixture(scope="function")
def catch_ltv_warning():
    with pytest.warns(UserWarning, match="adesverify instead"):
        yield


def test_ltv_validate_success(
    cli_runner, root_cert, ltv_input_to_validate, catch_ltv_warning
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--ltv-profile',
            'pades-lta',
            '--trust',
            root_cert,
            ltv_input_to_validate,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED' in result.output
    assert 'TIMESTAMP_TOKEN<INTACT:TRUSTED>' in result.output
    assert 'EXTENDED_WITH_LTA_UPDATES' in result.output


def test_ltv_validate_adobe_style(
    cli_runner, pki_arch, root_cert, catch_ltv_warning
):
    fname = write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=CertLabel('signer1'),
        tsa_label=ServiceLabel('tsa'),
        pades_style=False,
    )
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--ltv-profile',
            'adobe',
            '--trust',
            root_cert,
            fname,
        ],
    )
    assert not result.exception, result.output
    assert 'INTACT:TRUSTED' in result.output
    assert 'TIMESTAMP_TOKEN<INTACT:TRUSTED>' in result.output
    assert 'UNTOUCHED' in result.output


def test_ltv_validate_fail_no_revinfo(
    cli_runner, root_cert, input_to_validate, catch_ltv_warning
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--ltv-profile',
            'pades-lta',
            '--trust',
            root_cert,
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'REVINFO_FAILURE' in result.output


def test_ltv_validate_fail_no_revinfo_pretty(
    cli_runner, root_cert, input_to_validate, catch_ltv_warning
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--pretty-print',
            '--ltv-profile',
            'pades-lta',
            '--trust',
            root_cert,
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'No DSS found' in result.output


def test_ltv_validate_not_compatible_with_validation_time(
    cli_runner, root_cert, input_to_validate
):
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'validate',
            '--ltv-profile',
            'pades-lta',
            '--validation-time',
            '2020-11-01T10:00:00',
            '--trust',
            root_cert,
            input_to_validate,
        ],
    )
    assert result.exit_code == 1
    assert 'not compatible with --ltv-profile' in result.output
