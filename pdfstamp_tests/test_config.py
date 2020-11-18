import pytest

from pdfstamp import config
from pdfstamp_tests.samples import TESTING_CA_DIR


@pytest.mark.parametrize('trust_replace', [True, False])
def test_read_vc_kwargs(trust_replace):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/certs/ca.cert.pem'
            trust-replace: {'true' if trust_replace else 'false'}
            other-certs: '{TESTING_CA_DIR}/intermediate/certs/ca-chain.cert.pem'
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    vc_kwargs = cli_config.get_validation_context(as_dict=True)
    assert len(vc_kwargs['other_certs']) == 2
    if trust_replace:
        assert 'extra_trust_roots' not in vc_kwargs
        assert len(vc_kwargs['trust_roots']) == 1
    else:
        assert 'trust_roots' not in vc_kwargs
        assert len(vc_kwargs['extra_trust_roots']) == 1



def test_empty_config():
    cli_config: config.CLIConfig = config.parse_cli_config("")
    vc_kwargs = cli_config.get_validation_context(as_dict=True)
    assert 'extra_trust_roots' not in vc_kwargs
    assert 'trust_roots' not in vc_kwargs
    assert 'other_certs' not in vc_kwargs
