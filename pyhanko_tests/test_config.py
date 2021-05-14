from datetime import timedelta

import pytest

from pyhanko import config, stamp
from pyhanko.config import StdLogOutput, DEFAULT_ROOT_LOGGER_LEVEL, \
    DEFAULT_TIME_TOLERANCE, init_validation_context_kwargs
from pyhanko.pdf_utils.config_utils import ConfigurationError
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.stamp import QRStampStyle, TextStampStyle
from pyhanko_tests.samples import TESTING_CA_DIR


@pytest.mark.parametrize('trust_replace', [True, False])
def test_read_vc_kwargs(trust_replace):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            trust-replace: {'true' if trust_replace else 'false'}
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
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

    ku = cli_config.get_signer_key_usages()
    assert ku.key_usage is None
    assert ku.extd_key_usage is None

    with pytest.raises(ConfigurationError):
        cli_config.get_validation_context('theresnosuchvc')


def test_read_qr_config():
    from pyhanko_tests.test_utils import NOTO_SERIF_JP
    from pyhanko.pdf_utils.font import GlyphAccumulatorFactory, SimpleFontEngine

    config_string = f"""
    stamp-styles:
        default:
            text-box-style:
                font: {NOTO_SERIF_JP}
            type: qr
            background: __stamp__
        alternative1:
            text-box-style:
                font: {NOTO_SERIF_JP}
            background: pyhanko_tests/data/img/stamp-indexed.png
            type: qr
        alternative2:
            type: qr
        alternative3:
            type: text
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    default_qr_style = cli_config.get_stamp_style()
    assert isinstance(default_qr_style, QRStampStyle)
    assert default_qr_style.background is stamp.STAMP_ART_CONTENT
    assert isinstance(default_qr_style.text_box_style.font,
                      GlyphAccumulatorFactory)

    alternative1 = cli_config.get_stamp_style('alternative1')
    assert isinstance(alternative1, QRStampStyle)
    assert isinstance(alternative1.background, PdfImage)
    assert isinstance(alternative1.text_box_style.font,
                      GlyphAccumulatorFactory)

    alternative2 = cli_config.get_stamp_style('alternative2')
    assert isinstance(alternative2, QRStampStyle)
    assert alternative2.background is None
    assert isinstance(alternative2.text_box_style.font, SimpleFontEngine)

    alternative3 = cli_config.get_stamp_style('alternative3')
    assert isinstance(alternative3, TextStampStyle)
    assert alternative3.background is None
    assert isinstance(alternative3.text_box_style.font, SimpleFontEngine)

    with pytest.raises(ConfigurationError):
        cli_config.get_stamp_style('theresnosuchstyle')


def test_read_bad_config():
    config_string = f"""
    stamp-styles:
        default:
            type: qr
            blah: blah
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_stamp_style()


@pytest.mark.parametrize("bad_type", ['5', '[1,2,3]'])
def test_read_bad_config2(bad_type):
    config_string = f"""
    stamp-styles:
        default: {bad_type}
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_stamp_style()


def test_empty_config():
    cli_config: config.CLIConfig = config.parse_cli_config("")
    vc_kwargs = cli_config.get_validation_context(as_dict=True)
    assert 'extra_trust_roots' not in vc_kwargs
    assert 'trust_roots' not in vc_kwargs
    assert 'other_certs' not in vc_kwargs


def test_read_logging_config():
    config_string = """
    logging:
        root-level: DEBUG
        root-output: stdout
        by-module:
            example.test1:
                level: 50
                output: test.log
            example.test2:
                level: DEBUG
            example.test3:
                level: 10
                output: stderr
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)

    assert cli_config.log_config[None].output == StdLogOutput.STDOUT
    assert cli_config.log_config[None].level == 'DEBUG'

    assert cli_config.log_config['example.test1'].level == 50
    assert cli_config.log_config['example.test1'].output == 'test.log'
    assert cli_config.log_config['example.test2'].level == 'DEBUG'
    assert cli_config.log_config['example.test2'].output == StdLogOutput.STDERR
    assert cli_config.log_config['example.test3'].level == 10
    assert cli_config.log_config['example.test3'].output == StdLogOutput.STDERR


def test_read_logging_config_defaults():
    cli_config: config.CLIConfig = config.parse_cli_config("""
        logging:
            root-level: DEBUG
    """)

    assert cli_config.log_config[None].output == StdLogOutput.STDERR
    assert cli_config.log_config[None].level == 'DEBUG'
    assert list(cli_config.log_config.keys()) == [None]

    cli_config: config.CLIConfig = config.parse_cli_config("""
        logging:
            root-output: 'test.log'
    """)

    assert cli_config.log_config[None].output == 'test.log'
    assert cli_config.log_config[None].level == DEFAULT_ROOT_LOGGER_LEVEL
    assert list(cli_config.log_config.keys()) == [None]

    cli_config: config.CLIConfig = config.parse_cli_config("")
    assert cli_config.log_config[None].output == StdLogOutput.STDERR
    assert cli_config.log_config[None].level == DEFAULT_ROOT_LOGGER_LEVEL
    assert list(cli_config.log_config.keys()) == [None]


WRONG_CONFIGS = [
    # a bunch of type errors
    "logging: 5",
    """
    logging:
        by-module: 1
    """,
    """
    logging:
        root-output: [1, 2]
    """,
    """
    logging:
        root-level: [2, 3]
    """,
    """
    logging:
        by-module:
            test.example:
                level: 10
                output: 5
    """,
    """
    logging:
        by-module:
            0:
                level: 10
                
    """,
    # level is required for non-root logging specs
    """
    logging:
        by-module:
            test.example:
                output: 'abc.log'
    """
]


@pytest.mark.parametrize('config_str', WRONG_CONFIGS)
def test_read_logging_config_errors(config_str):
    with pytest.raises(ConfigurationError):
        config.parse_cli_config(config_str)


@pytest.mark.parametrize('key_usage_str, key_usages', [
    ('non_repudiation', {'non_repudiation'}),
    ('[non_repudiation, digital_signature]',
     {'non_repudiation', 'digital_signature'}),
    ('[]', set()),
])
def test_read_key_usage(key_usage_str, key_usages):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage == key_usages
    assert key_usage_settings.extd_key_usage is None


@pytest.mark.parametrize('key_usage_str, key_usages', [
    ('piv_content_signing', {'piv_content_signing'}),
    ('[piv_content_signing, code_signing]',
     {'piv_content_signing', 'code_signing'}),
    ('[]', set()),
    ('[2.16.840.1.101.3.6.7, code_signing]',
     {'piv_content_signing', 'code_signing'}),
    ('[2.16.840.1.101.3.6.7, "2.999"]',
     {'piv_content_signing', '2.999'}),
    ('2.16.840.1.101.3.6.7', {'piv_content_signing'}),
    ('"2.999"', {'2.999'}),
])
def test_read_extd_key_usage(key_usage_str, key_usages):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-extd-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage is None
    assert key_usage_settings.extd_key_usage == key_usages
    assert not key_usage_settings.match_all_key_usages


def test_read_key_usage_policy_1():
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage-policy:
                key-usage: [digital_signature, non_repudiation]
                match-all-key-usages: true
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage \
           == {'digital_signature', 'non_repudiation'}
    assert key_usage_settings.key_usage_forbidden is None
    assert key_usage_settings.extd_key_usage is None
    assert key_usage_settings.match_all_key_usages


def test_read_key_usage_policy_2():
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage-policy:
                key-usage: [digital_signature, non_repudiation]
                extd-key-usage: '2.999'
                explicit-extd-key-usage-required: true
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage \
           == {'digital_signature', 'non_repudiation'}
    assert key_usage_settings.extd_key_usage == {'2.999'}
    assert key_usage_settings.explicit_extd_key_usage_required


def test_read_key_usage_policy_3():
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage-policy:
                key-usage: [digital_signature, non_repudiation]
                key-usage-forbidden: data_encipherment
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage \
           == {'digital_signature', 'non_repudiation'}
    assert key_usage_settings.key_usage_forbidden == {'data_encipherment'}
    assert key_usage_settings.extd_key_usage is None
    assert not key_usage_settings.match_all_key_usages


@pytest.mark.parametrize('key_usage_str', [
    '0', '["non_repudiation", 2]', "[1, 2, 3]", "abcdef",
    '["no_such_key_usage"]',
])
def test_extd_key_usage_errors(key_usage_str):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-extd-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_signer_key_usages()


@pytest.mark.parametrize('key_usage_str', [
    '0', '["non_repudiation", 2]', "[1, 2, 3]", "abcdef",
    '["no_such_key_usage"]',
])
def test_key_usage_errors(key_usage_str):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_signer_key_usages()


@pytest.mark.parametrize('config_string, result', [
    (f"""
    time-tolerance: 5
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, 5),
    (f"""
    time-tolerance: 5
    validation-contexts:
        default:
            time-tolerance: 7
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, 7),
    (f"""
    validation-contexts:
        default:
            time-tolerance: 7
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, 7),

    (f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, DEFAULT_TIME_TOLERANCE)
])
def test_read_time_tolerance(config_string, result):
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    vc_kwargs = cli_config.get_validation_context(as_dict=True)
    assert vc_kwargs['time_tolerance'] == timedelta(seconds=result)


def test_read_time_tolerance_input_issues():
    config_string = f"""
    validation-contexts:
        default:
            time-tolerance: "this makes no sense"
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
    """
    with pytest.raises(ConfigurationError, match='time-tolerance.*'):
        cli_config: config.CLIConfig = config.parse_cli_config(config_string)
        cli_config.get_validation_context(as_dict=True)

    config_string = f"""
    time-tolerance: "this makes no sense"
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
    """
    with pytest.raises(ConfigurationError, match='time-tolerance.*'):
        cli_config: config.CLIConfig = config.parse_cli_config(config_string)
        cli_config.get_validation_context(as_dict=True)

    vc_kwargs = init_validation_context_kwargs(
        trust=[], trust_replace=False, other_certs=[]
    )
    assert 'retroactive_revinfo' not in vc_kwargs
    assert vc_kwargs['time_tolerance'] == timedelta(
        seconds=DEFAULT_TIME_TOLERANCE
    )


@pytest.mark.parametrize('config_string, result', [
    (f"""
    retroactive-revinfo: true
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, True),
    (f"""
    retroactive-revinfo: true
    validation-contexts:
        default:
            retroactive-revinfo: false
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, False),
    (f"""
    retroactive-revinfo: false
    validation-contexts:
        default:
            retroactive-revinfo: true
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, True),
    (f"""
    validation-contexts:
        default:
            retroactive-revinfo: true
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, True),
    (f"""
    validation-contexts:
        default:
            retroactive-revinfo: "yes"
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, True),
    (f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """, False)
])
def test_read_retroactive_revinfo(config_string, result):
    cli_config: config.CLIConfig = config.parse_cli_config(config_string)
    vc_kwargs = cli_config.get_validation_context(as_dict=True)
    if result is False:
        assert 'retroactive_revinfo' not in vc_kwargs
    else:
        assert vc_kwargs['retroactive_revinfo']
