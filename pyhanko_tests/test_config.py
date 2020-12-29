import pytest

from pyhanko import config, stamp
from pyhanko.config import StdLogOutput, DEFAULT_ROOT_LOGGER_LEVEL
from pyhanko.pdf_utils.config_utils import ConfigurationError
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.stamp import QRStampStyle, TextStampStyle
from pyhanko_tests.samples import TESTING_CA_DIR


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
