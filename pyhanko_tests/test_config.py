import pytest

from pyhanko import config, stamp
from pyhanko.misc import ConfigurationError
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


def test_read_qr_config():
    from pyhanko_tests.test_utils import NOTO_SERIF_JP
    from pyhanko.pdf_utils.font import GlyphAccumulator, SimpleFontEngine

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
    assert isinstance(default_qr_style.text_box_style.font, GlyphAccumulator)

    alternative1 = cli_config.get_stamp_style('alternative1')
    assert isinstance(alternative1, QRStampStyle)
    assert isinstance(alternative1.background, PdfImage)
    assert isinstance(alternative1.text_box_style.font, GlyphAccumulator)

    alternative2 = cli_config.get_stamp_style('alternative2')
    assert isinstance(alternative2, QRStampStyle)
    assert alternative2.background is None
    assert isinstance(alternative2.text_box_style.font, SimpleFontEngine)

    alternative3 = cli_config.get_stamp_style('alternative3')
    assert isinstance(alternative3, TextStampStyle)
    assert alternative3.background is None
    assert isinstance(alternative3.text_box_style.font, SimpleFontEngine)


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
