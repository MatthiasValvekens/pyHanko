import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Optional, Union

import pyhanko.config.pkcs11
import pytest
import yaml
from asn1crypto import x509
from pyhanko import stamp
from pyhanko.cli import config
from pyhanko.cli.commands.signing.pkcs11_cli import ModuleConfigWrapper
from pyhanko.cli.commands.signing.simple import KeyFileConfigWrapper
from pyhanko.config.api import ConfigurableMixin
from pyhanko.config.errors import ConfigurationError
from pyhanko.config.logging import DEFAULT_ROOT_LOGGER_LEVEL, StdLogOutput
from pyhanko.config.pkcs11 import TokenCriteria
from pyhanko.config.trust import (
    DEFAULT_TIME_TOLERANCE,
    init_validation_context_kwargs,
)
from pyhanko.pdf_utils import layout
from pyhanko.pdf_utils.content import ImportedPdfPage
from pyhanko.pdf_utils.images import PdfImage
from pyhanko.sign.signers.pdf_cms import (
    signer_from_p12_config,
    signer_from_pemder_config,
)
from pyhanko.stamp import QRStampStyle, TextStampStyle

from .samples import CRYPTO_DATA_DIR, TEST_DIR, TESTING_CA_DIR


def _parse_cli_config(config_string):
    return config.parse_cli_config(config_string).config


@pytest.mark.parametrize('trust_replace', [True, False])
def test_read_vc_kwargs(trust_replace):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            trust-replace: {'true' if trust_replace else 'false'}
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
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
    from pyhanko.pdf_utils.font import SimpleFontEngineFactory
    from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory

    from .test_text import NOTO_SERIF_JP

    config_string = f"""
    stamp-styles:
        default:
            text-box-style:
                font: {NOTO_SERIF_JP}
            type: qr
            background: __stamp__
            qr-position: right
            inner-content-layout:
                y-align: bottom
                x-align: mid
                margins:
                    left: 10
                    right: 10
        alternative1:
            text-box-style:
                font: {NOTO_SERIF_JP}
            background: {TEST_DIR}/data/img/stamp-indexed.png
            type: qr
        alternative2:
            type: qr
            background: {TEST_DIR}/data/pdf/pdf-background-test.pdf
        alternative3:
            type: text
        wrong-position:
            type: qr
            qr-position: bleh
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    default_qr_style = cli_config.get_stamp_style()
    assert isinstance(default_qr_style, QRStampStyle)
    assert default_qr_style.background is stamp.STAMP_ART_CONTENT
    assert isinstance(
        default_qr_style.text_box_style.font, GlyphAccumulatorFactory
    )
    assert default_qr_style.qr_position == stamp.QRPosition.RIGHT_OF_TEXT

    expected_layout = layout.SimpleBoxLayoutRule(
        x_align=layout.AxisAlignment.ALIGN_MID,
        y_align=layout.AxisAlignment.ALIGN_MIN,
        margins=layout.Margins(left=10, right=10),
    )
    assert default_qr_style.inner_content_layout == expected_layout

    alternative1 = cli_config.get_stamp_style('alternative1')
    assert isinstance(alternative1, QRStampStyle)
    assert isinstance(alternative1.background, PdfImage)
    assert isinstance(alternative1.text_box_style.font, GlyphAccumulatorFactory)
    assert alternative1.qr_position == stamp.QRPosition.LEFT_OF_TEXT

    alternative2 = cli_config.get_stamp_style('alternative2')
    assert isinstance(alternative2, QRStampStyle)
    assert isinstance(alternative2.background, ImportedPdfPage)
    assert isinstance(alternative2.text_box_style.font, SimpleFontEngineFactory)

    alternative3 = cli_config.get_stamp_style('alternative3')
    assert isinstance(alternative3, TextStampStyle)
    assert alternative3.background is None
    assert isinstance(alternative3.text_box_style.font, SimpleFontEngineFactory)

    with pytest.raises(ConfigurationError, match='not a valid QR position'):
        cli_config.get_stamp_style('wrong-position')

    with pytest.raises(ConfigurationError):
        cli_config.get_stamp_style('theresnosuchstyle')


def test_read_bad_config():
    config_string = f"""
    stamp-styles:
        default:
            type: qr
            blah: blah
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_stamp_style()


def test_read_bad_background_config():
    config_string = f"""
    stamp-styles:
        default:
            type: text
            background: 1234
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    with pytest.raises(ConfigurationError, match='must be a string'):
        cli_config.get_stamp_style()


@pytest.mark.parametrize("bad_type", ['5', '[1,2,3]'])
def test_read_bad_config2(bad_type):
    config_string = f"""
    stamp-styles:
        default: {bad_type}
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_stamp_style()


def test_empty_config():
    cli_config: config.CLIConfig = _parse_cli_config("")
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
    cli_config: config.CLIRootConfig = config.parse_cli_config(config_string)

    assert cli_config.log_config[None].output == StdLogOutput.STDOUT
    assert cli_config.log_config[None].level == 'DEBUG'

    assert cli_config.log_config['example.test1'].level == 50
    assert cli_config.log_config['example.test1'].output == 'test.log'
    assert cli_config.log_config['example.test2'].level == 'DEBUG'
    assert cli_config.log_config['example.test2'].output == StdLogOutput.STDERR
    assert cli_config.log_config['example.test3'].level == 10
    assert cli_config.log_config['example.test3'].output == StdLogOutput.STDERR


def test_read_logging_config_defaults():
    cli_config: config.CLIRootConfig = config.parse_cli_config(
        """
        logging:
            root-level: DEBUG
    """
    )

    assert cli_config.log_config[None].output == StdLogOutput.STDERR
    assert cli_config.log_config[None].level == 'DEBUG'
    assert list(cli_config.log_config.keys()) == [None]

    cli_config: config.CLIRootConfig = config.parse_cli_config(
        """
        logging:
            root-output: 'test.log'
    """
    )

    assert cli_config.log_config[None].output == 'test.log'
    assert cli_config.log_config[None].level == DEFAULT_ROOT_LOGGER_LEVEL
    assert list(cli_config.log_config.keys()) == [None]

    cli_config: config.CLIRootConfig = config.parse_cli_config("")
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
    """,
]


@pytest.mark.parametrize('config_str', WRONG_CONFIGS)
def test_read_logging_config_errors(config_str):
    with pytest.raises(ConfigurationError):
        _parse_cli_config(config_str)


@pytest.mark.parametrize(
    'key_usage_str, key_usages',
    [
        ('non_repudiation', {'non_repudiation'}),
        (
            '[non_repudiation, digital_signature]',
            {'non_repudiation', 'digital_signature'},
        ),
        ('[]', set()),
    ],
)
def test_read_key_usage(key_usage_str, key_usages):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage == key_usages
    assert key_usage_settings.extd_key_usage is None


@pytest.mark.parametrize(
    'key_usage_str, key_usages',
    [
        ('piv_content_signing', {'piv_content_signing'}),
        (
            '[piv_content_signing, code_signing]',
            {'piv_content_signing', 'code_signing'},
        ),
        ('[]', set()),
        (
            '[2.16.840.1.101.3.6.7, code_signing]',
            {'piv_content_signing', 'code_signing'},
        ),
        ('[2.16.840.1.101.3.6.7, "2.999"]', {'piv_content_signing', '2.999'}),
        ('2.16.840.1.101.3.6.7', {'piv_content_signing'}),
        ('"2.999"', {'2.999'}),
    ],
)
def test_read_extd_key_usage(key_usage_str, key_usages):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-extd-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
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
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage == {
        'digital_signature',
        'non_repudiation',
    }
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
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage == {
        'digital_signature',
        'non_repudiation',
    }
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
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    key_usage_settings = cli_config.get_signer_key_usages()
    assert key_usage_settings.key_usage == {
        'digital_signature',
        'non_repudiation',
    }
    assert key_usage_settings.key_usage_forbidden == {'data_encipherment'}
    assert key_usage_settings.extd_key_usage is None
    assert not key_usage_settings.match_all_key_usages


@pytest.mark.parametrize(
    'key_usage_str',
    [
        '0',
        '["non_repudiation", 2]',
        "[1, 2, 3]",
        "abcdef",
        '["no_such_key_usage"]',
    ],
)
def test_extd_key_usage_errors(key_usage_str):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-extd-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_signer_key_usages()


@pytest.mark.parametrize(
    'key_usage_str',
    [
        '0',
        '["non_repudiation", 2]',
        "[1, 2, 3]",
        "abcdef",
        '["no_such_key_usage"]',
    ],
)
def test_key_usage_errors(key_usage_str):
    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            signer-key-usage: {key_usage_str}
    """
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    with pytest.raises(ConfigurationError):
        cli_config.get_signer_key_usages()


@pytest.mark.parametrize(
    'config_string, result',
    [
        (
            f"""
    time-tolerance: 5
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            5,
        ),
        (
            f"""
    time-tolerance: 5
    validation-contexts:
        default:
            time-tolerance: 7
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            7,
        ),
        (
            f"""
    validation-contexts:
        default:
            time-tolerance: 7
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            7,
        ),
        (
            f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            DEFAULT_TIME_TOLERANCE.seconds,
        ),
    ],
)
def test_read_time_tolerance(config_string, result):
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
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
        cli_config: config.CLIConfig = _parse_cli_config(config_string)
        cli_config.get_validation_context(as_dict=True)

    config_string = f"""
    time-tolerance: "this makes no sense"
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
    """
    with pytest.raises(ConfigurationError, match='time-tolerance.*'):
        cli_config: config.CLIConfig = _parse_cli_config(config_string)
        cli_config.get_validation_context(as_dict=True)

    vc_kwargs = init_validation_context_kwargs(
        trust=[], trust_replace=False, other_certs=[]
    )
    assert 'retroactive_revinfo' not in vc_kwargs
    assert vc_kwargs['time_tolerance'] == DEFAULT_TIME_TOLERANCE


@pytest.mark.parametrize(
    'config_string, result',
    [
        (
            f"""
    retroactive-revinfo: true
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            True,
        ),
        (
            f"""
    retroactive-revinfo: true
    validation-contexts:
        default:
            retroactive-revinfo: false
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            False,
        ),
        (
            f"""
    retroactive-revinfo: false
    validation-contexts:
        default:
            retroactive-revinfo: true
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            True,
        ),
        (
            f"""
    validation-contexts:
        default:
            retroactive-revinfo: true
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            True,
        ),
        (
            f"""
    validation-contexts:
        default:
            retroactive-revinfo: "yes"
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            True,
        ),
        (
            f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """,
            False,
        ),
    ],
)
def test_read_retroactive_revinfo(config_string, result):
    cli_config: config.CLIConfig = _parse_cli_config(config_string)
    vc_kwargs = cli_config.get_validation_context(as_dict=True)
    if result is False:
        assert 'retroactive_revinfo' not in vc_kwargs
    else:
        assert vc_kwargs['retroactive_revinfo']


def test_read_pkcs11_config():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria:
                    label: testrsa
                cert-label: signer
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    with pytest.raises(ConfigurationError):
        ModuleConfigWrapper(cli_config).get_pkcs11_config('bar')

    assert setup.token_criteria == TokenCriteria('testrsa')
    assert setup.module_path == '/path/to/libfoo.so'
    assert len(setup.other_certs) == 2


def test_read_pkcs11_config_legacy():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-label: testrsa
                cert-label: signer
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    with pytest.deprecated_call():
        setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')

    assert setup.token_criteria == TokenCriteria('testrsa')


def test_read_pkcs11_config_legacy_with_extra_criteria():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-label: testrsa
                token-criteria:
                    serial: deadbeef
                cert-label: signer
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    with pytest.deprecated_call():
        setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')

    assert setup.token_criteria == TokenCriteria(
        label='testrsa', serial=b'\xde\xad\xbe\xef'
    )


def test_read_pkcs11_config_slot_no():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                cert-label: signer
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')

    assert setup.module_path == '/path/to/libfoo.so'
    assert setup.slot_no == 0
    assert len(setup.other_certs) == 2


def test_read_pkcs11_nothing_to_pull():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria:
                    label: testrsa
                cert-label: signer
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert len(setup.other_certs) == 0


def test_read_pkcs11_config_ids():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                cert-id: 5
                key-id: "74657374"
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert setup.cert_id == b'\x05'
    assert setup.key_id == b'test'


def test_read_pkcs11_config_external_cert():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                key-id: 10
                signing-certificate: '{TESTING_CA_DIR}/interm/signer1.cert.pem'
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert setup.cert_id is None
    assert setup.cert_label is None
    assert isinstance(setup.signing_certificate, x509.Certificate)


def test_read_pkcs11_config_bad_criteria_type():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria: bleh
                cert-label: signer
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    with pytest.raises(
        ConfigurationError, match="TokenCriteria requires a dictionary"
    ):
        ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')


def test_read_pkcs11_config_bad_serial():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria:
                    serial: bazz
                cert-label: signer
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    with pytest.raises(ConfigurationError, match="Failed to parse.*hex"):
        ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')


def test_read_pkcs11_config_no_cert_spec_or_key_spec():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
        """
    )
    with pytest.raises(ConfigurationError, match="Either 'key_id'"):
        ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')


def test_read_pkcs11_config_cert_label_from_key_label():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                key-label: signer
        """
    )
    cfg = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert (cfg.cert_label, cfg.cert_id) == ('signer', None)


def test_read_pkcs11_config_cert_id_from_key_id():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                key-id: deadbeef
        """
    )
    cfg = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert (cfg.cert_label, cfg.cert_id) == (None, b"\xde\xad\xbe\xef")


def test_read_pkcs11_config_key_id_from_cert_id():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                cert-id: "deadbeef"
        """
    )
    cfg = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert (cfg.key_label, cfg.key_id) == (None, b"\xde\xad\xbe\xef")


def test_read_pkcs11_config_key_label_from_cert_label():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                cert-label: "signer"
        """
    )
    cfg = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert (cfg.key_label, cfg.key_id) == ("signer", None)


def test_read_pkcs11_config_key_label_not_from_cert_label_if_key_id_defined():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                slot-no: 0
                cert-label: "signer"
                key-id: "deadbeef"
        """
    )
    cfg = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert (cfg.key_label, cfg.key_id) == (None, b"\xde\xad\xbe\xef")
    assert (cfg.cert_label, cfg.cert_id) == ("signer", None)


@pytest.mark.parametrize(
    'literal,exp_val',
    [
        ('prompt', pyhanko.config.pkcs11.PKCS11PinEntryMode.PROMPT),
        ('skip', pyhanko.config.pkcs11.PKCS11PinEntryMode.SKIP),
        ('defer', pyhanko.config.pkcs11.PKCS11PinEntryMode.DEFER),
        # fallbacks
        ('true', pyhanko.config.pkcs11.PKCS11PinEntryMode.PROMPT),
        ('false', pyhanko.config.pkcs11.PKCS11PinEntryMode.SKIP),
        ('1', pyhanko.config.pkcs11.PKCS11PinEntryMode.PROMPT),
        ('0', pyhanko.config.pkcs11.PKCS11PinEntryMode.SKIP),
    ],
)
def test_read_pkcs11_prompt_pin(literal, exp_val):
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria:
                    label: testrsa
                cert-label: signer
                prompt-pin: {literal}
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert setup.prompt_pin == exp_val


def test_read_pkcs11_prompt_pin_default():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria:
                    label: testrsa
                cert-label: signer
        """
    )
    setup = ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')
    assert setup.prompt_pin == pyhanko.config.pkcs11.PKCS11PinEntryMode.PROMPT


def test_read_pkcs11_prompt_pin_invalid():
    cli_config = _parse_cli_config(
        f"""
        pkcs11-setups:
            foo:
                module-path: /path/to/libfoo.so
                token-criteria:
                    label: testrsa
                cert-label: signer
                prompt-pin: foobar
        """
    )
    with pytest.raises(ConfigurationError, match='Invalid'):
        ModuleConfigWrapper(cli_config).get_pkcs11_config('foo')


def _signer_sanity_check(signer):
    digest = hashlib.sha256(b'Hello world!').digest()
    with pytest.deprecated_call():
        sig = signer.sign(digest, digest_algorithm='sha256')
    from pyhanko.sign.validation.generic_cms import validate_sig_integrity

    intact, valid = validate_sig_integrity(
        sig['content']['signer_infos'][0],
        cert=signer.signing_cert,
        expected_content_type='data',
        actual_digest=digest,
    )
    assert intact and valid


def test_read_pkcs12_config():
    cli_config = _parse_cli_config(
        f"""
        pkcs12-setups:
            foo:
                pfx-file: '{TESTING_CA_DIR}/interm/signer1.pfx'
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
        """
    )
    setup = KeyFileConfigWrapper(cli_config).get_pkcs12_config('foo')
    with pytest.raises(ConfigurationError):
        KeyFileConfigWrapper(cli_config).get_pkcs12_config('bar')

    assert len(setup.other_certs) == 2

    signer = signer_from_p12_config(setup)
    _signer_sanity_check(signer)


def test_read_pkcs12_config_null_pw():
    cli_config = _parse_cli_config(
        f"""
        pkcs12-setups:
            foo:
                pfx-file: '{TESTING_CA_DIR}/interm/signer1.pfx'
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
                pfx-passphrase: null
        """
    )
    setup = KeyFileConfigWrapper(cli_config).get_pkcs12_config('foo')
    assert len(setup.other_certs) == 2

    signer = signer_from_p12_config(setup)
    _signer_sanity_check(signer)


def test_read_pemder_config():
    cli_config = _parse_cli_config(
        f"""
        pemder-setups:
            foo:
                key-file: '{CRYPTO_DATA_DIR}/keys-rsa/signer.key.pem'
                cert-file: '{TESTING_CA_DIR}/interm/signer1.cert.pem'
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
                key-passphrase: secret
        """
    )
    setup = KeyFileConfigWrapper(cli_config).get_pemder_config('foo')
    with pytest.raises(ConfigurationError):
        KeyFileConfigWrapper(cli_config).get_pemder_config('bar')

    assert len(setup.other_certs) == 2

    signer = signer_from_pemder_config(setup)
    _signer_sanity_check(signer)


def test_read_pemder_config_wrong_passphrase():
    cli_config = _parse_cli_config(
        f"""
        pemder-setups:
            foo:
                key-file: '{CRYPTO_DATA_DIR}/keys-rsa/signer.key.pem'
                cert-file: '{TESTING_CA_DIR}/interm/signer1.cert.pem'
                key-passphrase: "this passphrase is wrong"
        """
    )
    setup = KeyFileConfigWrapper(cli_config).get_pemder_config('foo')
    with pytest.raises(ConfigurationError):
        signer_from_pemder_config(setup)


def test_read_pemder_config_missing_passphrase():
    cli_config = _parse_cli_config(
        f"""
        pemder-setups:
            foo:
                key-file: '{CRYPTO_DATA_DIR}/keys-rsa/signer.key.pem'
                cert-file: '{TESTING_CA_DIR}/interm/signer1.cert.pem'
        """
    )
    setup = KeyFileConfigWrapper(cli_config).get_pemder_config('foo')
    with pytest.raises(ConfigurationError):
        signer_from_pemder_config(setup)

    signer_from_pemder_config(setup, provided_key_passphrase=b'secret')


def test_read_pkcs12_config_wrong_passphrase():
    cli_config = _parse_cli_config(
        f"""
        pkcs12-setups:
            foo:
                pfx-file: '{TESTING_CA_DIR}/interm/signer1.pfx'
                other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
                pfx-passphrase: "this passphrase is wrong"
        """
    )
    setup = KeyFileConfigWrapper(cli_config).get_pkcs12_config('foo')
    with pytest.raises(ConfigurationError):
        signer_from_p12_config(setup)


@pytest.mark.parametrize(
    'cfg_str,expected_result',
    [
        (
            "x-align: left",
            layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MIN,
                y_align=layout.AxisAlignment.ALIGN_MID,
            ),
        ),
        (
            "y-align: bottom",
            layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MIN,
            ),
        ),
        (
            f"""
        y-align: bottom
        x-align: mid
        margins:
            left: 10
            right: 10
        """,
            layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MIN,
                margins=layout.Margins(left=10, right=10),
            ),
        ),
        (
            f"""
        y-align: bottom
        x-align: mid
        margins: [10, 10, 0, 0]
        """,
            layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MIN,
                margins=layout.Margins(left=10, right=10),
            ),
        ),
        (
            f"""
        y-align: bottom
        x-align: mid
        inner-content-scaling: none
        """,
            layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MIN,
                inner_content_scaling=layout.InnerScaling.NO_SCALING,
            ),
        ),
        (
            "inner-content-scaling: stretch-to-fit",
            layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MID,
                inner_content_scaling=layout.InnerScaling.STRETCH_TO_FIT,
            ),
        ),
    ],
)
def test_read_simple_layout_config(cfg_str, expected_result):
    config_dict = yaml.safe_load(cfg_str)
    result = layout.SimpleBoxLayoutRule.from_config(config_dict)
    assert result == expected_result


@pytest.mark.parametrize(
    'cfg_str,error',
    [
        ("x-align: bottom", "is not a valid horizontal"),
        ("y-align: right", "is not a valid vertical"),
        ("inner-content-scaling: foobar", "is not a valid inner scaling"),
    ],
)
def test_read_simple_layout_config_failures(cfg_str, error):
    config_dict = yaml.safe_load(cfg_str)
    with pytest.raises(ConfigurationError, match=error):
        layout.SimpleBoxLayoutRule.from_config(config_dict)


@dataclass(frozen=True)
class DemoConfigurableA(ConfigurableMixin):
    field1: int
    field2: Iterable[int]
    field3: Optional[int] = None
    field4: Optional[Iterable[int]] = None
    field5: Union[str, int] = 'abc'
    field6: Union[str, int, None] = None


@dataclass(frozen=True)
class DemoConfigurableB(ConfigurableMixin):
    some_field: Optional[DemoConfigurableA] = None


@pytest.mark.parametrize(
    'cfg_str, expected_field_val',
    [
        (
            """
            some_field:
                field1: 1
                field2: [1,2]
            """,
            DemoConfigurableA(field1=1, field2=[1, 2]),
        ),
        (
            """
            some_field:
                field1: 1
                field2: [1,2]
                field3: 5
            """,
            DemoConfigurableA(field1=1, field2=[1, 2], field3=5),
        ),
        (
            """
            some_field:
                field1: 1
                field2: [1,2]
                field3: 5
                field4: [6,7,8]
            """,
            DemoConfigurableA(
                field1=1, field2=[1, 2], field3=5, field4=[6, 7, 8]
            ),
        ),
        (
            """
            some_field:
                field1: 1
                field2: [1,2]
                field5: xyz
            """,
            DemoConfigurableA(field1=1, field2=[1, 2], field5='xyz'),
        ),
        (
            """
            some_field:
                field1: 1
                field2: [1,2]
                field5: 8
                field6: xyz
            """,
            DemoConfigurableA(field1=1, field2=[1, 2], field5=8, field6='xyz'),
        ),
        ("{}", None),
    ],
)
def test_configurable_recurse(cfg_str, expected_field_val):
    config_dict = yaml.safe_load(cfg_str)
    b = DemoConfigurableB.from_config(config_dict)
    assert b.some_field == expected_field_val


@pytest.mark.parametrize(
    "cfg_str",
    [
        """
    field2: [1,2]
    field3: 5
    """,
        """
    field1: 1
    field3: 5
    """,
        """
    field3: 5
    """,
        "{}",
    ],
)
def test_enforce_required(cfg_str):
    config_dict = yaml.safe_load(cfg_str)
    with pytest.raises(ConfigurationError, match="Missing required key"):
        DemoConfigurableA.from_config(config_dict)


def test_enforce_required_recursive():
    config_dict = yaml.safe_load(
        """
        some_field:
            field2: [1,2]
        """
    )
    with pytest.raises(
        ConfigurationError, match="Error while processing configurable field"
    ):
        DemoConfigurableB.from_config(config_dict)


def test_default_stamp_style_fetch():
    # regression test for fetching the default stamp style if not explicitly
    # defined

    config_string = f"""
    validation-contexts:
        default:
            trust: '{TESTING_CA_DIR}/root/root.cert.pem'
            other-certs: '{TESTING_CA_DIR}/ca-chain.cert.pem'
    """

    cli_config: config.CLIConfig = _parse_cli_config(config_string)

    result = cli_config.get_stamp_style(None)
    from pyhanko.sign import DEFAULT_SIGNING_STAMP_STYLE

    assert result == DEFAULT_SIGNING_STAMP_STYLE
