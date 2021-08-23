import enum
import logging
from datetime import timedelta
from typing import Dict, Optional, Union, List, Iterable
from dataclasses import dataclass

import yaml
from asn1crypto import x509

from pyhanko.pdf_utils import config_utils
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.config_utils import (
    check_config_keys, ConfigurationError
)
from pyhanko.pdf_utils.misc import get_and_apply

from pyhanko.sign import load_certs_from_pemder, SimpleSigner
from pyhanko.sign.general import KeyUsageConstraints
from pyhanko.sign.signers import DEFAULT_SIGNING_STAMP_STYLE
from pyhanko.stamp import QRStampStyle, TextStampStyle


class StdLogOutput(enum.Enum):
    STDERR = enum.auto()
    STDOUT = enum.auto()


@dataclass(frozen=True)
class LogConfig:
    level: Union[int, str]
    """
    Logging level, should be one of the levels defined in the logging module.
    """

    output: Union[StdLogOutput, str]
    """
    Name of the output file, or a standard one.
    """

    @staticmethod
    def parse_output_spec(spec) -> Union[StdLogOutput, str]:
        if not isinstance(spec, str):
            raise ConfigurationError(
                "Log output must be specified as a string."
            )
        spec_l = spec.lower()
        if spec_l == 'stderr':
            return StdLogOutput.STDERR
        elif spec_l == 'stdout':
            return StdLogOutput.STDOUT
        else:
            return spec


@dataclass
class CLIConfig:
    validation_contexts: Dict[str, dict]
    stamp_styles: Dict[str, dict]
    default_validation_context: str
    default_stamp_style: str
    time_tolerance: timedelta
    retroactive_revinfo: bool
    log_config: Dict[Optional[str], LogConfig]
    pemder_setups: Dict[str, dict]
    pkcs12_setups: Dict[str, dict]
    pkcs11_setups: Dict[str, dict]

    # TODO graceful error handling for syntax & type issues?

    def _get_validation_settings_raw(self, name=None):
        name = name or self.default_validation_context
        try:
            return self.validation_contexts[name]
        except KeyError:
            raise ConfigurationError(
                f"There is no validation context named '{name}'."
            )

    def get_validation_context(self, name=None, as_dict=False):
        vc_config = self._get_validation_settings_raw(name)
        vc_kwargs = parse_trust_config(
            vc_config, self.time_tolerance, self.retroactive_revinfo
        )
        return vc_kwargs if as_dict else ValidationContext(**vc_kwargs)

    def get_signer_key_usages(self, name=None) -> KeyUsageConstraints:
        vc_config = self._get_validation_settings_raw(name)

        try:
            policy_settings = dict(vc_config['signer-key-usage-policy'])
        except KeyError:
            policy_settings = {}

        # fallbacks to stay compatible with the simpler 0.5.0 signer-key-usage
        # and signer-extd-key-usage settings: copy old settings keys to
        # their corresponding values in the new one

        try:
            key_usage_strings = vc_config['signer-key-usage']
            policy_settings.setdefault('key-usage', key_usage_strings)
        except KeyError:
            pass

        try:
            key_usage_strings = vc_config['signer-extd-key-usage']
            policy_settings.setdefault('extd-key-usage', key_usage_strings)
        except KeyError:
            pass

        return KeyUsageConstraints.from_config(policy_settings)

    def get_stamp_style(self, name=None) -> TextStampStyle:
        name = name or self.default_stamp_style
        try:
            style_config = dict(self.stamp_styles[name])
        except KeyError:
            raise ConfigurationError(
                f"There is no stamp style named '{name}'."
            )
        except TypeError as e:
            raise ConfigurationError(e)
        cls = STAMP_STYLE_TYPES[style_config.pop('type', 'text')]
        return cls.from_config(style_config)

    def get_pkcs11_config(self, name):
        try:
            setup = self.pkcs11_setups[name]
        except KeyError:
            raise ConfigurationError(f"There's no PKCS#11 setup named '{name}'")
        return PKCS11SignatureConfig.from_config(setup)

    def get_pkcs12_config(self, name):
        try:
            setup = self.pkcs12_setups[name]
        except KeyError:
            raise ConfigurationError(f"There's no PKCS#12 setup named '{name}'")
        return PKCS12SignatureConfig.from_config(setup)

    def get_pemder_config(self, name):
        try:
            setup = self.pemder_setups[name]
        except KeyError:
            raise ConfigurationError(f"There's no PEM/DER setup named '{name}'")
        return PemDerSignatureConfig.from_config(setup)


def init_validation_context_kwargs(*, trust, trust_replace, other_certs,
                                   retroactive_revinfo=False,
                                   time_tolerance=None):
    if not isinstance(time_tolerance, timedelta):
        if time_tolerance is None:
            time_tolerance = timedelta(seconds=DEFAULT_TIME_TOLERANCE)
        elif isinstance(time_tolerance, int):
            time_tolerance = timedelta(seconds=time_tolerance)
        else:
            raise ConfigurationError(
                "time-tolerance parameter must be specified in seconds"
            )
    vc_kwargs = {'time_tolerance': time_tolerance}
    if retroactive_revinfo:
        vc_kwargs['retroactive_revinfo'] = True
    if trust:
        if isinstance(trust, str):
            trust = (trust,)
        # add trust roots to the validation context, or replace them
        trust_certs = list(load_certs_from_pemder(trust))
        if trust_replace:
            vc_kwargs['trust_roots'] = trust_certs
        else:
            vc_kwargs['extra_trust_roots'] = trust_certs
    if other_certs:
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        vc_kwargs['other_certs'] = list(load_certs_from_pemder(other_certs))
    return vc_kwargs


# TODO allow CRL/OCSP loading here as well (esp. CRL loading might be useful
#  in some cases)
# Time-related settings are probably better off in the CLI.

def parse_trust_config(trust_config, time_tolerance,
                       retroactive_revinfo) -> dict:
    check_config_keys(
        'ValidationContext',
        ('trust', 'trust-replace', 'other-certs',
         'time-tolerance', 'retroactive-revinfo',
         'signer-key-usage', 'signer-extd-key-usage',
         'signer-key-usage-policy'),
        trust_config
    )
    return init_validation_context_kwargs(
        trust=trust_config.get('trust'),
        trust_replace=trust_config.get('trust-replace', False),
        other_certs=trust_config.get('other-certs'),
        time_tolerance=trust_config.get('time-tolerance', time_tolerance),
        retroactive_revinfo=trust_config.get(
            'retroactive-revinfo', retroactive_revinfo
        )
    )


DEFAULT_ROOT_LOGGER_LEVEL = logging.INFO


def _retrieve_log_level(settings_dict, key, default=None) -> Union[int, str]:
    try:
        level_spec = settings_dict[key]
    except KeyError:
        if default is not None:
            return default
        raise ConfigurationError(
            f"Logging config for '{key}' does not define a log level."
        )
    if not isinstance(level_spec, (int, str)):
        raise ConfigurationError(
            f"Log levels must be int or str, not {type(level_spec)}"
        )
    return level_spec


def parse_logging_config(log_config_spec) -> Dict[Optional[str], LogConfig]:
    if not isinstance(log_config_spec, dict):
        raise ConfigurationError('logging config should be a dictionary')

    root_logger_level = _retrieve_log_level(
        log_config_spec, 'root-level', default=DEFAULT_ROOT_LOGGER_LEVEL
    )

    root_logger_output = get_and_apply(
        log_config_spec, 'root-output', LogConfig.parse_output_spec,
        default=StdLogOutput.STDERR
    )

    log_config = {None: LogConfig(root_logger_level, root_logger_output)}

    logging_by_module = log_config_spec.get('by-module', {})
    if not isinstance(logging_by_module, dict):
        raise ConfigurationError('logging.by-module should be a dict')

    for module, module_logging_settings in logging_by_module.items():
        if not isinstance(module, str):
            raise ConfigurationError(
                "Keys in logging.by-module should be strings"
            )
        level_spec = _retrieve_log_level(module_logging_settings, 'level')
        output_spec = get_and_apply(
            module_logging_settings, 'output', LogConfig.parse_output_spec,
            default=StdLogOutput.STDERR
        )
        log_config[module] = LogConfig(level=level_spec, output=output_spec)

    return log_config


@dataclass(frozen=True)
class PKCS12SignatureConfig(config_utils.ConfigurableMixin):
    """
    Configuration for a signature using key material on disk, contained
    in a PKCS#12 bundle.
    """

    pfx_file: str
    """Path to the PKCS#12 file."""

    other_certs: List[x509.Certificate] = None
    """Other relevant certificates."""

    pfx_passphrase: bytes = None
    """PKCS#12 passphrase (if relevant)."""

    prompt_passphrase: bool = True
    """
    Prompt for the PKCS#12 passphrase. Default is ``True``.

    .. note::
        If :attr:`key_passphrase` is not ``None``, this setting has no effect.
    """

    prefer_pss: bool = False
    """
    Prefer PSS to PKCS#1 v1.5 padding when creating RSA signatures.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)

        other_certs = config_dict.get('other_certs', ())
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        config_dict['other_certs'] = list(load_certs_from_pemder(other_certs))

        try:
            passphrase = config_dict['pfx_passphrase']
            if passphrase is not None:
                config_dict['pfx_passphrase'] = passphrase.encode('utf8')
        except KeyError:
            pass

    def instantiate(self, provided_pfx_passphrase: Optional[bytes] = None) \
            -> SimpleSigner:
        passphrase = self.pfx_passphrase or provided_pfx_passphrase
        result = SimpleSigner.load_pkcs12(
            pfx_file=self.pfx_file, passphrase=passphrase,
            other_certs=self.other_certs, prefer_pss=self.prefer_pss
        )
        if result is None:
            raise ConfigurationError("Error while loading key material")
        return result


@dataclass(frozen=True)
class PemDerSignatureConfig(config_utils.ConfigurableMixin):
    """
    Configuration for a signature using PEM or DER-encoded key material on disk.
    """

    key_file: str
    """Signer's private key."""

    cert_file: str
    """Signer's certificate."""

    other_certs: List[x509.Certificate] = None
    """Other relevant certificates."""

    key_passphrase: bytes = None
    """Signer's key passphrase (if relevant)."""

    prompt_passphrase: bool = True
    """
    Prompt for the key passphrase. Default is ``True``.

    .. note::
        If :attr:`key_passphrase` is not ``None``, this setting has no effect.
    """

    prefer_pss: bool = False
    """
    Prefer PSS to PKCS#1 v1.5 padding when creating RSA signatures.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)

        other_certs = config_dict.get('other_certs', ())
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        config_dict['other_certs'] = list(load_certs_from_pemder(other_certs))

        try:
            passphrase = config_dict['key_passphrase']
            if passphrase is not None:
                config_dict['key_passphrase'] = passphrase.encode('utf8')
        except KeyError:
            pass

    def instantiate(self, provided_key_passphrase: Optional[bytes] = None) \
            -> SimpleSigner:
        key_passphrase = self.key_passphrase or provided_key_passphrase
        result = SimpleSigner.load(
            key_file=self.key_file, cert_file=self.cert_file,
            other_certs=self.other_certs, prefer_pss=self.prefer_pss,
            key_passphrase=key_passphrase,
        )
        if result is None:
            raise ConfigurationError("Error while loading key material")
        return result


@dataclass(frozen=True)
class PKCS11SignatureConfig(config_utils.ConfigurableMixin):
    """
    Configuration for a PKCS#11 signature.

    This class is used to load PKCS#11 setup information from YAML
    configuration.
    """

    module_path: str
    """Path to the PKCS#11 module shared object."""

    token_label: str
    """PKCS#11 token name"""

    cert_label: str
    """PKCS#11 label of the signer's certificate."""

    other_certs: List[x509.Certificate] = None
    """Other relevant certificates."""

    key_label: Optional[str] = None
    """
    PKCS#11 label of the signer's private key, if different from
    :attr:`cert_label`.
    """

    slot_no: Optional[int] = None
    """
    Slot number of the PKCS#11 slot to use.
    """

    user_pin: Optional[str] = None
    """
    The user's PIN. If unspecified, the user will be prompted for a PIN
    if :attr:`prompt_pin` is ``True``.

    .. warning::
        Some PKCS#11 tokens do not allow the PIN code to be communicated in
        this way, but manage their own authentication instead (the Belgian eID
        middleware is one such example).
        For such tokens, leave this setting set to ``None`` and additionally
        set :attr:`prompt_pin` to ``False``.
    """

    prompt_pin: bool = True
    """
    Prompt for the user's PIN. Default is ``True``.

    .. note::
        If :attr:`user_pin` is not ``None``, this setting has no effect.
    """

    other_certs_to_pull: Optional[Iterable[str]] = ()
    """
    List labels of other certificates to pull from the PKCS#11 device.
    Defaults to the empty tuple. If ``None``, pull *all* certificates.
    """

    bulk_fetch: bool = True
    """
    Boolean indicating the fetching strategy.
    If ``True``, fetch all certs and filter the unneeded ones.
    If ``False``, fetch the requested certs one by one.
    Default value is ``True``, unless ``other_certs_to_pull`` has one or
    fewer elements, in which case it is always treated as ``False``.
    """

    prefer_pss: bool = False
    """
    Prefer PSS to PKCS#1 v1.5 padding when creating RSA signatures.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        other_certs = config_dict.get('other_certs', ())
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        config_dict['other_certs'] = list(load_certs_from_pemder(other_certs))


DEFAULT_VALIDATION_CONTEXT = DEFAULT_STAMP_STYLE = 'default'
DEFAULT_TIME_TOLERANCE = 10
STAMP_STYLE_TYPES = {
    'qr': QRStampStyle,
    'text': TextStampStyle,
}


def parse_cli_config(yaml_str):
    config_dict = yaml.safe_load(yaml_str) or {}

    # validation context config
    vcs = {DEFAULT_VALIDATION_CONTEXT: {}}
    try:
        vc_specs = config_dict['validation-contexts']
        vcs.update(vc_specs)
    except KeyError:
        pass

    # stamp style config
    # TODO this style is obviously not suited for non-signing scenarios
    #  (but it'll do for now)
    stamp_configs = {DEFAULT_STAMP_STYLE: DEFAULT_SIGNING_STAMP_STYLE}
    try:
        stamp_specs = config_dict['stamp-styles']
        stamp_configs.update(stamp_specs)
    except KeyError:
        pass

    # logging config
    log_config_spec = config_dict.get('logging', {})
    log_config = parse_logging_config(log_config_spec)

    pkcs11_setups = config_dict.get('pkcs11-setups', {})
    pkcs12_setups = config_dict.get('pkcs12-setups', {})
    pemder_setups = config_dict.get('pemder-setups', {})

    # some misc settings
    default_vc = config_dict.get(
        'default-validation-context', DEFAULT_VALIDATION_CONTEXT
    )
    default_stamp_style = config_dict.get(
        'default-stamp-style', DEFAULT_STAMP_STYLE
    )
    time_tolerance_seconds = config_dict.get(
        'time-tolerance', DEFAULT_TIME_TOLERANCE
    )
    if not isinstance(time_tolerance_seconds, int):
        raise ConfigurationError(
            "time-tolerance parameter must be specified in seconds"
        )

    time_tolerance = timedelta(seconds=time_tolerance_seconds)
    retroactive_revinfo = bool(config_dict.get('retroactive-revinfo', False))
    return CLIConfig(
        validation_contexts=vcs, default_validation_context=default_vc,
        time_tolerance=time_tolerance, retroactive_revinfo=retroactive_revinfo,
        stamp_styles=stamp_configs, default_stamp_style=default_stamp_style,
        log_config=log_config, pkcs11_setups=pkcs11_setups,
        pkcs12_setups=pkcs12_setups, pemder_setups=pemder_setups
    )
