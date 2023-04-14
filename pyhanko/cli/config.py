from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, Optional, Type

import yaml
from pyhanko_certvalidator import ValidationContext

from pyhanko.config.errors import ConfigurationError
from pyhanko.config.logging import LogConfig, parse_logging_config
from pyhanko.config.trust import DEFAULT_TIME_TOLERANCE, parse_trust_config
from pyhanko.sign.signers import DEFAULT_SIGNING_STAMP_STYLE
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.stamp import BaseStampStyle, QRStampStyle, TextStampStyle


@dataclass
class CLIConfig:
    validation_contexts: Dict[str, dict]
    stamp_styles: Dict[str, dict]
    default_validation_context: str
    default_stamp_style: str
    time_tolerance: timedelta
    retroactive_revinfo: bool
    log_config: Dict[Optional[str], LogConfig]
    raw_config: dict

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
            raise ConfigurationError(f"There is no stamp style named '{name}'.")
        except TypeError as e:
            raise ConfigurationError(e)
        cls = STAMP_STYLE_TYPES[style_config.pop('type', 'text')]
        return cls.from_config(style_config)


# TODO allow CRL/OCSP loading here as well (esp. CRL loading might be useful
#  in some cases)
# Time-related settings are probably better off in the CLI.


DEFAULT_VALIDATION_CONTEXT = DEFAULT_STAMP_STYLE = 'default'
STAMP_STYLE_TYPES: Dict[str, Type[BaseStampStyle]] = {
    'qr': QRStampStyle,
    'text': TextStampStyle,
}


def parse_cli_config(yaml_str) -> CLIConfig:
    config_dict = yaml.safe_load(yaml_str) or {}
    return CLIConfig(**process_config_dict(config_dict), raw_config=config_dict)


def process_config_dict(config_dict: dict) -> dict:
    # validation context config
    vcs: Dict[str, dict] = {DEFAULT_VALIDATION_CONTEXT: {}}
    try:
        vc_specs = config_dict['validation-contexts']
        vcs.update(vc_specs)
    except KeyError:
        pass

    # stamp style config
    # TODO this style is obviously not suited for non-signing scenarios
    #  (but it'll do for now)
    stamp_configs = {
        DEFAULT_STAMP_STYLE: {
            'stamp-text': DEFAULT_SIGNING_STAMP_STYLE.stamp_text,
            'background': '__stamp__',
        }
    }
    try:
        stamp_specs = config_dict['stamp-styles']
        stamp_configs.update(stamp_specs)
    except KeyError:
        pass

    # logging config
    log_config_spec = config_dict.get('logging', {})
    log_config = parse_logging_config(log_config_spec)

    # some misc settings
    default_vc = config_dict.get(
        'default-validation-context', DEFAULT_VALIDATION_CONTEXT
    )
    default_stamp_style = config_dict.get(
        'default-stamp-style', DEFAULT_STAMP_STYLE
    )
    time_tolerance_seconds = config_dict.get(
        'time-tolerance', DEFAULT_TIME_TOLERANCE.seconds
    )
    if not isinstance(time_tolerance_seconds, int):
        raise ConfigurationError(
            "time-tolerance parameter must be specified in seconds"
        )

    time_tolerance = timedelta(seconds=time_tolerance_seconds)
    retroactive_revinfo = bool(config_dict.get('retroactive-revinfo', False))
    return dict(
        validation_contexts=vcs,
        default_validation_context=default_vc,
        time_tolerance=time_tolerance,
        retroactive_revinfo=retroactive_revinfo,
        stamp_styles=stamp_configs,
        default_stamp_style=default_stamp_style,
        log_config=log_config,
    )
