from datetime import timedelta
from typing import Dict
from dataclasses import dataclass

import yaml
from certvalidator import ValidationContext
from pyhanko.pdf_utils.config_utils import check_config_keys, ConfigurationError
from pyhanko.sign import signers


# TODO add stamp styles etc.
from pyhanko.sign.signers import DEFAULT_SIGNING_STAMP_STYLE
from pyhanko.stamp import QRStampStyle, TextStampStyle


@dataclass
class CLIConfig:
    validation_contexts: Dict[str, dict]
    stamp_styles: Dict[str, dict]
    default_validation_context: str
    default_stamp_style: str
    time_tolerance: timedelta

    # TODO graceful error handling

    def get_validation_context(self, name=None, as_dict=False):
        name = name or self.default_validation_context
        vc_kwargs = parse_trust_config(
            self.validation_contexts[name], self.time_tolerance
        )
        return vc_kwargs if as_dict else ValidationContext(**vc_kwargs)

    def get_stamp_style(self, name=None) -> TextStampStyle:
        name = name or self.default_stamp_style
        try:
            style_config = dict(self.stamp_styles[name])
        except TypeError as e:
            raise ConfigurationError(e)
        cls = STAMP_STYLE_TYPES[style_config.pop('type', 'text')]
        return cls.from_config(style_config)


def init_validation_context_kwargs(trust, trust_replace, other_certs,
                                   time_tolerance=None):
    vc_kwargs = {
        'time_tolerance':
            timedelta(seconds=DEFAULT_TIME_TOLERANCE) if time_tolerance is None
            else time_tolerance
    }
    if trust:
        if isinstance(trust, str):
            trust = (trust,)
        # add trust roots to the validation context, or replace them
        trust_certs = list(signers.load_certs_from_pemder(trust))
        if trust_replace:
            vc_kwargs['trust_roots'] = trust_certs
        else:
            vc_kwargs['extra_trust_roots'] = trust_certs
    if other_certs:
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        vc_kwargs['other_certs'] = list(signers.load_certs_from_pemder(other_certs))
    return vc_kwargs


# TODO allow CRL/OCSP loading here as well (esp. CRL loading might be useful
#  in some cases)
# Time-related settings are probably better off in the CLI.

def parse_trust_config(trust_config, time_tolerance) -> dict:
    check_config_keys(
        'ValidationContext', ('trust', 'trust-replace', 'other-certs'),
        trust_config
    )
    return init_validation_context_kwargs(
        trust=trust_config.get('trust'),
        trust_replace=trust_config.get('trust-replace', False),
        other_certs=trust_config.get('other-certs'),
        time_tolerance=time_tolerance
    )


DEFAULT_VALIDATION_CONTEXT = DEFAULT_STAMP_STYLE = 'default'
DEFAULT_TIME_TOLERANCE = 10
STAMP_STYLE_TYPES = {
    'qr': QRStampStyle,
    'text': TextStampStyle,
}


def parse_cli_config(yaml_str):
    config_dict = yaml.safe_load(yaml_str) or {}

    vcs = {DEFAULT_VALIDATION_CONTEXT: {}}
    try:
        vc_specs = config_dict['validation-contexts']
        vcs.update(vc_specs)
    except KeyError:
        pass

    # TODO this style is obviously not suited for non-signing scenarios
    #  (but it'll do for now)
    stamp_configs = {DEFAULT_STAMP_STYLE: DEFAULT_SIGNING_STAMP_STYLE}
    try:
        stamp_specs = config_dict['stamp-styles']
        stamp_configs.update(stamp_specs)
    except KeyError:
        pass

    default_vc = config_dict.get(
        'default-validation-context', DEFAULT_VALIDATION_CONTEXT
    )
    default_stamp_style = config_dict.get(
        'default-stamp-style', DEFAULT_STAMP_STYLE
    )
    time_tolerance = timedelta(
        seconds=config_dict.get('time-tolerance', DEFAULT_TIME_TOLERANCE)
    )
    return CLIConfig(
        validation_contexts=vcs, default_validation_context=default_vc,
        time_tolerance=time_tolerance, stamp_styles=stamp_configs,
        default_stamp_style=default_stamp_style
    )
