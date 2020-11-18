from datetime import timedelta
from typing import Dict
from dataclasses import dataclass

import yaml
from certvalidator import ValidationContext
from pdfstamp.sign import signers


# TODO add stamp styles etc.

@dataclass
class CLIConfig:
    validation_contexts: Dict[str, dict]
    default_validation_context: str
    time_tolerance: timedelta

    def get_validation_context(self, name=None, as_dict=False):
        name = name or self.default_validation_context
        vc_kwargs = parse_trust_config(
            self.validation_contexts[name], self.time_tolerance
        )
        return vc_kwargs if as_dict else ValidationContext(**vc_kwargs)


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
        trust_certs = list(signers.load_ca_chain(trust))
        if trust_replace:
            vc_kwargs['trust_roots'] = trust_certs
        else:
            vc_kwargs['extra_trust_roots'] = trust_certs
    if other_certs:
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        vc_kwargs['other_certs'] = list(signers.load_ca_chain(other_certs))
    return vc_kwargs


# TODO allow CRL/OCSP loading here as well (esp. CRL loading might be useful
#  in some cases)
# Time-related settings are probably better off in the CLI.

# TODO set up general mechanism to verify expected config keys etc.

def parse_trust_config(trust_config, time_tolerance) -> dict:
    return init_validation_context_kwargs(
        trust=trust_config.get('trust'),
        trust_replace=trust_config.get('trust-replace', False),
        other_certs=trust_config.get('other-certs'),
        time_tolerance=time_tolerance
    )


DEFAULT_VALIDATION_CONTEXT = 'default'
DEFAULT_TIME_TOLERANCE = 10


def parse_cli_config(yaml_str):
    config_dict = yaml.safe_load(yaml_str) or {}

    vcs = {DEFAULT_VALIDATION_CONTEXT: {}}
    try:
        vc_specs = config_dict['validation-contexts']
        vcs.update(vc_specs)
    except KeyError:
        pass

    default_vc = config_dict.get(
        'default-validation-context', DEFAULT_VALIDATION_CONTEXT
    )
    time_tolerance = timedelta(
        seconds=config_dict.get('time-tolerance', DEFAULT_TIME_TOLERANCE)
    )
    return CLIConfig(
        validation_contexts=vcs, default_validation_context=default_vc,
        time_tolerance=time_tolerance
    )
