import dataclasses

__all__ = ['ConfigurationError', 'ConfigurableMixin']


class ConfigurationError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class ConfigurableMixin:

    @classmethod
    def process_entries(cls, config_dict):  # pragma: nocover
        pass

    @classmethod
    def from_config(cls, config_dict):
        check_config_keys(
            cls.__name__, {f.name for f in dataclasses.fields(cls)},
            config_dict
        )
        # in Python we need underscores
        config_dict = {
            key.replace('-', '_'): v for key, v in config_dict.items()
        }
        cls.process_entries(config_dict)
        # noinspection PyArgumentList
        return cls(**config_dict)


def check_config_keys(config_name, expected_keys, config_dict):
    # wrapper function to provide user-friendly errors
    #  (mainly intended for the CLI)
    # TODO What about type checking?
    if not isinstance(config_dict, dict):  # pragma: nocover
        raise ConfigurationError(
            f"{config_name} requires a dictionary to initialise."
        )
    # standardise on dashes for the yaml interface
    provided_keys = {key.replace('_', '-') for key in config_dict.keys()}
    expected_keys = {key.replace('_', '-') for key in expected_keys}
    if not (provided_keys <= expected_keys):
        unexpected_keys = provided_keys - expected_keys
        # this is easier to present to the user than a TypeError
        raise ConfigurationError(
            f"Unexpected {'key' if len(unexpected_keys) == 1 else 'keys'} "
            f"in configuration for {config_name}: "
            f"{','.join(key.replace('_', '-') for key in unexpected_keys)}."
        )
