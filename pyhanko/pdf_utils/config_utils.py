"""
This module contains utilities for allowing dataclasses to be populated by
user-provided configuration (e.g. from a Yaml file).

.. note::
    On naming conventions: this module converts hyphens in key names to
    underscores as a matter of course.
"""

import dataclasses

__all__ = ['ConfigurationError', 'ConfigurableMixin']


class ConfigurationError(ValueError):
    """Signal configuration errors."""
    pass


@dataclasses.dataclass(frozen=True)
class ConfigurableMixin:
    """General configuration mixin for dataclasses"""

    @classmethod
    def process_entries(cls, config_dict):
        """
        Hook method that can modify the configuration dictionary
        to overwrite or tweak some of their values (e.g. to convert string
        parameters into more complex Python objects)

        Subclasses that override this method should call
        ``super().process_entries()``, and leave keys that they do not
        recognise untouched.

        :param config_dict:
            A dictionary containing configuration values.
        :raises ConfigurationError:
            when there is a problem processing a relevant entry.
        """
        pass

    @classmethod
    def from_config(cls, config_dict):
        """
        Attempt to instantiate an object of the class on which it is called,
        by means of the configuration settings passed in.

        First, we check that the keys supplied in the dictionary correspond
        to data fields on the current class.
        Then, the dictionary is processed using the :meth:`process_entries`
        method. The resulting dictionary is passed to the initialiser
        of the current class as a kwargs dict.

        :param config_dict:
            A dictionary containing configuration values.
        :return:
            An instance of the class on which it is called.
        :raises ConfigurationError:
            when an unexpected configuration key is encountered or left
            unfilled, or when there is a problem processing one of the config
            values.
        """
        check_config_keys(
            cls.__name__, {f.name for f in dataclasses.fields(cls)},
            config_dict
        )
        # in Python we need underscores
        config_dict = {
            key.replace('-', '_'): v for key, v in config_dict.items()
        }
        cls.process_entries(config_dict)
        try:
            # noinspection PyArgumentList
            return cls(**config_dict)
        except TypeError as e:  # pragma: nocover
            raise ConfigurationError(e)


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
