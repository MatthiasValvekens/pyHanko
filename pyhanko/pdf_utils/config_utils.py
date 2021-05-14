"""
This module contains utilities for allowing dataclasses to be populated by
user-provided configuration (e.g. from a Yaml file).

.. note::
    On naming conventions: this module converts hyphens in key names to
    underscores as a matter of course.
"""

import dataclasses
import re

__all__ = [
    'ConfigurationError', 'ConfigurableMixin', 'check_config_keys',
    'OID_REGEX', 'process_oid', 'process_oids', 'process_bit_string_flags'
]

from typing import Type

from asn1crypto.core import ObjectIdentifier, BitString


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


OID_REGEX = re.compile(r'\d(\.\d+)+')


def process_oid(asn1crypto_class: Type[ObjectIdentifier], id_string,
                param_name):
    if not isinstance(id_string, str):
        raise ConfigurationError(
            f"Identifier '{repr(id_string)}' in '{param_name}' is not a string."
        )
    if OID_REGEX.fullmatch(id_string):
        # Attempt to translate OID strings to human-readable form
        # whenever possible
        return asn1crypto_class.map(id_string)
    else:
        try:
            # try to see if the usage string maps to an OID before
            # proceeding
            asn1crypto_class.unmap(id_string)
        except ValueError:
            raise ConfigurationError(
                f"'{id_string}' in '{param_name}' is not a valid "
                f"{asn1crypto_class.__name__}"
            )
        return id_string


def _ensure_strings(strings, param_name):

    err_msg = (
        f"'{param_name}' must be specified as a "
        "list of strings, or a string."
    )
    if isinstance(strings, str):
        strings = (strings,)
    elif not isinstance(strings, (list, tuple)):
        raise ConfigurationError(err_msg)

    return strings


def process_oids(asn1crypto_class: Type[ObjectIdentifier], strings, param_name):
    strings = _ensure_strings(strings, param_name)
    for usage_string in strings:
        yield process_oid(asn1crypto_class, usage_string, param_name)


def process_bit_string_flags(asn1crypto_class: Type[BitString], strings,
                             param_name):
    strings = _ensure_strings(strings, param_name)
    valid_values = asn1crypto_class._map.values()
    for flag_string in strings:
        if not isinstance(flag_string, str):
            raise ConfigurationError(
                f"Flag identifier '{repr(flag_string)}' is not a string."
            )
        elif flag_string not in valid_values:
            raise ConfigurationError(
                f"'{repr(flag_string)}' is not a valid "
                f"{asn1crypto_class.__name__} flag name."
            )
        # Use yield to keep the API consistent with process_oids, we don't
        # change anything
        yield flag_string
