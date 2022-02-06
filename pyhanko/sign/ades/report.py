"""
Module for AdES reporting data.

Defines enums for all AdES validation statuses defined in ETSI EN 319 102-1,
clause 5.1.3.
"""

import enum

__all__ = ['AdESStatus', 'AdESSubIndic', 'AdESFailure', 'AdESIndeterminate']

# TODO document these


class AdESStatus(enum.Enum):
    PASSED = enum.auto()
    INDETERMINATE = enum.auto()
    FAILED = enum.auto()


class AdESSubIndic:
    @property
    def status(self) -> AdESStatus:
        raise NotImplementedError


class AdESPassed(AdESSubIndic, enum.Enum):
    OK = enum.auto()

    @property
    def status(self) -> AdESStatus:
        return AdESStatus.PASSED


class AdESFailure(AdESSubIndic, enum.Enum):
    FORMAT_FAILURE = enum.auto()
    HASH_FAILURE = enum.auto()
    SIG_CRYPTO_FAILURE = enum.auto()
    REVOKED = enum.auto()

    @property
    def status(self):
        return AdESStatus.FAILED


class AdESIndeterminate(AdESSubIndic, enum.Enum):
    SIG_CONSTRAINTS_FAILURE = enum.auto()
    CHAIN_CONSTRAINTS_FAILURE = enum.auto()
    CERTIFICATE_CHAIN_GENERAL_FAILURE = enum.auto()
    CRYPTO_CONSTRAINTS_FAILURE = enum.auto()
    EXPIRED = enum.auto()
    NOT_YET_VALID = enum.auto()
    POLICY_PROCESSING_ERROR = enum.auto()
    SIGNATURE_POLICY_NOT_AVAILABLE = enum.auto()
    TIMESTAMP_ORDER_FAILURE = enum.auto()
    NO_SIGNING_CERTIFICATE_FOUND = enum.auto()
    NO_CERTIFICATE_CHAIN_FOUND = enum.auto()
    REVOKED_NO_POE = enum.auto()
    REVOKED_CA_NO_POE = enum.auto()
    OUT_OF_BOUNDS_NO_POE = enum.auto()
    CRYPTO_CONSTRAINTS_FAILURE_NO_POE = enum.auto()
    NO_POE = enum.auto()
    TRY_LATER = enum.auto()
    SIGNED_DATA_NOT_FOUND = enum.auto()
    GENERIC = enum.auto()

    @property
    def status(self):
        return AdESStatus.INDETERMINATE
