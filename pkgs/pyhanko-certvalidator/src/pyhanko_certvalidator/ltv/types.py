import abc
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo

__all__ = [
    'IssuedItemContainer',
    'ValidationTimingInfo',
    'ValidationTimingParams',
]

# TODO potentially re-home these at some point


@dataclass(frozen=True)
class ValidationTimingInfo:
    validation_time: datetime
    """
    Reference time for the validation.
    """

    best_signature_time: datetime
    """
    Earliest time at which the signature was known to exist.
    In the absence of other evidence, initialise this to
    :attr:`validation_time`.
    """

    point_in_time_validation: bool
    """
    Metadata parameter indicating whether the validation is considered
    "live" or historical.
    """

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> 'ValidationTimingInfo':
        now = datetime.now(tz=tz or timezone.utc)
        return ValidationTimingInfo(
            validation_time=now,
            best_signature_time=now,
            point_in_time_validation=False,
        )


@dataclass(frozen=True)
class ValidationTimingParams:
    timing_info: ValidationTimingInfo
    time_tolerance: timedelta

    @property
    def validation_time(self):
        return self.timing_info.validation_time

    @property
    def best_signature_time(self):
        return self.timing_info.best_signature_time

    @property
    def point_in_time_validation(self):
        return self.timing_info.point_in_time_validation


class IssuedItemContainer(abc.ABC):
    """
    A container for some data object issued by an entity (e.g. a certificate).
    """

    @property
    def issuance_date(self) -> datetime | None:
        """
        The issuance date of the item.
        """

        raise NotImplementedError
