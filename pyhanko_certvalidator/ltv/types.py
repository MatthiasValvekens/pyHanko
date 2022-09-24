import abc
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

# TODO potentially re-home these at some point


@dataclass(frozen=True)
class ValidationTimingInfo:
    validation_time: datetime
    use_poe_time: datetime
    point_in_time_validation: bool


@dataclass(frozen=True)
class ValidationTimingParams:
    timing_info: ValidationTimingInfo
    time_tolerance: timedelta

    @property
    def validation_time(self):
        return self.timing_info.validation_time

    @property
    def use_poe_time(self):
        return self.timing_info.use_poe_time

    @property
    def point_in_time_validation(self):
        return self.timing_info.point_in_time_validation


class IssuedItemContainer(abc.ABC):
    @property
    def issuance_date(self) -> Optional[datetime]:
        raise NotImplementedError
