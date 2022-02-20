import abc
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

# TODO potentially re-home these at some point


@dataclass(frozen=True)
class ValidationTimingInfo:
    validation_time: datetime
    use_poe_time: datetime
    time_tolerance: timedelta
    point_in_time_validation: bool


class IssuedItemContainer(abc.ABC):
    @property
    def issuance_date(self) -> Optional[datetime]:
        raise NotImplementedError
