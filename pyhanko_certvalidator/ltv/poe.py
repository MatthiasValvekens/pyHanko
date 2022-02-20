import hashlib
from datetime import datetime, timezone
from typing import Optional, Union

from asn1crypto import core


class POEManager:

    def __init__(self, current_dt_override: Optional[datetime] = None):
        self._poes = {}
        self._current_dt_override = current_dt_override

    def register(self, data: Union[bytes, core.Asn1Value],
                 dt: Optional[datetime] = None) -> datetime:
        if isinstance(data, core.Asn1Value):
            data = data.dump()
        digest = hashlib.sha256(data).digest()
        return self.register_by_digest(digest, dt)

    def register_by_digest(self, digest: bytes, dt: Optional[datetime] = None) \
            -> datetime:
        dt = dt or self._current_dt_override or datetime.now(timezone.utc)
        try:
            cur_poe = self._poes[digest]
            if cur_poe <= dt:
                return cur_poe
        except KeyError:
            pass
        self._poes[digest] = dt
        return dt

    def __iter__(self):
        return iter(self._poes.items())

    def __getitem__(self, item: Union[bytes, core.Asn1Value]):
        return self.register(item, dt=None)

    def __ior__(self, other):
        if not isinstance(other, POEManager):
            raise TypeError
        for digest, dt in iter(other):
            self.register_by_digest(digest, dt)