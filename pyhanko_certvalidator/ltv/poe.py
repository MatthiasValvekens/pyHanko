import hashlib
from datetime import datetime, timezone
from typing import Dict, Optional, Union

from asn1crypto import core

__all__ = ['POEManager', 'digest_for_poe']


def digest_for_poe(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class POEManager:
    """
    Class to manage proof-of-existence (POE) claims.

    :param current_dt_override:
        Override the current time.
    """

    def __init__(self, current_dt_override: Optional[datetime] = None):
        self._poes: Dict[bytes, datetime] = {}
        self._current_dt_override = current_dt_override

    def register(
        self, data: Union[bytes, core.Asn1Value], dt: Optional[datetime] = None
    ) -> datetime:
        """
        Register a new POE claim if no POE for an earlier time is available.

        :param data:
            Data to register a POE claim for.
        :param dt:
            The POE time to register. If ``None``, assume the current time.
        :return:
            The oldest POE datetime available.
        """
        if isinstance(data, core.Asn1Value):
            data = data.dump()
        digest = digest_for_poe(data)
        return self.register_by_digest(digest, dt)

    def register_by_digest(
        self, digest: bytes, dt: Optional[datetime] = None
    ) -> datetime:
        """
        Register a new POE claim if no POE for an earlier time is available.

        :param digest:
            SHA-256 digest of the data to register a POE claim for.
        :param dt:
            The POE time to register. If ``None``, assume the current time.
        :return:
            The oldest POE datetime available.
        """
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
        """
        Iterate over the current earliest known POE for all items currently
        being managed.

        Returns an iterator with ``(digest, poe_dt)`` pairs.
        """
        return iter(self._poes.items())

    def __getitem__(self, item: Union[bytes, core.Asn1Value]) -> datetime:
        """
        Return the earliest available POE for an item.

        .. note::
            This is an alias for :meth:`register` with `dt=None`, and hence
            will register the current time as the POE time for the given item.
            This side effect is intentional.

        :param item:
            Item to get the current POE time for.
        :return:
            A datetime object representing the earliest available POE for the
            item.
        """
        return self.register(item, dt=None)

    def __ior__(self, other):
        """
        Combine data in another POE manager with the POEs managed by this
        instance.
        """
        if not isinstance(other, POEManager):
            raise TypeError
        for digest, dt in iter(other):
            self.register_by_digest(digest, dt)

    def __copy__(self):
        new_instance = POEManager(current_dt_override=self._current_dt_override)
        new_instance._poes = dict(self._poes)
        return new_instance
