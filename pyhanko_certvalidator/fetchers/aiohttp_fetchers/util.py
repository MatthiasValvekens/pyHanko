import aiohttp

from typing import Union
from ..api import DEFAULT_USER_AGENT
from ..common_utils import queue_fetch_task

__all__ = ['LazySession', 'AIOHttpMixin']


class LazySession:

    def __init__(self):
        self._session = None

    async def get_session(self):
        session = self._session
        if session is None:
            self._session = session = aiohttp.ClientSession()
        return session

    async def close(self):
        session = self._session
        if session is not None:
            await session.close()


class AIOHttpMixin:

    def __init__(self, session: Union[aiohttp.ClientSession, LazySession],
                 user_agent=None, per_request_timeout=10):
        self._session = session
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.per_request_timeout = per_request_timeout
        self.__results = {}
        self.__result_events = {}
        super().__init__()

    async def get_session(self) -> aiohttp.ClientSession:
        session = self._session
        if isinstance(session, LazySession):
            return await session.get_session()
        else:
            return session

    def get_results(self):
        return self.__results.values()

    def get_results_for_tag(self, tag):
        return self.__results[tag]

    def _iter_results(self):
        yield from self.__results.items()

    async def _post_fetch_task(self, tag, async_fun):
        return await queue_fetch_task(
            self.__results, self.__result_events, tag, async_fun
        )
