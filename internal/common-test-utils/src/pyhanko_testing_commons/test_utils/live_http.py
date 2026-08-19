"""Ambient in-process HTTP serving for certomancer PKI architectures.

Architectures are registered one at a time, so a test only serves what it
asked for and anything else still fails to resolve.
"""

import asyncio
import threading
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import TypeVar
from urllib.parse import urlsplit

import aiohttp
import aiohttp.test_utils
import aiohttp.web
import requests_mock
from certomancer.integrations.aiohttp_illusionist import (
    AsyncIllusionist,
    _FakeResolver,
)
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import PKIArchitecture
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import util as _session_mod

__all__ = [
    'PKIServiceRegistry',
    'live_pki_services',
    'redirect_default_sessions',
]

T = TypeVar('T')

_Handler = Callable[
    [aiohttp.web.Request], Awaitable[aiohttp.web.StreamResponse]
]


class _ServerLoop:
    """An event loop running in a daemon thread, hosting the test server.

    The server cannot live on the same loop as the code under test: the
    synchronous entry points each open and close their own loop through
    ``asyncio.run``, and when the test itself is synchronous there is no loop
    in scope to attach a server to.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run, name='pyhanko-test-http', daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro: Awaitable[T]) -> T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()


_server_loop: _ServerLoop | None = None
_server_loop_lock = threading.Lock()


def _get_server_loop() -> _ServerLoop:
    global _server_loop
    with _server_loop_lock:
        if _server_loop is None:
            _server_loop = _ServerLoop()
        return _server_loop


class PKIServiceRegistry:
    """The set of PKI services currently being served.

    Populated through :meth:`register`, the counterpart of
    ``Illusionist(arch).register(mocker)``.
    """

    def __init__(self, mocker: requests_mock.Mocker) -> None:
        self._routes: dict[tuple[str, str], _Handler] = {}
        # transitional: still serves the code paths that run on ``requests``
        self._mocker = mocker

    def register(
        self, arch: PKIArchitecture, at_time: datetime | None = None
    ) -> None:
        """Serve an architecture's OCSP responders, CRL repositories, time
        stamping services and service plugins.

        :param arch:
            The architecture to serve.
        :param at_time:
            Fixed time to answer requests at. Defaults to the current time,
            which under ``freeze_time`` is the frozen one.
        """

        illusionist = AsyncIllusionist(arch, at_time=at_time)
        # certomancer builds a whole application; all this needs is the
        # handlers out of it, since routing happens through _dispatch
        for resource in illusionist.build_app().router.resources():
            for route in resource:
                key = (route.method, resource.canonical)
                self._routes[key] = route.handler
        Illusionist(arch, at_time=at_time).register(self._mocker)

    def post(
        self,
        url: str,
        *,
        content: Callable[[bytes], bytes],
        content_type: str | None = None,
    ) -> None:
        """Serve a POST endpoint from a callback over the request body.

        The counterpart of ``requests_mock.post(url, content=..., headers=...)``
        for endpoints certomancer does not provide — a timestamping service
        that answers with the wrong content type, say.

        :param url:
            URL to serve; only its path is used.
        :param content:
            Callback producing the response body from the request body.
        :param content_type:
            Response content type. Defaults to ``application/octet-stream``,
            as it does in ``aiohttp``.
        """

        async def handle(
            request: aiohttp.web.Request,
        ) -> aiohttp.web.StreamResponse:
            return aiohttp.web.Response(
                body=content(await request.read()),
                content_type=content_type,
            )

        self._routes['POST', urlsplit(url).path] = handle
        self._mocker.post(
            url,
            content=lambda request, _context: content(request.body),
            headers=({'Content-Type': content_type} if content_type else {}),
        )

    async def _dispatch(
        self, request: aiohttp.web.Request
    ) -> aiohttp.web.StreamResponse:
        try:
            handler = self._routes[request.method, request.path]
        except KeyError:
            raise aiohttp.web.HTTPNotFound(
                text=(
                    f"No PKI service registered at "
                    f"{request.method} {request.path}"
                )
            )
        return await handler(request)


@contextmanager
def redirect_default_sessions(port: int) -> Iterator[None]:
    """Point every implicitly created client session at the given port.

    Patches the factory behind
    :class:`~pyhanko_certvalidator.fetchers.aiohttp_fetchers.util.LazySession`,
    which is what both the default fetcher backend and the default timestamp
    client fall back on when the caller supplies no session of their own.
    """

    def factory() -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                resolver=_FakeResolver(port), use_dns_cache=False
            )
        )

    original = _session_mod._default_session
    _session_mod._default_session = factory
    try:
        yield
    finally:
        _session_mod._default_session = original


@contextmanager
def live_pki_services() -> Iterator[PKIServiceRegistry]:
    """Start the PKI service server and route default sessions to it.

    The ambient equivalent of ``requests_mock.Mocker()``; the yielded registry
    stands in for the mocker that architectures get registered against.
    """

    with requests_mock.Mocker(real_http=False) as mocker:
        registry = PKIServiceRegistry(mocker)
        app = aiohttp.web.Application()
        app.router.add_route('*', '/{tail:.*}', registry._dispatch)
        server = aiohttp.test_utils.TestServer(app)
        loop = _get_server_loop()
        # the access logger reads the local UTC offset, which is not always
        # available while the clock is patched
        loop.run(server.start_server(access_log=None))
        try:
            port = server.port
            assert port is not None
            with redirect_default_sessions(port):
                yield registry
        finally:
            loop.run(server.close())
