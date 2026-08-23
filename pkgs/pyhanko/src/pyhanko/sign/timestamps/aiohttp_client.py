import warnings
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import aiohttp
from asn1crypto import tsp
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.util import LazySession

from .api import TimeStamper
from .common_utils import TimestampRequestError, set_tsp_headers

__all__ = ['AIOHttpTimeStamper', 'HTTPTimeStamper']


def _coerce_auth(auth) -> aiohttp.BasicAuth | None:
    if auth is None or isinstance(auth, aiohttp.BasicAuth):
        return auth
    if isinstance(auth, tuple) and len(auth) == 2:
        login, password = auth
        return aiohttp.BasicAuth(login, password)
    raise TypeError(
        "Timestamp client authentication must be an 'aiohttp.BasicAuth' "
        f"object or a (user, password) pair, not {type(auth).__name__}"
    )


class HTTPTimeStamper(TimeStamper):
    """
    .. versionchanged:: 0.37.0
        Reimplemented on top of ``aiohttp``, and merged with the former
        ``AIOHttpTimeStamper``.

    Standard HTTP-based timestamp client.
    """

    def __init__(
        self,
        url,
        https=False,
        timeout=5,
        auth: aiohttp.BasicAuth | tuple[str, str] | None = None,
        headers=None,
        session: 'aiohttp.ClientSession | LazySession | None' = None,
    ):
        """
        Initialise the timestamp client.

        :param url:
            URL where the server listens for timestamp requests.
        :param https:
            Enforce HTTPS.
        :param timeout:
            Timeout (in seconds)
        :param auth:
            Authentication credentials, either as an :class:`aiohttp.BasicAuth`
            object or as a ``(user, password)`` pair.
        :param headers:
            Other headers to include.
        :param session:
            Client session to issue requests with. If left unspecified, a
            session is created and closed for the duration of every request.

            .. versionadded:: 1.0.0
        """
        if https and not url.startswith('https:'):  # pragma: nocover
            raise ValueError('Timestamp URL is not HTTPS.')
        self.url = url
        self.timeout = timeout
        self.auth = _coerce_auth(auth)
        self.headers = headers
        self._session = session
        super().__init__()

    def request_headers(self) -> dict:
        """
        Format the HTTP request headers.

        :return:
            Header dictionary.
        """
        return set_tsp_headers(self.headers or {})

    async def async_request_headers(self) -> dict:
        """
        Format the HTTP request headers.
        Subclasses that need to derive headers asynchronously — to mint a
        short-lived credential, say — can override this instead of
        :meth:`request_headers`.

        :return:
            Header dictionary.
        """
        return self.request_headers()

    @asynccontextmanager
    async def _acquire_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        session = self._session
        if session is None:
            # A timestamper is routinely reused across top-level calls, each of
            # which runs its own event loop, so it cannot hold on to a session
            # of its own. There is nothing to pool anyway: a timestamp request
            # is a single POST.
            own_session = LazySession()
            try:
                yield own_session.get_session()
            finally:
                await own_session.close()
        elif isinstance(session, LazySession):
            yield session.get_session()
        else:
            yield session

    async def async_request_tsa_response(
        self, req: tsp.TimeStampReq
    ) -> tsp.TimeStampResp:
        cl_timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = await self.async_request_headers()
        try:
            async with (
                self._acquire_session() as session,
                session.post(
                    url=self.url,
                    headers=headers,
                    data=req.dump(),
                    auth=self.auth,
                    raise_for_status=True,
                    timeout=cl_timeout,
                ) as response,
            ):
                response_data = await response.read()
                ct = response.headers.get('Content-Type')
                if ct != 'application/timestamp-reply':
                    msg = (
                        f'Timestamp server response is malformed: '
                        f'expected content type '
                        f'application/timestamp-reply, but got {ct}.'
                    )
                    raise aiohttp.ContentTypeError(
                        response.request_info,
                        response.history,
                        message=msg,
                        headers=response.headers,
                    )
        except (aiohttp.ClientError, OSError) as e:
            raise TimestampRequestError(
                'Error while contacting timestamp service',
            ) from e
        return tsp.TimeStampResp.load(response_data)


class AIOHttpTimeStamper(HTTPTimeStamper):
    """
    .. deprecated:: 0.37.0
        :class:`~pyhanko.sign.timestamps.aiohttp_client.HTTPTimeStamper` is now
        implemented on top of ``aiohttp`` as well, and takes an optional
        ``session`` argument. Use it instead; this class will be removed in a
        future release.

    Timestamp client that issues its requests through a caller-supplied
    ``aiohttp`` session.
    """

    def __init__(
        self,
        url,
        session: aiohttp.ClientSession | LazySession,
        https=False,
        timeout=5,
        headers=None,
        auth: aiohttp.BasicAuth | None = None,
    ):
        """
        Initialise the timestamp client.

        :param url:
            URL where the server listens for timestamp requests.
        :param session:
            Client session to issue requests with.
        :param https:
            Enforce HTTPS.
        :param timeout:
            Timeout (in seconds)
        :param headers:
            Other headers to include.
        :param auth:
            `aiohttp.BasicAuth` object with authentication credentials.
        """
        warnings.warn(
            "'AIOHttpTimeStamper' is deprecated and will be removed in a "
            "future release; use 'HTTPTimeStamper' with a 'session' argument "
            "instead",
            DeprecationWarning,
        )
        super().__init__(
            url,
            https=https,
            timeout=timeout,
            auth=auth,
            headers=headers,
            session=session,
        )
