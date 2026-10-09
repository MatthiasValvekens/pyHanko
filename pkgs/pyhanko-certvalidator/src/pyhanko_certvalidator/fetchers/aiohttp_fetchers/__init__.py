import aiohttp

from ..api import FetcherBackend, Fetchers, FetchLimits
from ..common_utils import FetchBudget
from .cert_fetch_client import AIOHttpCertificateFetcher
from .crl_client import AIOHttpCRLFetcher
from .ocsp_client import AIOHttpOCSPFetcher
from .util import LazySession

__all__ = ['AIOHttpFetcherBackend']


class AIOHttpFetcherBackend(FetcherBackend):
    """
    :param limits:
        .. versionadded:: 0.33.0

        Bounds on the amount of fetching performed by the fetchers produced
        by this backend, see :class:`.FetchLimits`. Every call to
        :meth:`get_fetchers` starts a fresh budget.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession | None = None,
        per_request_timeout=10,
        *,
        limits: FetchLimits = FetchLimits(),  # noqa: B008
    ):
        self.session = session or LazySession()
        self.per_request_timeout = per_request_timeout
        self.limits = limits

    def get_fetchers(self) -> Fetchers:
        session = self.session
        to = self.per_request_timeout
        budget = FetchBudget(self.limits)
        return Fetchers(
            ocsp_fetcher=AIOHttpOCSPFetcher(
                session, per_request_timeout=to, budget=budget
            ),
            crl_fetcher=AIOHttpCRLFetcher(
                session, per_request_timeout=to, budget=budget
            ),
            cert_fetcher=AIOHttpCertificateFetcher(
                session, per_request_timeout=to, budget=budget
            ),
        )

    async def close(self):
        session = self.session
        # only close the session if it's a lazy session;
        # a session passed in by the caller is their own responsibility
        if isinstance(session, LazySession):
            await session.close()
