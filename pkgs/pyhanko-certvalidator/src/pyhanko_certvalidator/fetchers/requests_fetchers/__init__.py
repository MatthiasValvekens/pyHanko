"""
Fetcher implementation using the ``requests`` library for backwards
compatibility. This fetcher backend doesn't take advantage of asyncio, but
has the advantage of not requiring any resource management on the caller's part.
"""

from ..api import FetcherBackend, Fetchers, FetchLimits
from ..common_utils import FetchBudget
from .cert_fetch_client import RequestsCertificateFetcher
from .crl_client import RequestsCRLFetcher
from .ocsp_client import RequestsOCSPFetcher

__all__ = ['RequestsFetcherBackend']


class RequestsFetcherBackend(FetcherBackend):
    """
    :param limits:
        .. versionadded:: 0.33.0

        Bounds on the amount of fetching performed by the fetchers produced
        by this backend, see :class:`.FetchLimits`. Every call to
        :meth:`get_fetchers` starts a fresh budget.
    """

    def __init__(
        self,
        per_request_timeout=10,
        *,
        limits: FetchLimits = FetchLimits(),  # noqa: B008
    ):
        self.per_request_timeout = per_request_timeout
        self.limits = limits

    def get_fetchers(self) -> Fetchers:
        to = self.per_request_timeout
        budget = FetchBudget(self.limits)
        return Fetchers(
            ocsp_fetcher=RequestsOCSPFetcher(
                per_request_timeout=to, budget=budget
            ),
            crl_fetcher=RequestsCRLFetcher(
                per_request_timeout=to, budget=budget
            ),
            cert_fetcher=RequestsCertificateFetcher(
                per_request_timeout=to, budget=budget
            ),
        )

    async def close(self):
        # don't need to do anything
        return
