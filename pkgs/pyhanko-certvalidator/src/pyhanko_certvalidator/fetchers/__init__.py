from importlib.util import find_spec

from .api import (
    CertificateFetcher,
    CRLFetcher,
    FetcherBackend,
    Fetchers,
    OCSPFetcher,
    OwnedFetcherBackend,
)

__all__ = [
    'CRLFetcher',
    'CertificateFetcher',
    'FetcherBackend',
    'Fetchers',
    'OCSPFetcher',
    'OwnedFetcherBackend',
]


def _default_fetcher_backend() -> FetcherBackend:
    """
    Instantiate the fetcher backend used when the caller does not supply one.

    Which backend that is, is internal policy; the resources it holds are the
    responsibility of whoever called this, which is why there is no public
    equivalent.

    The preference order is ``aiohttp`` first, then ``requests``, falling
    back to an :class:`ImportError` if neither is installed.
    """

    # deferred so that no HTTP library is imported by code paths that never
    # fetch
    if find_spec('aiohttp') is not None:
        from .aiohttp_fetchers import AIOHttpFetcherBackend

        return AIOHttpFetcherBackend()
    if find_spec('requests') is not None:
        from .requests_fetchers import RequestsFetcherBackend

        return RequestsFetcherBackend()
    raise ImportError(
        "Fetching revocation info and certificates over the network "
        "requires an HTTP backend, but neither 'aiohttp' nor 'requests' is "
        "installed. You can install the missing dependencies by running "
        "\"pip install 'pyhanko-certvalidator[async-http]'\"."
    )
