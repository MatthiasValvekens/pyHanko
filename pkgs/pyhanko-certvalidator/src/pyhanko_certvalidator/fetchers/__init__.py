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
    """

    # deferred so that aiohttp is not imported by code paths that never fetch
    from .aiohttp_fetchers import AIOHttpFetcherBackend

    return AIOHttpFetcherBackend()
