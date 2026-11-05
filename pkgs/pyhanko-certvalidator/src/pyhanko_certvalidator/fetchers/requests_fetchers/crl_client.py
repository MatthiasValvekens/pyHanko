import logging
from collections.abc import Iterable

import requests
from asn1crypto import cms, crl, pem, x509

from ... import errors
from ...util import issuer_serial
from ..api import CRLFetcher
from ..common_utils import (
    FetchKind,
    crl_fetch_url_groups,
    crl_job_results_as_completed,
    first_successful_fetch,
)
from .util import RequestsFetcherMixin

logger = logging.getLogger(__name__)


class RequestsCRLFetcher(CRLFetcher, RequestsFetcherMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._by_cert = {}

    async def fetch(
        self,
        cert: x509.Certificate | cms.AttributeCertificateV2,
        *,
        use_deltas=True,
    ):
        iss_serial = issuer_serial(cert)
        try:
            return self._by_cert[iss_serial]
        except KeyError:
            pass

        results = []
        async for fetched_crl in self._fetch(cert, use_deltas=use_deltas):
            results.append(fetched_crl)
        self._by_cert[iss_serial] = results
        return results

    async def _fetch_single(self, url):
        async def task():
            self._charge(FetchKind.CRL)
            logger.info(f"Requesting CRL from {url}...")
            try:
                response = await self._get(
                    url, acceptable_content_types=('application/pkix-crl',)
                )
                data = response.content
                if pem.detect(data):
                    _, _, data = pem.unarmor(data)
                return crl.CertificateList.load(data)
            except (ValueError, requests.RequestException) as e:
                raise errors.CRLFetchError(
                    f"Failure to fetch CRL from URL {url}"
                ) from e

        return await self._perform_fetch(url, task)

    async def _fetch(self, cert: x509.Certificate, *, use_deltas):
        url_groups = crl_fetch_url_groups(cert, use_deltas=use_deltas)

        jobs = (self._fetch_from_any(urls) for urls in url_groups)
        async for result in crl_job_results_as_completed(jobs):
            yield result

    async def _fetch_from_any(self, urls):
        # Don't hit the network for the other alternatives if we already
        # have a CRL from one of them.
        for url in urls:
            cached = self._cached_success(url)
            if cached is not None:
                return cached
        return await first_successful_fetch(
            (self._fetch_single(url) for url in urls), FetchKind.CRL
        )

    def fetched_crls(self) -> Iterable[crl.CertificateList]:
        return {crl_ for crl_ in self.get_results()}

    def fetched_crls_for_cert(self, cert) -> Iterable[crl.CertificateList]:
        return self._by_cert[issuer_serial(cert)]
