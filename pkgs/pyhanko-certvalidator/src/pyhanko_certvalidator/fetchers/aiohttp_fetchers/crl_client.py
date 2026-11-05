import logging
from collections.abc import Iterable

import aiohttp
from asn1crypto import cms, crl, pem, x509

from ... import errors
from ...util import issuer_serial
from ..api import CRLFetcher
from ..common_utils import (
    FetchBudget,
    FetchKind,
    crl_fetch_url_groups,
    crl_job_results_as_completed,
    first_successful_fetch,
)
from .util import AIOHttpMixin, LazySession

logger = logging.getLogger(__name__)


class AIOHttpCRLFetcher(CRLFetcher, AIOHttpMixin):
    def __init__(
        self,
        session: aiohttp.ClientSession | LazySession,
        user_agent=None,
        per_request_timeout=10,
        *,
        budget: FetchBudget | None = None,
    ):
        super().__init__(
            session, user_agent, per_request_timeout, budget=budget
        )
        self._by_cert: dict[bytes, list[crl.CertificateList]] = {}

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

    async def _fetch(self, cert: x509.Certificate, *, use_deltas):
        url_groups = crl_fetch_url_groups(cert, use_deltas=use_deltas)

        if not url_groups:
            return

        if isinstance(cert, x509.Certificate):
            target = cert.subject.human_friendly
        else:
            # TODO log audit ID
            target = "attribute certificate"
        logger.info(f"Retrieving CRLs for {target}...")

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
            (self._single_fetch(url) for url in urls), FetchKind.CRL
        )

    async def _single_fetch(self, url):
        async def task():
            self._charge(FetchKind.CRL)
            return await _grab_crl(
                url,
                user_agent=self.user_agent,
                session=self.get_session(),
                timeout=self.per_request_timeout,
            )

        return await self._post_fetch_task(url, task)

    def fetched_crls(self) -> Iterable[crl.CertificateList]:
        return {crl_ for crl_ in self.get_results()}

    def fetched_crls_for_cert(self, cert) -> Iterable[crl.CertificateList]:
        return self._by_cert[issuer_serial(cert)]


async def _grab_crl(
    url, *, user_agent, session: aiohttp.ClientSession, timeout
):
    """
    Fetches a CRL and parses it

    :param url:
        A unicode string of the URL to fetch the CRL from

    :param user_agent:
        A unicode string of the user agent to use when fetching the URL

    :param session:
        ``aiohttp`` client session to use.

    :param timeout:
        Timeout in seconds.

    :return:
        An asn1crypto.crl.CertificateList object
    """
    try:
        logger.info(f"Requesting CRL from {url}...")
        headers = {'Accept': 'application/pkix-crl', 'User-Agent': user_agent}
        cl_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(
            url=url, headers=headers, timeout=cl_timeout, raise_for_status=True
        ) as response:
            data = await response.read()
        if pem.detect(data):
            _, _, data = pem.unarmor(data)
        return crl.CertificateList.load(data)
    except (ValueError, aiohttp.ClientError) as e:
        raise errors.CRLFetchError(
            f"Failure to fetch CRL from URL {url}"
        ) from e
