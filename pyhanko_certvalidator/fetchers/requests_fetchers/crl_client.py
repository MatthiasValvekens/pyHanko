from typing import Iterable

import logging
import requests
from asn1crypto import crl, x509, pem

from ... import errors
from .util import RequestsFetcherMixin
from ..api import CRLFetcher
from ..common_utils import crl_job_results_as_completed


logger = logging.getLogger(__name__)


class RequestsCRLFetcher(CRLFetcher, RequestsFetcherMixin):

    async def fetch(self, cert: x509.Certificate, *, use_deltas=True):
        # Cache the futures so we don't end up queuing tons of requests
        # in concurrent execution scenarios.
        tag = cert.issuer_serial

        async def task():
            results = []
            async for fetched_crl in self._fetch(cert, use_deltas=use_deltas):
                results.append(fetched_crl)
            return results

        return await self._perform_fetch(tag, task)

    async def _fetch_single(self, url):
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

    async def _fetch(self, cert: x509.Certificate, *, use_deltas):

        # FIXME: Same as corresponding aiohttp FIXME note
        sources = cert.crl_distribution_points
        if use_deltas:
            sources.extend(cert.delta_crl_distribution_points)

        if not sources:
            return

        logger.info(f"Retrieving CRLs for {cert.subject.human_friendly}...")

        def _fetch_jobs():
            for distribution_point in sources:
                url = distribution_point.url
                # Only fetch CRLs over http
                #  (or https, but that doesn't really happen all that often)
                # In particular, don't attempt to grab CRLs over LDAP
                if url.startswith('http'):
                    yield self._fetch_single(url)

        async for result in crl_job_results_as_completed(_fetch_jobs()):
            yield result

    def fetched_crls(self) -> Iterable[crl.CertificateList]:
        return {crl_ for crls in self.get_results() for crl_ in crls}

    def fetched_crls_for_cert(self, cert) -> Iterable[crl.CertificateList]:
        return self.get_results_for_tag(cert.issuer_serial)
