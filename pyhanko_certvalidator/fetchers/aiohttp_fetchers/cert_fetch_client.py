import asyncio
from typing import Union, Iterable

import aiohttp
import logging
from asn1crypto import x509

from ...errors import CertificateFetchError
from ..api import CertificateFetcher
from .util import AIOHttpMixin, LazySession
from ..common_utils import (
    unpack_cert_content, ACCEPTABLE_STRICT_CERT_CONTENT_TYPES,
    ACCEPTABLE_CERT_PEM_ALIASES
)


logger = logging.getLogger(__name__)


class AIOHttpCertificateFetcher(CertificateFetcher, AIOHttpMixin):
    def __init__(self, session: Union[aiohttp.ClientSession, LazySession],
                 user_agent=None, per_request_timeout=10, permit_pem=True):
        super().__init__(session, user_agent, per_request_timeout)
        self.permit_pem = permit_pem

    async def fetch_certs(self, url, url_origin_type):
        """
        Fetch one or more certificates from a URL.

        :param url:
            URL to fetch.
        :param url_origin_type:
            Parameter indicating where the URL came from (e.g. 'CRL'),
            for error reporting purposes.
        :raises:
            CertificateFetchError - when a network I/O or decoding error occurs
        :return:
            An iterable of asn1crypto.x509.Certificate objects.
        """

        async def task():
            try:
                logger.info(f"Fetching certificates from {url}...")
                return await _grab_certs(
                    url, permit_pem=self.permit_pem,
                    timeout=self.per_request_timeout,
                    user_agent=self.user_agent,
                    session=await self.get_session(),
                    url_origin_type=url_origin_type
                )
            except (ValueError, aiohttp.ClientError) as e:
                raise CertificateFetchError(
                    f"Failed to fetch certificate(s) from url {url}."
                ) from e

        return await self._post_fetch_task(url, task)

    # FIXME improve error granularity (allow job to succeed if one of the
    #  fetches fails)
    async def fetch_cert_issuers(self, cert: x509.Certificate):
        aia_value = cert.authority_information_access_value
        if aia_value is None:
            return
        fetch_jobs = []
        for entry in aia_value:
            if entry['access_method'].native == 'ca_issuers':
                location = entry['access_location']
                if location.name != 'uniform_resource_identifier':
                    continue
                url = location.native
                if url.startswith('http'):
                    fetch_jobs.append(
                        self.fetch_certs(url, url_origin_type='certificate')
                    )
        logger.info(
            f"Retrieving issuer certs for {cert.subject.human_friendly}..."
        )
        for fetch_job in asyncio.as_completed(fetch_jobs):
            certs_fetched = await fetch_job
            for cert in certs_fetched:
                yield cert

    async def fetch_crl_issuers(self, certificate_list):
        fetch_jobs = [
            self.fetch_certs(url, url_origin_type='CRL')
            for url in certificate_list.issuer_cert_urls
        ]
        for fetch_job in asyncio.as_completed(fetch_jobs):
            certs_fetched = await fetch_job
            for cert in certs_fetched:
                yield cert

    def fetched_certs(self) -> Iterable[x509.Certificate]:
        return self.get_results()


async def _grab_certs(url, *, user_agent, session: aiohttp.ClientSession,
                      url_origin_type, timeout, permit_pem=True):
    """
    Grab one or more certificates from a caIssuers URL.

    We accept two types of content in the response:
      - A single DER-encoded X.509 certificate
      - A PKCS#7 'certs-only' SignedData message
      - PEM-encoded certificates (if permit_pem=True)

    Note: strictly speaking, you're not supposed to use PEM to serve certs for
    AIA purposes in PEM format, but people do it anyway.
    """

    acceptable_cts = ACCEPTABLE_STRICT_CERT_CONTENT_TYPES
    if permit_pem:
        acceptable_cts += ACCEPTABLE_CERT_PEM_ALIASES

    headers = {
        'Accept': ','.join(acceptable_cts),
        'User-Agent': user_agent
    }
    cl_timeout = aiohttp.ClientTimeout(timeout)
    async with session.get(url=url, headers=headers, timeout=cl_timeout,
                           raise_for_status=True) as response:
        response_data = await response.read()
        ct_err = None
        try:
            content_type = response.headers['Content-Type'].strip()
            if content_type not in acceptable_cts:
                ct_err = (
                    f"Unacceptable content type '{repr(content_type)}' "
                    f"when fetching issuer certificate for {url_origin_type} "
                    f"from URL {url}."
                )
        except KeyError:
            ct_err = (
                f"Unclear content type when fetching issuer "
                f"certificate for {url_origin_type} from URL "
                f"{url}."
            )

        if ct_err is not None:
            raise aiohttp.ContentTypeError(
                response.request_info, response.history,
                message=ct_err, headers=response.headers,
            )
    certs = unpack_cert_content(response_data, content_type, url, permit_pem)
    return list(certs)
