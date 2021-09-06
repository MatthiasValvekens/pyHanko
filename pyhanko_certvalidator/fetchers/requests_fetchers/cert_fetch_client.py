from typing import Iterable
import logging
import requests

from asn1crypto import x509

from ...errors import CertificateFetchError
from ..api import CertificateFetcher
from .util import RequestsFetcherMixin
from ..common_utils import (
    unpack_cert_content, ACCEPTABLE_STRICT_CERT_CONTENT_TYPES,
    ACCEPTABLE_CERT_PEM_ALIASES
)

logger = logging.getLogger(__name__)


class RequestsCertificateFetcher(CertificateFetcher, RequestsFetcherMixin):
    """
    Implementation of async CertificateFetcher API using requests, for backwards
    compatibility. This class does not require resource management.
    """

    def __init__(self, user_agent=None, per_request_timeout=10,
                 permit_pem=True):
        super().__init__(user_agent, per_request_timeout)
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
                results = await self._grab_certs(
                    url, url_origin_type=url_origin_type,
                    permit_pem=self.permit_pem,
                )
            except (ValueError, requests.RequestException) as e:
                raise CertificateFetchError(
                    f"Failed to fetch certificate(s) from url {url}."
                ) from e
            return list(results)
        return await self._perform_fetch(url, task)

    async def fetch_cert_issuers(self, cert: x509.Certificate):
        aia_value = cert.authority_information_access_value
        if aia_value is None:
            return
        for entry in aia_value:
            if entry['access_method'].native == 'ca_issuers':
                location = entry['access_location']
                if location.name != 'uniform_resource_identifier':
                    continue
                url = location.native
                if url.startswith('http'):
                    fetched_certs = await self.fetch_certs(
                        url, url_origin_type='certificate'
                    )
                    for cert in fetched_certs:
                        yield cert

    async def fetch_crl_issuers(self, certificate_list):
        for url in certificate_list.issuer_cert_urls:
            for cert in await self.fetch_certs(url, url_origin_type='CRL'):
                yield cert

    def fetched_certs(self) -> Iterable[x509.Certificate]:
        return self.get_results()

    async def _grab_certs(self, url, *, url_origin_type, permit_pem=True):
        """
        Grab one or more certificates from a caIssuers URL.

        We accept two types of content in the response:
          - A single DER-encoded X.509 certificate
          - A PKCS#7 'certs-only' SignedData message
          - PEM-encoded certificates (if permit_pem=True)

        Note: strictly speaking, you're not supposed to use PEM to serve certs
        for AIA purposes in PEM format, but people do it anyway.
        """

        acceptable_cts = ACCEPTABLE_STRICT_CERT_CONTENT_TYPES
        if permit_pem:
            acceptable_cts += ACCEPTABLE_CERT_PEM_ALIASES

        response = await self._get(url, acceptable_content_types=acceptable_cts)
        content_type = response.headers['Content-Type'].strip()
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
            raise requests.RequestException(ct_err)
        certs = unpack_cert_content(
            response.content, content_type, url, permit_pem
        )
        return certs
