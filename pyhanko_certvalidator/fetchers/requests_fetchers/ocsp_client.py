from typing import Iterable, Union

import logging
import requests
from asn1crypto import ocsp, x509, cms

from ... import errors
from ..api import OCSPFetcher
from .util import RequestsFetcherMixin
from ..common_utils import (
    process_ocsp_response_data, format_ocsp_request, ocsp_job_get_earliest
)
from ...util import issuer_serial, get_ocsp_urls

logger = logging.getLogger(__name__)


class RequestsOCSPFetcher(OCSPFetcher, RequestsFetcherMixin):

    def __init__(self, user_agent=None, per_request_timeout=10,
                 certid_hash_algo='sha1', request_nonces=True):
        super().__init__(user_agent, per_request_timeout)
        if certid_hash_algo not in ('sha1', 'sha256'):
            raise ValueError(
                f'certid_hash_algo must be one of "sha1", "sha256", not '
                f'{repr(certid_hash_algo)}'
            )
        self.certid_hash_algo = certid_hash_algo
        self.request_nonces = request_nonces

    async def fetch(self,
                    cert: Union[x509.Certificate, cms.AttributeCertificateV2],
                    issuer: x509.Certificate) -> ocsp.OCSPResponse:

        tag = (issuer_serial(cert), issuer.issuer_serial)
        return await self._perform_fetch(tag, lambda: self._fetch(cert, issuer))

    async def _fetch_single(self, ocsp_url, ocsp_request):
        try:
            logger.info(f"Requesting OCSP response from {ocsp_url}...")
            response = await self._post(
                url=ocsp_url, data=ocsp_request.dump(),
                content_type='application/ocsp-request',
                acceptable_content_types=('application/ocsp-response',)
            )
            return process_ocsp_response_data(
                response.content, ocsp_request=ocsp_request,
                ocsp_url=ocsp_url
            )
        except (ValueError, requests.RequestException) as e:
            raise errors.OCSPFetchError(
                f"Failed to fetch OCSP response from {ocsp_url}",
            ) from e

    async def _fetch(self,
                     cert: Union[x509.Certificate, cms.AttributeCertificateV2],
                     issuer: x509.Certificate):
        ocsp_request = format_ocsp_request(
            cert, issuer, certid_hash_algo=self.certid_hash_algo,
            request_nonces=self.request_nonces
        )
        ocsp_urls = get_ocsp_urls(cert)
        if not ocsp_urls:
            raise errors.OCSPFetchError("No URLs to fetch OCSP responses from")

        if isinstance(cert, x509.Certificate):
            target = cert.subject.human_friendly
        else:
            # TODO log audit ID
            target = "attribute certificate"
        logger.info(
            f"Fetching OCSP status for {target} from url(s) "
            f"{';'.join(ocsp_urls)}..."
        )
        ocsp_response = await ocsp_job_get_earliest(
            self._fetch_single(ocsp_url, ocsp_request)
            for ocsp_url in ocsp_urls
        )
        return ocsp_response

    def fetched_responses(self) -> Iterable[ocsp.OCSPResponse]:
        return self.get_results()

    def fetched_responses_for_cert(
            self, cert: Union[x509.Certificate, cms.AttributeCertificateV2]) \
            -> Iterable[ocsp.OCSPResponse]:
        target_is = issuer_serial(cert)
        return {
            resp for (subj_is, _), resp in self._iter_results()
            if subj_is == target_is
        }
