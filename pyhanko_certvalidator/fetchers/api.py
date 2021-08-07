import abc
from dataclasses import dataclass
from typing import AsyncGenerator, Iterable

from asn1crypto import x509, ocsp, crl
from pyhanko_certvalidator.version import __version__

__all__ = [
    'OCSPFetcher', 'CRLFetcher', 'CertificateFetcher',
    'Fetchers', 'FetcherBackend', 'DEFAULT_USER_AGENT'
]

DEFAULT_USER_AGENT = 'pyhanko_certvalidator %s' % __version__


class OCSPFetcher(abc.ABC):
    # TODO docstring
    async def fetch(self, cert: x509.Certificate, issuer: x509.Certificate) \
            -> ocsp.OCSPResponse:
        raise NotImplementedError

    def fetched_responses(self) -> Iterable[ocsp.OCSPResponse]:
        raise NotImplementedError

    def fetched_responses_for_cert(self, cert: x509.Certificate) \
            -> Iterable[ocsp.OCSPResponse]:
        raise NotImplementedError


class CRLFetcher(abc.ABC):

    async def fetch(self, cert: x509.Certificate, *, use_deltas=None) \
            -> Iterable[crl.CertificateList]:
        """
        Fetches the CRLs for a certificate.

        :param cert:
            An asn1crypto.x509.Certificate object to get the CRL for

        :param use_deltas:
            A boolean indicating if delta CRLs should be fetched

        :raises:
            CRLFetchError - when a network/IO error or decoding error occurs

        :return:
            An iterable of CRLs fetched.
        """
        # side note: we don't want this to be a generator, because in principle,
        #  we always need to consider CRLs from all distribution points together
        #  anyway, so there's no "stream processing" to speak of.
        # (this is currently not 100% efficient in the default implementation,
        #  see comments below)
        raise NotImplementedError

    def fetched_crls(self) -> Iterable[crl.CertificateList]:
        raise NotImplementedError

    def fetched_crls_for_cert(self, cert: x509.Certificate) \
            -> Iterable[crl.CertificateList]:
        raise NotImplementedError


class CertificateFetcher(abc.ABC):

    def fetch_cert_issuers(self, cert: x509.Certificate) \
            -> AsyncGenerator[x509.Certificate, None]:
        """
        Fetches certificates from the authority information access extension of
        an asn1crypto.x509.Certificate

        :param cert:
            An asn1crypto.x509.Certificate object

        :raises:
            CertificateFetchError - when a network I/O or decoding error occurs

        :return:
            An asynchronous generator yielding asn1crypto.x509.Certificate
            objects that were fetched.
        """
        raise NotImplementedError

    def fetch_crl_issuers(self, certificate_list) \
            -> AsyncGenerator[x509.Certificate, None]:
        """
        Fetches certificates from the authority information access extension of
        an asn1crypto.crl.CertificateList.

        :param certificate_list:
            An asn1crypto.crl.CertificateList object

        :raises:
            CertificateFetchError - when a network I/O or decoding error occurs

        :return:
            An asynchronous generator yielding asn1crypto.x509.Certificate
            objects that were fetched.
        """
        raise NotImplementedError

    def fetched_certs(self) -> Iterable[x509.Certificate]:
        raise NotImplementedError


@dataclass(frozen=True)
class Fetchers:
    ocsp_fetcher: OCSPFetcher
    crl_fetcher: CRLFetcher
    cert_fetcher: CertificateFetcher


class FetcherBackend(abc.ABC):

    def get_fetchers(self) -> Fetchers:
        raise NotImplementedError

    async def close(self):
        pass

    async def __aenter__(self) -> Fetchers:
        return self.get_fetchers()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return await self.close()
