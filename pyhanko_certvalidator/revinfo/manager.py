from typing import Iterable, Optional, List

from asn1crypto import crl, ocsp, x509

from pyhanko_certvalidator.authority import Authority
from pyhanko_certvalidator.errors import OCSPFetchError
from pyhanko_certvalidator.fetchers import Fetchers
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy
from pyhanko_certvalidator.registry import CertificateRegistry
from pyhanko_certvalidator.revinfo.archival import CRLWithPOE, OCSPWithPOE, \
    sort_freshest_first, POE


class RevinfoManager:

    def __init__(self, certificate_registry: CertificateRegistry,
                 revinfo_policy: CertRevTrustPolicy,
                 crls: Iterable[CRLWithPOE], ocsps: Iterable[OCSPWithPOE],
                 allow_fetching: bool = False,
                 fetchers: Optional[Fetchers] = None):
        self._certificate_registry = certificate_registry
        self._revinfo_policy = revinfo_policy

        self._revocation_certs = {}
        self._crl_issuer_map = {}

        self._crls = []
        if crls:
            self._crls = sort_freshest_first(crls)

        self._ocsps = []
        if ocsps:
            self._ocsps = ocsps = sort_freshest_first(ocsps)
            for ocsp_response in ocsps:
                self._extract_ocsp_certs(ocsp_response)

        self._allow_fetching = allow_fetching
        self._fetchers = fetchers

    @property
    def certificate_registry(self) -> CertificateRegistry:
        return self._certificate_registry

    @property
    def fetching_allowed(self) -> bool:
        return self._allow_fetching

    @property
    def revinfo_policy(self) -> CertRevTrustPolicy:
        return self._revinfo_policy

    @property
    def crls(self) -> List[crl.CertificateList]:
        """
        A list of all cached :class:`crl.CertificateList` objects
        """

        raw_crls = [with_poe.crl_data for with_poe in self._crls]
        if not self._allow_fetching:
            return raw_crls
        return list(self._fetchers.crl_fetcher.fetched_crls()) + raw_crls

    @property
    def ocsps(self) -> List[ocsp.OCSPResponse]:
        """
        A list of all cached :class:`ocsp.OCSPResponse` objects
        """

        raw_ocsps = [with_poe.ocsp_response_data for with_poe in self._ocsps]
        if not self._allow_fetching:
            return raw_ocsps

        return list(self._fetchers.ocsp_fetcher.fetched_responses()) + raw_ocsps

    @property
    def new_revocation_certs(self) -> List[x509.Certificate]:
        """
        A list of newly-fetched :class:`x509.Certificate` objects that were
        obtained from OCSP responses and CRLs
        """

        return list(self._revocation_certs.values())

    def _extract_ocsp_certs(self, ocsp_response: OCSPWithPOE):
        """
        Extracts any certificates included with an OCSP response and adds them
        to the certificate registry

        :param ocsp_response:
            An asn1crypto.ocsp.OCSPResponse object to look for certs inside of
        """

        registry = self._certificate_registry
        revo_certs = self._revocation_certs

        basic = ocsp_response.extract_basic_ocsp_response()
        if basic is not None and basic['certs']:
            for other_cert in basic['certs']:
                if registry.add_other_cert(other_cert):
                    revo_certs[other_cert.issuer_serial] = other_cert

    def record_crl_issuer(self, certificate_list, cert):
        """
        Records the certificate that issued a certificate list. Used to reduce
        processing code when dealing with self-issued certificates and multiple
        CRLs.

        :param certificate_list:
            An ans1crypto.crl.CertificateList object

        :param cert:
            An ans1crypto.x509.Certificate object
        """

        self._crl_issuer_map[certificate_list.signature] = cert

    def check_crl_issuer(self, certificate_list) -> Optional[x509.Certificate]:
        """
        Checks to see if the certificate that signed a certificate list has
        been found

        :param certificate_list:
            An ans1crypto.crl.CertificateList object

        :return:
            None if not found, or an asn1crypto.x509.Certificate object of the
            issuer
        """

        return self._crl_issuer_map.get(certificate_list.signature)

    async def async_retrieve_crls_with_poe(self, cert) -> List[CRLWithPOE]:
        """
        .. versionadded:: 0.20.0

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A list of :class:`CRLWithPOE` objects
        """
        if not self._allow_fetching:
            return self._crls

        fetchers = self._fetchers
        try:
            crls = fetchers.crl_fetcher.fetched_crls_for_cert(cert)
        except KeyError:
            crls = await fetchers.crl_fetcher.fetch(cert)
        with_poe = [
            CRLWithPOE(POE.fresh(), crl_data)
            for crl_data in crls
        ]
        return with_poe + self._crls

    async def async_retrieve_ocsps_with_poe(self, cert, authority: Authority) \
            -> List[OCSPWithPOE]:
        """
        .. versionadded:: 0.20.0

        :param cert:
            An asn1crypto.x509.Certificate object

        :param authority:
            The issuing authority for the certificate

        :return:
            A list of :class:`OCSPWithPOE` objects
        """

        if not self._allow_fetching:
            return self._ocsps

        fetchers = self._fetchers
        ocsps = [
            OCSPWithPOE(POE.fresh(), resp)
            for resp in fetchers.ocsp_fetcher.fetched_responses_for_cert(cert)
        ]
        if not ocsps:
            ocsp_response_data \
                = await fetchers.ocsp_fetcher.fetch(cert, authority)
            ocsps = OCSPWithPOE.load_multi(
                POE.fresh(), ocsp_response_data
            )

            # Responses can contain certificates that are useful in
            # validating the response itself. We can use these since they
            # will be validated using the local trust roots.
            for resp in ocsps:
                try:
                    self._extract_ocsp_certs(resp)
                except ValueError:
                    raise OCSPFetchError(
                        "Failed to extract certificates from "
                        "fetched OCSP response"
                    )

        return ocsps + self._ocsps

