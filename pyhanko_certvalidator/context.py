import asyncio
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import binascii
from typing import Optional, Iterable, Union, List

from asn1crypto import crl, ocsp, x509
from asn1crypto.util import timezone

from ._errors import pretty_message
from ._types import type_name
from .errors import OCSPFetchError
from .fetchers import Fetchers, FetcherBackend, default_fetcher_backend
from .path import ValidationPath
from .policy_decl import RevocationCheckingPolicy, CertRevTrustPolicy
from .registry import CertificateRegistry
from .revinfo_archival import OCSPWithPOE, RevinfoFreshnessPOE, CRLWithPOE, \
    ValidationTimingInfo, sort_freshest_first


@dataclass(frozen=True)
class ACTargetDescription:
    """
    Value type to guide attribute certificate targeting checks, for
    attribute certificates that use the target information extension.

    As stipulated in RFC 5755, an AC targeting check passes if the
    information in the relevant :class:`.AATargetDescription` matches
    at least one ``Target`` in the AC's target information extension.
    """

    validator_names: List[x509.GeneralName] = field(default_factory=list)
    """
    The validating entity's names.

    This value is matched directly against any ``Target``s that use the
    ``targetName`` alternative.
    """

    group_memberships: List[x509.GeneralName] = field(default_factory=list)
    """
    The validating entity's group memberships.

    This value is matched against any ``Target``s that use the ``targetGroup``
    alternative.
    """


class ValidationContext:

    # A pyhanko_certvalidator.registry.CertificateRegistry() object
    certificate_registry = None

    # A set of unicode strings of hash algorithms to be considered weak. Valid
    # options include: "md2", "md5", "sha1"
    weak_hash_algos = None

    # A set of byte strings of the SHA-1 hashes of certificates that are whitelisted
    _whitelisted_certs = None

    # A dict with keys being an asn1crypto.x509.Certificate.signature byte
    # string of a certificate. Each value is a
    # pyhanko_certvalidator.path.ValidationPath object of a fully-validated path
    # for that certificate.
    _validate_map = None

    # A dict with keys being an asn1crypto.crl.CertificateList.signature byte
    # string of a CRL. Each value is an asn1crypto.x509.Certificate object of
    # the validated issuer of the CRL.
    _crl_issuer_map = None

    # If CRLs or OCSP responses can be fetched from the network
    _allow_fetching = False

    _crls = None

    _ocsps = None

    # A dict with keys being an asn1crypto.x509.Certificate.issuer_serial byte
    # string of the certificate, and the value being an
    # asn1crypto.x509.Certificate object containing a certificate from a CRL
    # or OCSP response that was fetched. Only certificates not already part of
    # the .certificate_registry are added to this dict.
    _revocation_certs = None

    # Any exceptions that were ignored while the revocation_mode is "soft-fail"
    _soft_fail_exceptions = None

    # By default, any CRLs or OCSP responses that are passed to the constructor
    # are chccked. If _allow_fetching is True, any CRLs or OCSP responses that
    # can be downloaded will also be checked. The next two attributes change
    # that behavior.

    _fetchers: Fetchers = None

    _acceptable_ac_targets = None

    def __init__(
            self,
            trust_roots: Optional[Iterable[x509.Certificate]] = None,
            extra_trust_roots: Optional[Iterable[x509.Certificate]] = None,
            other_certs: Optional[Iterable[x509.Certificate]] = None,
            whitelisted_certs: Optional[Iterable[Union[bytes, str]]] = None,
            moment: Optional[datetime] = None,
            use_poe_time: Optional[datetime] = None,
            allow_fetching: bool = False,
            crls: Optional[Iterable[Union[bytes, crl.CertificateList]]] = None,
            ocsps: Optional[Iterable[Union[bytes, ocsp.OCSPResponse]]] = None,
            revocation_mode: str = "soft-fail",
            revinfo_policy: Optional[CertRevTrustPolicy] = None,
            weak_hash_algos: Iterable[str] = None,
            time_tolerance: timedelta = timedelta(seconds=1),
            retroactive_revinfo: bool = False,
            fetcher_backend: FetcherBackend = None,
            acceptable_ac_targets: Optional[ACTargetDescription] = None,
            fetchers: Fetchers = None):
        """
        :param trust_roots:
            If the operating system's trust list should not be used, instead
            pass a list of byte strings containing DER or PEM-encoded X.509
            certificates, or asn1crypto.x509.Certificate objects. These
            certificates will be used as the trust roots for the path being
            built.

        :param extra_trust_roots:
            If the operating system's trust list should be used, but augmented
            with one or more extra certificates. This should be a list of byte
            strings containing DER or PEM-encoded X.509 certificates, or
            asn1crypto.x509.Certificate objects.

        :param other_certs:
            A list of byte strings containing DER or PEM-encoded X.509
            certificates, or a list of asn1crypto.x509.Certificate objects.
            These other certs are usually provided by the service/item being
            validated. In TLS, these would be intermediate chain certs.

        :param whitelisted_certs:
            None or a list of byte strings or unicode strings of the SHA-1
            fingerprint of one or more certificates. The fingerprint is a hex
            encoding of the SHA-1 byte string, optionally separated into pairs
            by spaces or colons. These whilelisted certificates will not be
            checked for validity dates. If one of the certificates is an
            end-entity certificate in a certificate path, any TLS hostname
            mismatches, key usage errors or extended key usage errors will also
            be ignored.

        :param moment:
            If certificate validation should be performed based on a date and
            time other than right now. A datetime.datetime object with a tzinfo
            value. If this parameter is specified, then the only way to check
            OCSP and CRL responses is to pass them via the crls and ocsps
            parameters. Can not be combined with allow_fetching=True.

        :param use_poe_time:
            The presumptive time at which the certificate was used.
            Assumed equal to :class:`moment` if unspecified.

            .. note::
                The difference is significant in some point-in-time validation
                models, where the signature is validated after a
                "cooldown period" of sorts.

        :param crls:
            None or a list/tuple of asn1crypto.crl.CertificateList objects of
            pre-fetched/cached CRLs to be utilized during validation of paths

        :param ocsps:
            None or a list/tuple of asn1crypto.ocsp.OCSPResponse objects of
            pre-fetched/cached OCSP responses to be utilized during validation
            of paths

        :param allow_fetching:
            A bool - if HTTP requests should be made to fetch CRLs and OCSP
            responses. If this is True and certificates contain the location of
            a CRL or OCSP responder, an HTTP request will be made to obtain
            information for revocation checking.

        :param revocation_mode:
            A unicode string of the revocation mode to use: "soft-fail" (the
            default), "hard-fail" or "require". In "soft-fail" mode, any sort of
            error in fetching or locating revocation information is ignored. In
            "hard-fail" mode, if a certificate has a known CRL or OCSP and it
            can not be checked, it is considered a revocation failure. In
            "require" mode, every certificate in the certificate path must have
            a CRL or OCSP.

        :param weak_hash_algos:
            A set of unicode strings of hash algorithms that should be
            considered weak.

        :param time_tolerance:
            Time delta tolerance allowed in validity checks.
            Defaults to one second.

        :param retroactive_revinfo:
            Treat revocation info as retroactively valid, i.e. ignore the
            ``this_update`` field in CRLs and OCSP responses.
            Defaults to ``False``.

            .. warning::
                Be careful with this option, since it will cause incorrect
                behaviour for CAs that make use of certificate holds or other
                reversible revocation methods.
        """

        if revinfo_policy is None:
            revinfo_policy = CertRevTrustPolicy(
                RevocationCheckingPolicy.from_legacy(revocation_mode),
                retroactive_revinfo=retroactive_revinfo
            )
        elif revinfo_policy.freshness is not None:
            raise NotImplementedError("Freshness has not been implemented yet.")
        elif revinfo_policy.expected_post_expiry_revinfo_time is not None:
            raise NotImplementedError(
                "Dealing with post-expiry revocation info has not been "
                "implemented yet."
            )
        self.revinfo_policy = revinfo_policy

        if crls is not None:
            new_crls = []
            for crl_ in crls:
                if isinstance(crl_, bytes):
                    crl_ = crl.CertificateList.load(crl_)
                if isinstance(crl_, crl.CertificateList):
                    crl_ = CRLWithPOE(RevinfoFreshnessPOE.unknown(), crl_)
                if isinstance(crl_, CRLWithPOE):
                    new_crls.append(crl_)
                else:
                    # TODO update error messages
                    raise TypeError(pretty_message(
                        '''
                        crls must be a list of byte strings or
                        asn1crypto.crl.CertificateList objects, not %s
                        ''',
                        type_name(crl_)
                    ))
            crls = sort_freshest_first(new_crls)

        if ocsps is not None:
            new_ocsps = []
            for ocsp_ in ocsps:
                if isinstance(ocsp_, bytes):
                    ocsp_ = ocsp.OCSPResponse.load(ocsp_)
                if isinstance(ocsp_, ocsp.OCSPResponse):
                    extr = OCSPWithPOE.load_multi(
                        RevinfoFreshnessPOE.unknown(), ocsp_
                    )
                    new_ocsps.extend(extr)
                elif isinstance(ocsp_, OCSPWithPOE):
                    new_ocsps.append(ocsp_)
                else:
                    raise TypeError(pretty_message(
                        '''
                        ocsps must be a list of byte strings or
                        asn1crypto.ocsp.OCSPResponse objects, not %s
                        ''',
                        type_name(ocsp_)
                    ))
            ocsps = sort_freshest_first(new_ocsps)

        rev_essential = revinfo_policy.revocation_checking_policy.essential
        if moment is not None:
            if allow_fetching:
                raise ValueError(pretty_message(
                    '''
                    allow_fetching must be False when moment is specified
                    '''
                ))

        elif not allow_fetching and crls is None and ocsps is None \
                and rev_essential:
            raise ValueError(pretty_message(
                '''
                revocation data is not optional and allow_fetching is False,
                however crls and ocsps are both None, meaning that no validation
                can happen
                '''
            ))

        if moment is None:
            moment = datetime.now(timezone.utc)
            point_in_time_validation = False
        elif moment.utcoffset() is None:
            raise ValueError(pretty_message(
                '''
                moment is a naive datetime object, meaning the tzinfo
                attribute is not set to a valid timezone
                '''
            ))
        else:
            point_in_time_validation = True

        if use_poe_time is None:
            use_poe_time = moment
        elif use_poe_time.utcoffset() is None:
            raise ValueError(pretty_message(
                '''
                use_poe_time is a naive datetime object, meaning the tzinfo
                attribute is not set to a valid timezone
                '''
            ))

        self._whitelisted_certs = set()
        if whitelisted_certs is not None:
            for whitelisted_cert in whitelisted_certs:
                if isinstance(whitelisted_cert, bytes):
                    whitelisted_cert = whitelisted_cert.decode('ascii')
                # Allow users to copy from various OS and browser info dialogs,
                # some of which separate the hex char pairs via spaces or colons
                whitelisted_cert = whitelisted_cert.replace(' ', '').replace(':', '')
                self._whitelisted_certs.add(
                    binascii.unhexlify(whitelisted_cert.encode('ascii'))
                )

        if weak_hash_algos is not None:
            self.weak_hash_algos = set(weak_hash_algos)
        else:
            self.weak_hash_algos = {'md2', 'md5', 'sha1'}

        cert_fetcher = None
        if allow_fetching:
            # externally managed fetchers
            if fetchers is not None:
                self._fetchers = fetchers
            else:
                # fetcher managed by this validation context,
                # but backend possibly managed externally
                if fetcher_backend is None:
                    # in this case, we load the default requests-based
                    # backend, since the caller doesn't do any resource
                    # management
                    fetcher_backend = default_fetcher_backend()
                self._fetchers = fetchers = fetcher_backend.get_fetchers()
            cert_fetcher = fetchers.cert_fetcher

        self.certificate_registry = CertificateRegistry(
            trust_roots, extra_trust_roots, other_certs,
            cert_fetcher=cert_fetcher
        )

        self._validate_map = {}
        self._crl_issuer_map = {}

        self._revocation_certs = {}

        self._crls = []
        if crls:
            self._crls = crls

        self._ocsps = []
        if ocsps:
            self._ocsps = ocsps
            for ocsp_response in ocsps:
                self._extract_ocsp_certs(ocsp_response)

        self._allow_fetching = bool(allow_fetching)
        self._soft_fail_exceptions = []
        time_tolerance = (
            abs(time_tolerance) if time_tolerance else timedelta(0)
        )
        self.timing_info = ValidationTimingInfo(
            validation_time=moment, use_poe_time=use_poe_time,
            time_tolerance=time_tolerance,
            point_in_time_validation=point_in_time_validation
        )

        self._acceptable_ac_targets = acceptable_ac_targets

    @property
    def retroactive_revinfo(self) -> bool:
        return self.revinfo_policy.retroactive_revinfo

    @property
    def time_tolerance(self) -> timedelta:
        return self.timing_info.time_tolerance

    @property
    def moment(self) -> datetime:
        return self.timing_info.validation_time

    @property
    def use_poe_time(self) -> datetime:
        return self.timing_info.use_poe_time

    @property
    def fetching_allowed(self) -> bool:
        return self._allow_fetching

    @property
    def crls(self):
        """
        A list of all cached asn1crypto.crl.CertificateList objects
        """

        raw_crls = [with_poe.crl_data for with_poe in self._crls]
        if not self._allow_fetching:
            return raw_crls
        return list(self._fetchers.crl_fetcher.fetched_crls()) + raw_crls

    @property
    def ocsps(self):
        """
        A list of all cached asn1crypto.ocsp.OCSPResponse objects
        """

        raw_ocsps = [with_poe.ocsp_response_data for with_poe in self._ocsps]
        if not self._allow_fetching:
            return raw_ocsps

        return list(self._fetchers.ocsp_fetcher.fetched_responses()) + raw_ocsps

    @property
    def new_revocation_certs(self):
        """
        A list of newly-fetched asn1crypto.x509.Certificate objects that were
        obtained from OCSP responses and CRLs
        """

        return list(self._revocation_certs.values())

    @property
    def soft_fail_exceptions(self):
        """
        A list of soft-fail exceptions that were ignored during checks
        """

        return self._soft_fail_exceptions

    def is_whitelisted(self, cert):
        """
        Checks to see if a certificate has been whitelisted

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A bool - if the certificate is whitelisted
        """

        return cert.sha1 in self._whitelisted_certs

    def _report_soft_fail(self, e: Exception):
        self._soft_fail_exceptions.append(e)

    async def async_retrieve_crls(self, cert):
        """
        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A list of asn1crypto.crl.CertificateList objects
        """
        results = await self.async_retrieve_crls_with_poe(cert)
        return [res.crl_data for res in results]

    async def async_retrieve_crls_with_poe(self, cert):
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
            CRLWithPOE(RevinfoFreshnessPOE.fresh(), crl_data)
            for crl_data in crls
        ]
        return with_poe + self._crls

    def retrieve_crls(self, cert):
        """
        .. deprecated:: 0.17.0
            Use :meth:`async_retrieve_crls` instead.

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A list of asn1crypto.crl.CertificateList objects
        """

        warnings.warn(
            "'retrieve_crls' is deprecated, use 'async_retrieve_crls' instead",
            DeprecationWarning
        )
        if not self._allow_fetching:
            return self._crls
        return asyncio.run(self.async_retrieve_crls(cert))

    async def async_retrieve_ocsps(self, cert, issuer):
        """
        :param cert:
            An asn1crypto.x509.Certificate object

        :param issuer:
            An asn1crypto.x509.Certificate object of cert's issuer

        :return:
            A list of asn1crypto.ocsp.OCSPResponse objects
        """
        results = await self.async_retrieve_ocsps_with_poe(cert, issuer)
        return [res.ocsp_response_data for res in results]

    async def async_retrieve_ocsps_with_poe(self, cert, issuer):
        """
        .. versionadded:: 0.20.0

        :param cert:
            An asn1crypto.x509.Certificate object

        :param issuer:
            An asn1crypto.x509.Certificate object of cert's issuer

        :return:
            A list of :class:`OCSPWithPOE` objects
        """

        if not self._allow_fetching:
            return self._ocsps

        fetchers = self._fetchers
        ocsps = [
            OCSPWithPOE(RevinfoFreshnessPOE.fresh(), resp)
            for resp in fetchers.ocsp_fetcher.fetched_responses_for_cert(cert)
        ]
        if not ocsps:
            ocsp_response_data \
                = await fetchers.ocsp_fetcher.fetch(cert, issuer)
            ocsps = OCSPWithPOE.load_multi(
                RevinfoFreshnessPOE.fresh(), ocsp_response_data
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

    def retrieve_ocsps(self, cert, issuer):
        """
        .. deprecated:: 0.17.0
            Use :meth:`async_retrieve_ocsps` instead.

        :param cert:
            An asn1crypto.x509.Certificate object

        :param issuer:
            An asn1crypto.x509.Certificate object of cert's issuer

        :return:
            A list of asn1crypto.ocsp.OCSPResponse objects
        """

        warnings.warn(
            "'retrieve_ocsps' is deprecated, use "
            "'async_retrieve_ocsps' instead",
            DeprecationWarning
        )

        if not self._allow_fetching:
            return self._ocsps
        return asyncio.run(self.async_retrieve_ocsps(cert, issuer))

    def _extract_ocsp_certs(self, ocsp_response: OCSPWithPOE):
        """
        Extracts any certificates included with an OCSP response and adds them
        to the certificate registry

        :param ocsp_response:
            An asn1crypto.ocsp.OCSPResponse object to look for certs inside of
        """

        basic = ocsp_response.extract_basic_ocsp_response()
        if basic['certs']:
            for other_cert in basic['certs']:
                if self.certificate_registry.add_other_cert(other_cert):
                    self._revocation_certs[other_cert.issuer_serial] = other_cert

    def record_validation(self, cert, path):
        """
        Records that a certificate has been validated, along with the path that
        was used for validation. This helps reduce duplicate work when
        validating a ceritifcate and related resources such as CRLs and OCSPs.

        :param cert:
            An ans1crypto.x509.Certificate object

        :param path:
            A pyhanko_certvalidator.path.ValidationPath object
        """

        self._validate_map[cert.signature] = path

    def check_validation(self, cert):
        """
        Checks to see if a certificate has been validated, and if so, returns
        the ValidationPath used to validate it.

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            None if not validated, or a pyhanko_certvalidator.path.ValidationPath
            object of the validation path
        """

        # CA certs are automatically trusted since they are from the trust list
        if self.certificate_registry.is_ca(cert) and cert.signature not in self._validate_map:
            self._validate_map[cert.signature] = ValidationPath(cert)

        return self._validate_map.get(cert.signature)

    def clear_validation(self, cert):
        """
        Clears the record that a certificate has been validated

        :param cert:
            An ans1crypto.x509.Certificate object
        """

        if cert.signature in self._validate_map:
            del self._validate_map[cert.signature]

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

    def check_crl_issuer(self, certificate_list):
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

    @property
    def acceptable_ac_targets(self) -> ACTargetDescription:
        return self._acceptable_ac_targets


