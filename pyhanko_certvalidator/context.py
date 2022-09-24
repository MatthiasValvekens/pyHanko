import asyncio
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import binascii
from typing import Optional, Iterable, Union, List

from asn1crypto import crl, ocsp, x509
from asn1crypto.util import timezone

from .authority import AuthorityWithCert, CertTrustAnchor
from .revinfo.manager import RevinfoManager
from .util import pretty_message
from .fetchers import Fetchers, FetcherBackend, default_fetcher_backend
from .path import ValidationPath
from .policy_decl import RevocationCheckingPolicy, CertRevTrustPolicy
from .registry import CertificateRegistry, TrustRootList, TrustManager, SimpleTrustManager, PathBuilder
from .revinfo.archival import \
    process_legacy_crl_input, \
    process_legacy_ocsp_input
from .ltv.types import ValidationTimingParams, ValidationTimingInfo
from .ltv.poe import POEManager


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

    # A set of byte strings of the SHA-1 hashes of certificates that
    # are whitelisted
    _whitelisted_certs = None

    # A dict with keys being an asn1crypto.x509.Certificate.signature byte
    # string of a certificate. Each value is a
    # pyhanko_certvalidator.path.ValidationPath object of a fully-validated path
    # for that certificate.
    _validate_map = None

    # Any exceptions that were ignored while the revocation_mode is "soft-fail"
    _soft_fail_exceptions = None

    # By default, any CRLs or OCSP responses that are passed to the constructor
    # are chccked. If _allow_fetching is True, any CRLs or OCSP responses that
    # can be downloaded will also be checked. The next two attributes change
    # that behavior.

    _acceptable_ac_targets = None

    def __init__(
            self,
            trust_roots: Optional[TrustRootList] = None,
            extra_trust_roots: Optional[TrustRootList] = None,
            other_certs: Optional[Iterable[x509.Certificate]] = None,
            whitelisted_certs: Optional[Iterable[Union[bytes, str]]] = None,
            moment: Optional[datetime] = None,
            # FIXME before releasing the AdES stuff,
            #  check if this still makes sense to include, or we should stick
            #  to `moment` only at this level of the API
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
            poe_manager: Optional[POEManager] = None,
            revinfo_manager: Optional[RevinfoManager] = None,
            certificate_registry: Optional[CertificateRegistry] = None,
            trust_manager: Optional[TrustManager] = None,
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
        :param revinfo_manager:
            Internal API, to be elaborated.
        :param trust_manager:
            Internal API, to be elaborated.
        :param certificate_registry:
            Internal API, to be elaborated.
        """

        if revinfo_policy is None:
            revinfo_policy = CertRevTrustPolicy(
                RevocationCheckingPolicy.from_legacy(revocation_mode),
                retroactive_revinfo=retroactive_revinfo
            )
        elif revinfo_policy.expected_post_expiry_revinfo_time is not None:
            raise NotImplementedError(
                "Dealing with post-expiry revocation info has not been "
                "implemented yet."
            )

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

        # TODO factor this out into a separate class that can deprecate
        #  algorithms at specific times (in accordance with AdES).
        #  For now, we consider all weak algorithms broken forever for all
        #  validation purposes.
        if weak_hash_algos is not None:
            self.weak_hash_algos = set(weak_hash_algos)
        else:
            self.weak_hash_algos = {'md2', 'md5', 'sha1'}

        cert_fetcher = None
        if allow_fetching:
            # not None -> externally managed fetchers
            if fetchers is None:
                # fetcher managed by this validation context,
                # but backend possibly managed externally
                if fetcher_backend is None:
                    # in this case, we load the default requests-based
                    # backend, since the caller doesn't do any resource
                    # management
                    fetcher_backend = default_fetcher_backend()
                fetchers = fetcher_backend.get_fetchers()
            cert_fetcher = fetchers.cert_fetcher
        else:
            fetchers = None

        if certificate_registry is None:
            certificate_registry = CertificateRegistry \
                .build(other_certs or (), cert_fetcher=cert_fetcher)

        self.certificate_registry: CertificateRegistry = certificate_registry

        if trust_manager is None:
            trust_manager = SimpleTrustManager.build(
                trust_roots=trust_roots, extra_trust_roots=extra_trust_roots
            )
        if isinstance(trust_manager, SimpleTrustManager):
            for root in trust_manager.iter_certs():
                certificate_registry.register(root)

        self.path_builder = PathBuilder(
            trust_manager=trust_manager,
            registry=certificate_registry
        )
        crls = process_legacy_crl_input(crls) if crls else ()
        ocsps = process_legacy_ocsp_input(ocsps) if ocsps else ()

        if revinfo_manager is None:
            revinfo_manager = RevinfoManager(
                certificate_registry=certificate_registry,
                poe_manager=poe_manager or POEManager(),
                revinfo_policy=revinfo_policy, crls=crls, ocsps=ocsps,
                fetchers=fetchers
            )
        self._revinfo_manager = revinfo_manager

        self._validate_map = {}

        self._soft_fail_exceptions = []
        time_tolerance = (
            abs(time_tolerance) if time_tolerance else timedelta(0)
        )
        self.timing_params = ValidationTimingParams(
            ValidationTimingInfo(
                validation_time=moment, use_poe_time=use_poe_time,
                point_in_time_validation=point_in_time_validation
            ),
            time_tolerance=time_tolerance,
        )

        self._acceptable_ac_targets = acceptable_ac_targets

    @property
    def revinfo_manager(self) -> RevinfoManager:
        return self._revinfo_manager

    @property
    def revinfo_policy(self) -> CertRevTrustPolicy:
        return self._revinfo_manager.revinfo_policy

    @property
    def retroactive_revinfo(self) -> bool:
        return self.revinfo_policy.retroactive_revinfo

    @property
    def time_tolerance(self) -> timedelta:
        return self.timing_params.time_tolerance

    @property
    def moment(self) -> datetime:
        return self.timing_params.validation_time

    @property
    def use_poe_time(self) -> datetime:
        return self.timing_params.use_poe_time

    @property
    def fetching_allowed(self) -> bool:
        return self.revinfo_manager.fetching_allowed

    @property
    def crls(self) -> List[crl.CertificateList]:
        """
        A list of all cached :class:`crl.CertificateList` objects
        """
        return self._revinfo_manager.crls

    @property
    def ocsps(self) -> List[ocsp.OCSPResponse]:
        """
        A list of all cached :class:`ocsp.OCSPResponse` objects
        """

        return self._revinfo_manager.ocsps

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
        results = await self._revinfo_manager.async_retrieve_crls(cert)
        return [res.crl_data for res in results]

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
        if not self.revinfo_manager.fetching_allowed:
            return self.revinfo_manager.crls
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
        results = await self._revinfo_manager\
            .async_retrieve_ocsps(cert, AuthorityWithCert(issuer))
        return [res.ocsp_response_data for res in results]

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

        if not self.revinfo_manager.fetching_allowed:
            return self.revinfo_manager.ocsps
        return asyncio.run(self.async_retrieve_ocsps(cert, issuer))

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

        if self.path_builder.trust_manager.is_root(cert) and \
                cert.signature not in self._validate_map:
            self._validate_map[cert.signature] = ValidationPath(
                trust_anchor=CertTrustAnchor(cert),
                interm=[], leaf=None
            )

        return self._validate_map.get(cert.signature)

    def clear_validation(self, cert):
        """
        Clears the record that a certificate has been validated

        :param cert:
            An ans1crypto.x509.Certificate object
        """

        if cert.signature in self._validate_map:
            del self._validate_map[cert.signature]

    @property
    def acceptable_ac_targets(self) -> ACTargetDescription:
        return self._acceptable_ac_targets
