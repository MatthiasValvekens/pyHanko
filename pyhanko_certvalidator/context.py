# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import binascii

from asn1crypto import crl, ocsp
from asn1crypto.util import timezone
from requests import RequestException

from . import ocsp_client, crl_client
from ._errors import pretty_message
from ._types import type_name, byte_cls, str_cls
from .errors import SoftFailError
from .name_trees import default_permitted_subtrees, PKIXSubtrees, \
    default_excluded_subtrees
from .path import ValidationPath
from .registry import CertificateRegistry


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

    # A dict with keys being an asn1crypto.x509.Certificate.issuer_serial byte
    # string of the certificate the CRLs are for. Each value is a list
    # asn1crypto.crl.CertificateList objects.
    _fetched_crls = None

    # A dict with keys being an asn1crypto.x509.Certificate.issuer_serial byte
    # string of the certificate the responses are for. Each value is a list
    # asn1crypto.ocsp.OCSPResponse objects.
    _fetched_ocsps = None

    # If CRLs or OCSP responses can be fetched from the network
    _allow_fetching = False

    # A list of asn1crypto.crl.CertificateList objects
    _crls = None

    # A list of asn1crypto.ocsp.OCSPResponse objects
    _ocsps = None

    # A dict with keys being an asn1crypto.x509.Certificate.issuer_serial byte
    # string of the certificate, and the value being an
    # asn1crypto.x509.Certificate object containing a certificate from a CRL
    # or OCSP response that was fetched. Only certificates not already part of
    # the .certificate_registry are added to this dict.
    _revocation_certs = None

    # A dict of keyword params to pass to certificates.crl_client.fetch()
    _crl_fetch_params = None

    # A dict of keyword params to pass to certificates.ocsp_client.fetch()
    _ocsp_fetch_params = None

    # Any exceptions that were ignored while the revocation_mode is "soft-fail"
    _soft_fail_exceptions = None

    # A datetime.datetime object to use when checking the validity
    # period of certificates
    moment = None

    # By default, any CRLs or OCSP responses that are passed to the constructor
    # are chccked. If _allow_fetching is True, any CRLs or OCSP responses that
    # can be downloaded will also be checked. The next two attributes change
    # that behavior.

    # A bool - if all CRL and OCSP revocation checks should be skipped, even if
    # provided to the constructor. This is strictly used internally, and if for
    # the purpose of skipping revocation checks on an single-purpose OCSP
    # responder certificate.
    _skip_revocation_checks = None

    # A unicode string of the revocation mode - "soft-fail", "hard-fail",
    # or "require"
    _revocation_mode = None

    def __init__(self, trust_roots=None, extra_trust_roots=None, other_certs=None,
                 whitelisted_certs=None, moment=None, allow_fetching=False, crls=None,
                 crl_fetch_params=None, ocsps=None, ocsp_fetch_params=None,
                 revocation_mode="soft-fail", weak_hash_algos=None,
                 time_tolerance=timedelta(seconds=1),
                 retroactive_revinfo=False):
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

        :param crls:
            None or a list/tuple of asn1crypto.crl.CertificateList objects of
            pre-fetched/cached CRLs to be utilized during validation of paths

        :param crl_fetch_params:
            None or a dict of keyword args to pass to
            pyhanko_certvalidator.crl_client.fetch() when fetching CRLs or associated
            certificates. Only applicable when allow_fetching=True.

        :param ocsps:
            None or a list/tuple of asn1crypto.ocsp.OCSPResponse objects of
            pre-fetched/cached OCSP responses to be utilized during validation
            of paths

        :param ocsp_fetch_params:
            None or a dict of keyword args to pass to
            pyhanko_certvalidator.ocsp_client.fetch() when fetching OSCP responses.
            Only applicable when allow_fetching=True.

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

        if crls is not None:
            if not isinstance(crls, (list, tuple)):
                raise TypeError(pretty_message(
                    '''
                    crls must be a list of byte strings or
                    asn1crypto.crl.CertificateList objects, not %s
                    ''',
                    type_name(crls)
                ))
            new_crls = []
            for crl_ in crls:
                if not isinstance(crl_, crl.CertificateList):
                    if not isinstance(crl_, byte_cls):
                        raise TypeError(pretty_message(
                            '''
                            crls must be a list of byte strings or
                            asn1crypto.crl.CertificateList objects, not %s
                            ''',
                            type_name(crl_)
                        ))
                    crl_ = crl.CertificateList.load(crl_)
                new_crls.append(crl_)
            crls = new_crls

        if ocsps is not None:
            if not isinstance(ocsps, list):
                raise TypeError(pretty_message(
                    '''
                    ocsps must be a list of byte strings or
                    asn1crypto.ocsp.OCSPResponse objects, not %s
                    ''',
                    type_name(ocsps)
                ))
            new_ocsps = []
            for ocsp_ in ocsps:
                if not isinstance(ocsp_, ocsp.OCSPResponse):
                    if not isinstance(ocsp_, byte_cls):
                        raise TypeError(pretty_message(
                            '''
                            ocsps must be a list of byte strings or
                            asn1crypto.ocsp.OCSPResponse objects, not %s
                            ''',
                            type_name(ocsp_)
                        ))
                    ocsp_ = ocsp.OCSPResponse.load(ocsp_)
                new_ocsps.append(ocsp_)
            ocsps = new_ocsps

        if moment is not None:
            if allow_fetching:
                raise ValueError(pretty_message(
                    '''
                    allow_fetching must be False when moment is specified
                    '''
                ))

        elif not allow_fetching and crls is None and ocsps is None and revocation_mode != "soft-fail":
            raise ValueError(pretty_message(
                '''
                revocation_mode is "%s" and allow_fetching is False, however
                crls and ocsps are both None, meaning that no validation can
                happen
                '''
            ))

        if crl_fetch_params is not None and not isinstance(crl_fetch_params, dict):
            raise TypeError(pretty_message(
                '''
                crl_fetch_params must be a dict, not %s
                ''',
                type_name(crl_fetch_params)
            ))

        if ocsp_fetch_params is not None and not isinstance(ocsp_fetch_params, dict):
            raise TypeError(pretty_message(
                '''
                ocsp_fetch_params must be a dict, not %s
                ''',
                type_name(ocsp_fetch_params)
            ))

        if moment is None:
            moment = datetime.now(timezone.utc)
        else:
            if not isinstance(moment, datetime):
                raise TypeError(pretty_message(
                    '''
                    moment must be a datetime object, not %s
                    ''',
                    type_name(moment)
                ))

            if moment.utcoffset() is None:
                raise ValueError(pretty_message(
                    '''
                    moment is a naive datetime object, meaning the tzinfo
                    attribute is not set to a valid timezone
                    '''
                ))

        if revocation_mode not in set(['soft-fail', 'hard-fail', 'require']):
            raise ValueError(pretty_message(
                '''
                revocation_mode must be one of "soft-fail", "hard-fail",
                "require", not %s
                ''',
                repr(revocation_mode)
            ))

        self._whitelisted_certs = set()
        if whitelisted_certs is not None:
            for whitelisted_cert in whitelisted_certs:
                if isinstance(whitelisted_cert, byte_cls):
                    whitelisted_cert = whitelisted_cert.decode('ascii')
                if not isinstance(whitelisted_cert, str_cls):
                    raise TypeError(pretty_message(
                        '''
                        whitelisted_certs must contain only byte strings or
                        unicode strings, not %s
                        ''',
                        type_name(whitelisted_cert)
                    ))
                # Allow users to copy from various OS and browser info dialogs,
                # some of which separate the hex char pairs via spaces or colons
                whitelisted_cert = whitelisted_cert.replace(' ', '').replace(':', '')
                self._whitelisted_certs.add(
                    binascii.unhexlify(whitelisted_cert.encode('ascii'))
                )

        if weak_hash_algos is not None:
            if not isinstance(weak_hash_algos, set):
                raise TypeError(pretty_message(
                    '''
                    weak_hash_algos must be a set of unicode strings, not %s
                    ''',
                    type_name(weak_hash_algos)
                ))
        else:
            weak_hash_algos = set(['md2', 'md5', 'sha1'])

        self.certificate_registry = CertificateRegistry(
            trust_roots,
            extra_trust_roots,
            other_certs
        )

        self.moment = moment

        self._validate_map = {}
        self._crl_issuer_map = {}

        self._fetched_crls = {}
        self._fetched_ocsps = {}
        self._revocation_certs = {}

        self._crls = []
        if crls:
            self._crls = crls

        self._ocsps = []
        if ocsps:
            self._ocsps = ocsps
            for ocsp_response in ocsps:
                self._extract_ocsp_certs(ocsp_response)

        self._crl_fetch_params = crl_fetch_params or {}
        self._ocsp_fetch_params = ocsp_fetch_params or {}

        self._allow_fetching = bool(allow_fetching)
        self._skip_revocation_checks = False
        self._revocation_mode = revocation_mode
        self._soft_fail_exceptions = []
        self.weak_hash_algos = weak_hash_algos
        self.time_tolerance = (
            abs(time_tolerance) if time_tolerance else timedelta(0)
        )
        self.retroactive_revinfo = retroactive_revinfo

    @property
    def crls(self):
        """
        A list of all cached asn1crypto.crl.CertificateList objects
        """

        if not self._allow_fetching:
            return self._crls

        output = []
        for issuer_serial in self._fetched_crls:
            output.extend(self._fetched_crls[issuer_serial])
        return output

    @property
    def ocsps(self):
        """
        A list of all cached asn1crypto.ocsp.OCSPResponse objects
        """

        if not self._allow_fetching:
            return self._ocsps

        output = []
        for issuer_serial in self._fetched_ocsps:
            output.extend(self._fetched_ocsps[issuer_serial])
        return output

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

    @property
    def revocation_mode(self):
        """
        A unicode string of the revocation checking mode: "soft-fail",
        "hard-fail", or "require"
        """

        return self._revocation_mode

    def is_whitelisted(self, cert):
        """
        Checks to see if a certificate has been whitelisted

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A bool - if the certificate is whitelisted
        """

        return cert.sha1 in self._whitelisted_certs

    def retrieve_crls(self, cert):
        """
        :param cert:
            An asn1crypto.x509.Certificate object

        :param path:
            A pyhanko_certvalidator.path.ValidationPath object for the cert

        :return:
            A list of asn1crypto.crl.CertificateList objects
        """

        if not self._allow_fetching:
            return self._crls

        if cert.issuer_serial not in self._fetched_crls:
            try:
                crls = crl_client.fetch(
                    cert,
                    **self._crl_fetch_params
                )
                self._fetched_crls[cert.issuer_serial] = crls
                for crl_ in crls:
                    try:
                        certs = crl_client.fetch_certs(
                            crl_,
                            user_agent=self._crl_fetch_params.get('user_agent'),
                            timeout=self._crl_fetch_params.get('timeout')
                        )
                        for cert_ in certs:
                            if self.certificate_registry.add_other_cert(cert_):
                                self._revocation_certs[cert_.issuer_serial] = cert_
                    except (RequestException, socket.error):
                        pass
            except (RequestException, socket.error) as e:
                self._fetched_crls[cert.issuer_serial] = []
                if self._revocation_mode == "soft-fail":
                    self._soft_fail_exceptions.append(e)
                    raise SoftFailError()
                else:
                    raise

        return self._fetched_crls[cert.issuer_serial]

    def retrieve_ocsps(self, cert, issuer):
        """
        :param cert:
            An asn1crypto.x509.Certificate object

        :param issuer:
            An asn1crypto.x509.Certificate object of cert's issuer

        :return:
            A list of asn1crypto.ocsp.OCSPResponse objects
        """

        if not self._allow_fetching:
            return self._ocsps

        if cert.issuer_serial not in self._fetched_ocsps:
            try:
                ocsp_response = ocsp_client.fetch(
                    cert,
                    issuer,
                    **self._ocsp_fetch_params
                )

                self._fetched_ocsps[cert.issuer_serial] = [ocsp_response]

                # Responses can contain certificates that are useful in validating the
                # response itself. We can use these since they will be validated using
                # the local trust roots.
                self._extract_ocsp_certs(ocsp_response)
            except (RequestException, socket.error) as e:
                self._fetched_ocsps[cert.issuer_serial] = []
                if self._revocation_mode == "soft-fail":
                    self._soft_fail_exceptions.append(e)
                    raise SoftFailError()
                else:
                    raise

        return self._fetched_ocsps[cert.issuer_serial]

    def _extract_ocsp_certs(self, ocsp_response):
        """
        Extracts any certificates included with an OCSP response and adds them
        to the certificate registry

        :param ocsp_response:
            An asn1crypto.ocsp.OCSPResponse object to look for certs inside of
        """

        status = ocsp_response['response_status'].native
        if status == 'successful':
            response_bytes = ocsp_response['response_bytes']
            if response_bytes['response_type'].native == 'basic_ocsp_response':
                response = response_bytes['response'].parsed
                if response['certs']:
                    for other_cert in response['certs']:
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


@dataclass(frozen=True)
class PKIXValidationParams:
    user_initial_policy_set: frozenset = frozenset(['any_policy'])
    """
    Set of policies that the user is willing to accept. By default, any policy
    is acceptable.
    
    When setting this parameter to a non-default value, you probably want to
    set :attr:`initial_explicit_policy` as well.
    
    .. note::
        These are specified in the policy domain of the trust root(s), and
        subject to policy mapping by intermediate certificate authorities.
    """

    initial_policy_mapping_inhibit: bool = False
    """
    Flag indicating whether policy mapping is forbidden along the entire    
    certification chains. By default, policy mapping is permitted.
    
    .. note::
        Policy constraints on intermediate certificates may force policy mapping
        to be inhibited from some point onwards.
    """

    initial_explicit_policy: bool = False
    """
    Flag indicating whether path validation must terminate with at least one
    permissible policy; see :attr:`user_initial_policy_set`.
    By default, no such requirement is imposed.
    
    .. note::
        If :attr:`user_initial_policy_set` is set to its default value of
        ``{'any_policy'}``, the effect is that the path validation must accept
        at least one policy, without specifying which.
        
    .. warning::
        Due to widespread mis-specification of policy extensions in the wild,
        many real-world certification chains terminate with an empty set
        (or rather, tree) of valid policies. Therefore, this flag is set to 
        ``False`` by default.
    """

    initial_any_policy_inhibit: bool = False
    """
    Flag indicating whether ``anyPolicy`` should be left unprocessed when it
    appears in a certificate. By default, ``anyPolicy`` is always processed
    when it appears.
    """

    initial_permitted_subtrees: PKIXSubtrees = \
        field(default_factory=default_permitted_subtrees)
    """
    Set of permitted subtrees for each name type, indicating restrictions
    to impose on subject names (and alternative names) in the certification
    path.
    
    By default, all names are permitted.
    This behaviour can be modified by name constraints on intermediate CA
    certificates.
    """

    initial_excluded_subtrees: PKIXSubtrees = field(
        default_factory=default_excluded_subtrees
    )
    """
    Set of excluded subtrees for each name type, indicating restrictions
    to impose on subject names (and alternative names) in the certification
    path.

    By default, no names are excluded.
    This behaviour can be modified by name constraints on intermediate CA
    certificates.
    """
