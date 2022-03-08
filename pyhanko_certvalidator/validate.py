# coding: utf-8

import asyncio
import datetime
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional, Set, Dict, Union

from asn1crypto import x509, crl, ocsp, algos, cms, core
from asn1crypto.keys import PublicKeyInfo
from asn1crypto.x509 import Validity
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, ec, dsa, ed25519, ed448
)

from . import asn1_types
from ._errors import pretty_message
from .asn1_types import AAControls
from .context import (
    ValidationContext, PKIXValidationParams,
    RevocationCheckingRule, CertRevTrustPolicy, RevocationCheckingPolicy,
    ACTargetDescription
)
from .name_trees import PermittedSubtrees, ExcludedSubtrees, \
    process_general_subtrees
from .errors import (
    CRLNoMatchesError,
    CRLValidationError,
    CRLValidationIndeterminateError,
    CRLFetchError,
    CertificateFetchError,
    InvalidCertificateError,
    OCSPValidationError,
    OCSPNoMatchesError,
    OCSPValidationIndeterminateError,
    OCSPFetchError,
    ValidationError,
    PathValidationError,
    RevokedError,
    PathBuildingError,
)
from .path import ValidationPath, QualifiedPolicy

from .registry import CertificateCollection, LayeredCertificateStore, \
    SimpleCertificateStore, CertificateRegistry
from .util import extract_dir_name, extract_ac_issuer_dir_name, \
    get_ac_extension_value, get_relevant_crl_dps, get_declared_revinfo

logger = logging.getLogger(__name__)


def validate_path(validation_context, path,
                  parameters: PKIXValidationParams = None):
    """
    Validates the path using the algorithm from
    https://tools.ietf.org/html/rfc5280#section-6.1.

    Critical extensions on the end-entity certificate are not validated
    and are left up to the consuming application to process and/or fail on.

    .. note::
        This is a synchronous equivalent of :func:`.async_validate_path` that
        calls the latter in a new event loop. As such, it can't be used
        from within asynchronous code.

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the path to validate

    :param parameters:
        Additional input parameters to the PKIX validation algorithm.
        These are not used when validating CRLs and OCSP responses.

    :raises:
        pyhanko_certvalidator.errors.PathValidationError - when an error occurs validating the path
        pyhanko_certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked

    :return:
        The final certificate in the path - an instance of
        asn1crypto.x509.Certificate
    """

    result = asyncio.run(
        async_validate_path(validation_context, path, parameters=parameters)
    )
    return result


async def async_validate_path(validation_context, path,
                              parameters: PKIXValidationParams = None):
    """
    Validates the path using the algorithm from
    https://tools.ietf.org/html/rfc5280#section-6.1.

    Critical extensions on the end-entity certificate are not validated
    and are left up to the consuming application to process and/or fail on.

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the path to validate

    :param parameters:
        Additional input parameters to the PKIX validation algorithm.
        These are not used when validating CRLs and OCSP responses.

    :raises:
        pyhanko_certvalidator.errors.PathValidationError - when an error occurs validating the path
        pyhanko_certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked

    :return:
        The final certificate in the path - an instance of
        asn1crypto.x509.Certificate
    """

    return await _validate_path(validation_context, path, parameters=parameters)


def validate_tls_hostname(validation_context: ValidationContext,
                          cert: x509.Certificate, hostname: str):
    """
    Validates the end-entity certificate from a
    pyhanko_certvalidator.path.ValidationPath object to ensure that the certificate
    is valid for the hostname provided and that the certificate is valid for
    the purpose of a TLS connection.

    THE CERTIFICATE PATH MUST BE VALIDATED SEPARATELY VIA validate_path()!

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param cert:
        An asn1crypto.x509.Certificate object returned from validate_path()

    :param hostname:
        A unicode string of the TLS server hostname

    :raises:
        pyhanko_certvalidator.errors.InvalidCertificateError - when the certificate is not valid for TLS or the hostname
    """

    if validation_context.is_whitelisted(cert):
        return

    if not cert.is_valid_domain_ip(hostname):
        raise InvalidCertificateError(pretty_message(
            '''
            The X.509 certificate provided is not valid for %s. Valid hostnames
            include: %s
            ''',
            hostname,
            ', '.join(cert.valid_domains)
        ))

    bad_key_usage = cert.key_usage_value and 'digital_signature' not in cert.key_usage_value.native
    bad_ext_key_usage = cert.extended_key_usage_value and 'server_auth' not in cert.extended_key_usage_value.native

    if bad_key_usage or bad_ext_key_usage:
        raise InvalidCertificateError(pretty_message(
            '''
            The X.509 certificate provided is not valid for securing TLS
            connections
            '''
        ))


def validate_usage(validation_context: ValidationContext,
                   cert: x509.Certificate,
                   key_usage: Set[str],
                   extended_key_usage: Set[str],
                   extended_optional: bool):
    """
    Validates the end-entity certificate from a
    pyhanko_certvalidator.path.ValidationPath object to ensure that the certificate
    is valid for the key usage and extended key usage purposes specified.

    THE CERTIFICATE PATH MUST BE VALIDATED SEPARATELY VIA validate_path()!

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param cert:
        An asn1crypto.x509.Certificate object returned from validate_path()

    :param key_usage:
        A set of unicode strings of the required key usage purposes

    :param extended_key_usage:
        A set of unicode strings of the required extended key usage purposes

    :param extended_optional:
        A bool - if the extended_key_usage extension may be omitted and still
        considered valid

    :raises:
        pyhanko_certvalidator.errors.InvalidCertificateError - when the certificate is not valid for the usages specified
    """

    if validation_context.is_whitelisted(cert):
        return

    if key_usage is None:
        key_usage = set()

    if extended_key_usage is None:
        extended_key_usage = set()

    missing_key_usage = key_usage
    if cert.key_usage_value:
        missing_key_usage = key_usage - cert.key_usage_value.native

    missing_extended_key_usage = set()
    if extended_optional is False and not cert.extended_key_usage_value:
        missing_extended_key_usage = extended_key_usage
    elif cert.extended_key_usage_value is not None:
        missing_extended_key_usage = extended_key_usage - set(cert.extended_key_usage_value.native)

    if missing_key_usage or missing_extended_key_usage:
        plural = 's' if len(missing_key_usage | missing_extended_key_usage) > 1 else ''
        friendly_purposes = []
        for purpose in sorted(missing_key_usage | missing_extended_key_usage):
            friendly_purposes.append(purpose.replace('_', ' '))
        raise InvalidCertificateError(pretty_message(
            '''
            The X.509 certificate provided is not valid for the purpose%s of %s
            ''',
            plural,
            ', '.join(friendly_purposes)
        ))


def validate_aa_usage(validation_context: ValidationContext,
                      cert: x509.Certificate,
                      extended_key_usage: Optional[Set[str]] = None):
    """
    Validate AA certificate profile conditions in RFC 5755 § 4.5

    :param validation_context:
    :param cert:
    :param extended_key_usage:
    :return:
    """
    if validation_context.is_whitelisted(cert):
        return

    # Check key usage requirements
    validate_usage(
        validation_context, cert, key_usage={'digital_signature'},
        extended_key_usage=extended_key_usage or set(),
        extended_optional=extended_key_usage is not None
    )

    # Check basic constraints: AA must not be a CA
    bc = cert.basic_constraints_value
    if bc is not None and bool(bc['ca']):
        raise InvalidCertificateError(pretty_message(
            '''
            The X.509 certificate provided is a CA certificate, so
            it cannot be used to validate attribute certificates.
            '''
        ))


def _validate_ac_targeting(attr_cert: cms.AttributeCertificateV2,
                           acceptable_targets: ACTargetDescription):

    target_info = get_ac_extension_value(attr_cert, 'target_information')
    if target_info is None:
        return

    target: asn1_types.Target
    for targets in target_info:
        for target in targets:
            if target.name == 'target_name':
                gen_name: x509.GeneralName = target.chosen
                valid_names = acceptable_targets.validator_names
            elif target.name == 'target_group':
                gen_name: x509.GeneralName = target.chosen
                valid_names = acceptable_targets.group_memberships
            else:
                logger.info(
                    f"'{target.name}' is not supported as a targeting mode; "
                    f"ignoring."
                )
                continue
            try:
                target_ok = gen_name in valid_names
            except ValueError:
                # fall back to binary comparison in case the name type is not
                # supported by asn1crypto's comparison logic for GeneralName
                #  (we could be more efficient here, but this is probably
                #   rare, so let's follow YAGNI)
                target_ok = gen_name.dump() in {n.dump() for n in valid_names}
            if target_ok:
                return

    # TODO log audit identity
    raise InvalidCertificateError("AC targeting check failed")


SUPPORTED_AC_EXTENSIONS = frozenset([
    'authority_information_access',
    'authority_key_identifier',
    'crl_distribution_points',
    'freshest_crl',
    'key_identifier',
    'no_rev_avail',
    'target_information',
    # NOTE: we don't actively process this extension, but we never log holder
    # identifying information, so the purpose of the audit identity
    # extension is still satisfied.
    # TODO actually use audit_identity for logging purposes, falling back
    #  to holder info if audit_identity is not available.
    'audit_identity'
])


def _parse_iss_serial(iss_serial: cms.IssuerSerial, err_msg_prefix: str) \
        -> bytes:
    """
    Render a cms.IssuerSerial value into something that matches
    x509.Certificate.issuer_serial output.
    """
    issuer_names = iss_serial['issuer']
    issuer_dirname = extract_dir_name(issuer_names, err_msg_prefix)
    result_bytes = b'%s:%d' % (
        issuer_dirname.sha256, iss_serial['serial'].native
    )
    return result_bytes


def _process_aki_ext(aki_ext: x509.AuthorityKeyIdentifier):

    aki = aki_ext['key_identifier'].native  # could be None
    auth_iss_ser = auth_iss_dirname = None
    if not isinstance(aki_ext['authority_cert_issuer'], core.Void):
        auth_iss_dirname = extract_dir_name(
            aki_ext['authority_cert_issuer'],
            "Could not decode authority issuer in AKI extension"
        )
        auth_ser = aki_ext['authority_cert_serial_number'].native
        if auth_ser is not None:
            auth_iss_ser = b'%s:%d' % (auth_ser.sha256, auth_ser)

    return aki, auth_iss_dirname, auth_iss_ser


def _candidate_ac_issuers(attr_cert: cms.AttributeCertificateV2,
                          registry: CertificateCollection):
    # TODO support matching against subjectAltName?
    #  Outside the scope of RFC 5755, but it might make sense

    issuer_rec = attr_cert['ac_info']['issuer']
    aa_names: Optional[x509.GeneralNames] = None
    aa_iss_serial: Optional[bytes] = None
    if issuer_rec.name == 'v1_form':
        aa_names = issuer_rec.chosen
    else:
        issuerv2: cms.V2Form = issuer_rec.chosen
        if not isinstance(issuerv2['issuer_name'], core.Void):
            aa_names = issuerv2['issuer_name']
        if not isinstance(issuerv2['base_certificate_id'], core.Void):
            # not allowed by RFC 5755, but let's parse it anyway if
            # we encounter it
            aa_iss_serial = _parse_iss_serial(
                issuerv2['base_certificate_id'],
                "Could not identify AA issuer in base_certificate_id"
            )
        if not isinstance(issuerv2['object_digest_info'], core.Void):
            # TODO support objectdigestinfo? Also not allowed by RFC 5755
            raise NotImplementedError(
                "Could not identify AA; objectDigestInfo is not supported."
            )

    # Process the AKI extension if there is one
    aki_ext = get_ac_extension_value(attr_cert, 'authority_key_identifier')
    if aki_ext is not None:
        aki, aa_issuer, aki_aa_iss_serial = _process_aki_ext(aki_ext)
        if aki_aa_iss_serial is not None:
            if aa_iss_serial is not None and aa_iss_serial != aki_aa_iss_serial:
                raise InvalidCertificateError(
                    "AC's AKI extension and issuer include conflicting "
                    "identifying information for the issuing AA"
                )
            else:
                aa_iss_serial = aki_aa_iss_serial
    else:
        aki = None

    candidates = ()
    aa_name = None
    if aa_names is not None:
        aa_name = extract_dir_name(aa_names, "Could not identify AA by name")
    if aa_iss_serial is not None:
        exact_cert = registry.retrieve_by_issuer_serial(aa_iss_serial)
        if exact_cert is not None:
            candidates = (exact_cert,)
    elif aa_name is not None:
        candidates = registry.retrieve_by_name(aa_name)

    for aa_candidate in candidates:
        if aa_name is not None and aa_candidate.subject != aa_name:
            continue
        if aki is not None and aa_candidate.key_identifier != aki:
            # AC's AKI doesn't match candidate's SKI
            continue
        yield aa_candidate


def _check_ac_signature(attr_cert: cms.AttributeCertificateV2,
                        aa_cert: x509.Certificate,
                        validation_context: ValidationContext):

    sd_algo = attr_cert['signature_algorithm']
    embedded_sd_algo = attr_cert['ac_info']['signature']
    if sd_algo.native != embedded_sd_algo.native:
        raise InvalidCertificateError(pretty_message(
            '''
            Signature algorithm declaration in signed portion of AC does not
            match the signature algorithm declaration on the envelope.
            '''
        ))

    signature_algo = sd_algo.signature_algo
    hash_algo = attr_cert['signature_algorithm'].hash_algo

    if hash_algo in validation_context.weak_hash_algos:
        raise PathValidationError(pretty_message(
            '''
            The attribute certificate could not be validated because 
            the signature uses the weak hash algorithm %s
            ''',
            hash_algo
        ))

    try:
        _validate_sig(
            signature=attr_cert['signature'].native,
            signed_data=attr_cert['ac_info'].dump(),
            # TODO support PK parameter inheritance?
            #  (would have to remember the working public key from the
            #  validation algo)
            # low-priority since this only affects DSA in practice
            public_key_info=aa_cert.public_key,
            sig_algo=signature_algo, hash_algo=hash_algo,
            parameters=attr_cert['signature_algorithm']['parameters']
        )
    except PSSParameterMismatch:
        raise PathValidationError(pretty_message(
            '''
            The signature parameters for the attribute certificate
            do not match the constraints on the public key.
            '''
        ))
    except InvalidSignature:
        raise PathValidationError(pretty_message(
            '''
            The attribute certificate could not be validated because the
            signature could not be verified.
            ''',
        ))


def check_ac_holder_match(holder_cert: x509.Certificate, holder: cms.Holder):
    """
    Match a candidate holder certificate against the holder entry of an
    attribute certificate.

    :param holder_cert:
        Candidate holder certificate.
    :param holder:
        Holder value to match against.
    :return:
        Return the parts of the holder entry that mismatched as a set.
        Possible values are `'base_certificate_id'`, `'entity_name'` and
        `'object_digest_info'`.
        If the returned set is empty, all entries in the holder entry
        matched the information in the certificate.
    """

    base_cert_id = holder['base_certificate_id']
    mismatches = set()
    # TODO what about subjectAltName matches?

    if not isinstance(base_cert_id, core.Void):
        # repurpose _parse_iss_serial since RFC 5755 restricts
        # baseCertificateID.issuer to a single DN
        designated_iss_serial = _parse_iss_serial(
            base_cert_id, "Could not identify holder certificate issuer"
        )
        if designated_iss_serial != holder_cert.issuer_serial:
            mismatches.add('base_certificate_id')

    entity_name = holder['entity_name']
    # TODO what about subjectAltName matches?
    if not isinstance(entity_name, core.Void):
        holder_dn = extract_dir_name(
            entity_name,
            "Could not identify AC holder DN"
        )
        if holder_dn != holder_cert.subject:
            mismatches.add('entity_name')

    # TODO implement objectDigestInfo support
    obj_digest_info = holder['object_digest_info']
    if not isinstance(obj_digest_info, core.Void):
        raise NotImplementedError(
            "Object digest info is currently not supported"
        )
    return mismatches


@dataclass(frozen=True)
class ACValidationResult:
    """
    The result of a successful attribute certificate validation.
    """

    attr_cert: cms.AttributeCertificateV2
    """
    The attribute certificate that was validated.
    """

    aa_cert: x509.Certificate
    """
    The attribute authority that issued the certificate.
    """

    aa_path: ValidationPath
    """
    The validation path of the attribute authority's certificate.
    """

    approved_attributes: Dict[str, cms.AttCertAttribute]
    """
    Approved attributes in the attribute certificate, possibly filtered by
    AA controls.
    """


async def async_validate_ac(
        attr_cert: cms.AttributeCertificateV2,
        validation_context: ValidationContext,
        aa_pkix_params: PKIXValidationParams = PKIXValidationParams(),
        holder_cert: Optional[x509.Certificate] = None) -> ACValidationResult:
    """
    Validate an attribute certificate with respect to a given validation
    context.

    :param attr_cert:
        The attribute certificate to validate.
    :param validation_context:
        The validation context to validate against.
    :param aa_pkix_params:
        PKIX validation parameters to supply to the path validation algorithm
        applied to the attribute authority's certificate.
    :param holder_cert:
        Certificate of the presumed holder to match against the AC's holder
        entry. If not provided, the holder check is left to the caller to
        perform.

        .. note::
            This is a convenience option in case there's only one reasonable
            candidate holder certificate (e.g. when the attribute certificates
            are part of a CMS SignedData value with only a single signer).
    :return:
        An :class:`.ACValidationResult` detailing the validation result,
        if successful.
    """

    # Process extensions
    # We do this first because all later steps may involve potentially slow
    #  network IO, so this allows quicker failure.
    extensions_present = {
        ext['extn_id'].native: bool(ext['critical'])
        for ext in attr_cert['ac_info']['extensions']
    }
    unsupported_critical_extensions = {
        ext for ext, crit in extensions_present.items()
        if crit and ext not in SUPPORTED_AC_EXTENSIONS
    }
    if unsupported_critical_extensions:
        raise PathValidationError(pretty_message(
            '''
            The AC could not be validated because it contains the
            following unsupported critical extension%s: %s
            ''',
            's' if len(unsupported_critical_extensions) != 1 else '',
            ', '.join(sorted(unsupported_critical_extensions)),
        ))
    if 'target_information' in extensions_present:
        targ_desc = validation_context.acceptable_ac_targets
        if targ_desc is None:
            raise InvalidCertificateError(pretty_message(
                '''
                The attribute certificate is targeted, but no targeting
                information is available in the validation context.
                '''
            ))
        _validate_ac_targeting(attr_cert, targ_desc)

    validity = attr_cert['ac_info']['att_cert_validity_period']

    def _describe(**_kwargs):
        return 'the attribute certificate'

    _check_validity(
        validity=Validity({
            'not_before': validity['not_before_time'],
            'not_after': validity['not_after_time'],
        }),
        moment=validation_context.moment,
        tolerance=validation_context.time_tolerance,
        describe_current_cert=_describe
    )

    ac_holder = attr_cert['ac_info']['holder']
    if len(ac_holder) == 0:
        raise InvalidCertificateError("AC holder entry is empty")

    if holder_cert is not None:
        mismatches = check_ac_holder_match(holder_cert, ac_holder)
        if mismatches:
            raise InvalidCertificateError(
                f"Could not match AC holder entry against supplied holder "
                f"certificate; mismatched entries: {', '.join(mismatches)}"
            )

    registry = validation_context.certificate_registry
    aa_candidates = _candidate_ac_issuers(attr_cert, registry)

    exceptions = []
    aa_path: Optional[ValidationPath] = None
    for aa_candidate in aa_candidates:
        try:
            validate_aa_usage(validation_context, aa_candidate)
        except InvalidCertificateError as e:
            exceptions.append(e)
            continue
        try:
            paths = await registry.async_build_paths(aa_candidate)
        except PathBuildingError as e:
            exceptions.append(e)
            continue

        for candidate_path in paths:
            try:
                await _validate_path(
                    validation_context, candidate_path,
                    end_entity_name_override="AA certificate",
                    parameters=aa_pkix_params
                )
                aa_path = candidate_path
                break
            except ValidationError as e:
                exceptions.append(e)

    if aa_path is None:
        # TODO log audit identifier
        if not exceptions:
            raise PathBuildingError(
                "Could not find a suitable AA for the attribute certificate"
            )
        else:
            raise exceptions[0]

    # check the signature
    aa_cert = aa_path.last
    _check_ac_signature(attr_cert, aa_cert, validation_context)

    if 'no_rev_avail' not in extensions_present:
        await _check_revocation(
            attr_cert, validation_context, aa_path,
            end_entity_name_override="attribute certificate",
            is_ee_cert=True,
            describe_current_cert=_describe_cert(0, 0, "attribute certificate")
        )

    ok_attrs = {
        attr['type'].native: attr
        for attr in attr_cert['ac_info']['attributes']
        if aa_path.aa_attr_in_scope(attr['type'])
    }

    return ACValidationResult(
        attr_cert=attr_cert, aa_cert=aa_cert,
        aa_path=aa_path, approved_attributes=ok_attrs
    )


@dataclass
class _PathValidationState:
    """
    State variables that need to be maintained while traversing a certification
    path
    """

    valid_policy_tree: Optional['PolicyTreeRoot']
    explicit_policy: int
    inhibit_any_policy: int
    policy_mapping: int
    max_path_length: int
    max_aa_path_length: int
    working_public_key: x509.PublicKeyInfo
    working_issuer_name: x509.Name
    permitted_subtrees: PermittedSubtrees
    excluded_subtrees: ExcludedSubtrees
    aa_controls_used: bool = False

    def update_policy_restrictions(self, cert: x509.Certificate):
        # Step 3 h
        if not cert.self_issued:
            # Step 3 h 1
            if self.explicit_policy != 0:
                self.explicit_policy -= 1
            # Step 3 h 2
            if self.policy_mapping != 0:
                self.policy_mapping -= 1
            # Step 3 h 3
            if self.inhibit_any_policy != 0:
                self.inhibit_any_policy -= 1

        # Step 3 i
        policy_constraints = cert.policy_constraints_value
        if policy_constraints:
            # Step 3 i 1
            require_explicit_policy = \
                policy_constraints['require_explicit_policy'].native
            if require_explicit_policy is not None:
                self.explicit_policy = min(
                    self.explicit_policy, require_explicit_policy
                )
            # Step 3 i 2
            inhibit_policy_mapping = \
                policy_constraints['inhibit_policy_mapping'].native
            if inhibit_policy_mapping is not None:
                self.policy_mapping = min(
                    self.policy_mapping, inhibit_policy_mapping
                )

        # Step 3 j
        if cert.inhibit_any_policy_value is not None:
            self.inhibit_any_policy = min(
                cert.inhibit_any_policy_value.native,
                self.inhibit_any_policy
            )

    def process_policies(self, index: int,
                         certificate_policies, any_policy_uninhibited,
                         describe_current_cert):

        if certificate_policies and self.valid_policy_tree is not None:
            self.valid_policy_tree = _update_policy_tree(
                certificate_policies, self.valid_policy_tree,
                depth=index,
                any_policy_uninhibited=any_policy_uninhibited
            )

        # Step 2 e
        elif certificate_policies is None:
            self.valid_policy_tree = None

        # Step 2 f
        if self.valid_policy_tree is None and self.explicit_policy <= 0:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because there is no valid set
                of policies for %s
                ''',
                describe_current_cert(definite=True)
            ))

    def check_name_constraints(self, cert, describe_current_cert):
        # name constraint processing
        whitelist_result = self.permitted_subtrees.accept_cert(cert)
        if not whitelist_result:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because not all names of
                the %s are in the permitted namespace of the issuing
                authority. %s
                ''',
                describe_current_cert(),
                whitelist_result.error_message
            ))
        blacklist_result = self.excluded_subtrees.accept_cert(cert)
        if not blacklist_result:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because some names of
                the %s are excluded from the namespace of the issuing
                authority. %s
                ''',
                describe_current_cert(),
                blacklist_result.error_message
            ))

    def check_certificate_signature(self, cert, weak_hash_algos,
                                    describe_current_cert):

        signature_algo = cert['signature_algorithm'].signature_algo
        hash_algo = cert['signature_algorithm'].hash_algo

        if hash_algo in weak_hash_algos:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the signature of %s
                uses the weak hash algorithm %s
                ''',
                describe_current_cert(definite=True),
                hash_algo
            ))

        try:
            _validate_sig(
                signature=cert['signature_value'].native,
                signed_data=cert['tbs_certificate'].dump(),
                public_key_info=self.working_public_key,
                sig_algo=signature_algo, hash_algo=hash_algo,
                parameters=cert['signature_algorithm']['parameters']
            )
        except PSSParameterMismatch:
            raise PathValidationError(pretty_message(
                '''
                The signature parameters for %s do not match the constraints
                on the public key.
                ''',
                describe_current_cert(definite=True)
            ))
        except InvalidSignature:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the signature of %s
                could not be verified
                ''',
                describe_current_cert(definite=True)
            ))


def _update_policy_tree(certificate_policies,
                        valid_policy_tree: 'PolicyTreeRoot', depth: int,
                        any_policy_uninhibited: bool) \
        -> Optional['PolicyTreeRoot']:
    cert_any_policy = None
    cert_policy_identifiers = set()

    # Step 2 d 1
    for policy in certificate_policies:
        policy_identifier = policy['policy_identifier'].native

        if policy_identifier == 'any_policy':
            cert_any_policy = policy
            continue

        cert_policy_identifiers.add(policy_identifier)

        policy_qualifiers = policy['policy_qualifiers']

        policy_id_match = False
        parent_any_policy = None

        # Step 2 d 1 i
        for node in valid_policy_tree.at_depth(depth - 1):
            if node.valid_policy == 'any_policy':
                parent_any_policy = node
            if policy_identifier not in node.expected_policy_set:
                continue
            policy_id_match = True
            node.add_child(
                policy_identifier,
                policy_qualifiers,
                {policy_identifier}
            )

        # Step 2 d 1 ii
        if not policy_id_match and parent_any_policy:
            parent_any_policy.add_child(
                policy_identifier,
                policy_qualifiers,
                {policy_identifier}
            )

    # Step 2 d 2
    if cert_any_policy and any_policy_uninhibited:
        for node in valid_policy_tree.at_depth(depth - 1):
            for expected_policy_identifier in node.expected_policy_set:
                if expected_policy_identifier not in cert_policy_identifiers:
                    node.add_child(
                        expected_policy_identifier,
                        cert_any_policy['policy_qualifiers'],
                        {expected_policy_identifier}
                    )

    # Step 2 d 3
    valid_policy_tree = _prune_policy_tree(valid_policy_tree, depth - 1)
    return valid_policy_tree


def _prune_policy_tree(valid_policy_tree, depth):
    for node in valid_policy_tree.walk_up(depth):
        if not node.children:
            node.parent.remove_child(node)
    if not valid_policy_tree.children:
        valid_policy_tree = None
    return valid_policy_tree


# TODO allow delegation to calling library here?
SUPPORTED_EXTENSIONS = frozenset([
    'authority_information_access',
    'authority_key_identifier',
    'basic_constraints',
    'crl_distribution_points',
    'extended_key_usage',
    'freshest_crl',
    'key_identifier',
    'key_usage',
    'ocsp_no_check',
    'certificate_policies',
    'policy_mappings',
    'policy_constraints',
    'inhibit_any_policy',
    'name_constraints',
    'subject_alt_name',
    'aa_controls'
])


async def _validate_path(validation_context: ValidationContext,
                         path: ValidationPath,
                         end_entity_name_override: Optional[str] = None,
                         parameters: PKIXValidationParams = None):
    """
    Internal copy of validate_path() that allows overriding the name of the
    end-entity certificate as used in exception messages. This functionality is
    used during chain validation when dealing with indirect CRLs issuer or
    OCSP responder certificates.

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the path to validate

    :param end_entity_name_override:
        A unicode string of the name to use for the final certificate in the
        path. This is necessary when dealing with indirect CRL issuers or
        OCSP responder certificates.

    :param parameters:
        Additional input parameters to the PKIX validation algorithm.
        These are not used when validating CRLs and OCSP responses.

    :return:
        The final certificate in the path - an instance of
        asn1crypto.x509.Certificate
    """

    moment = validation_context.moment

    # Inputs

    trust_anchor = path.first

    # We skip the trust anchor when measuring the path since technically
    # the trust anchor is not part of the path
    # TODO If the trust anchor has NameConstraints etc., we might want to
    #  intersect those with the parameters that were passed in, and make that
    #  behaviour togglable.
    path_length = len(path) - 1

    # Step 1: initialization
    parameters = parameters or PKIXValidationParams()

    state = _PathValidationState(
        # Step 1 a
        valid_policy_tree=PolicyTreeRoot.init_policy_tree(
            'any_policy', set(), {'any_policy'}
        ),
        # Steps 1 b-c
        permitted_subtrees=PermittedSubtrees(
            parameters.initial_permitted_subtrees
        ),
        excluded_subtrees=ExcludedSubtrees(
            parameters.initial_excluded_subtrees
        ),
        # Steps 1 d-f
        explicit_policy=(
            0 if parameters.initial_explicit_policy
            else path_length + 1
        ),
        inhibit_any_policy=(
            0 if parameters.initial_any_policy_inhibit
            else path_length + 1
        ),
        policy_mapping=(
            0 if parameters.initial_policy_mapping_inhibit
            else path_length + 1
        ),
        # Steps 1 g-j
        working_public_key=trust_anchor.public_key,
        working_issuer_name=trust_anchor.subject,
        # Step 1 k
        max_path_length=(
            path_length if trust_anchor.max_path_length is None
            else trust_anchor.max_path_length
        ),
        # NOTE: the algorithm (for now) assumes that the AA CA of RFC 5755 is
        # trusted by fiat, and does not require chaining up to a distinct CA.
        # In particular, we assume that the AA CA is the trust anchor in the
        # path. This matches the validation model used in signature policies
        # (where there are separate trust trees for attributes)
        max_aa_path_length=path_length
    )

    # Step 2: basic processing
    completed_path = ValidationPath(trust_anchor)
    validation_context.record_validation(trust_anchor, completed_path)

    cert: x509.Certificate
    cert = trust_anchor
    for index in range(1, path_length + 1):
        cert = path[index]

        describe_current_cert = _describe_cert(
            index, path_length, end_entity_name_override
        )
        # Step 2 a 1
        state.check_certificate_signature(
            cert, validation_context.weak_hash_algos, describe_current_cert
        )

        # Step 2 a 2
        if not validation_context.is_whitelisted(cert):
            tolerance = validation_context.time_tolerance
            validity = cert['tbs_certificate']['validity']
            _check_validity(
                validity=validity, moment=moment, tolerance=tolerance,
                describe_current_cert=describe_current_cert
            )

        # Step 2 a 3 - CRL/OCSP
        await _check_revocation(
            cert=cert, validation_context=validation_context, path=path,
            end_entity_name_override=end_entity_name_override,
            describe_current_cert=describe_current_cert,
            is_ee_cert=index == path_length
        )

        # Step 2 a 4
        if cert.issuer != state.working_issuer_name:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the %s issuer name
                could not be matched
                ''',
                describe_current_cert(),
            ))

        # Steps 2 b-c
        if index == path_length or not cert.self_issued:
            state.check_name_constraints(cert, describe_current_cert)

        # Steps 2 d
        state.process_policies(
            index,
            cert.certificate_policies_value,
            #  (see step 2 d 2)
            any_policy_uninhibited=(
                state.inhibit_any_policy > 0 or
                (index < path_length and cert.self_issued)
            ),
            describe_current_cert=describe_current_cert
        )

        if index < path_length:
            # Step 3: prepare for certificate index+1
            _prepare_next_step(
                index, cert, state,
                describe_current_cert=describe_current_cert
            )

        _check_aa_controls(cert, state, index, describe_current_cert)

        # Step 3 o / 4 f
        # Check for critical unsupported extensions
        unsupported_critical_extensions = \
            cert.critical_extensions - SUPPORTED_EXTENSIONS
        if unsupported_critical_extensions:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because %s contains the
                following unsupported critical extension%s: %s
                ''',
                describe_current_cert(definite=True),
                's' if len(unsupported_critical_extensions) != 1 else '',
                ', '.join(sorted(unsupported_critical_extensions)),
            ))

        if validation_context:
            # TODO I left this in from the original code,
            #  but caching intermediate results might not be appropriate at all
            #  times. For example, handling for self-issued certs is different
            #  depending on whether they're treated as an end-entity or not.
            completed_path = completed_path.copy().append(cert)
            validation_context.record_validation(cert, completed_path)

    # Step 4: wrap-up procedure

    # Steps 4 c-e skipped since this method doesn't output it
    # Step 4 f skipped since this method defers that to the calling application
    # --> only policy processing remains

    qualified_policies = _finish_policy_processing(
        state=state, cert=cert,
        acceptable_policies=parameters.user_initial_policy_set,
        path_length=path_length,
        cert_description=_describe_cert(
            path_length, path_length, end_entity_name_override
        )(definite=True)
    )
    path._set_qualified_policies(qualified_policies)
    # TODO cache valid policies on intermediate certs too?
    completed_path._set_qualified_policies(qualified_policies)

    return cert


def _check_validity(validity: Validity, moment, tolerance,
                    describe_current_cert):
    if moment < validity['not_before'].native - tolerance:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because %s is not valid
            until %s
            ''',
            describe_current_cert(definite=True),
            validity['not_before'].native.strftime('%Y-%m-%d %H:%M:%SZ')
        ))
    if moment > validity['not_after'].native + tolerance:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because %s expired %s
            ''',
            describe_current_cert(definite=True),
            validity['not_after'].native.strftime('%Y-%m-%d %H:%M:%SZ')
        ))


def _finish_policy_processing(state, cert, acceptable_policies, path_length,
                              cert_description):
    # Step 4 a
    if state.explicit_policy != 0:
        state.explicit_policy -= 1
    # Step 4 b
    if cert.policy_constraints_value:
        if cert.policy_constraints_value['require_explicit_policy'].native == 0:
            state.explicit_policy = 0
    # Step 4 g
    # Step 4 g i
    if state.valid_policy_tree is None:
        intersection = None

    # Step 4 g ii
    elif acceptable_policies == {'any_policy'}:
        intersection = state.valid_policy_tree

    # Step 4 g iii
    else:
        intersection = _prune_unacceptable_policies(
            path_length, state.valid_policy_tree, acceptable_policies
        )
    qualified_policies = frozenset()
    if intersection is not None:
        # collect policies in a user-friendly format and attach them to the
        # path object
        def _enum_policies():
            accepted_policy: PolicyTreeNode
            for accepted_policy in intersection.at_depth(path_length):
                listed_pol = accepted_policy.valid_policy
                if listed_pol != 'any_policy':
                    # the first ancestor that is a child of any_policy
                    # will have an ID that makes sense in the user's policy
                    # domain (here 'ancestor' includes the node itself)
                    user_domain_policy_id = next(
                        ancestor.valid_policy
                        for ancestor in accepted_policy.path_to_root()
                        if ancestor.parent.valid_policy == 'any_policy'
                    )
                else:
                    # any_policy can't be mapped, so we don't have to do
                    # any walking up the tree. This also covers the corner case
                    # where the path length is 0 (in this case, PKIX validation
                    # is pointless, but we have to deal with it gracefully)
                    user_domain_policy_id = 'any_policy'

                yield QualifiedPolicy(
                    user_domain_policy_id=user_domain_policy_id,
                    issuer_domain_policy_id=listed_pol,
                    qualifiers=frozenset(accepted_policy.qualifier_set)
                )

        qualified_policies = frozenset(_enum_policies())
    elif state.explicit_policy == 0:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because there is no valid set of
            policies for %s
            ''',
            cert_description
        ))
    return qualified_policies


async def _check_revocation(cert, validation_context: ValidationContext, path,
                            end_entity_name_override, describe_current_cert,
                            is_ee_cert):
    ocsp_status_good = False
    revocation_check_failed = False
    ocsp_matched = False
    crl_matched = False
    soft_fail = False
    failures = []
    cert_has_crl, cert_has_ocsp = get_declared_revinfo(cert)
    revinfo_declared = cert_has_crl or cert_has_ocsp
    rev_check_policy = \
        validation_context.revinfo_policy.revocation_checking_policy
    rev_rule = rev_check_policy.ee_certificate_rule if is_ee_cert \
        else rev_check_policy.intermediate_ca_cert_rule

    # for OCSP, we don't bother if there's nothing in the certificate's AIA
    if rev_rule.ocsp_relevant and cert_has_ocsp:
        try:
            await verify_ocsp_response(
                cert,
                path,
                validation_context,
                cert_description=describe_current_cert(definite=True),
                end_entity_name_override=end_entity_name_override
            )
            ocsp_status_good = True
            ocsp_matched = True
        except OCSPValidationIndeterminateError as e:
            failures.extend([failure[0] for failure in e.failures])
            revocation_check_failed = True
            ocsp_matched = True
        except OCSPNoMatchesError:
            pass
        except OCSPFetchError as e:
            if rev_rule.tolerant:
                soft_fail = True
                validation_context._report_soft_fail(e)
            else:
                failures.append(e)
                revocation_check_failed = True
    if not ocsp_status_good and rev_rule.ocsp_mandatory:
        if failures:
            err_str = '; '.join(str(f) for f in failures)
        else:
            err_str = 'an applicable OCSP response could not be found'
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because the mandatory OCSP
            check(s) for %s failed: %s
            ''',
            describe_current_cert(definite=True),
            err_str
        ))
    status_good = (
        ocsp_status_good and
        rev_rule != RevocationCheckingRule.CRL_AND_OCSP_REQUIRED
    )

    crl_status_good = False
    # do not attempt to check CRLs (even cached ones) if there are no
    # distribution points, unless we have to
    crl_required_by_policy = rev_rule.crl_mandatory or (
        not status_good
        and rev_rule == RevocationCheckingRule.CRL_OR_OCSP_REQUIRED
    )
    crl_fetchable = rev_rule.crl_relevant and cert_has_crl
    if crl_required_by_policy or (crl_fetchable and not status_good):
        try:
            cert_description = describe_current_cert(definite=True)
            await verify_crl(
                cert, path,
                validation_context,
                cert_description=cert_description,
                end_entity_name_override=end_entity_name_override
            )
            revocation_check_failed = False
            crl_status_good = True
            crl_matched = True
        except CRLValidationIndeterminateError as e:
            failures.extend([failure[0] for failure in e.failures])
            revocation_check_failed = True
            crl_matched = True
        except CRLNoMatchesError:
            pass
        except CRLFetchError as e:
            if rev_rule.tolerant:
                soft_fail = True
                validation_context._report_soft_fail(e)
            else:
                failures.append(e)
                revocation_check_failed = True

    if not crl_status_good and rev_rule.crl_mandatory:
        if failures:
            err_str = '; '.join(str(f) for f in failures)
        else:
            err_str = 'an applicable CRL could not be found'
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because the mandatory CRL
            check(s) for %s failed: %s
            ''',
            describe_current_cert(definite=True),
            err_str
        ))

    # If we still didn't find a match, the certificate has CRL/OCSP entries
    # but we couldn't query any of them. Let's check if this is disqualifying.
    # With 'strict' the fact that there's no match (irrespective
    # of certificate properties) is enough to cause a failure,
    # otherwise we have to check.
    expected_revinfo = rev_rule.strict or (
        revinfo_declared and
        rev_rule == RevocationCheckingRule.CHECK_IF_DECLARED
    )
    # Did we find any revinfo that "has jurisdiction"?
    matched = crl_matched or ocsp_matched
    expected_revinfo_not_found = not matched and expected_revinfo
    if not soft_fail:
        if not status_good and matched and revocation_check_failed:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the %s revocation
                checks failed: %s
                ''',
                describe_current_cert(),
                '; '.join(failures)
            ))
        if expected_revinfo_not_found:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because no revocation
                information could be found for %s
                ''',
                describe_current_cert(definite=True)
            ))


def _check_aa_controls(cert: x509.Certificate, state: _PathValidationState,
                       index, describe_current_cert):
    aa_controls = AAControls.read_extension_value(cert)
    if aa_controls is not None:
        if not state.aa_controls_used and index > 1:
            raise PathValidationError(pretty_message(
                '''
                AA controls extension only present on part of the certificate
                chain: %s has AA controls while preceding certificates do not.
                ''',
                describe_current_cert(definite=True)
            ))
        state.aa_controls_used = True
        # deal with path length
        new_max_aa_path_length = aa_controls['path_len_constraint'].native
        if new_max_aa_path_length is not None \
                and new_max_aa_path_length < state.max_aa_path_length:
            state.max_aa_path_length = new_max_aa_path_length
    elif state.aa_controls_used:
        raise PathValidationError(pretty_message(
            '''
            AA controls extension only present on part of the certificate chain:
            %s has no AA controls
            ''',
            describe_current_cert(definite=True)
        ))


def _prepare_next_step(index, cert: x509.Certificate,
                       state: _PathValidationState,
                       describe_current_cert):
    if cert.policy_mappings_value:
        policy_map = _enumerate_policy_mappings(
            cert.policy_mappings_value,
            describe_current_cert=describe_current_cert
        )

        # Step 3 b
        if state.valid_policy_tree is not None:
            state.valid_policy_tree = _apply_policy_mapping(
                policy_map, state.valid_policy_tree, depth=index,
                policy_mapping_uninhibited=state.policy_mapping > 0
            )

    # Step 3 c
    state.working_issuer_name = cert.subject

    # Steps 3 d-f

    # Handle inheritance of DSA parameters from a signing CA to the
    # next in the chain
    # NOTE: we don't perform this step for RSASSA-PSS since there the
    #  parameters are drawn form the signature parameters, where they
    #  must always be present.
    copy_params = None
    if cert.public_key.algorithm == 'dsa' \
            and cert.public_key.hash_algo is None:
        if state.working_public_key.algorithm == 'dsa':
            key_alg = state.working_public_key['algorithm']
            copy_params = key_alg['parameters'].copy()

    if copy_params:
        working_public_key = cert.public_key.copy()
        working_public_key['algorithm']['parameters'] = copy_params
        state.working_public_key = working_public_key
    else:
        state.working_public_key = cert.public_key

    # Step 3 g
    nc_value: x509.NameConstraints = cert.name_constraints_value
    if nc_value is not None:
        new_permitted_subtrees = nc_value['permitted_subtrees']
        if new_permitted_subtrees is not None:
            state.permitted_subtrees.intersect_with(
                process_general_subtrees(new_permitted_subtrees)
            )
        new_excluded_subtrees = nc_value['excluded_subtrees']
        if new_excluded_subtrees is not None:
            state.excluded_subtrees.union_with(
                process_general_subtrees(new_excluded_subtrees)
            )

    # Step 3 h-j
    state.update_policy_restrictions(cert)

    # Step 3 k
    if not cert.ca:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because %s is not a CA
            ''',
            describe_current_cert(definite=True)
        ))

    # Step 3 l
    if not cert.self_issued:
        if state.max_path_length == 0:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because it exceeds the
                maximum path length
                '''
            ))
        state.max_path_length -= 1
        if state.max_aa_path_length == 0:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because it exceeds the
                maximum path length for an AA certificate
                '''
            ))
        state.max_aa_path_length -= 1

    # Step 3 m
    if cert.max_path_length is not None \
            and cert.max_path_length < state.max_path_length:
        state.max_path_length = cert.max_path_length

    # Step 3 n
    if cert.key_usage_value \
            and 'key_cert_sign' not in cert.key_usage_value.native:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because %s is not allowed
            to sign certificates
            ''',
            describe_current_cert(definite=True)
        ))


def _enumerate_policy_mappings(mappings: Iterable[x509.PolicyMapping],
                               describe_current_cert):
    policy_map = defaultdict(set)
    for mapping in mappings:
        issuer_domain_policy = mapping['issuer_domain_policy'].native
        subject_domain_policy = mapping['subject_domain_policy'].native

        policy_map[issuer_domain_policy].add(subject_domain_policy)

        # Step 3 a
        if issuer_domain_policy == 'any_policy' \
                or subject_domain_policy == 'any_policy':
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because %s contains
                a policy mapping for the "any policy"
                ''',
                describe_current_cert(definite=True)
            ))

    return policy_map


def _apply_policy_mapping(policy_map, valid_policy_tree, depth: int,
                          policy_mapping_uninhibited: bool):

    for issuer_domain_policy, subject_domain_policies in policy_map.items():

        # Step 3 b 1
        if policy_mapping_uninhibited:
            issuer_domain_policy_match = False
            cert_any_policy = None

            for node in valid_policy_tree.at_depth(depth):
                if node.valid_policy == 'any_policy':
                    cert_any_policy = node
                if node.valid_policy == issuer_domain_policy:
                    issuer_domain_policy_match = True
                    node.expected_policy_set = subject_domain_policies

            if not issuer_domain_policy_match and cert_any_policy:
                cert_any_policy.parent.add_child(
                    issuer_domain_policy,
                    cert_any_policy.qualifier_set,
                    subject_domain_policies
                )

        # Step 3 b 2
        else:
            for node in valid_policy_tree.at_depth(depth):
                if node.valid_policy == issuer_domain_policy:
                    node.parent.remove_child(node)
            valid_policy_tree = _prune_policy_tree(
                valid_policy_tree, depth - 1
            )
    return valid_policy_tree


def _prune_unacceptable_policies(path_length, valid_policy_tree,
                                 acceptable_policies) \
        -> Optional['PolicyTreeRoot']:
    # Step 4 g iii 1: compute nodes that branch off any_policy
    #  In other words, find all policies that are valid and meaningful in
    #  the trust root(s) namespace. We don't care about what policy mapping
    #  transformed them into; that's taken care of by the validation
    #  algorithm.
    #  Note: set() consumes the iterator to avoid operating on the tree
    #  while iterating over it. Performance is probably not a concern
    #  anyhow.
    valid_policy_node_set = set(valid_policy_tree.nodes_in_current_domain())

    # Step 4 g iii 2: eliminate unacceptable policies
    def _filter_acceptable():
        for policy_node in valid_policy_node_set:
            policy_id = policy_node.valid_policy
            if policy_id == 'any_policy' or \
                    policy_id in acceptable_policies:
                yield policy_id
            else:
                policy_node.parent.remove_child(policy_node)

    # list of policies that were explicitly valid
    valid_and_acceptable = set(_filter_acceptable())

    # Step 4 g iii 3: if the final layer contains an anyPolicy node
    # (there can be at most one), expand it out into acceptable policies
    # that are not explicitly qualified already
    try:
        final_any_policy: PolicyTreeNode = next(
            policy_node for policy_node
            in valid_policy_tree.at_depth(path_length)
            if policy_node.valid_policy == 'any_policy'
        )
        wildcard_parent = final_any_policy.parent
        assert wildcard_parent is not None
        wildcard_quals = final_any_policy.qualifier_set
        for acceptable_policy in \
                (acceptable_policies - valid_and_acceptable):
            wildcard_parent.add_child(
                acceptable_policy, wildcard_quals, {acceptable_policy}
            )
        # prune the anyPolicy node
        wildcard_parent.remove_child(final_any_policy)
    except StopIteration:
        pass

    # Step 4 g iii 4: prune the policy tree
    return _prune_policy_tree(valid_policy_tree, path_length - 1)


def _describe_cert(index, last_index, end_entity_name_override):
    """
    :param index:
        An integer of the index of the certificate in the path

    :param last_index:
        An integer of the last index in the path

    :param end_entity_name_override:
        None or a unicode string of the name to use for the final certificate
        in the path. Used for indirect CRL issuer and OCSP responder
        certificates.

    :return:
        A unicode string describing the position of a certificate in the chain
    """

    def _describe(definite=False):
        if index != last_index:
            return 'intermediate certificate %s' % index

        prefix = 'the ' if definite else ''

        if end_entity_name_override is not None:
            return prefix + end_entity_name_override

        return prefix + 'end-entity certificate'
    return _describe


OCSP_PROVENANCE_ERR = (
    "Unable to verify OCSP response since response signing "
    "certificate could not be validated"
)


async def _validate_delegated_ocsp_provenance(
        responder_cert: x509.Certificate,
        issuer: x509.Certificate,
        validation_context: ValidationContext,
        ee_path: ValidationPath,
        end_entity_name_override,
        cert_description):
    # OCSP responder certs must be issued directly by the CA on behalf of
    # which they act.
    # Moreover, RFC 6960 says that we don't have to accept OCSP responses signed
    # with a different key than the one used to sign subscriber certificates.

    if end_entity_name_override is None:
        end_entity_name_override = cert_description + ' OCSP responder'

    issuer_chain = ee_path.copy().truncate_to(issuer)
    responder_chain = issuer_chain.append(responder_cert)
    if responder_cert.ocsp_no_check_value is not None:
        # we don't have to check the revocation of the OCSP responder,
        # so do a simplified check
        revinfo_policy = CertRevTrustPolicy(
            revocation_checking_policy=RevocationCheckingPolicy(
                ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
                # this one should never trigger
                intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK
            )
        )
        vc = ValidationContext(
            trust_roots=[issuer],
            allow_fetching=False, revinfo_policy=revinfo_policy,
            moment=validation_context.moment,
            weak_hash_algos=validation_context.weak_hash_algos,
            time_tolerance=validation_context.time_tolerance
        )

        try:
            # verify the truncated path
            await _validate_path(
                vc, path=ValidationPath(issuer).append(responder_cert),
                end_entity_name_override=end_entity_name_override
            )
        except PathValidationError as e:
            raise OCSPValidationError(OCSP_PROVENANCE_ERR) from e
        # record validation in the original VC
        # TODO maybe have an (issuer, [verified_responder]) cache?
        #  caching OCSP responder validation results with everything else is
        #  probably somewhat incorrect
        validation_context.record_validation(responder_cert, responder_chain)
    else:
        try:
            await _validate_path(
                validation_context, path=responder_chain,
                end_entity_name_override=end_entity_name_override
            )
        except PathValidationError as e:
            raise OCSPValidationError(OCSP_PROVENANCE_ERR) from e


def _ocsp_allowed(responder_cert: x509.Certificate):
    extended_key_usage = responder_cert.extended_key_usage_value
    return (
        extended_key_usage is not None
        and 'ocsp_signing' in extended_key_usage.native
    )


@dataclass
class _OCSPErrs:
    failures: list = field(default_factory=list)
    mismatch_failures: int = 0


async def _handle_single_ocsp_resp(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        issuer: x509.Certificate,
        path: ValidationPath,
        ocsp_response: ocsp.OCSPResponse,
        validation_context: ValidationContext,
        moment: datetime.datetime,
        errs: _OCSPErrs, cert_description=None,
        end_entity_name_override=None) -> bool:

    certificate_registry = validation_context.certificate_registry
    # Make sure that we get a valid response back from the OCSP responder
    status = ocsp_response['response_status'].native
    if status != 'successful':
        errs.mismatch_failures += 1
        return False

    response_bytes = ocsp_response['response_bytes']
    if response_bytes['response_type'].native != 'basic_ocsp_response':
        errs.mismatch_failures += 1
        return False

    response = response_bytes['response'].parsed
    tbs_response = response['tbs_response_data']

    # With a valid response, now a check is performed to see if the response is
    # applicable for the cert and moment requested
    cert_response = tbs_response['responses'][0]

    response_cert_id = cert_response['cert_id']

    issuer_hash_algo = response_cert_id['hash_algorithm']['algorithm'].native

    is_pkc = isinstance(cert, x509.Certificate)
    if is_pkc:
        cert_issuer_name_hash = getattr(cert.issuer, issuer_hash_algo)
        cert_serial_number = cert.serial_number
    else:
        iss_name = extract_ac_issuer_dir_name(cert)
        cert_issuer_name_hash = getattr(iss_name, issuer_hash_algo)
        cert_serial_number = cert['ac_info']['serial_number'].native
    cert_issuer_key_hash = getattr(issuer.public_key, issuer_hash_algo)

    key_hash_mismatch = \
        response_cert_id['issuer_key_hash'].native != cert_issuer_key_hash

    name_mismatch = \
        response_cert_id['issuer_name_hash'].native != cert_issuer_name_hash
    serial_mismatch = \
        response_cert_id['serial_number'].native != cert_serial_number

    if (name_mismatch or serial_mismatch) and key_hash_mismatch:
        errs.mismatch_failures += 1
        return False

    if name_mismatch:
        errs.failures.append((
            'OCSP response issuer name hash does not match',
            ocsp_response
        ))
        return False

    if serial_mismatch:
        errs.failures.append((
            'OCSP response certificate serial number does not match',
            ocsp_response
        ))
        return False

    if key_hash_mismatch:
        errs.failures.append((
            'OCSP response issuer key hash does not match',
            ocsp_response
        ))
        return False

    retroactive = validation_context.retroactive_revinfo
    tolerance = validation_context.time_tolerance

    this_update = cert_response['this_update'].native
    if this_update is not None and not retroactive \
            and moment < this_update - tolerance:
        errs.failures.append((
            'OCSP response is from after the validation time',
            ocsp_response
        ))
        return False

    next_update = cert_response['next_update'].native
    if next_update is not None and moment > next_update + tolerance:
        errs.failures.append((
            'OCSP response is from before the validation time',
            ocsp_response
        ))
        return False

    # To verify the response as legitimate, the responder cert must be located
    cert_store: CertificateCollection = certificate_registry
    # prioritise the certificates included with the response, if there
    # are any
    if response['certs']:
        cert_store = LayeredCertificateStore([
            SimpleCertificateStore.from_certs(response['certs']),
            certificate_registry
        ])
    if tbs_response['responder_id'].name == 'by_key':
        key_identifier = tbs_response['responder_id'].native
        responder_cert = cert_store.retrieve_by_key_identifier(key_identifier)
    else:
        candidate_responder_certs = cert_store.retrieve_by_name(
            tbs_response['responder_id'].chosen
        )
        responder_cert = candidate_responder_certs[0] if \
            candidate_responder_certs else None
    if not responder_cert:
        errs.failures.append((
            pretty_message(
                '''
                Unable to verify OCSP response since response signing
                certificate could not be located
                '''
            ),
            ocsp_response
        ))
        return False

    # If the cert signing the OCSP response is not the issuer, it must be
    # issued by the cert issuer and be valid for OCSP responses
    if issuer.issuer_serial == responder_cert.issuer_serial:
        # let's check whether the certs are actually the same
        # (by comparing the signatures as a proxy)
        issuer_sig = bytes(issuer['signature_value'])
        responder_sig = bytes(responder_cert['signature_value'])
        authorized = issuer_sig == responder_sig
    # If OCSP is being delegated
    # check whether the relevant OCSP-related extensions are present.
    # Also, explicitly disallow delegation for attribute authorities
    # since they cannot act as CAs and hence can't issue responder certificates.
    # This would otherwise be detected during path validation or while checking
    # the basicConstraints on the AA certificate, but this is more explicit.
    elif not _ocsp_allowed(responder_cert) or not is_pkc:
        authorized = False
    else:
        try:
            await _validate_delegated_ocsp_provenance(
                responder_cert=responder_cert, issuer=issuer,
                validation_context=validation_context, ee_path=path,
                end_entity_name_override=end_entity_name_override,
                cert_description=cert_description
            )
            authorized = True
        except OCSPValidationError as e:
            errs.failures.append((e.args[0], ocsp_response))
            return False
    if not authorized:
        errs.failures.append((
            pretty_message(
                '''
                Unable to verify OCSP response since response was
                signed by an unauthorized certificate
                '''
            ),
            ocsp_response
        ))
        return False

    # Determine what algorithm was used to sign the response
    signature_algo = response['signature_algorithm'].signature_algo
    hash_algo = response['signature_algorithm'].hash_algo

    # Verify that the response was properly signed by the validated certificate
    try:
        _validate_sig(
            signature=response['signature'].native,
            signed_data=tbs_response.dump(),
            public_key_info=responder_cert.public_key,
            sig_algo=signature_algo, hash_algo=hash_algo,
            parameters=response['signature_algorithm']['parameters']
        )
    except PSSParameterMismatch:
        errs.failures.append((
            'The signature parameters on the OCSP response do not match '
            'the constraints on the public key',
            ocsp_response
        ))
    except InvalidSignature:
        errs.failures.append((
            'Unable to verify OCSP response signature',
            ocsp_response
        ))
        return False

    # Finally check to see if the certificate has been revoked
    status = cert_response['cert_status'].name
    if status == 'good':
        return True

    if status == 'revoked':
        revocation_info = cert_response['cert_status'].chosen
        if revocation_info['revocation_reason'].native is None:
            reason = crl.CRLReason('unspecified').human_friendly
        else:
            reason = revocation_info['revocation_reason'].human_friendly
        date = revocation_info['revocation_time'].native.strftime('%Y-%m-%d')
        time = revocation_info['revocation_time'].native.strftime('%H:%M:%S')
        raise RevokedError(pretty_message(
            '''
            OCSP response indicates %s was revoked at %s on %s, due to %s
            ''',
            cert_description,
            time,
            date,
            reason
        ))


async def verify_ocsp_response(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        path: ValidationPath,
        validation_context: ValidationContext,
        cert_description: Optional[str] = None,
        end_entity_name_override: Optional[str] = None):
    """
    Verifies an OCSP response, checking to make sure the certificate has not
    been revoked. Fulfills the requirements of
    https://tools.ietf.org/html/rfc6960#section-3.2.

    :param cert:
        An asn1cyrpto.x509.Certificate object or
        an asn1crypto.cms.AttributeCertificateV2 object to verify the OCSP
        response for

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the cert's
        validation path, or in the case of an AC, the AA's validation path.

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        caching validation information

    :param cert_description:
        None or a unicode string containing a description of the certificate to
        be used in exception messages

    :param end_entity_name_override:
        None or a unicode string of the name to use for the end-entity
        certificate when including in exception messages

    :raises:
        pyhanko_certvalidator.errors.OCSPNoMatchesError - when none of the OCSP responses match the certificate
        pyhanko_certvalidator.errors.OCSPValidationIndeterminateError - when the OCSP response could not be verified
        pyhanko_certvalidator.errors.RevokedError - when the OCSP response indicates the certificate has been revoked
    """

    if cert_description is None:
        cert_description = 'the certificate'

    moment = validation_context.moment

    if isinstance(cert, x509.Certificate):
        try:
            cert_issuer = path.find_issuer(cert)
        except LookupError:
            raise CRLNoMatchesError(pretty_message(
                '''
                Could not determine issuer certificate for %s in path.
                ''',
                cert_description
            ))
    else:
        cert_issuer = path.last

    errs = _OCSPErrs()
    ocsp_responses = await validation_context.async_retrieve_ocsps(
        cert, cert_issuer
    )

    for ocsp_response in ocsp_responses:
        try:
            ocsp_good = await _handle_single_ocsp_resp(
                cert=cert, issuer=cert_issuer, path=path,
                ocsp_response=ocsp_response,
                validation_context=validation_context, moment=moment,
                errs=errs, cert_description=cert_description,
                end_entity_name_override=end_entity_name_override
            )
            if ocsp_good:
                return
        except ValueError as e:
            msg = "Generic processing error while validating OCSP response."
            logging.debug(msg, exc_info=e)
            errs.failures.append((msg, ocsp_response))

    if errs.mismatch_failures == len(ocsp_responses):
        raise OCSPNoMatchesError(pretty_message(
            '''
            No OCSP responses were issued for %s
            ''',
            cert_description
        ))

    raise OCSPValidationIndeterminateError(
        pretty_message(
            '''
            Unable to determine if %s is revoked due to insufficient
            information from OCSP responses
            ''',
            cert_description
        ),
        errs.failures
    )


async def _find_candidate_crl_issuers(crl_issuer_name: x509.Name,
                                      certificate_list: crl.CertificateList,
                                      *, cert_issuer: x509.Certificate,
                                      cert_registry: CertificateRegistry):
    # first, look in the cache for certs issued by the issuer named
    # in the issuing distribution point
    candidates = cert_registry.retrieve_by_name(
        crl_issuer_name, cert_issuer
    )
    issuing_authority = certificate_list.issuer
    if not candidates and crl_issuer_name != certificate_list.issuer:
        # next, look for certs issued by the issuer named as the issuing
        # authority of the CRL
        candidates = cert_registry.retrieve_by_name(
            issuing_authority, cert_issuer
        )
    if not candidates and cert_registry.fetcher is not None:
        candidates = []
        valid_names = {crl_issuer_name, issuing_authority}
        # Try to download certificates from URLs in the AIA extension,
        # if there is one
        async for cert in \
                cert_registry.fetcher.fetch_crl_issuers(certificate_list):
            # filter by name
            if cert.subject in valid_names:
                candidates.insert(0, cert)
    return candidates


async def _find_crl_issuer(
        crl_issuer_name: x509.Name,
        certificate_list: crl.CertificateList,
        *, cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        cert_issuer: x509.Certificate,
        cert_path: ValidationPath,
        validation_context: ValidationContext,
        is_indirect: bool,
        end_entity_name_override,
        cert_description):

    cert_sha256 = hashlib.sha256(cert.dump()).digest()
    candidates_skipped = 0
    signatures_failed = 0
    unauthorized_certs = 0

    candidate_crl_issuers = await _find_candidate_crl_issuers(
        crl_issuer_name, certificate_list, cert_issuer=cert_issuer,
        cert_registry=validation_context.certificate_registry
    )

    crl_issuer = None
    for candidate_crl_issuer in candidate_crl_issuers:
        direct_issuer = candidate_crl_issuer.subject == cert_issuer.subject

        # In some cases an indirect CRL issuer is a certificate issued
        # by the certificate issuer. However, we need to ensure that
        # the candidate CRL issuer is not the certificate being checked,
        # otherwise we may be checking an incorrect CRL and produce
        # incorrect results.
        indirect_issuer = (
            candidate_crl_issuer.issuer == cert_issuer.subject
            and candidate_crl_issuer.sha256 != cert_sha256
        )

        if not direct_issuer and not indirect_issuer and not is_indirect:
            candidates_skipped += 1
            continue

        # Step f
        candidate_crl_issuer_path = None

        if validation_context:
            candidate_crl_issuer_path = \
                validation_context.check_validation(candidate_crl_issuer)

        if candidate_crl_issuer_path is None:
            candidate_crl_issuer_path = cert_path.copy()\
                .truncate_to_issuer(candidate_crl_issuer)
            candidate_crl_issuer_path.append(candidate_crl_issuer)
            try:
                # Pre-emptively mark a path as validated to prevent recursion
                if validation_context:
                    validation_context.record_validation(
                        candidate_crl_issuer, candidate_crl_issuer_path
                    )

                temp_override = end_entity_name_override
                if temp_override is None and candidate_crl_issuer.sha256 != cert_issuer.sha256:
                    temp_override = cert_description + ' CRL issuer'
                await _validate_path(
                    validation_context,
                    candidate_crl_issuer_path,
                    end_entity_name_override=temp_override
                )

            except PathValidationError as e:
                # If the validation did not work out, clear it
                if validation_context:
                    validation_context.clear_validation(candidate_crl_issuer)

                # We let a revoked error fall through since step k will catch
                # it with a correct error message
                if isinstance(e, RevokedError):
                    raise
                raise CRLValidationError(
                    'CRL issuer certificate path could not be validated')

        key_usage_value = candidate_crl_issuer.key_usage_value
        if key_usage_value and 'crl_sign' not in key_usage_value.native:
            unauthorized_certs += 1
            continue

        try:
            # Step g
            _verify_signature(certificate_list, candidate_crl_issuer.public_key)

            crl_issuer = candidate_crl_issuer
            break

        except CRLValidationError:
            signatures_failed += 1
            continue

    if crl_issuer is not None:
        validation_context.record_crl_issuer(certificate_list, crl_issuer)
        return crl_issuer
    elif candidates_skipped == len(candidate_crl_issuers):
        raise CRLNoMatchesError()
    else:
        if signatures_failed == len(candidate_crl_issuers):
            raise CRLValidationError(
                'CRL signature could not be verified'
            )
        elif unauthorized_certs == len(candidate_crl_issuers):
            raise CRLValidationError(
                'The CRL issuer is not authorized to sign CRLs',
            )
        else:
            raise CRLValidationError(
                'Unable to locate CRL issuer certificate',
            )


KNOWN_CRL_EXTENSIONS = {'issuer_alt_name', 'crl_number', 'delta_crl_indicator',
                        'issuing_distribution_point',
                        'authority_key_identifier', 'freshest_crl',
                        'authority_information_access'}

VALID_REVOCATION_REASONS = {'key_compromise', 'ca_compromise',
                            'affiliation_changed', 'superseded',
                            'cessation_of_operation', 'certificate_hold',
                            'privilege_withdrawn', 'aa_compromise'}


@dataclass
class _CRLErrs:
    failures: list = field(default_factory=list)
    issuer_failures: int = 0


def _find_matching_delta_crl(delta_lists, crl_issuer_name: x509.Name,
                                   crl_idp: crl.IssuingDistributionPoint,
                                   parent_crl_aki: Optional[bytes]):
    for candidate_delta_cl in delta_lists:
        # Step c 1
        if candidate_delta_cl.issuer != crl_issuer_name:
            continue

        # Step c 2
        delta_crl_idp = candidate_delta_cl.issuing_distribution_point_value
        if (crl_idp is None and delta_crl_idp is not None) or (
                crl_idp is not None and delta_crl_idp is None):
            continue

        if crl_idp is not None \
                and crl_idp.native != delta_crl_idp.native:
            continue

        # Step c 3
        if parent_crl_aki != candidate_delta_cl.authority_key_identifier:
            continue

        return candidate_delta_cl


def _match_dps_idp_names(crl_idp: crl.IssuingDistributionPoint,
                         crl_dps: Optional[x509.CRLDistributionPoints],
                         crl_issuer: x509.Certificate,
                         crl_issuer_name: x509.Name) -> bool:

    # Step b 2 i
    has_idp_name = False
    has_dp_name = False
    idp_dp_match = False

    idp_general_names = []
    idp_dp_name = crl_idp['distribution_point']
    if idp_dp_name:
        has_idp_name = True
        if idp_dp_name.name == 'full_name':
            for general_name in idp_dp_name.chosen:
                idp_general_names.append(general_name)
        else:
            inner_extended_issuer_name = crl_issuer.subject.copy()
            inner_extended_issuer_name.chosen.append(
                idp_dp_name.chosen.untag())
            idp_general_names.append(x509.GeneralName(
                name='directory_name',
                value=inner_extended_issuer_name
            ))

    if crl_dps:
        for dp in crl_dps:
            if idp_dp_match:
                break
            dp_name = dp['distribution_point']
            if dp_name:
                has_dp_name = True
                if dp_name.name == 'full_name':
                    for general_name in dp_name.chosen:
                        if general_name in idp_general_names:
                            idp_dp_match = True
                            break
                else:
                    inner_extended_issuer_name = crl_issuer.subject.copy()
                    inner_extended_issuer_name.chosen.append(
                        dp_name.chosen.untag())
                    dp_extended_issuer_name = x509.GeneralName(
                        name='directory_name',
                        value=inner_extended_issuer_name
                    )

                    if dp_extended_issuer_name in idp_general_names:
                        idp_dp_match = True

            elif dp['crl_issuer']:
                has_dp_name = True
                for dp_crl_issuer_name in dp['crl_issuer']:
                    if dp_crl_issuer_name in idp_general_names:
                        idp_dp_match = True
                        break
    else:
        # If there is no DP, we consider the CRL issuer name to be it
        has_dp_name = True
        general_name = x509.GeneralName(
            name='directory_name',
            value=crl_issuer_name
        )
        if general_name in idp_general_names:
            idp_dp_match = True

    return idp_dp_match or not has_idp_name or not has_dp_name


def _handle_crl_idp_ext_constraints(cert: x509.Certificate,
                                    certificate_list: crl.CertificateList,
                                    crl_issuer: x509.Certificate,
                                    crl_idp: crl.IssuingDistributionPoint,
                                    crl_issuer_name: x509.Name,
                                    errs: _CRLErrs) -> bool:
    match = _match_dps_idp_names(
        crl_idp=crl_idp, crl_dps=cert.crl_distribution_points_value,
        crl_issuer=crl_issuer,
        crl_issuer_name=crl_issuer_name,
    )
    if not match:
        errs.failures.append((
            pretty_message(
                '''
                The CRL issuing distribution point extension does not
                share any names with the certificate CRL distribution
                point extension
                '''
            ),
            certificate_list
        ))
        errs.issuer_failures += 1
        return False

    # Step b 2 ii
    if crl_idp['only_contains_user_certs'].native:
        if cert.basic_constraints_value and \
                cert.basic_constraints_value['ca'].native:
            errs.failures.append((
                pretty_message(
                    '''
                    CRL only contains end-entity certificates and
                    certificate is a CA certificate
                    '''
                ),
                certificate_list
            ))
            return False

    # Step b 2 iii
    if crl_idp['only_contains_ca_certs'].native:
        if not cert.basic_constraints_value or \
                cert.basic_constraints_value['ca'].native is False:
            errs.failures.append((
                pretty_message(
                    '''
                    CRL only contains CA certificates and certificate
                    is an end-entity certificate
                    '''
                ),
                certificate_list
            ))
            return False

    # Step b 2 iv
    if crl_idp['only_contains_attribute_certs'].native:
        errs.failures.append((
            'CRL only contains attribute certificates',
            certificate_list
        ))
        return False

    return True


def _handle_attr_cert_crl_idp_ext_constraints(
        certificate_list: crl.CertificateList,
        crl_dps: Optional[x509.CRLDistributionPoints],
        crl_issuer: x509.Certificate,
        crl_idp: crl.IssuingDistributionPoint,
        crl_issuer_name: x509.Name,
        errs: _CRLErrs) -> bool:

    match = _match_dps_idp_names(
        crl_idp=crl_idp, crl_dps=crl_dps,
        crl_issuer=crl_issuer, crl_issuer_name=crl_issuer_name,
    )
    if not match:
        errs.failures.append((
            pretty_message(
                '''
                The CRL issuing distribution point extension does not
                share any names with the attribute certificate's
                CRL distribution point extension
                '''
            ),
            certificate_list
        ))
        errs.issuer_failures += 1
        return False

    # Step b 2 ii
    pkc_only = (
       crl_idp['only_contains_user_certs'].native
       or crl_idp['only_contains_ca_certs'].native
    )
    if pkc_only:
        errs.failures.append((
            pretty_message(
                '''
                CRL only contains public-key certificates, but
                certificate is an attribute certificate
                '''
            ),
            certificate_list
        ))
        return False

    return True


async def _handle_single_crl(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        cert_issuer: x509.Certificate,
        certificate_list: crl.CertificateList,
        path: ValidationPath,
        validation_context: ValidationContext,
        delta_lists_by_issuer,
        use_deltas: bool, errs: _CRLErrs,
        cert_description=None,
        end_entity_name_override=None):

    moment = validation_context.moment
    certificate_registry = validation_context.certificate_registry
    crl_idp: crl.IssuingDistributionPoint \
        = certificate_list.issuing_distribution_point_value
    delta_certificate_list = None

    is_pkc = isinstance(cert, x509.Certificate)

    is_indirect = False

    if crl_idp and crl_idp['indirect_crl'].native:
        is_indirect = True
        crl_idp_name = crl_idp['distribution_point']
        if crl_idp_name:
            if crl_idp_name.name == 'full_name':
                crl_issuer_name = crl_idp_name.chosen[0].chosen
            else:
                crl_issuer_name = cert_issuer.subject.copy().chosen.append(
                    crl_idp_name.chosen
                )
        elif certificate_list.authority_key_identifier:
            tmp_crl_issuer = certificate_registry.retrieve_by_key_identifier(
                certificate_list.authority_key_identifier
            )
            crl_issuer_name = tmp_crl_issuer.subject
        else:
            errs.failures.append((
                'CRL is marked as an indirect CRL, but provides no '
                'mechanism for locating the CRL issuer certificate',
                certificate_list
            ))
            return None
    else:
        crl_issuer_name = certificate_list.issuer

    # check if we already know the issuer of this CRL
    crl_issuer = validation_context.check_crl_issuer(certificate_list)
    # if not, attempt to determine it
    if not crl_issuer:
        try:
            crl_issuer = await _find_crl_issuer(
                crl_issuer_name, certificate_list,
                cert=cert, cert_issuer=cert_issuer,
                cert_path=path,
                validation_context=validation_context,
                is_indirect=is_indirect,
                end_entity_name_override=end_entity_name_override,
                cert_description=cert_description
            )
        except CRLNoMatchesError:
            # this no-match issue will be dealt with at a higher level later
            errs.issuer_failures += 1
            return None
        except (CertificateFetchError, CRLValidationError) as e:
            errs.failures.append((e.args[0], certificate_list))
            return None

    # Step b 1
    has_dp_crl_issuer = False
    dp_match = False

    if is_pkc:
        crl_dps = cert.crl_distribution_points_value
    else:
        crl_dps = get_ac_extension_value(cert, 'crl_distribution_points')
    if crl_dps:
        crl_issuer_general_name = x509.GeneralName(
            name='directory_name',
            value=crl_issuer.subject
        )
        for dp in crl_dps:
            if dp['crl_issuer']:
                has_dp_crl_issuer = True
                if crl_issuer_general_name in dp['crl_issuer']:
                    dp_match = True

    same_issuer = crl_issuer.subject == cert_issuer.subject
    indirect_match = has_dp_crl_issuer and dp_match and is_indirect
    missing_idp = has_dp_crl_issuer and (not dp_match or not is_indirect)
    indirect_crl_issuer = crl_issuer.issuer == cert_issuer.subject

    if (not same_issuer and not indirect_match and not indirect_crl_issuer) \
            or missing_idp:
        errs.issuer_failures += 1
        return None

    # Check to make sure the CRL is valid for the moment specified
    tolerance = validation_context.time_tolerance
    retroactive = validation_context.retroactive_revinfo
    crl_this_update = certificate_list['tbs_cert_list']['this_update'].native
    if not retroactive and moment < crl_this_update - tolerance:
        errs.failures.append((
            'CRL is from after the validation time',
            certificate_list
        ))
        return None
    crl_next_update = certificate_list['tbs_cert_list']['next_update'].native
    if moment > crl_next_update + tolerance:
        errs.failures.append((
            'CRL should have been regenerated by the validation time',
            certificate_list
        ))
        return None

    # Step b 2

    if crl_idp is not None:
        if is_pkc:
            crl_idp_match = _handle_crl_idp_ext_constraints(
                cert=cert, certificate_list=certificate_list,
                crl_issuer=crl_issuer, crl_idp=crl_idp,
                crl_issuer_name=crl_issuer_name, errs=errs
            )
        else:
            crl_idp_match = _handle_attr_cert_crl_idp_ext_constraints(
                crl_dps=crl_dps, certificate_list=certificate_list,
                crl_issuer=crl_issuer, crl_idp=crl_idp,
                crl_issuer_name=crl_issuer_name, errs=errs
            )
        # error reporting is taken care of in the delegated method
        if not crl_idp_match:
            return None

    # Step c
    if use_deltas and certificate_list.freshest_crl_value \
            and len(certificate_list.freshest_crl_value) > 0:
        candidate_delta_lists = \
            delta_lists_by_issuer.get(crl_issuer_name.hashable, [])
        delta_certificate_list = _find_matching_delta_crl(
            delta_lists=candidate_delta_lists,
            crl_issuer_name=crl_issuer_name, crl_idp=crl_idp,
            parent_crl_aki=certificate_list.authority_key_identifier
        )

    # Step d
    idp_reasons = None

    if crl_idp and crl_idp['only_some_reasons'].native is not None:
        idp_reasons = crl_idp['only_some_reasons'].native

    reason_keys = None
    if idp_reasons:
        reason_keys = idp_reasons

    if reason_keys is None:
        interim_reasons = VALID_REVOCATION_REASONS.copy()
    else:
        interim_reasons = reason_keys

    # Step e
    # We don't skip a CRL if it only contains reasons already checked since
    # a certificate issuer can self-issue a new cert that is used for CRLs

    if certificate_list.critical_extensions - KNOWN_CRL_EXTENSIONS:
        errs.failures.append((
            'One or more unrecognized critical extensions are present in '
            'the CRL',
            certificate_list
        ))
        return None

    if use_deltas and delta_certificate_list and \
            delta_certificate_list.critical_extensions - KNOWN_CRL_EXTENSIONS:
        errs.failures.append((
            'One or more unrecognized critical extensions are present in '
            'the delta CRL',
            delta_certificate_list
        ))
        return None

    # Step h
    if use_deltas and delta_certificate_list:
        try:
            _verify_signature(delta_certificate_list, crl_issuer.public_key)
        except CRLValidationError:
            errs.failures.append((
                'Delta CRL signature could not be verified',
                certificate_list,
                delta_certificate_list
            ))
            return None

        retroactive = validation_context.retroactive_revinfo
        crl_this_update = \
            delta_certificate_list['tbs_cert_list']['this_update'].native
        if not retroactive and moment < crl_this_update - tolerance:
            errs.failures.append((
                'Delta CRL is from after the validation time',
                certificate_list,
                delta_certificate_list
            ))
            return None
        crl_next_update = \
            delta_certificate_list['tbs_cert_list']['next_update'].native
        if moment > crl_next_update + tolerance:
            errs.failures.append((
                'Delta CRL is from before the validation time',
                certificate_list,
                delta_certificate_list
            ))
            return None

    # Step i
    revoked_reason = None
    revoked_date = None

    if use_deltas and delta_certificate_list:
        try:
            revoked_date, revoked_reason = \
                _find_cert_in_list(cert, cert_issuer,
                                   delta_certificate_list, crl_issuer)
        except NotImplementedError:
            errs.failures.append((
                'One or more unrecognized critical extensions are present in '
                'the CRL entry for the certificate',
                delta_certificate_list
            ))
            return None

    # Step j
    if revoked_reason is None:
        try:
            revoked_date, revoked_reason = \
                _find_cert_in_list(cert, cert_issuer,
                                   certificate_list, crl_issuer)
        except NotImplementedError:
            errs.failures.append((
                'One or more unrecognized critical extensions are present in '
                'the CRL entry for the certificate',
                certificate_list
            ))
            return None

    # Step k
    if revoked_reason and revoked_reason.native == 'remove_from_crl':
        revoked_reason = None
        revoked_date = None

    if revoked_reason:
        reason = revoked_reason.human_friendly
        date = revoked_date.native.strftime('%Y-%m-%d')
        time = revoked_date.native.strftime('%H:%M:%S')
        raise RevokedError(pretty_message(
            '''
            CRL indicates %s was revoked at %s on %s, due to %s
            ''',
            cert_description,
            time,
            date,
            reason
        ))

    return interim_reasons




async def verify_crl(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        path: ValidationPath,
        validation_context: ValidationContext, use_deltas=True,
        cert_description: Optional[str] = None,
        end_entity_name_override: Optional[str] = None):
    """
    Verifies a certificate against a list of CRLs, checking to make sure the
    certificate has not been revoked. Uses the algorithm from
    https://tools.ietf.org/html/rfc5280#section-6.3 as a basis, but the
    implementation differs to allow CRLs from unrecorded locations.

    :param cert:
        An asn1crypto.x509.Certificate or asn1crypto.cms.AttributeCertificateV2
        object to check for in the CRLs

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the cert's
        validation path, or in the case of an AC, the AA's validation path.

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for caching
        validation information

    :param use_deltas:
        A boolean indicating if delta CRLs should be used

    :param cert_description:
        A unicode string containing a description of the certificate to be used
        in exception messages

    :param end_entity_name_override:
        None or a unicode string of the name to use for the end-entity
        certificate when including in exception messages

    :raises:
        pyhanko_certvalidator.errors.CRLNoMatchesError - when none of the CRLs match the certificate
        pyhanko_certvalidator.errors.CRLValidationError - when any error occurs trying to verify the CertificateList
        pyhanko_certvalidator.errors.RevokedError - when the CRL indicates the certificate has been revoked
    """

    is_pkc = isinstance(cert, x509.Certificate)
    if cert_description is None:
        cert_description = f'the {"" if is_pkc else "attribute "}certificate'

    certificate_lists = await validation_context.async_retrieve_crls(cert)

    if is_pkc:
        try:
            cert_issuer = path.find_issuer(cert)
        except LookupError:
            raise CRLNoMatchesError(pretty_message(
                '''
                Could not determine issuer certificate for %s in path.
                ''',
                cert_description
            ))
    else:
        cert_issuer = path.last

    errs = _CRLErrs()

    complete_lists_by_issuer = defaultdict(list)
    delta_lists_by_issuer = defaultdict(list)
    for certificate_list in certificate_lists:
        try:
            issuer_hashable = certificate_list.issuer.hashable
            if certificate_list.delta_crl_indicator_value is None:
                complete_lists_by_issuer[issuer_hashable]\
                    .append(certificate_list)
            else:
                delta_lists_by_issuer[issuer_hashable].append(certificate_list)
        except ValueError as e:
            msg = "Generic processing error while classifying CRL."
            logging.debug(msg, exc_info=e)
            errs.failures.append((msg, certificate_list))

    # In the main loop, only complete CRLs are processed, so delta CRLs are
    # weeded out of the to-do list
    crls_to_process = []
    for issuer_crls in complete_lists_by_issuer.values():
        crls_to_process.extend(issuer_crls)
    total_crls = len(crls_to_process)

    # Build a lookup table for the Distribution point objects associated with
    # an issuer name hashable
    distribution_point_map = {}

    sources = get_relevant_crl_dps(cert, use_deltas=use_deltas)
    for distribution_point in sources:
        if isinstance(distribution_point['crl_issuer'], x509.GeneralNames):
            dp_name_hashes = []
            for general_name in distribution_point['crl_issuer']:
                if general_name.name == 'directory_name':
                    dp_name_hashes.append(general_name.chosen.hashable)
        elif is_pkc:
            dp_name_hashes = [cert.issuer.hashable]
        else:
            iss_dir_name = extract_ac_issuer_dir_name(cert)
            dp_name_hashes = [iss_dir_name.hashable]
        for dp_name_hash in dp_name_hashes:
            if dp_name_hash not in distribution_point_map:
                distribution_point_map[dp_name_hash] = []
            distribution_point_map[dp_name_hash].append(distribution_point)

    checked_reasons = set()

    while len(crls_to_process) > 0:
        certificate_list = crls_to_process.pop(0)
        try:
            interim_reasons = await _handle_single_crl(
                cert=cert, cert_issuer=cert_issuer,
                certificate_list=certificate_list, path=path,
                validation_context=validation_context,
                delta_lists_by_issuer=delta_lists_by_issuer,
                use_deltas=use_deltas, errs=errs,
                cert_description=cert_description,
                end_entity_name_override=end_entity_name_override
            )
            if interim_reasons is not None:
                # Step l
                checked_reasons |= interim_reasons
        except ValueError as e:
            msg = "Generic processing error while validating CRL."
            logging.debug(msg, exc_info=e)
            errs.failures.append((msg, certificate_list))

    # CRLs should not include this value, but at least one of the examples
    # from the NIST test suite does
    checked_reasons -= {'unused'}

    if checked_reasons != VALID_REVOCATION_REASONS:
        if total_crls == errs.issuer_failures:
            raise CRLNoMatchesError(pretty_message(
                '''
                No CRLs were issued by the issuer of %s, or any indirect CRL
                issuer
                ''',
                cert_description
            ))

        if not errs.failures:
            errs.failures.append((
                'The available CRLs do not cover all revocation reasons',
            ))

        raise CRLValidationIndeterminateError(
            pretty_message(
                '''
                Unable to determine if %s is revoked due to insufficient
                information from known CRLs
                ''',
                cert_description
            ),
            errs.failures
        )


def _verify_signature(certificate_list, public_key):
    """
    Verifies the digital signature on an asn1crypto.crl.CertificateList object

    :param certificate_list:
        An asn1crypto.crl.CertificateList object

    :raises:
        pyhanko_certvalidator.errors.CRLValidationError - when the signature is invalid or uses an unsupported algorithm
    """

    signature_algo = certificate_list['signature_algorithm'].signature_algo
    hash_algo = certificate_list['signature_algorithm'].hash_algo

    try:
        _validate_sig(
            signature=certificate_list['signature'].native,
            signed_data=certificate_list['tbs_cert_list'].dump(),
            public_key_info=public_key,
            sig_algo=signature_algo, hash_algo=hash_algo,
            parameters=certificate_list['signature_algorithm']['parameters']
        )
    except PSSParameterMismatch as e:
        raise CRLValidationError(
            'Invalid signature parameters on CertificateList'
        ) from e
    except InvalidSignature:
        raise CRLValidationError('Unable to verify the signature of the CertificateList')


KNOWN_CRL_ENTRY_EXTENSIONS = {
    'crl_reason', 'hold_instruction_code', 'invalidity_date',
    'certificate_issuer'
}


def _find_cert_in_list(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        issuer: x509.Certificate,
        certificate_list: crl.CertificateList,
        crl_issuer: x509.Certificate):
    """
    Looks for a cert in the list of revoked certificates

    :param cert:
        An asn1crypto.x509.Certificate object of the cert being checked,
        or an asn1crypto.cms.AttributeCertificateV2 object in the case
        of an attribute certificate.

    :param issuer:
        An asn1crypto.x509.Certificate object of the cert issuer

    :param certificate_list:
        An ans1crypto.crl.CertificateList object to look in for the cert

    :param crl_issuer:
        An asn1crypto.x509.Certificate object of the CRL issuer

    :return:
        A tuple of (None, None) if not present, otherwise a tuple of
        (asn1crypto.x509.Time object, asn1crypto.crl.CRLReason object)
        representing the date/time the object was revoked and why
    """

    revoked_certificates \
        = certificate_list['tbs_cert_list']['revoked_certificates']

    if isinstance(cert, x509.Certificate):
        cert_serial = cert.serial_number
    else:
        cert_serial = cert['ac_info']['serial_number'].native

    issuer_name = issuer.subject

    last_issuer_name = crl_issuer.subject
    for revoked_cert in revoked_certificates:
        # If any unknown critical extensions, the entry can not be used
        if revoked_cert.critical_extensions - KNOWN_CRL_ENTRY_EXTENSIONS:
            raise NotImplementedError()

        if revoked_cert.issuer_name and \
                revoked_cert.issuer_name != last_issuer_name:
            last_issuer_name = revoked_cert.issuer_name
        if last_issuer_name != issuer_name:
            continue

        if revoked_cert['user_certificate'].native != cert_serial:
            continue

        if not revoked_cert.crl_reason_value:
            crl_reason = crl.CRLReason('unspecified')
        else:
            crl_reason = revoked_cert.crl_reason_value

        return revoked_cert['revocation_date'], crl_reason

    return None, None


class PolicyTreeRoot:
    """
    A generic policy tree node, used for the root node in the tree
    """

    # None for the root node, an instance of PolicyTreeNode or PolicyTreeRoot
    # for all other nodes
    parent = None

    # A list of PolicyTreeNode objects
    children = None

    @classmethod
    def init_policy_tree(cls, valid_policy, qualifier_set, expected_policy_set):
        """
        Accepts values for a PolicyTreeNode that will be created at depth 0

        :param valid_policy:
            A unicode string of a policy name or OID

        :param qualifier_set:
            An instance of asn1crypto.x509.PolicyQualifierInfos

        :param expected_policy_set:
            A set of unicode strings containing policy names or OIDs
        """
        root = PolicyTreeRoot()
        root.add_child(valid_policy, qualifier_set, expected_policy_set)
        return root

    def __init__(self):
        self.children = []

    def add_child(self, valid_policy, qualifier_set, expected_policy_set):
        """
        Creates a new PolicyTreeNode as a child of this node

        :param valid_policy:
            A unicode string of a policy name or OID

        :param qualifier_set:
            An instance of asn1crypto.x509.PolicyQualifierInfos

        :param expected_policy_set:
            A set of unicode strings containing policy names or OIDs
        """

        child = PolicyTreeNode(valid_policy, qualifier_set, expected_policy_set)
        child.parent = self
        self.children.append(child)

    def remove_child(self, child):
        """
        Removes a child from this node

        :param child:
            An instance of PolicyTreeNode
        """

        self.children.remove(child)

    def at_depth(self, depth):
        """
        Returns a generator yielding all nodes in the tree at a specific depth

        :param depth:
            An integer >= 0 of the depth of nodes to yield

        :return:
            A generator yielding PolicyTreeNode objects
        """

        for child in list(self.children):
            if depth == 0:
                yield child
            else:
                for grandchild in child.at_depth(depth - 1):
                    yield grandchild

    def walk_up(self, depth):
        """
        Returns a generator yielding all nodes in the tree at a specific depth,
        or above. Yields nodes starting with leaves and traversing up to the
        root.

        :param depth:
            An integer >= 0 of the depth of nodes to walk up from

        :return:
            A generator yielding PolicyTreeNode objects
        """

        for child in list(self.children):
            if depth != 0:
                for grandchild in child.walk_up(depth - 1):
                    yield grandchild
            yield child

    def nodes_in_current_domain(self) -> Iterable['PolicyTreeNode']:
        """
        Returns a generator yielding all nodes in the tree that are children
        of an ``any_policy`` node.
        """

        for child in self.children:
            yield child
            if child.valid_policy == 'any_policy':
                yield from child.nodes_in_current_domain()


class PolicyTreeNode(PolicyTreeRoot):
    """
    A policy tree node that is used for all nodes but the root
    """

    # A unicode string of a policy name or OID
    valid_policy = None

    # An instance of asn1crypto.x509.PolicyQualifierInfos
    qualifier_set = None

    # A set of unicode strings containing policy names or OIDs
    expected_policy_set = None

    def __init__(self, valid_policy, qualifier_set, expected_policy_set):
        """
        :param valid_policy:
            A unicode string of a policy name or OID

        :param qualifier_set:
            An instance of asn1crypto.x509.PolicyQualifierInfos

        :param expected_policy_set:
            A set of unicode strings containing policy names or OIDs
        """
        super().__init__()

        self.valid_policy = valid_policy
        self.qualifier_set = qualifier_set
        self.expected_policy_set = expected_policy_set

    def path_to_root(self):
        node = self
        while node is not None:
            yield node
            node = node.parent


class PSSParameterMismatch(InvalidSignature):
    pass


class DSAParametersUnavailable(InvalidSignature):
    # TODO Technically, such a signature isn't _really_ invalid
    #  (we merely couldn't validate it).
    # However, this is only an issue for CRLs and OCSP responses that
    # make use of DSA parameter inheritance, which is pretty much a
    # completely irrelevant problem in this day and age, so treating those
    # signatures as invalid as a matter of course seems pretty much OK.
    pass


def _validate_sig(signature: bytes, signed_data: bytes,
                  public_key_info: PublicKeyInfo,
                  sig_algo: str, hash_algo: str, parameters=None):

    if sig_algo == 'dsa' and \
            public_key_info['algorithm']['parameters'].native is None:
        raise DSAParametersUnavailable(
            "DSA public key parameters were not provided."
        )

    # pyca/cryptography can't load PSS-exclusive keys without some help:
    if public_key_info.algorithm == 'rsassa_pss':
        public_key_info = public_key_info.copy()
        assert isinstance(parameters, algos.RSASSAPSSParams)
        pss_key_params = public_key_info['algorithm']['parameters'].native
        if pss_key_params is not None and pss_key_params != parameters.native:
            raise PSSParameterMismatch(
                "Public key info includes PSS parameters that do not match "
                "those on the signature"
            )
        # set key type to generic RSA, discard parameters
        public_key_info['algorithm'] = {'algorithm': 'rsa'}

    pub_key = serialization.load_der_public_key(public_key_info.dump())

    if sig_algo == 'rsassa_pkcs1v15':
        assert isinstance(pub_key, rsa.RSAPublicKey)
        hash_algo = getattr(hashes, hash_algo.upper())()
        pub_key.verify(signature, signed_data, padding.PKCS1v15(), hash_algo)
    elif sig_algo == 'rsassa_pss':
        assert isinstance(pub_key, rsa.RSAPublicKey)
        assert isinstance(parameters, algos.RSASSAPSSParams)
        mga: algos.MaskGenAlgorithm = parameters['mask_gen_algorithm']
        if not mga['algorithm'].native == 'mgf1':
            raise NotImplementedError("Only MFG1 is supported")

        mgf_md_name = mga['parameters']['algorithm'].native

        salt_len: int = parameters['salt_length'].native

        mgf_md = getattr(hashes, mgf_md_name.upper())()
        pss_padding = padding.PSS(
            mgf=padding.MGF1(algorithm=mgf_md),
            salt_length=salt_len
        )
        hash_algo = getattr(hashes, hash_algo.upper())()
        pub_key.verify(signature, signed_data, pss_padding, hash_algo)
    elif sig_algo == 'dsa':
        assert isinstance(pub_key, dsa.DSAPublicKey)
        hash_algo = getattr(hashes, hash_algo.upper())()
        pub_key.verify(signature, signed_data, hash_algo)
    elif sig_algo == 'ecdsa':
        assert isinstance(pub_key, ec.EllipticCurvePublicKey)
        hash_algo = getattr(hashes, hash_algo.upper())()
        pub_key.verify(signature, signed_data, ec.ECDSA(hash_algo))
    elif sig_algo == 'ed25519':
        assert isinstance(pub_key, ed25519.Ed25519PublicKey)
        pub_key.verify(signature, signed_data)
    elif sig_algo == 'ed448':
        assert isinstance(pub_key, ed448.Ed448PublicKey)
        pub_key.verify(signature, signed_data)
    else:  # pragma: nocover
        raise NotImplementedError(
            f"Signature mechanism {sig_algo} is not supported."
        )
