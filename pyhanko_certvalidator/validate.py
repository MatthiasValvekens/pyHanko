# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import x509, crl
from oscrypto import asymmetric
import oscrypto.errors

from ._errors import pretty_message
from ._types import str_cls, type_name
from .context import ValidationContext
from .errors import (
    CRLNoMatchesError,
    CRLValidationError,
    CRLValidationIndeterminateError,
    InvalidCertificateError,
    OCSPNoMatchesError,
    OCSPValidationIndeterminateError,
    PathValidationError,
    RevokedError,
    SoftFailError,
)
from .path import ValidationPath


def validate_path(validation_context, path):
    """
    Validates the path using the algorithm from
    https://tools.ietf.org/html/rfc5280#section-6.1, with the exception
    that name constraints are not checked or enforced.

    Critical extensions on the end-entity certificate are not validated
    and are left up to the consuming application to process and/or fail on.

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the path to validate

    :raises:
        pyhanko_certvalidator.errors.PathValidationError - when an error occurs validating the path
        pyhanko_certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked

    :return:
        The final certificate in the path - an instance of
        asn1crypto.x509.Certificate
    """

    return _validate_path(validation_context, path)


def validate_tls_hostname(validation_context, cert, hostname):
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

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            pyhanko_certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

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


def validate_usage(validation_context, cert, key_usage, extended_key_usage, extended_optional):
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

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            pyhanko_certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    if validation_context.is_whitelisted(cert):
        return

    if key_usage is None:
        key_usage = set()

    if extended_key_usage is None:
        extended_key_usage = set()

    if not isinstance(key_usage, set):
        raise TypeError(pretty_message(
            '''
            key_usage must be a set of unicode strings, not %s
            ''',
            type_name(key_usage)
        ))

    if not isinstance(extended_key_usage, set):
        raise TypeError(pretty_message(
            '''
            extended_key_usage must be a set of unicode strings, not %s
            ''',
            type_name(extended_key_usage)
        ))

    if not isinstance(extended_optional, bool):
        raise TypeError(pretty_message(
            '''
            extended_optional must be a boolean, not %s
            ''',
            type_name(extended_optional)
        ))

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


def _validate_path(validation_context, path, end_entity_name_override=None):
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

    :return:
        The final certificate in the path - an instance of
        asn1crypto.x509.Certificate
    """

    if not isinstance(path, ValidationPath):
        raise TypeError(pretty_message(
            '''
            path must be an instance of pyhanko_certvalidator.path.ValidationPath,
            not %s
            ''',
            type_name(path)
        ))

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            pyhanko_certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    moment = validation_context.moment

    if end_entity_name_override is not None and not isinstance(end_entity_name_override, str_cls):
        raise TypeError(pretty_message(
            '''
            end_entity_name_override must be a unicode string, not %s
            ''',
            type_name(end_entity_name_override)
        ))

    # Inputs

    trust_anchor = path.first

    # We skip the trust anchor when measuring the path since technically
    # the trust anchor is not part of the path
    path_length = len(path) - 1

    # We don't accept any certificate policy or name constraint values as input
    # and instead just start allowing everything during initialization

    # Step 1: initialization

    # Step 1 a
    valid_policy_tree = PolicyTreeRoot('any_policy', set(), set(['any_policy']))

    # Steps 1 b-c skipped since they relate to name constraints

    # Steps 1 d-f
    # We do not use initial-explicit-policy, initial-any-policy-inhibit or
    # initial-policy-mapping-inhibit, so they are all set to the path length + 1
    explicit_policy = path_length + 1
    inhibit_any_policy = path_length + 1
    policy_mapping = path_length + 1

    # Steps 1 g-i
    working_public_key = trust_anchor.public_key
    # Step 1 j
    working_issuer_name = trust_anchor.subject
    # Step 1 k
    max_path_length = path_length
    if trust_anchor.max_path_length is not None:
        max_path_length = trust_anchor.max_path_length

    # Step 2: basic processing
    index = 1
    last_index = len(path) - 1

    completed_path = ValidationPath(trust_anchor)
    validation_context.record_validation(trust_anchor, completed_path)

    cert = trust_anchor
    while index <= last_index:
        cert = path[index]

        # Step 2 a 1
        signature_algo = cert['signature_algorithm'].signature_algo
        hash_algo = cert['signature_algorithm'].hash_algo

        if hash_algo in validation_context.weak_hash_algos:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the signature of %s
                uses the weak hash algorithm %s
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True),
                hash_algo
            ))

        if signature_algo == 'rsassa_pkcs1v15':
            verify_func = asymmetric.rsa_pkcs1v15_verify
        elif signature_algo == 'dsa':
            verify_func = asymmetric.dsa_verify
        elif signature_algo == 'ecdsa':
            verify_func = asymmetric.ecdsa_verify
        else:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the signature of %s
                uses the unsupported algorithm %s
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True),
                signature_algo
            ))

        try:
            key_object = asymmetric.load_public_key(working_public_key)
            verify_func(key_object, cert['signature_value'].native, cert['tbs_certificate'].dump(), hash_algo)

        except (oscrypto.errors.SignatureError):
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the signature of %s
                could not be verified
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True)
            ))

        # Step 2 a 2
        if not validation_context.is_whitelisted(cert):
            validity = cert['tbs_certificate']['validity']
            tolerance = validation_context.time_tolerance
            if moment < validity['not_before'].native - tolerance:
                raise PathValidationError(pretty_message(
                    '''
                    The path could not be validated because %s is not valid
                    until %s
                    ''',
                    _cert_type(index, last_index, end_entity_name_override, definite=True),
                    validity['not_before'].native.strftime('%Y-%m-%d %H:%M:%SZ')
                ))
            if moment > validity['not_after'].native + tolerance:
                raise PathValidationError(pretty_message(
                    '''
                    The path could not be validated because %s expired %s
                    ''',
                    _cert_type(index, last_index, end_entity_name_override, definite=True),
                    validity['not_after'].native.strftime('%Y-%m-%d %H:%M:%SZ')
                ))

        # Step 2 a 3 - CRL/OCSP
        if not validation_context._skip_revocation_checks:
            status_good = False
            revocation_check_failed = False
            matched = False
            soft_fail = False
            failures = []
            expect_revinfo = bool(
                cert.ocsp_urls or cert.crl_distribution_points
            )

            if cert.ocsp_urls or validation_context.revocation_mode == 'require':
                try:
                    verify_ocsp_response(
                        cert,
                        path,
                        validation_context,
                        cert_description=_cert_type(
                            index,
                            last_index,
                            end_entity_name_override,
                            definite=True
                        ),
                        end_entity_name_override=end_entity_name_override
                    )
                    status_good = True
                    matched = True
                except (OCSPValidationIndeterminateError) as e:
                    failures.extend([failure[0] for failure in e.failures])
                    revocation_check_failed = True
                    matched = True
                except (SoftFailError):
                    soft_fail = True
                except (OCSPNoMatchesError):
                    pass

            if not status_good and (cert.crl_distribution_points or validation_context.revocation_mode == 'require'):
                try:
                    cert_description = _cert_type(index, last_index, end_entity_name_override, definite=True)
                    verify_crl(
                        cert,
                        path,
                        validation_context,
                        cert_description=cert_description,
                        end_entity_name_override=end_entity_name_override
                    )
                    revocation_check_failed = False
                    status_good = True
                    matched = True
                except (CRLValidationIndeterminateError) as e:
                    failures.extend([failure[0] for failure in e.failures])
                    revocation_check_failed = True
                    matched = True
                except (SoftFailError):
                    soft_fail = True
                except (CRLNoMatchesError):
                    pass

            # The certificate has CRL/OCSP entries but we couldn't query any of
            # them. This should fail the validation if hard-fail is turned on.
            expected_revinfo_not_found = not matched and (
                # with 'require' the fact that there's no match (irrespective
                # of certificate properties) is enough to cause a failure.
                validation_context.revocation_mode == 'require'
                or (
                    expect_revinfo
                    and validation_context.revocation_mode == 'hard-fail'
                )
            )
            if not soft_fail:
                if not status_good and matched and revocation_check_failed:
                    raise PathValidationError(pretty_message(
                        '''
                        The path could not be validated because the %s revocation
                        checks failed: %s
                        ''',
                        _cert_type(index, last_index, end_entity_name_override),
                        '; '.join(failures)
                    ))
                if expected_revinfo_not_found:
                    raise PathValidationError(pretty_message(
                        '''
                        The path could not be validated because no revocation
                        information could be found for %s
                        ''',
                        _cert_type(index, last_index, end_entity_name_override, definite=True)
                    ))

        # Step 2 a 4
        if cert.issuer != working_issuer_name:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because the %s issuer name
                could not be matched
                ''',
                _cert_type(index, last_index, end_entity_name_override),
            ))

        # Steps 2 b-c skipped since they relate to name constraints

        # Steps 2 d
        if cert.certificate_policies_value and valid_policy_tree is not None:

            cert_any_policy = None
            cert_policy_identifiers = set()

            # Step 2 d 1
            for policy in cert.certificate_policies_value:
                policy_identifier = policy['policy_identifier'].native

                if policy_identifier == 'any_policy':
                    cert_any_policy = policy
                    continue

                cert_policy_identifiers.add(policy_identifier)

                policy_qualifiers = policy['policy_qualifiers']

                policy_id_match = False
                parent_any_policy = None

                # Step 2 d 1 i
                for node in valid_policy_tree.at_depth(index - 1):
                    if node.valid_policy == 'any_policy':
                        parent_any_policy = node
                    if policy_identifier not in node.expected_policy_set:
                        continue
                    policy_id_match = True
                    node.add_child(
                        policy_identifier,
                        policy_qualifiers,
                        set([policy_identifier])
                    )

                # Step 2 d 1 ii
                if not policy_id_match and parent_any_policy:
                    parent_any_policy.add_child(
                        policy_identifier,
                        policy_qualifiers,
                        set([policy_identifier])
                    )

            # Step 2 d 2
            if cert_any_policy and (inhibit_any_policy > 0 or (index < path_length and cert.self_issued)):
                for node in valid_policy_tree.at_depth(index - 1):
                    for expected_policy_identifier in node.expected_policy_set:
                        if expected_policy_identifier not in cert_policy_identifiers:
                            node.add_child(
                                expected_policy_identifier,
                                cert_any_policy['policy_qualifiers'],
                                set([expected_policy_identifier])
                            )

            # Step 2 d 3
            for node in valid_policy_tree.walk_up(index - 1):
                if not node.children:
                    node.parent.remove_child(node)
            if len(valid_policy_tree.children) == 0:
                valid_policy_tree = None

        # Step 2 e
        if cert.certificate_policies_value is None:
            valid_policy_tree = None

        # Step 2 f
        if valid_policy_tree is None and explicit_policy <= 0:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because there is no valid set
                of policies for %s
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True),
            ))

        if index != last_index:
            # Step 3: prepare for certificate index+1

            if cert.policy_mappings_value:
                policy_map = {}
                for mapping in cert.policy_mappings_value:
                    issuer_domain_policy = mapping['issuer_domain_policy'].native
                    subject_domain_policy = mapping['subject_domain_policy'].native

                    if issuer_domain_policy not in policy_map:
                        policy_map[issuer_domain_policy] = set()
                    policy_map[issuer_domain_policy].add(subject_domain_policy)

                    # Step 3 a
                    if issuer_domain_policy == 'any_policy' or subject_domain_policy == 'any_policy':
                        raise PathValidationError(pretty_message(
                            '''
                            The path could not be validated because %s contains
                            a policy mapping for the "any policy"
                            ''',
                            _cert_type(index, last_index, end_entity_name_override, definite=True)
                        ))

                # Step 3 b
                if valid_policy_tree is not None:
                    for mapping in cert.policy_mappings_value:
                        issuer_domain_policy = mapping['issuer_domain_policy'].native

                        # Step 3 b 1
                        if policy_mapping > 0:
                            issuer_domain_policy_match = False
                            cert_any_policy = None

                            for node in valid_policy_tree.at_depth(index):
                                if node.valid_policy == 'any_policy':
                                    cert_any_policy = node
                                if node.valid_policy == issuer_domain_policy:
                                    issuer_domain_policy_match = True
                                    node.expected_policy_set = policy_map[issuer_domain_policy]

                            if not issuer_domain_policy_match and cert_any_policy:
                                cert_any_policy.parent.add_child(
                                    issuer_domain_policy,
                                    cert_any_policy.qualifier_set,
                                    policy_map[issuer_domain_policy]
                                )

                        # Step 3 b 2
                        elif policy_mapping == 0:
                            for node in valid_policy_tree.at_depth(index):
                                if node.valid_policy == issuer_domain_policy:
                                    node.parent.remove_child(node)
                            for node in valid_policy_tree.walk_up(index - 1):
                                if not node.children:
                                    node.parent.remove_child(node)
                            if len(valid_policy_tree.children) == 0:
                                valid_policy_tree = None

            # Step 3 c
            working_issuer_name = cert.subject

            # Steps 3 d-f

            # Handle inheritance of DSA parameters from a signing CA to the
            # next in the chain
            copy_params = None
            if cert.public_key.algorithm == 'dsa' and cert.public_key.hash_algo is None:
                if working_public_key.algorithm == 'dsa':
                    copy_params = working_public_key['algorithm']['parameters'].copy()

            working_public_key = cert.public_key

            if copy_params:
                working_public_key['algorithm']['parameters'] = copy_params

            # Step 3 g skipped since it relates to name constraints

            # Step 3 h
            if not cert.self_issued:
                # Step 3 h 1
                if explicit_policy != 0:
                    explicit_policy -= 1
                # Step 3 h 2
                if policy_mapping != 0:
                    policy_mapping -= 1
                # Step 3 h 3
                if inhibit_any_policy != 0:
                    inhibit_any_policy -= 1

            # Step 3 i
            if cert.policy_constraints_value:
                # Step 3 i 1
                require_explicit_policy = cert.policy_constraints_value['require_explicit_policy'].native
                if require_explicit_policy is not None and require_explicit_policy < explicit_policy:
                    explicit_policy = require_explicit_policy
                # Step 3 i 2
                inhibit_policy_mapping = cert.policy_constraints_value['inhibit_policy_mapping'].native
                if inhibit_policy_mapping is not None and inhibit_policy_mapping < policy_mapping:
                    policy_mapping = inhibit_policy_mapping

            # Step 3 j
            if cert.inhibit_any_policy_value:
                inhibit_any_policy = min(cert.inhibit_any_policy_value.native, inhibit_any_policy)

            # Step 3 k
            if not cert.ca:
                raise PathValidationError(pretty_message(
                    '''
                    The path could not be validated because %s is not a CA
                    ''',
                    _cert_type(index, last_index, end_entity_name_override, definite=True)
                ))

            # Step 3 l
            if not cert.self_issued:
                if max_path_length == 0:
                    raise PathValidationError(pretty_message(
                        '''
                        The path could not be validated because it exceeds the
                        maximum path length
                        '''
                    ))
                max_path_length -= 1

            # Step 3 m
            if cert.max_path_length is not None and cert.max_path_length < max_path_length:
                max_path_length = cert.max_path_length

            # Step 3 n
            if cert.key_usage_value and 'key_cert_sign' not in cert.key_usage_value.native:
                raise PathValidationError(pretty_message(
                    '''
                    The path could not be validated because %s is not allowed
                    to sign certificates
                    ''',
                    _cert_type(index, last_index, end_entity_name_override, definite=True)
                ))

        # Step 3 o
        # Check for critical unsupported extensions
        supported_extensions = set([
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
        ])
        unsupported_critical_extensions = cert.critical_extensions - supported_extensions
        if unsupported_critical_extensions:
            raise PathValidationError(pretty_message(
                '''
                The path could not be validated because %s contains the
                following unsupported critical extension%s: %s
                ''',
                _cert_type(index, last_index, end_entity_name_override, definite=True),
                's' if len(unsupported_critical_extensions) != 1 else '',
                ', '.join(sorted(unsupported_critical_extensions)),
            ))

        if validation_context:
            completed_path = completed_path.copy().append(cert)
            validation_context.record_validation(cert, completed_path)

        index += 1

    # Step 4: wrap-up procedure

    # Step 4 a
    if explicit_policy != 0:
        explicit_policy -= 1

    # Step 4 b
    if cert.policy_constraints_value:
        if cert.policy_constraints_value['require_explicit_policy'].native == 0:
            explicit_policy = 0

    # Steps 4 c-e skipped since this method doesn't output it
    # Step 4 f skipped since this method defers that to the calling application

    # Step 4 g

    # Step 4 g i
    if valid_policy_tree is None:
        intersection = None

    # Step 4 g ii
    else:
        intersection = valid_policy_tree

    # Step 4 g iii is skipped since the initial policy set is always any_policy

    if explicit_policy == 0 and intersection is None:
        raise PathValidationError(pretty_message(
            '''
            The path could not be validated because there is no valid set of
            policies for %s
            ''',
            _cert_type(last_index, last_index, end_entity_name_override, definite=True)
        ))

    return cert


def _cert_type(index, last_index, end_entity_name_override, definite=False):
    """
    :param index:
        An integer of the index of the certificate in the path

    :param last_index:
        An integer of the last index in the path

    :param end_entity_name_override:
        None or a unicode string of the name to use for the final certificate
        in the path. Used for indirect CRL issuer and OCSP responder
        certificates.

    :param definite:
        When returning the string "end-entity certificate", passing this flag
        as True will prepend "the " to the result

    :return:
        A unicode string describing the position of a certificate in the chain
    """

    if index != last_index:
        return 'intermediate certificate %s' % index

    prefix = 'the ' if definite else ''

    if end_entity_name_override is not None:
        return prefix + end_entity_name_override

    return prefix + 'end-entity certificate'


def _self_signed(cert):
    """
    Determines if a certificate is self-signed

    :param cert:
        An asn1crypto.x509.Certificate object to check

    :return:
        A boolean - True if the certificate is self-signed, False otherwise
    """

    self_signed = cert.self_signed

    if self_signed == 'yes':
        return True
    if self_signed == 'no':
        return False

    # In the case of "maybe", we have to check the signature
    signature_algo = cert['signature_algorithm'].signature_algo
    hash_algo = cert['signature_algorithm'].hash_algo

    if signature_algo == 'rsassa_pkcs1v15':
        verify_func = asymmetric.rsa_pkcs1v15_verify
    elif signature_algo == 'dsa':
        verify_func = asymmetric.dsa_verify
    elif signature_algo == 'ecdsa':
        verify_func = asymmetric.ecdsa_verify
    else:
        raise PathValidationError(pretty_message(
            '''
            Unable to verify the signature of the certificate since it uses
            the unsupported algorithm %s
            ''',
            signature_algo
        ))

    try:
        key_object = asymmetric.load_certificate(cert)
        verify_func(key_object, cert['signature_value'].native, cert['tbs_certificate'].dump(), hash_algo)
        return True

    except (oscrypto.errors.SignatureError):
        return False


def verify_ocsp_response(cert, path, validation_context, cert_description=None, end_entity_name_override=None):
    """
    Verifies an OCSP response, checking to make sure the certificate has not
    been revoked. Fulfills the requirements of
    https://tools.ietf.org/html/rfc6960#section-3.2.

    :param cert:
        An asn1cyrpto.x509.Certificate object to verify the OCSP reponse for

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object for the cert

    :param validation_context:
        A pyhanko_certvalidator.context.ValidationContext object to use for caching
        validation information

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

    if not isinstance(cert, x509.Certificate):
        raise TypeError(pretty_message(
            '''
            cert must be an instance of asn1crypto.x509.Certificate, not %s
            ''',
            type_name(cert)
        ))

    if not isinstance(path, ValidationPath):
        raise TypeError(pretty_message(
            '''
            path must be an instance of pyhanko_certvalidator.path.ValidationPath,
            not %s
            ''',
            type_name(path)
        ))

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            pyhanko_certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    if cert_description is None:
        cert_description = 'the certificate'

    if not isinstance(cert_description, str_cls):
        raise TypeError(pretty_message(
            '''
            cert_description must be a unicode string, not %s
            ''',
            type_name(cert_description)
        ))

    moment = validation_context.moment

    issuer = path.find_issuer(cert)
    certificate_registry = validation_context.certificate_registry

    failures = []
    mismatch_failures = 0

    ocsp_responses = validation_context.retrieve_ocsps(cert, issuer)

    for ocsp_response in ocsp_responses:

        # Make sure that we get a valid response back from the OCSP responder
        status = ocsp_response['response_status'].native
        if status != 'successful':
            mismatch_failures += 1
            continue

        response_bytes = ocsp_response['response_bytes']
        if response_bytes['response_type'].native != 'basic_ocsp_response':
            mismatch_failures += 1
            continue

        response = response_bytes['response'].parsed
        tbs_response = response['tbs_response_data']

        # With a valid response, now a check is performed to see if the response is
        # applicable for the cert and moment requested
        cert_response = tbs_response['responses'][0]

        response_cert_id = cert_response['cert_id']

        issuer_hash_algo = response_cert_id['hash_algorithm']['algorithm'].native
        cert_issuer_name_hash = getattr(cert.issuer, issuer_hash_algo)
        cert_issuer_key_hash = getattr(issuer.public_key, issuer_hash_algo)

        key_hash_mismatch = response_cert_id['issuer_key_hash'].native != cert_issuer_key_hash

        name_mismatch = response_cert_id['issuer_name_hash'].native != cert_issuer_name_hash
        serial_mismatch = response_cert_id['serial_number'].native != cert.serial_number

        if (name_mismatch or serial_mismatch) and key_hash_mismatch:
            mismatch_failures += 1
            continue

        if name_mismatch:
            failures.append((
                'OCSP response issuer name hash does not match',
                ocsp_response
            ))
            continue

        if serial_mismatch:
            failures.append((
                'OCSP response certificate serial number does not match',
                ocsp_response
            ))
            continue

        if key_hash_mismatch:
            failures.append((
                'OCSP response issuer key hash does not match',
                ocsp_response
            ))
            continue

        retroactive = validation_context.retroactive_revinfo
        tolerance = validation_context.time_tolerance

        if not retroactive and moment < cert_response['this_update'].native - tolerance:
            failures.append((
                'OCSP response is from after the validation time',
                ocsp_response
            ))
            continue

        if moment > cert_response['next_update'].native + tolerance:
            failures.append((
                'OCSP response is from before the validation time',
                ocsp_response
            ))
            continue

        # To verify the response as legitimate, the responder cert must be located
        if tbs_response['responder_id'].name == 'by_key':
            key_identifier = tbs_response['responder_id'].native
            signing_cert = certificate_registry.retrieve_by_key_identifier(key_identifier)
        else:
            candidate_signing_certs = certificate_registry.retrieve_by_name(
                tbs_response['responder_id'].chosen,
                None
            )
            signing_cert = candidate_signing_certs[0] if candidate_signing_certs else None
        if not signing_cert:
            failures.append((
                pretty_message(
                    '''
                    Unable to verify OCSP response since response signing
                    certificate could not be located
                    '''
                ),
                ocsp_response
            ))
            continue

        # The responder cert has to have a valid path back to one of the trust roots
        if not certificate_registry.is_ca(signing_cert):
            signing_cert_paths = certificate_registry.build_paths(signing_cert)
            for signing_cert_path in signing_cert_paths:
                try:
                    # Store the original revocation check value
                    changed_revocation_flags = False
                    skip_ocsp = signing_cert.ocsp_no_check_value is not None
                    skip_ocsp = skip_ocsp or signing_cert_path == path
                    if skip_ocsp and validation_context._skip_revocation_checks is False:
                        changed_revocation_flags = True

                        original_revocation_mode = validation_context.revocation_mode
                        new_revocation_mode = "soft-fail" if original_revocation_mode == "soft-fail" else "hard-fail"

                        validation_context._skip_revocation_checks = True
                        validation_context._revocation_mode = new_revocation_mode

                    if end_entity_name_override is None and signing_cert.sha256 != issuer.sha256:
                        end_entity_name_override = cert_description + ' OCSP responder'
                    _validate_path(
                        validation_context,
                        signing_cert_path,
                        end_entity_name_override=end_entity_name_override
                    )
                    signing_cert_issuer = signing_cert_path.find_issuer(signing_cert)
                    break

                except (PathValidationError):
                    continue

                finally:
                    if changed_revocation_flags:
                        validation_context._skip_revocation_checks = False
                        validation_context._revocation_mode = original_revocation_mode

            else:
                failures.append((
                    pretty_message(
                        '''
                        Unable to verify OCSP response since response signing
                        certificate could not be validated
                        '''
                    ),
                    ocsp_response
                ))
                continue

        # If the cert signing the OCSP response is not the issuer, it must be issued
        # by the cert issuer and be valid for OCSP responses
        if issuer.issuer_serial != signing_cert.issuer_serial:
            if signing_cert_issuer.issuer_serial != issuer.issuer_serial:
                failures.append((
                    pretty_message(
                        '''
                        Unable to verify OCSP response since response was
                        signed by an unauthorized certificate
                        '''
                    ),
                    ocsp_response
                ))
                continue
            extended_key_usage = signing_cert.extended_key_usage_value
            if 'ocsp_signing' not in extended_key_usage.native:
                failures.append((
                    pretty_message(
                        '''
                        Unable to verify OCSP response since response was
                        signed by an unauthorized certificate
                        '''
                    ),
                    ocsp_response
                ))
                continue

        # Determine what algorithm was used to sign the response
        signature_algo = response['signature_algorithm'].signature_algo
        hash_algo = response['signature_algorithm'].hash_algo

        if signature_algo == 'rsassa_pkcs1v15':
            verify_func = asymmetric.rsa_pkcs1v15_verify
        elif signature_algo == 'dsa':
            verify_func = asymmetric.dsa_verify
        elif signature_algo == 'ecdsa':
            verify_func = asymmetric.ecdsa_verify
        else:
            failures.append((
                pretty_message(
                    '''
                    Unable to verify OCSP response since response signature
                    uses the unsupported algorithm %s
                    ''',
                    signature_algo
                ),
                ocsp_response
            ))
            continue

        # Verify that the response was properly signed by the validated certificate
        try:
            key_object = asymmetric.load_certificate(signing_cert)
            verify_func(key_object, response['signature'].native, tbs_response.dump(), hash_algo)
        except (oscrypto.errors.SignatureError):
            failures.append((
                'Unable to verify OCSP response signature',
                ocsp_response
            ))
            continue

        # Finally check to see if the certificate has been revoked
        status = cert_response['cert_status'].name
        if status == 'good':
            return

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

    if mismatch_failures == len(ocsp_responses):
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
        failures
    )


def verify_crl(cert, path, validation_context, use_deltas=True, cert_description=None, end_entity_name_override=None):
    """
    Verifies a certificate against a list of CRLs, checking to make sure the
    certificate has not been revoked. Uses the algorithm from
    https://tools.ietf.org/html/rfc5280#section-6.3 as a basis, but the
    implementation differs to allow CRLs from unrecorded locations.

    :param cert:
        An asn1cyrpto.x509.Certificate object to check for in the CRLs

    :param path:
        A pyhanko_certvalidator.path.ValidationPath object of the cert's validation path

    :param certificate_lists:
        A list of asn1crypto.crl.CertificateList objects

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

    if not isinstance(cert, x509.Certificate):
        raise TypeError(pretty_message(
            '''
            cert must be an instance of asn1crypto.x509.Certificate, not %s
            ''',
            type_name(cert)
        ))

    if not isinstance(path, ValidationPath):
        raise TypeError(pretty_message(
            '''
            path must be an instance of pyhanko_certvalidator.path.ValidationPath,
            not %s
            ''',
            type_name(path)
        ))

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            pyhanko_certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    if cert_description is None:
        cert_description = 'the certificate'

    if not isinstance(cert_description, str_cls):
        raise TypeError(pretty_message(
            '''
            cert_description must be a unicode string, not %s
            ''',
            type_name(cert_description)
        ))

    moment = validation_context.moment
    certificate_registry = validation_context.certificate_registry

    certificate_lists = validation_context.retrieve_crls(cert)

    cert_issuer = path.find_issuer(cert)

    complete_lists_by_issuer = {}
    delta_lists_by_issuer = {}
    for certificate_list in certificate_lists:
        issuer_hashable = certificate_list.issuer.hashable
        if certificate_list.delta_crl_indicator_value is None:
            if issuer_hashable not in complete_lists_by_issuer:
                complete_lists_by_issuer[issuer_hashable] = []
            complete_lists_by_issuer[issuer_hashable].append(certificate_list)
        else:
            if issuer_hashable not in delta_lists_by_issuer:
                delta_lists_by_issuer[issuer_hashable] = []
            delta_lists_by_issuer[issuer_hashable].append(certificate_list)

    # In the main loop, only complete CRLs are processed, so delta CRLs are
    # weeded out of the todo list
    crls_to_process = []
    for issuer_crls in complete_lists_by_issuer.values():
        crls_to_process.extend(issuer_crls)
    total_crls = len(crls_to_process)

    # Build a lookup table for the Distribution point objects associated with
    # an issuer name hashable
    distribution_point_map = {}
    sources = [cert.crl_distribution_points]
    if use_deltas:
        sources.extend(cert.delta_crl_distribution_points)
    for dp_list in sources:
        for distribution_point in dp_list:
            if isinstance(distribution_point['crl_issuer'], x509.GeneralNames):
                dp_name_hashes = []
                for general_name in distribution_point['crl_issuer']:
                    if general_name.name == 'directory_name':
                        dp_name_hashes.append(general_name.chosen.hashable)
            else:
                dp_name_hashes = [cert.issuer.hashable]
            for dp_name_hash in dp_name_hashes:
                if dp_name_hash not in distribution_point_map:
                    distribution_point_map[dp_name_hash] = []
                distribution_point_map[dp_name_hash].append(distribution_point)

    valid_reasons = set([
        'key_compromise',
        'ca_compromise',
        'affiliation_changed',
        'superseded',
        'cessation_of_operation',
        'certificate_hold',
        'privilege_withdrawn',
        'aa_compromise',
    ])

    known_extensions = set([
        'issuer_alt_name',
        'crl_number',
        'delta_crl_indicator',
        'issuing_distribution_point',
        'authority_key_identifier',
        'freshest_crl',
        'authority_information_access',
    ])

    checked_reasons = set()

    failures = []
    issuer_failures = 0

    while len(crls_to_process) > 0:
        certificate_list = crls_to_process.pop(0)
        crl_idp = certificate_list.issuing_distribution_point_value
        delta_certificate_list = None
        delta_crl_idp = None

        interim_reasons = set()

        crl_issuer = None
        crl_issuer_name = None
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
                failures.append((
                    'CRL is marked as an indirect CRL, but provides no '
                    'mechanism for locating the CRL issuer certificate',
                    certificate_list
                ))
                continue
        else:
            crl_issuer_name = certificate_list.issuer

        if not crl_issuer:
            crl_issuer = validation_context.check_crl_issuer(certificate_list)

        if not crl_issuer:
            candidate_crl_issuers = certificate_registry.retrieve_by_name(crl_issuer_name, cert_issuer)
            candidates_skipped = 0
            signatures_failed = 0
            unauthorized_certs = 0

            if not candidate_crl_issuers and crl_issuer_name != certificate_list.issuer:
                candidate_crl_issuers = certificate_registry.retrieve_by_name(certificate_list.issuer, cert_issuer)

            for candidate_crl_issuer in candidate_crl_issuers:
                direct_issuer = candidate_crl_issuer.subject == cert_issuer.subject

                # In some cases an indirect CRL issuer is a certificate issued
                # by the certificate issuer. However, we need to ensure that
                # the candidate CRL issuer is not the certificate being checked,
                # otherwise we may be checking an incorrect CRL and produce
                # incorrect results.
                indirect_issuer = candidate_crl_issuer.issuer == cert_issuer.subject
                indirect_issuer = indirect_issuer and candidate_crl_issuer.sha256 != cert.sha256

                if not direct_issuer and not indirect_issuer and not is_indirect:
                    candidates_skipped += 1
                    continue

                # Step f
                candidate_crl_issuer_path = None

                if validation_context:
                    candidate_crl_issuer_path = validation_context.check_validation(candidate_crl_issuer)

                if candidate_crl_issuer_path is None:
                    candidate_crl_issuer_path = path.copy().truncate_to_issuer(candidate_crl_issuer)
                    candidate_crl_issuer_path.append(candidate_crl_issuer)
                    try:
                        # Pre-emptively mark a path as validated to prevent recursion
                        if validation_context:
                            validation_context.record_validation(candidate_crl_issuer, candidate_crl_issuer_path)

                        temp_override = end_entity_name_override
                        if temp_override is None and candidate_crl_issuer.sha256 != cert_issuer.sha256:
                            temp_override = cert_description + ' CRL issuer'
                        _validate_path(
                            validation_context,
                            candidate_crl_issuer_path,
                            end_entity_name_override=temp_override
                        )

                    except (PathValidationError) as e:
                        # If the validation did not work out, clear it
                        if validation_context:
                            validation_context.clear_validation(candidate_crl_issuer)

                        # We let a revoked error fall through since step k will catch
                        # it with a correct error message
                        if isinstance(e, RevokedError):
                            raise
                        raise CRLValidationError('CRL issuer certificate path could not be validated')

                key_usage_value = candidate_crl_issuer.key_usage_value
                if key_usage_value and 'crl_sign' not in key_usage_value.native:
                    unauthorized_certs += 1
                    continue

                try:
                    # Step g
                    _verify_signature(certificate_list, candidate_crl_issuer)

                    crl_issuer = candidate_crl_issuer
                    break

                except (CRLValidationError):
                    signatures_failed += 1
                    continue

            if crl_issuer is None:
                if candidates_skipped == len(candidate_crl_issuers):
                    issuer_failures += 1
                else:
                    if signatures_failed == len(candidate_crl_issuers):
                        failures.append((
                            'CRL signature could not be verified',
                            certificate_list
                        ))
                    elif unauthorized_certs == len(candidate_crl_issuers):
                        failures.append((
                            'The CRL issuer is not authorized to sign CRLs',
                            certificate_list
                        ))
                    else:
                        failures.append((
                            'Unable to locate CRL issuer certificate',
                            certificate_list
                        ))
                continue
            else:
                validation_context.record_crl_issuer(certificate_list, crl_issuer)

        # Step b 1
        has_dp_crl_issuer = False
        dp_match = False

        dps = cert.crl_distribution_points_value
        if dps:
            crl_issuer_general_name = x509.GeneralName(
                name='directory_name',
                value=crl_issuer.subject
            )
            for dp in dps:
                if dp['crl_issuer']:
                    has_dp_crl_issuer = True
                    if crl_issuer_general_name in dp['crl_issuer']:
                        dp_match = True

        same_issuer = crl_issuer.subject == cert_issuer.subject
        indirect_match = has_dp_crl_issuer and dp_match and is_indirect
        missing_idp = has_dp_crl_issuer and (not dp_match or not is_indirect)
        indirect_crl_issuer = crl_issuer.issuer == cert_issuer.subject

        if (not same_issuer and not indirect_match and not indirect_crl_issuer) or missing_idp:
            issuer_failures += 1
            continue

        # Check to make sure the CRL is valid for the moment specified
        tolerance = validation_context.time_tolerance
        retroactive = validation_context.retroactive_revinfo
        crl_this_update = certificate_list['tbs_cert_list']['this_update'].native
        if not retroactive and moment < crl_this_update - tolerance:
            failures.append((
                'CRL is from after the validation time',
                certificate_list
            ))
            continue
        crl_next_update = certificate_list['tbs_cert_list']['next_update'].native
        if moment > crl_next_update + tolerance:
            failures.append((
                'CRL should have been regenerated by the validation time',
                certificate_list
            ))
            continue

        # Step b 2

        if crl_idp is not None:
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
                    inner_extended_issuer_name.chosen.append(idp_dp_name.chosen.untag())
                    idp_general_names.append(x509.GeneralName(
                        name='directory_name',
                        value=inner_extended_issuer_name
                    ))

            dps = cert.crl_distribution_points_value
            if dps:
                for dp in dps:
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
                            inner_extended_issuer_name.chosen.append(dp_name.chosen.untag())
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

            idp_dp_match_failed = has_idp_name and has_dp_name and not idp_dp_match

            if idp_dp_match_failed:
                failures.append((
                    pretty_message(
                        '''
                        The CRL issuing distribution point extension does not
                        share any names with the certificate CRL distribution
                        point extension
                        '''
                    ),
                    certificate_list
                ))
                issuer_failures += 1
                continue

            # Step b 2 ii
            if crl_idp['only_contains_user_certs'].native:
                if cert.basic_constraints_value and cert.basic_constraints_value['ca'].native:
                    failures.append((
                        pretty_message(
                            '''
                            CRL only contains end-entity certificates and
                            certificate is a CA certificate
                            '''
                        ),
                        certificate_list
                    ))
                    continue

            # Step b 2 iii
            if crl_idp['only_contains_ca_certs'].native:
                if not cert.basic_constraints_value or cert.basic_constraints_value['ca'].native is False:
                    failures.append((
                        pretty_message(
                            '''
                            CRL only contains CA certificates and certificate
                            is an end-entity certificate
                            '''
                        ),
                        certificate_list
                    ))
                    continue

            # Step b 2 iv
            if crl_idp['only_contains_attribute_certs'].native:
                failures.append((
                    'CRL only contains attribute certificates',
                    certificate_list
                ))
                continue

        # Step c
        if use_deltas and certificate_list.freshest_crl_value and len(certificate_list.freshest_crl_value) > 0:
            for candidate_delta_cl in delta_lists_by_issuer.get(crl_issuer_name.hashable, []):

                # Step c 1
                if candidate_delta_cl.issuer != crl_issuer_name:
                    continue

                # Step c 2
                delta_crl_idp = candidate_delta_cl.issuing_distribution_point_value
                if (crl_idp is None and delta_crl_idp is not None) or (crl_idp is not None and delta_crl_idp is None):
                    continue

                if crl_idp and crl_idp.native != delta_crl_idp.native:
                    continue

                # Step c 3
                if certificate_list.authority_key_identifier != candidate_delta_cl.authority_key_identifier:
                    continue

                delta_certificate_list = candidate_delta_cl
                break

        # Step d
        idp_reasons = None

        if crl_idp and crl_idp['only_some_reasons'].native is not None:
            idp_reasons = crl_idp['only_some_reasons'].native

        reason_keys = None
        if idp_reasons:
            reason_keys = idp_reasons

        if reason_keys is None:
            interim_reasons = valid_reasons.copy()
        else:
            interim_reasons = reason_keys

        # Step e
        # We don't skip a CRL if it only contains reasons already checked since
        # a certificate issuer can self-issue a new cert that is used for CRLs

        if certificate_list.critical_extensions - known_extensions:
            failures.append((
                'One or more unrecognized critical extensions are present in '
                'the CRL',
                certificate_list
            ))
            continue

        if use_deltas and delta_certificate_list and delta_certificate_list.critical_extensions - known_extensions:
            failures.append((
                'One or more unrecognized critical extensions are present in '
                'the delta CRL',
                delta_certificate_list
            ))
            continue

        # Step h
        if use_deltas and delta_certificate_list:
            try:
                _verify_signature(delta_certificate_list, crl_issuer)
            except (CRLValidationError):
                failures.append((
                    'Delta CRL signature could not be verified',
                    certificate_list,
                    delta_certificate_list
                ))
                continue

            retroactive = validation_context.retroactive_revinfo
            crl_this_update = delta_certificate_list['tbs_cert_list']['this_update'].native
            if not retroactive and moment < crl_this_update - tolerance:
                failures.append((
                    'Delta CRL is from after the validation time',
                    certificate_list,
                    delta_certificate_list
                ))
                continue
            crl_next_update = delta_certificate_list['tbs_cert_list']['next_update'].native
            if moment > crl_next_update + tolerance:
                failures.append((
                    'Delta CRL is from before the validation time',
                    certificate_list,
                    delta_certificate_list
                ))
                continue

        # Step i
        revoked_reason = None
        revoked_date = None

        if use_deltas and delta_certificate_list:
            try:
                revoked_date, revoked_reason = _find_cert_in_list(cert, cert_issuer, delta_certificate_list, crl_issuer)
            except (NotImplementedError):
                failures.append((
                    'One or more critical extensions are present in the CRL '
                    'entry for the certificate',
                    delta_certificate_list
                ))
                continue

        # Step j
        if revoked_reason is None:
            try:
                revoked_date, revoked_reason = _find_cert_in_list(cert, cert_issuer, certificate_list, crl_issuer)
            except (NotImplementedError):
                failures.append((
                    'One or more critical extensions are present in the CRL '
                    'entry for the certificate',
                    certificate_list
                ))
                continue

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

        # Step l
        checked_reasons |= interim_reasons

    # CRLs should not include this value, but at least one of the examples
    # from the NIST test suite does
    checked_reasons -= set(['unused'])

    if checked_reasons != valid_reasons:
        if total_crls == issuer_failures:
            raise CRLNoMatchesError(pretty_message(
                '''
                No CRLs were issued by the issuer of %s, or any indirect CRL
                issuer
                ''',
                cert_description
            ))

        if not failures:
            failures.append((
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
            failures
        )


def _verify_signature(certificate_list, crl_issuer):
    """
    Verifies the digital signature on an asn1crypto.crl.CertificateList object

    :param certificate_list:
        An asn1crypto.crl.CertificateList object

    :param crl_issuer:
        An asn1crypto.x509.Certificate object of the CRL issuer

    :raises:
        pyhanko_certvalidator.errors.CRLValidationError - when the signature is invalid or uses an unsupported algorithm
    """

    signature_algo = certificate_list['signature_algorithm'].signature_algo
    hash_algo = certificate_list['signature_algorithm'].hash_algo

    if signature_algo == 'rsassa_pkcs1v15':
        verify_func = asymmetric.rsa_pkcs1v15_verify
    elif signature_algo == 'dsa':
        verify_func = asymmetric.dsa_verify
    elif signature_algo == 'ecdsa':
        verify_func = asymmetric.ecdsa_verify
    else:
        raise CRLValidationError(pretty_message(
            '''
            Unable to verify the CertificateList since the signature uses the
            unsupported algorithm %s
            ''',
            signature_algo
        ))

    try:
        key_object = asymmetric.load_certificate(crl_issuer)
        verify_func(
            key_object,
            certificate_list['signature'].native,
            certificate_list['tbs_cert_list'].dump(),
            hash_algo
        )
    except (oscrypto.errors.SignatureError):
        raise CRLValidationError('Unable to verify the signature of the CertificateList')


def _find_cert_in_list(cert, issuer, certificate_list, crl_issuer):
    """
    Looks for a cert in the list of revoked certificates

    :param cert:
        An asn1crypto.x509.Certificate object of the cert being checked

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

    revoked_certificates = certificate_list['tbs_cert_list']['revoked_certificates']

    cert_serial = cert.serial_number
    issuer_name = issuer.subject

    known_extensions = set([
        'crl_reason',
        'hold_instruction_code',
        'invalidity_date',
        'certificate_issuer'
    ])

    last_issuer_name = crl_issuer.subject
    for revoked_cert in revoked_certificates:
        # If any unknown critical extensions, the entry can not be used
        if revoked_cert.critical_extensions - known_extensions:
            raise NotImplementedError()

        if revoked_cert.issuer_name and revoked_cert.issuer_name != last_issuer_name:
            last_issuer_name = revoked_cert.issuer_name
        if last_issuer_name != issuer_name:
            continue

        if revoked_cert['user_certificate'].native != cert_serial:
            continue

        if not revoked_cert.crl_reason_value:
            crl_reason = crl.CRLReason('unspecified')
        else:
            crl_reason = revoked_cert.crl_reason_value

        return (revoked_cert['revocation_date'], crl_reason)

    return (None, None)


class PolicyTreeRoot():
    """
    A generic policy tree node, used for the root node in the tree
    """

    # None for the root node, an instance of PolicyTreeNode or PolicyTreeRoot
    # for all other nodes
    parent = None

    # A list of PolicyTreeNode objects
    children = None

    def __init__(self, valid_policy, qualifier_set, expected_policy_set):
        """
        Accepts values for a PolicyTreeNode that will be created at depth 0

        :param valid_policy:
            A unicode string of a policy name or OID

        :param qualifier_set:
            An instance of asn1crypto.x509.PolicyQualifierInfos

        :param expected_policy_set:
            A set of unicode strings containing policy names or OIDs
        """

        self.children = []
        self.add_child(valid_policy, qualifier_set, expected_policy_set)

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

        self.valid_policy = valid_policy
        self.qualifier_set = qualifier_set
        self.expected_policy_set = expected_policy_set
        self.children = []
