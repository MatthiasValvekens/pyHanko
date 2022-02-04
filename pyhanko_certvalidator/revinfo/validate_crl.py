import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Union, List, Optional, Dict

from asn1crypto import x509, crl, cms
from cryptography.exceptions import InvalidSignature

from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator._state import ValProcState
from pyhanko_certvalidator._errors import pretty_message
from pyhanko_certvalidator.errors import PathValidationError, RevokedError, \
    CRLValidationError, CRLNoMatchesError, CertificateFetchError, \
    CRLValidationIndeterminateError, PSSParameterMismatch
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.registry import CertificateRegistry
from pyhanko_certvalidator.revinfo.archival import CRLWithPOE, \
    RevinfoUsabilityRating
from pyhanko_certvalidator.revinfo.constants import VALID_REVOCATION_REASONS, \
    KNOWN_CRL_EXTENSIONS, KNOWN_CRL_ENTRY_EXTENSIONS
from pyhanko_certvalidator.util import get_ac_extension_value, \
    get_relevant_crl_dps, extract_ac_issuer_dir_name, validate_sig


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
        proc_state: ValProcState):

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

                temp_override = proc_state.ee_name_override
                if candidate_crl_issuer.sha256 != cert_issuer.sha256:
                    temp_override = proc_state.describe_cert() + ' CRL issuer'
                from pyhanko_certvalidator.validate import intl_validate_path
                await intl_validate_path(
                    validation_context,
                    candidate_crl_issuer_path,
                    proc_state=ValProcState(
                        path_len=len(candidate_crl_issuer_path) - 1,
                        is_side_validation=True,
                        ee_name_override=temp_override
                    )
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
            _verify_crl_signature(certificate_list, candidate_crl_issuer.public_key)

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


@dataclass
class _CRLErrs:
    failures: list = field(default_factory=list)
    issuer_failures: int = 0


def _find_matching_delta_crl(delta_lists: List[CRLWithPOE],
                             crl_issuer_name: x509.Name,
                             crl_idp: crl.IssuingDistributionPoint,
                             parent_crl_aki: Optional[bytes]) -> CRLWithPOE:
    for candidate_delta_cl_with_poe in delta_lists:
        candidate_delta_cl = candidate_delta_cl_with_poe.crl_data
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

        return candidate_delta_cl_with_poe


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
        certificate_list_with_poe: CRLWithPOE,
        path: ValidationPath,
        validation_context: ValidationContext,
        delta_lists_by_issuer: Dict[str, List[CRLWithPOE]],
        use_deltas: bool, errs: _CRLErrs,
        proc_state: ValProcState):

    certificate_registry = validation_context.certificate_registry
    certificate_list = certificate_list_with_poe.crl_data
    crl_idp: crl.IssuingDistributionPoint \
        = certificate_list.issuing_distribution_point_value

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
                certificate_list_with_poe
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
                proc_state=proc_state
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

    freshness_result = certificate_list_with_poe.usable_at(
        validation_context.moment,
        policy=validation_context.revinfo_policy,
        timing_info=validation_context.timing_info
    )
    if freshness_result != RevinfoUsabilityRating.OK:
        if freshness_result == RevinfoUsabilityRating.STALE:
            msg = 'CRL is stale'
        elif freshness_result == RevinfoUsabilityRating.TOO_NEW:
            msg = 'CRL is too recent'
        else:
            msg = 'CRL freshness could not be established'
        errs.failures.append((msg, certificate_list_with_poe))
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
    delta_certificate_list_with_poe = delta_certificate_list = None
    if use_deltas and certificate_list.freshest_crl_value \
            and len(certificate_list.freshest_crl_value) > 0:
        candidate_delta_lists = \
            delta_lists_by_issuer.get(crl_issuer_name.hashable, [])
        delta_certificate_list_with_poe = _find_matching_delta_crl(
            delta_lists=candidate_delta_lists,
            crl_issuer_name=crl_issuer_name, crl_idp=crl_idp,
            parent_crl_aki=certificate_list.authority_key_identifier
        )
        delta_certificate_list = delta_certificate_list_with_poe.crl_data

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
            certificate_list_with_poe
        ))
        return None

    if use_deltas and delta_certificate_list and \
            delta_certificate_list.critical_extensions - KNOWN_CRL_EXTENSIONS:
        errs.failures.append((
            'One or more unrecognized critical extensions are present in '
            'the delta CRL',
            delta_certificate_list_with_poe
        ))
        return None

    # Step h
    if use_deltas and delta_certificate_list:
        try:
            _verify_crl_signature(delta_certificate_list, crl_issuer.public_key)
        except CRLValidationError:
            errs.failures.append((
                'Delta CRL signature could not be verified',
                delta_certificate_list_with_poe
            ))
            return None

        freshness_result = delta_certificate_list_with_poe.usable_at(
            validation_context.moment,
            policy=validation_context.revinfo_policy,
            timing_info=validation_context.timing_info
        )
        if freshness_result != RevinfoUsabilityRating.OK:
            if freshness_result == RevinfoUsabilityRating.STALE:
                msg = 'Delta CRL is stale'
            elif freshness_result == RevinfoUsabilityRating.TOO_NEW:
                msg = 'Delta CRL is too recent'
            else:
                msg = 'Delta CRL freshness could not be established'
            errs.failures.append((msg, delta_certificate_list_with_poe))
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
        raise RevokedError.from_state(pretty_message(
            '''
            CRL indicates %s was revoked at %s on %s, due to %s
            ''',
            proc_state.describe_cert(),
            time,
            date,
            reason
        ), proc_state)

    return interim_reasons


async def verify_crl(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        path: ValidationPath,
        validation_context: ValidationContext, use_deltas=True,
        proc_state: Optional[ValProcState] = None):
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

    :param proc_state:
        Internal state for error reporting and policy application decisions.

    :raises:
        pyhanko_certvalidator.errors.CRLNoMatchesError - when none of the CRLs match the certificate
        pyhanko_certvalidator.errors.CRLValidationError - when any error occurs trying to verify the CertificateList
        pyhanko_certvalidator.errors.RevokedError - when the CRL indicates the certificate has been revoked
    """

    is_pkc = isinstance(cert, x509.Certificate)
    proc_state = proc_state or ValProcState(
        path_len=len(path) - 1, is_side_validation=False,
        ee_name_override="attribute certificate" if not is_pkc else None
    )

    certificate_lists = await validation_context.async_retrieve_crls_with_poe(
        cert
    )

    if is_pkc:
        try:
            cert_issuer = path.find_issuer(cert)
        except LookupError:
            raise CRLNoMatchesError(pretty_message(
                '''
                Could not determine issuer certificate for %s in path.
                ''',
                proc_state.describe_cert()
            ))
    else:
        cert_issuer = path.last

    errs = _CRLErrs()

    complete_lists_by_issuer = defaultdict(list)
    delta_lists_by_issuer = defaultdict(list)
    for certificate_list_with_poe in certificate_lists:
        certificate_list = certificate_list_with_poe.crl_data
        try:
            issuer_hashable = certificate_list.issuer.hashable
            if certificate_list.delta_crl_indicator_value is None:
                complete_lists_by_issuer[issuer_hashable]\
                    .append(certificate_list_with_poe)
            else:
                delta_lists_by_issuer[issuer_hashable].append(
                    certificate_list_with_poe
                )
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
        certificate_list_with_poe = crls_to_process.pop(0)
        try:
            interim_reasons = await _handle_single_crl(
                cert=cert, cert_issuer=cert_issuer,
                certificate_list_with_poe=certificate_list_with_poe,
                path=path, validation_context=validation_context,
                delta_lists_by_issuer=delta_lists_by_issuer,
                use_deltas=use_deltas, errs=errs,
                proc_state=proc_state
            )
            if interim_reasons is not None:
                # Step l
                checked_reasons |= interim_reasons
        except ValueError as e:
            msg = "Generic processing error while validating CRL."
            logging.debug(msg, exc_info=e)
            errs.failures.append((msg, certificate_list_with_poe))

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
                proc_state.describe_cert()
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
                proc_state.describe_cert()
            ),
            errs.failures
        )


def _verify_crl_signature(certificate_list, public_key):
    """
    Verifies the digital signature on an asn1crypto.crl.CertificateList object

    :param certificate_list:
        An asn1crypto.crl.CertificateList object

    :raises:
        pyhanko_certvalidator.errors.CRLValidationError - when the signature is
        invalid or uses an unsupported algorithm
    """

    signature_algo = certificate_list['signature_algorithm'].signature_algo
    hash_algo = certificate_list['signature_algorithm'].hash_algo

    try:
        validate_sig(
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
        raise CRLValidationError(
            'Unable to verify the signature of the CertificateList'
        )


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
