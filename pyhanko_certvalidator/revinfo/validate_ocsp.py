import datetime
import logging
from dataclasses import dataclass, field
from typing import Union, Optional

from asn1crypto import x509, cms, crl
from asn1crypto.crl import CRLReason
from asn1crypto.keys import PublicKeyInfo
from cryptography.exceptions import InvalidSignature

from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator._state import ValProcState
from pyhanko_certvalidator.errors import PathValidationError, \
    OCSPValidationError, PSSParameterMismatch, RevokedError, \
    OCSPNoMatchesError, OCSPValidationIndeterminateError
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, \
    RevocationCheckingPolicy, RevocationCheckingRule
from pyhanko_certvalidator.registry import CertificateCollection, \
    LayeredCertificateStore, SimpleCertificateStore
from pyhanko_certvalidator.revinfo.archival import OCSPWithPOE, \
    RevinfoUsabilityRating
from pyhanko_certvalidator.authority import Authority, \
    AuthorityWithCert, TrustAnchor
from pyhanko_certvalidator.util import (
    pretty_message, extract_ac_issuer_dir_name, validate_sig, ConsList
)

OCSP_PROVENANCE_ERR = (
    "Unable to verify OCSP response since response signing "
    "certificate could not be validated"
)


def _delegated_ocsp_response_path(
        responder_cert: x509.Certificate,
        issuer: Authority, ee_path: ValidationPath):

    if isinstance(issuer, AuthorityWithCert):
        responder_chain = ee_path \
            .truncate_to_and_append(issuer.certificate, responder_cert)
    else:
        responder_chain = ValidationPath(
            trust_anchor=TrustAnchor(issuer),
            interm=[], leaf=responder_cert
        )
    return responder_chain


async def _validate_delegated_ocsp_provenance(
        responder_cert: x509.Certificate,
        issuer: Authority,
        validation_context: ValidationContext,
        ee_path: ValidationPath,
        proc_state: ValProcState):

    if proc_state.check_path_verif_recursion(responder_cert):
        # we permit this for CRLs for historical reasons, but there's no
        # sane reason why this would make sense for OCSP responders, so
        # throw an error
        raise PathValidationError.from_state(
            "Recursion detected in OCSP responder authorisation check for "
            "responder certificate %s." % responder_cert.subject.human_friendly,
            proc_state
        )

    from pyhanko_certvalidator.validate import intl_validate_path

    # OCSP responder certs must be issued directly by the CA on behalf of
    # which they act.
    # Moreover, RFC 6960 says that we don't have to accept OCSP responses signed
    # with a different key than the one used to sign subscriber certificates.
    ocsp_ee_name_override = (
        proc_state.describe_cert(never_def=True) + ' OCSP responder'
    )

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
            trust_roots=[TrustAnchor(issuer)],
            allow_fetching=False, revinfo_policy=revinfo_policy,
            moment=validation_context.moment,
            weak_hash_algos=validation_context.weak_hash_algos,
            time_tolerance=validation_context.time_tolerance
        )

        ocsp_trunc_path = ValidationPath(
            trust_anchor=TrustAnchor(issuer), interm=[],
            leaf=responder_cert
        )
        ocsp_trunc_proc_state = ValProcState(
            cert_path_stack=proc_state.cert_path_stack.cons(ocsp_trunc_path),
            ee_name_override=ocsp_ee_name_override
        )
        try:
            # verify the truncated path
            await intl_validate_path(
                vc, path=ocsp_trunc_path, proc_state=ocsp_trunc_proc_state
            )
        except PathValidationError as e:
            raise OCSPValidationError(OCSP_PROVENANCE_ERR) from e
        # record validation in the original VC
        # TODO maybe have an (issuer, [verified_responder]) cache?
        #  caching OCSP responder validation results with everything else is
        #  probably somewhat incorrect

        responder_chain = \
            _delegated_ocsp_response_path(responder_cert, issuer, ee_path)
        validation_context.record_validation(responder_cert, responder_chain)
    else:
        responder_chain = \
            _delegated_ocsp_response_path(responder_cert, issuer, ee_path)

        ocsp_proc_state = ValProcState(
            cert_path_stack=proc_state.cert_path_stack.cons(responder_chain),
            ee_name_override=ocsp_ee_name_override
        )
        try:
            await intl_validate_path(
                validation_context, path=responder_chain,
                proc_state=ocsp_proc_state
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


def _match_ocsp_certid(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        issuer: Authority,
        ocsp_response: OCSPWithPOE,
        errs: _OCSPErrs) -> bool:

    cert_response = ocsp_response.extract_single_response()
    if cert_response is None:
        errs.mismatch_failures += 1
        return False

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
    return True


def _identify_responder_cert(
        ocsp_response: OCSPWithPOE, cert_store: CertificateCollection,
        errs: _OCSPErrs) -> Optional[x509.Certificate]:
    # To verify the response as legitimate, the responder cert must be located

    # prioritise the certificates included with the response, if there
    # are any
    response = ocsp_response.extract_basic_ocsp_response()
    # should be ensured by successful extraction earlier
    assert response is not None
    if response['certs']:
        cert_store = LayeredCertificateStore([
            SimpleCertificateStore.from_certs(response['certs']),
            cert_store
        ])

    tbs_response = response['tbs_response_data']
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
    return responder_cert


def _precheck_ocsp_responder_auth(
        responder_cert: x509.Certificate,
        issuer: Authority, is_pkc: bool) -> Optional[bool]:
    """
    This function checks OCSP conditions that don't require path validation
    to pass. If ``None`` is returned, path validation is necessary to proceed.
    """

    # If the cert signing the OCSP response is not the issuer, it must be
    # issued by the cert issuer and be valid for OCSP responses.
    # We currently do _not_ allow naked trust anchor keys to be used in OCSP
    # validation (but that may change in the future). This decision is based on
    # a conservative reading of RFC 6960.
    # First, check whether the certs are the same.
    if isinstance(issuer, AuthorityWithCert) and \
            issuer.certificate.issuer_serial == responder_cert.issuer_serial:
        issuer_cert = issuer.certificate
        # let's check whether the certs are actually the same
        # (by comparing the signatures as a proxy)
        # -> literal interpretation of 4.2.2.2 in RFC 6960
        issuer_sig = bytes(issuer_cert['signature_value'])
        responder_sig = bytes(responder_cert['signature_value'])
        return issuer_sig == responder_sig
    # If OCSP is being delegated
    # check whether the relevant OCSP-related extensions are present.
    # Also, explicitly disallow delegation for attribute authorities
    # since they cannot act as CAs and hence can't issue responder certificates.
    # This would otherwise be detected during path validation or while checking
    # the basicConstraints on the AA certificate, but this is more explicit.
    elif not _ocsp_allowed(responder_cert) or not is_pkc:
        return False
    return None


async def _check_ocsp_authorisation(
        responder_cert: x509.Certificate,
        issuer: Authority,
        cert_path: ValidationPath,
        ocsp_response: OCSPWithPOE,
        validation_context: ValidationContext,
        is_pkc: bool,
        errs: _OCSPErrs, proc_state: ValProcState) -> bool:

    simple_check = _precheck_ocsp_responder_auth(responder_cert, issuer, is_pkc)

    # we can take an early out in this case
    if simple_check is not None:
        auth_ok = simple_check
    else:
        try:
            await _validate_delegated_ocsp_provenance(
                responder_cert=responder_cert, issuer=issuer,
                validation_context=validation_context, ee_path=cert_path,
                proc_state=proc_state
            )
            auth_ok = True
        except OCSPValidationError as e:
            errs.failures.append((e.args[0], ocsp_response))
            auth_ok = False
    if not auth_ok:
        errs.failures.append((
            pretty_message(
                '''
                Unable to verify OCSP response since response was
                signed by an unauthorized certificate
                '''
            ),
            ocsp_response
        ))
    return auth_ok


def _check_ocsp_status(ocsp_response: OCSPWithPOE, proc_state: ValProcState):
    cert_response = ocsp_response.extract_single_response()

    # Finally check to see if the certificate has been revoked
    status = cert_response['cert_status'].name
    if status == 'good':
        return True

    if status == 'revoked':
        revocation_info = cert_response['cert_status'].chosen
        reason: CRLReason = revocation_info['revocation_reason']
        if reason.native is None:
            reason = crl.CRLReason('unspecified')
        revocation_dt: datetime = revocation_info['revocation_time'].native
        raise RevokedError.format(
            reason=reason, revocation_dt=revocation_dt,
            revinfo_type='OCSP response', proc_state=proc_state
        )
    return False


def _verify_ocsp_signature(
        responder_key: PublicKeyInfo,
        ocsp_response: OCSPWithPOE,
        errs: _OCSPErrs) -> bool:

    response = ocsp_response.extract_basic_ocsp_response()
    # Determine what algorithm was used to sign the response
    signature_algo = response['signature_algorithm'].signature_algo
    hash_algo = response['signature_algorithm'].hash_algo

    # Verify that the response was properly signed by the validated certificate
    tbs_response = response['tbs_response_data']
    try:
        validate_sig(
            signature=response['signature'].native,
            signed_data=tbs_response.dump(),
            public_key_info=responder_key,
            sig_algo=signature_algo, hash_algo=hash_algo,
            parameters=response['signature_algorithm']['parameters']
        )
        return True
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


def _assess_ocsp_relevance(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        issuer: Authority,
        ocsp_response: OCSPWithPOE,
        cert_store: CertificateCollection,
        errs: _OCSPErrs) -> Optional[x509.Certificate]:

    matched = _match_ocsp_certid(
        cert, issuer=issuer, ocsp_response=ocsp_response, errs=errs
    )
    if not matched:
        return None

    responder_cert = _identify_responder_cert(
        ocsp_response, cert_store=cert_store, errs=errs
    )
    if not responder_cert:
        return None

    signature_ok = _verify_ocsp_signature(
        responder_key=responder_cert.public_key, ocsp_response=ocsp_response,
        errs=errs
    )
    if not signature_ok:
        return None
    return responder_cert


async def _handle_single_ocsp_resp(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        issuer: Authority,
        path: ValidationPath,
        ocsp_response: OCSPWithPOE,
        validation_context: ValidationContext,
        errs: _OCSPErrs, proc_state: ValProcState) -> bool:

    responder_cert = _assess_ocsp_relevance(
        cert=cert, issuer=issuer,
        ocsp_response=ocsp_response,
        cert_store=validation_context.certificate_registry, errs=errs,
    )
    if responder_cert is None:
        return False

    freshness_result = ocsp_response.usable_at(
        policy=validation_context.revinfo_policy,
        timing_info=validation_context.timing_info,
    )
    if freshness_result != RevinfoUsabilityRating.OK:
        if freshness_result == RevinfoUsabilityRating.STALE:
            msg = 'OCSP response is not recent enough'
        elif freshness_result == RevinfoUsabilityRating.TOO_NEW:
            msg = 'OCSP response is too recent'
        else:
            msg = 'OCSP response freshness could not be established'
        errs.failures.append((msg, ocsp_response))
        return False

    # check whether the responder cert is authorised
    authorised = await _check_ocsp_authorisation(
        responder_cert, issuer=issuer, cert_path=path,
        ocsp_response=ocsp_response, validation_context=validation_context,
        is_pkc=isinstance(cert, x509.Certificate),
        errs=errs, proc_state=proc_state
    )
    if not authorised:
        return False

    return _check_ocsp_status(ocsp_response, proc_state)


async def verify_ocsp_response(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        path: ValidationPath,
        validation_context: ValidationContext,
        proc_state: Optional[ValProcState] = None):
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

    :param proc_state:
        Internal state for error reporting and policy application decisions.

    :raises:
        pyhanko_certvalidator.errors.OCSPNoMatchesError - when none of the OCSP responses match the certificate
        pyhanko_certvalidator.errors.OCSPValidationIndeterminateError - when the OCSP response could not be verified
        pyhanko_certvalidator.errors.RevokedError - when the OCSP response indicates the certificate has been revoked
    """

    proc_state = proc_state or ValProcState(cert_path_stack=ConsList.sing(path))

    cert_description = proc_state.describe_cert()

    try:
        cert_issuer = path.find_issuing_authority(cert)
    except LookupError:
        raise OCSPNoMatchesError(pretty_message(
            '''
            Could not determine issuer certificate for %s in path.
            ''',
            proc_state.describe_cert()
        ))

    errs = _OCSPErrs()
    ocsp_responses = await validation_context.revinfo_manager\
        .async_retrieve_ocsps_with_poe(cert, cert_issuer)

    for ocsp_response in ocsp_responses:
        try:
            ocsp_good = await _handle_single_ocsp_resp(
                cert=cert, issuer=cert_issuer, path=path,
                ocsp_response=ocsp_response,
                validation_context=validation_context,
                errs=errs, proc_state=proc_state
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
