import datetime
import logging
from dataclasses import dataclass, field
from typing import Union, Optional

from asn1crypto import x509, cms, crl
from asn1crypto.crl import CRLReason
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
from pyhanko_certvalidator.trust_anchor import CertTrustAnchor
from pyhanko_certvalidator.util import (
    pretty_message, extract_ac_issuer_dir_name, validate_sig
)

OCSP_PROVENANCE_ERR = (
    "Unable to verify OCSP response since response signing "
    "certificate could not be validated"
)


async def _validate_delegated_ocsp_provenance(
        responder_cert: x509.Certificate,
        issuer: x509.Certificate,
        validation_context: ValidationContext,
        ee_path: ValidationPath,
        proc_state: ValProcState):

    from pyhanko_certvalidator.validate import intl_validate_path

    # OCSP responder certs must be issued directly by the CA on behalf of
    # which they act.
    # Moreover, RFC 6960 says that we don't have to accept OCSP responses signed
    # with a different key than the one used to sign subscriber certificates.
    ocsp_ee_name_override = proc_state.describe_cert() + ' OCSP responder'

    issuer_chain = ee_path.truncate_to(issuer)
    responder_chain = issuer_chain.copy_and_append(responder_cert)
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

        ocsp_trunc_path = ValidationPath(
            trust_anchor=CertTrustAnchor(issuer), certs=[responder_cert]
        )
        ocsp_trunc_proc_state = ValProcState(
            path_len=1, is_side_validation=True,
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
        validation_context.record_validation(responder_cert, responder_chain)
    else:
        ocsp_proc_state = ValProcState(
            path_len=len(responder_chain) - 1,
            is_side_validation=True, ee_name_override=ocsp_ee_name_override
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


async def _handle_single_ocsp_resp(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        issuer: x509.Certificate,
        path: ValidationPath,
        ocsp_response: OCSPWithPOE,
        validation_context: ValidationContext,
        moment: datetime.datetime,
        errs: _OCSPErrs, proc_state: ValProcState) -> bool:

    certificate_registry = validation_context.certificate_registry
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

    freshness_result = ocsp_response.usable_at(
        validation_time=moment, policy=validation_context.revinfo_policy,
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

    # To verify the response as legitimate, the responder cert must be located
    cert_store: CertificateCollection = certificate_registry
    # prioritise the certificates included with the response, if there
    # are any

    response = ocsp_response.extract_basic_ocsp_response()
    # should be ensured by successful extraction earlier
    assert response is not None
    if response['certs']:
        cert_store = LayeredCertificateStore([
            SimpleCertificateStore.from_certs(response['certs']),
            certificate_registry
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
                proc_state=proc_state
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
        validate_sig(
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
        reason: CRLReason = revocation_info['revocation_reason']
        if reason.native is None:
            reason = crl.CRLReason('unspecified')
        reason_str = reason.human_friendly
        revocation_dt: datetime = revocation_info['revocation_time'].native
        date = revocation_dt.strftime('%Y-%m-%d')
        time = revocation_dt.strftime('%H:%M:%S')
        raise RevokedError(pretty_message(
            '''
            OCSP response indicates %s was revoked at %s on %s, due to %s
            ''',
            proc_state.describe_cert(),
            time,
            date,
            reason_str
        ), reason, revocation_dt, proc_state)


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

    proc_state = proc_state or ValProcState(
        path_len=path.pkix_len, is_side_validation=False
    )

    cert_description = proc_state.describe_cert()
    moment = validation_context.moment

    if isinstance(cert, x509.Certificate):
        try:
            cert_issuer = path.find_issuer(cert)
        except LookupError:
            raise OCSPNoMatchesError(pretty_message(
                '''
                Could not determine issuer certificate for %s in path.
                ''',
                cert_description
            ))
    else:
        cert_issuer = path.last

    errs = _OCSPErrs()
    ocsp_responses = await validation_context.revinfo_manager\
        .async_retrieve_ocsps_with_poe(cert, cert_issuer)

    for ocsp_response in ocsp_responses:
        try:
            ocsp_good = await _handle_single_ocsp_resp(
                cert=cert, issuer=cert_issuer, path=path,
                ocsp_response=ocsp_response,
                validation_context=validation_context, moment=moment,
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