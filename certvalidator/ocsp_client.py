# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import requests
import os

from asn1crypto import core, ocsp, x509, algos
from requests import RequestException

from . import errors
from ._types import str_cls, type_name
from .version import __version__


def fetch(cert, issuer, hash_algo='sha1', nonce=True, user_agent=None, timeout=10):
    """
    Fetches an OCSP response for a certificate

    :param cert:
        An asn1cyrpto.x509.Certificate object to get an OCSP reponse for

    :param issuer:
        An asn1crypto.x509.Certificate object that is the issuer of cert

    :param hash_algo:
        A unicode string of "sha1" or "sha256"

    :param nonce:
        A boolean - if the nonce extension should be used to prevent replay
        attacks

    :param user_agent:
        The HTTP user agent to use when requesting the OCSP response. If None,
        a default is used in the format "certvalidation 1.0.0".

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :raises:
        RequestException - when a URL/HTTP error occurs
        socket.error - when a socket error occurs

    :return:
        An asn1crypto.ocsp.OCSPResponse object
    """

    if not isinstance(cert, x509.Certificate):
        raise TypeError('cert must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(cert))

    if not isinstance(issuer, x509.Certificate):
        raise TypeError('issuer must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(issuer))

    if hash_algo not in set(['sha1', 'sha256']):
        raise ValueError('hash_algo must be one of "sha1", "sha256", not %s' % repr(hash_algo))

    if not isinstance(nonce, bool):
        raise TypeError('nonce must be a bool, not %s' % type_name(nonce))

    if user_agent is None:
        user_agent = 'certvalidator %s' % __version__
    elif not isinstance(user_agent, str_cls):
        raise TypeError('user_agent must be a unicode string, not %s' % type_name(user_agent))

    cert_id = ocsp.CertId({
        'hash_algorithm': algos.DigestAlgorithm({'algorithm': hash_algo}),
        'issuer_name_hash': getattr(cert.issuer, hash_algo),
        'issuer_key_hash': getattr(issuer.public_key, hash_algo),
        'serial_number': cert.serial_number,
    })

    request = ocsp.Request({
        'req_cert': cert_id,
    })
    tbs_request = ocsp.TBSRequest({
        'request_list': ocsp.Requests([request]),
    })

    if nonce:
        nonce_extension = ocsp.TBSRequestExtension({
            'extn_id': 'nonce',
            'critical': False,
            'extn_value': core.OctetString(core.OctetString(os.urandom(16)).dump())
        })
        tbs_request['request_extensions'] = ocsp.TBSRequestExtensions([nonce_extension])

    ocsp_request = ocsp.OCSPRequest({
        'tbs_request': tbs_request,
    })

    last_e = None
    for ocsp_url in cert.ocsp_urls:
        try:
            headers = {
                'Accept': 'application/ocsp-response',
                'Content-Type': 'application/ocsp-request',
                'User-Agent': user_agent
            }
            response = requests.post(
                url=ocsp_url, timeout=timeout, headers=headers,
                data=ocsp_request.dump()
            )
            ocsp_response = ocsp.OCSPResponse.load(response.content)
            status = ocsp_response['response_status'].native
            if status != 'successful':
                raise errors.OCSPValidationError(
                    'OCSP server at %s returned an error. Status was \'%s\'.'
                    % (ocsp_url, status)
                )

            request_nonce = ocsp_request.nonce_value
            response_nonce = ocsp_response.nonce_value
            if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
                raise errors.OCSPValidationError(
                    'Unable to verify OCSP response since the request and response nonces do not match'
                )
            return ocsp_response

        except RequestException as e:
            last_e = e

    raise last_e
