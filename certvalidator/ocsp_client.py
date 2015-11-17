# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

from asn1crypto import core, ocsp, x509, algos

from . import errors
from ._types import str_cls, type_name
from ._version import __version__

if sys.version_info < (3,):
    from urllib2 import Request, urlopen, HTTPError

else:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError


def fetch(cert, issuer, hash_algo='sha1', nonce=True, user_agent=None, timeout=None):
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
        certvalidator.errors.OCSPValidationError - when an HTTP error occurs

    :return:
        An asn1crypto.ocsp.OCSPResponse object
    """

    if not isinstance(cert, x509.Certificate):
        raise TypeError('cert must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(cert))

    if not isinstance(issuer, x509.Certificate):
        raise TypeError('issuer must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(issuer))

    if hash_algo not in ('sha1', 'sha256'):
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

    for ocsp_url in cert.ocsp_urls:
        try:
            request = Request(ocsp_url)
            request.add_header(b'Accept', b'application/ocsp-response')
            request.add_header(b'Content-Type', b'application/ocsp-request')
            request.add_header(b'User-Agent', user_agent.encode('iso-8859-1'))
            response = urlopen(request, ocsp_request.dump(), timeout)
            ocsp_response = ocsp.OCSPResponse.load(response.read())
            request_nonce = ocsp_request.nonce_value
            response_nonce = ocsp_response.nonce_value
            if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
                raise errors.OCSPValidationError(
                    'Unable to verify OCSP response since the request and response nonces do not match'
                )
            return ocsp_response

        except (HTTPError):
            continue

    plural = 's' if len(cert.ocsp_urls) != 1 else ''
    raise errors.OCSPValidationError('OCSP request%s could not be sent due to HTTP error%s' % (plural, plural))
