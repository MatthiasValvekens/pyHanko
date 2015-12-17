# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

from asn1crypto import core, ocsp, x509, algos, util

from . import errors
from ._types import str_cls, type_name
from ._version import __version__

if sys.version_info < (3,):
    from urllib2 import Request, urlopen, URLError

else:
    from urllib.request import Request, urlopen
    from urllib.error import URLError


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
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
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
            if sys.version_info < (3,):
                ocsp_url = util.iri_to_uri(ocsp_url)
            request = Request(ocsp_url)
            _add_header(request, 'Accept', 'application/ocsp-response')
            _add_header(request, 'Content-Type', 'application/ocsp-request')
            _add_header(request, 'User-Agent', user_agent)
            response = urlopen(request, ocsp_request.dump(), timeout)
            ocsp_response = ocsp.OCSPResponse.load(response.read())
            request_nonce = ocsp_request.nonce_value
            response_nonce = ocsp_response.nonce_value
            if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
                raise errors.OCSPValidationError(
                    'Unable to verify OCSP response since the request and response nonces do not match'
                )
            return ocsp_response

        except (URLError) as e:
            last_e = e

    raise last_e


def _add_header(request, name, value):
    """
    Adds a header to a urllib2/urllib.request Request object, ensuring values
    are encoded appropriately based on the version of Python

    :param request:
        An instance of urllib2.Request or urllib.request.Request

    :param name:
        A unicode string of the header name

    :param value:
        A unicode string of the header value
    """

    if sys.version_info < (3,):
        name = name.encode('iso-8859-1')
        value = value.encode('iso-8859-1')

    request.add_header(name, value)
