# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from asn1crypto import crl, x509, cms, pem, util

from ._types import str_cls, type_name
from ._version import __version__

if sys.version_info < (3,):
    from urllib2 import Request, urlopen

else:
    from urllib.request import Request, urlopen


def fetch(cert, use_deltas=True, user_agent=None, timeout=10):
    """
    Fetches the CRLs for a certificate

    :param cert:
        An asn1cyrpto.x509.Certificate object to get the CRL for

    :param use_deltas:
        A boolean indicating if delta CRLs should be fetched

    :param user_agent:
        The HTTP user agent to use when requesting the CRL. If None,
        a default is used in the format "certvalidation 1.0.0".

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :raises:
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
        socket.error - when a socket error occurs

    :return:
        A list asn1crypto.crl.CertificateList objects
    """

    if not isinstance(cert, x509.Certificate):
        raise TypeError('cert must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(cert))

    if user_agent is None:
        user_agent = 'certvalidator %s' % __version__
    elif not isinstance(user_agent, str_cls):
        raise TypeError('user_agent must be a unicode string, not %s' % type_name(user_agent))

    output = []

    sources = cert.crl_distribution_points
    if use_deltas:
        sources.extend(cert.delta_crl_distribution_points)

    for distribution_point in sources:
        url = distribution_point.url
        output.append(_grab_crl(user_agent, url, timeout))

    return output


def _grab_crl(user_agent, url, timeout):
    """
    Fetches a CRL and parses it

    :param user_agent:
        A unicode string of the user agent to use when fetching the URL

    :param url:
        A unicode string of the URL to fetch the CRL from

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :return:
        An asn1crypto.crl.CertificateList object
    """

    if sys.version_info < (3,):
        url = util.iri_to_uri(url)
    request = Request(url)
    request.add_header(b'Accept', b'application/pkix-crl')
    request.add_header(b'User-Agent', user_agent.encode('iso-8859-1'))
    response = urlopen(request, None, timeout)
    data = response.read()
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return crl.CertificateList.load(data)


def fetch_certs(certificate_list, user_agent=None, timeout=10):
    """
    Fetches certificates from the authority information access extension of
    an asn1crypto.crl.CertificateList object and places them into the
    cert registry.

    :param certificate_list:
        An asn1crypto.crl.CertificateList object

    :param user_agent:
        The HTTP user agent to use when requesting the CRL. If None,
        a default is used in the format "certvalidation 1.0.0".

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :raises:
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
        socket.error - when a socket error occurs

    :return:
        A list of any asn1crypto.x509.Certificate objects that were fetched
    """

    output = []

    if user_agent is None:
        user_agent = 'certvalidator %s' % __version__
    elif not isinstance(user_agent, str_cls):
        raise TypeError('user_agent must be a unicode string, not %s' % type_name(user_agent))

    for url in certificate_list.issuer_cert_urls:
        if sys.version_info < (3,):
            url = util.iri_to_uri(url)
        request = Request(url)
        request.add_header(b'Accept', b'application/pkix-cert,application/pkcs7-mime')
        request.add_header(b'User-Agent', user_agent.encode('iso-8859-1'))
        response = urlopen(request, None, timeout)

        content_type = response.headers['Content-Type'].strip()
        response_data = response.read()

        if content_type == 'application/pkix-cert':
            output.append(x509.Certificate.load(response_data))

        elif content_type == 'application/pkcs7-mime':
            signed_data = cms.SignedData.load(response_data)
            if isinstance(signed_data['certificates'], cms.CertificateSet):
                for cert_choice in signed_data['certificates']:
                    if cert_choice.name == 'certificate':
                        output.append(cert_choice.chosen)
        else:
            raise ValueError('Unknown content type of %s when fetching issuer certificate for CRL' % repr(content_type))

    return output
