# coding: utf-8
"""
Various abstractions to cater for Python2/3 differences.
"""
from __future__ import unicode_literals, division, absolute_import, print_function
import sys
from asn1crypto import util

if sys.version_info < (3,):
    from urllib2 import Request as _Request
    from urllib2 import urlopen, URLError  # noqa
else:
    from urllib.request import Request as _Request
    from urllib.request import urlopen  # noqa
    from urllib.error import URLError  # noqa

if sys.version_info < (3,):
    class Request(_Request):
        """
        Wrapper for the Request object of urllib2 to add conversion of URI to
        URI before setting the url attribute and encode header values before
        setting them.
        """
        def __init__(self, url, data=None, headers={}, origin_req_host=None, unverifiable=False):
            """
            Wrapper for the ``__init__`` method of urllib that converts IRI's
            to URI's before setting the url attribute.

            :param url str: Valid URL
            :param data str: Data to send to the server or None
            :param headers dict: Dictionary containing [header type]: [header
                value] items
            :param origin_req_host str: Host name or IP address of the original
                request that was initiated
            :param unverifiable bool: Indicates whether the request is
                unverifiable, as defined by RFC 2965.
            """
            url = util.iri_to_uri(url)
            _Request.__init__(self, url, data, headers, origin_req_host, unverifiable)

        def add_header(self, name, value):
            """
            Wrapper for the add_header method of urllib2 to properly encode the
            headers

            :param name str: name of the header type
            :param value str: value of the header
            """
            _Request.add_header(
                self,
                name.encode('iso-8859-1'),
                value.encode('iso-8859-1')
            )
else:
    class Request(_Request):
        """
        Wrapper for the Request object of urllib to add a ``get_host()``
        method.
        """
        def get_host(self):
            """
            Wrapper to add a ``get_host()`` method to urllib.

            :return str: The hostname Request will connect to possibly with a
                colon and port number suffixed
            """
            return self.host
