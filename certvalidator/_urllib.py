# coding: utf-8
"""
Compatibility shims between urllib2 (Python 2) and urllib.request (Python 3)
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import warnings

from asn1crypto import util

if sys.version_info < (3,):
    from urllib2 import Request as _Request
    from urllib2 import urlopen, URLError  # noqa
else:
    from urllib.request import Request as _Request
    from urllib.request import urlopen  # noqa
    from urllib.error import URLError  # noqa


if sys.version_info < (3,):

    warnings.filterwarnings(
        'ignore',
        "object has no _reuse/_drop methods",
        module='socket'
    )

    class Request(_Request, object):
        """
        Compatibility shim to make urrlib2.Request handle unicode
        """

        def __init__(self, url):
            """
            Wrapper that converts IRI's to URI's before passing to super, and
            automatically adds the Host header

            :param url:
                A unicode string of the URL to request
            """

            super(Request, self).__init__(util.iri_to_uri(url))
            self.add_header('Host', self.get_host().decode('ascii').split(":")[0])

        def add_header(self, name, value):
            """
            Wrapper for the add_header method of urllib2 to properly encode the
            headers

            :param name:
                A unicode string of the header name

            :param value:
                A unicode string of the header value
            """

            super(Request, self).add_header(
                name.encode('iso-8859-1'),
                value.encode('iso-8859-1')
            )

else:

    class Request(_Request):
        """
        Automatically adds the Host header
        """

        def __init__(self, url):
            """
            Wrapper that automatically sets the Host header

            :param url:
                A unicode string of the URL to request
            """

            super().__init__(url)
            self.add_header('Host', self.host.split(":")[0])
