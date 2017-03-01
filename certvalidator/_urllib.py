# coding: utf-8
"""
Various abstractions to cater for Python2/3 differences.
"""
from __future__ import unicode_literals, division, absolute_import, print_function
import sys


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


def _get_host(request):
    """
    Get's the hostname from the request object according to the python version.

    :param request:
        An instance of urllib2.Request or urllib.request.Request

    :returns:
        A string containing the hostname without colon and portnumber.
    """

    if sys.version_info < (3,):
        return request.get_host().split(":")[0]
    return request.host.split(":")[0]
