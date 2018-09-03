# coding: utf-8

"""
This file was originally derived from
https://github.com/pypa/pip/blob/3e713708088aedb1cde32f3c94333d6e29aaf86e/src/pip/_internal/pep425tags.py

The following license covers that code:

Copyright (c) 2008-2018 The pip developers (see AUTHORS.txt file)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import os
import ctypes
import re
import platform

if sys.version_info >= (2, 7):
    import sysconfig

if sys.version_info < (3,):
    str_cls = unicode  # noqa
else:
    str_cls = str


def _pep425_implementation():
    """
    :return:
        A 2 character unicode string of the implementation - 'cp' for cpython
        or 'pp' for PyPy
    """

    return 'pp' if hasattr(sys, 'pypy_version_info') else 'cp'


def _pep425_version():
    """
    :return:
        A tuple of integers representing the Python version number
    """

    if hasattr(sys, 'pypy_version_info'):
        return (sys.version_info[0], sys.pypy_version_info.major,
                sys.pypy_version_info.minor)
    else:
        return (sys.version_info[0], sys.version_info[1])


def _pep425_supports_manylinux():
    """
    :return:
        A boolean indicating if the machine can use manylinux1 packages
    """

    try:
        import _manylinux
        return bool(_manylinux.manylinux1_compatible)
    except (ImportError, AttributeError):
        pass

    # Check for glibc 2.5
    try:
        proc = ctypes.CDLL(None)
        gnu_get_libc_version = proc.gnu_get_libc_version
        gnu_get_libc_version.restype = ctypes.c_char_p

        ver = gnu_get_libc_version()
        if not isinstance(ver, str_cls):
            ver = ver.decode('ascii')
        match = re.match(r'(\d+)\.(\d+)', ver)
        return match and match.group(1) == '2' and int(match.group(2)) >= 5

    except (AttributeError):
        return False


def _pep425_get_abi():
    """
    :return:
        A unicode string of the system abi. Will be something like: "cp27m",
        "cp33m", etc.
    """

    try:
        soabi = sysconfig.get_config_var('SOABI')
        if soabi:
            if soabi.startswith('cpython-'):
                return 'cp%s' % soabi.split('-')[1]
            return soabi.replace('.', '_').replace('-', '_')
    except (IOError, NameError):
        pass

    impl = _pep425_implementation()
    suffix = ''
    if impl == 'cp':
        suffix += 'm'
    if sys.maxunicode == 0x10ffff and sys.version_info < (3, 3):
        suffix += 'u'
    return '%s%s%s' % (impl, ''.join(map(str_cls, _pep425_version())), suffix)


def _pep425tags():
    """
    :return:
        A list of 3-element tuples with unicode strings or None:
         [0] implementation tag - cp33, pp27, cp26, py2, py2.py3
         [1] abi tag - cp26m, None
         [2] arch tag - linux_x86_64, macosx_10_10_x85_64, etc
    """

    tags = []

    versions = []
    version_info = _pep425_version()
    major = version_info[:-1]
    for minor in range(version_info[-1], -1, -1):
        versions.append(''.join(map(str, major + (minor,))))

    impl = _pep425_implementation()

    abis = []
    abi = _pep425_get_abi()
    if abi:
        abis.append(abi)
    abi3 = _pep425_implementation() == 'cp' and sys.version_info >= (3,)
    if abi3:
        abis.append('abi3')
    abis.append('none')

    if sys.platform == 'darwin':
        plat_ver = platform.mac_ver()
        ver_parts = plat_ver[0].split('.')
        minor = int(ver_parts[1])
        arch = plat_ver[2]
        if sys.maxsize == 2147483647:
            arch = 'i386'
        arches = []
        while minor > 5:
            arches.append('macosx_10_%s_%s' % (minor, arch))
            arches.append('macosx_10_%s_intel' % (minor,))
            arches.append('macosx_10_%s_universal' % (minor,))
            minor -= 1
    else:
        if sys.platform == 'win32':
            if 'amd64' in sys.version.lower():
                arches = ['win_amd64']
            arches = [sys.platform]
        elif hasattr(os, 'uname'):
            (plat, _, _, _, machine) = os.uname()
            plat = plat.lower().replace('/', '')
            machine.replace(' ', '_').replace('/', '_')
            if plat == 'linux' and sys.maxsize == 2147483647:
                machine = 'i686'
            arch = '%s_%s' % (plat, machine)
            if _pep425_supports_manylinux():
                arches = [arch.replace('linux', 'manylinux1'), arch]
            else:
                arches = [arch]

    for abi in abis:
        for arch in arches:
            tags.append(('%s%s' % (impl, versions[0]), abi, arch))

    if abi3:
        for version in versions[1:]:
            for arch in arches:
                tags.append(('%s%s' % (impl, version), 'abi3', arch))

    for arch in arches:
        tags.append(('py%s' % (versions[0][0]), 'none', arch))

    tags.append(('%s%s' % (impl, versions[0]), 'none', 'any'))
    tags.append(('%s%s' % (impl, versions[0][0]), 'none', 'any'))

    for i, version in enumerate(versions):
        tags.append(('py%s' % (version,), 'none', 'any'))
        if i == 0:
            tags.append(('py%s' % (version[0]), 'none', 'any'))

    tags.append(('py2.py3', 'none', 'any'))

    return tags
