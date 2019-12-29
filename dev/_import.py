# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import sys
import os

from . import build_root, package_name, package_root

if sys.version_info < (3,):
    getcwd = os.getcwdu
else:
    getcwd = os.getcwd


def _import_from(mod, path, mod_dir=None, allow_error=False):
    """
    Imports a module from a specific path

    :param mod:
        A unicode string of the module name

    :param path:
        A unicode string to the directory containing the module

    :param mod_dir:
        If the sub directory of "path" is different than the "mod" name,
        pass the sub directory as a unicode string

    :param allow_error:
        If an ImportError should be raised when the module can't be imported

    :return:
        None if not loaded, otherwise the module
    """

    if mod_dir is None:
        mod_dir = mod.replace('.', os.sep)

    if not os.path.exists(path):
        return None

    if not os.path.exists(os.path.join(path, mod_dir)) \
            and not os.path.exists(os.path.join(path, mod_dir + '.py')):
        return None

    if os.sep in mod_dir:
        append, mod_dir = mod_dir.rsplit(os.sep, 1)
        path = os.path.join(path, append)

    try:
        mod_info = imp.find_module(mod_dir, [path])
        return imp.load_module(mod, *mod_info)
    except ImportError:
        if allow_error:
            raise
        return None


def _preload(require_oscrypto, print_info):
    """
    Preloads asn1crypto and optionally oscrypto from a local source checkout,
    or from a normal install

    :param require_oscrypto:
        A bool if oscrypto needs to be preloaded

    :param print_info:
        A bool if info about asn1crypto and oscrypto should be printed
    """

    if print_info:
        print('Working dir: ' + getcwd())
        print('Python ' + sys.version.replace('\n', ''))

    asn1crypto = None
    oscrypto = None

    if require_oscrypto:
        # Some CI services don't use the package name for the dir
        if package_name == 'oscrypto':
            oscrypto_dir = package_root
        else:
            oscrypto_dir = os.path.join(build_root, 'oscrypto')
        oscrypto_tests = None
        if os.path.exists(oscrypto_dir):
            oscrypto_tests = _import_from('oscrypto_tests', oscrypto_dir, 'tests')
        if oscrypto_tests is None:
            import oscrypto_tests
        asn1crypto, oscrypto = oscrypto_tests.local_oscrypto()

    else:
        if package_name == 'asn1crypto':
            asn1crypto_dir = package_root
        else:
            asn1crypto_dir = os.path.join(build_root, 'asn1crypto')
        if os.path.exists(asn1crypto_dir):
            asn1crypto = _import_from('asn1crypto', asn1crypto_dir)
        if asn1crypto is None:
            import asn1crypto

    if print_info:
        print(
            '\nasn1crypto: %s, %s' % (
                asn1crypto.__version__,
                os.path.dirname(asn1crypto.__file__)
            )
        )
        if require_oscrypto:
            print(
                'oscrypto: %s backend, %s, %s' % (
                    oscrypto.backend(),
                    oscrypto.__version__,
                    os.path.dirname(oscrypto.__file__)
                )
            )
