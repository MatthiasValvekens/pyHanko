# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import unittest
import re
import sys

from . import build_root

from tests import test_classes


def run(matcher=None, ci=False):
    """
    Runs the tests

    :param matcher:
        A unicode string containing a regular expression to use to filter test
        names by. A value of None will cause no filtering.

    :return:
        A bool - if the tests succeeded
    """

    if not ci:
        print('Python ' + sys.version.replace('\n', ''))

    oscrypto_tests_module_info = imp.find_module('tests', [os.path.join(build_root, 'oscrypto')])
    oscrypto_tests = imp.load_module('oscrypto.tests', *oscrypto_tests_module_info)
    asn1crypto, oscrypto = oscrypto_tests.local_oscrypto()
    if not ci:
        print(
            '\nasn1crypto: %s, %s' % (
                asn1crypto.__version__,
                os.path.dirname(asn1crypto.__file__)
            )
        )
        print(
            'oscrypto: %s backend, %s, %s\n' % (
                oscrypto.backend(),
                oscrypto.__version__,
                os.path.dirname(oscrypto.__file__)
            )
        )

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_classes():
        if matcher:
            names = loader.getTestCaseNames(test_class)
            for name in names:
                if re.search(matcher, name):
                    suite.addTest(test_class(name))
        else:
            suite.addTest(loader.loadTestsFromTestCase(test_class))
    verbosity = 2 if matcher else 1
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=verbosity).run(suite)
    return result.wasSuccessful()
