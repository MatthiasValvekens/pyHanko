# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import unittest


def make_suite():
    """
    Constructs a unittest.TestSuite() of all tests for the package. For use
    with setuptools.

    :return:
        A unittest.TestSuite() object
    """

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for test_class in test_classes():
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite


def test_classes():
    """
    Returns a list of unittest.TestCase classes for the package

    :return:
        A list of unittest.TestCase classes
    """

    # Make sure the module is loaded from this source folder
    module_name = 'certvalidator'
    src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    module_info = imp.find_module(module_name, [src_dir])
    imp.load_module(module_name, *module_info)

    from .test_certificate_validator import CertificateValidatorTests
    from .test_crl_client import CRLClientTests
    from .test_ocsp_client import OCSPClientTests
    from .test_registry import RegistryTests
    from .test_validate import ValidateTests


    return [
        CertificateValidatorTests,
        CRLClientTests,
        OCSPClientTests,
        RegistryTests,
        ValidateTests
    ]
