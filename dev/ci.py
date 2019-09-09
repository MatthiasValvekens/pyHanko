# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import os
import imp

from . import build_root


deps_dir = os.path.join(build_root, 'modularcrypto-deps')
if os.path.exists(deps_dir):
    sys.path.insert(1, deps_dir)

if sys.version_info[0:2] not in [(2, 6), (3, 2)]:
    from .lint import run as run_lint
else:
    run_lint = None

if sys.version_info[0:2] != (3, 2):
    from .coverage import run as run_coverage
    run_tests = None

else:
    from .tests import run as run_tests
    run_coverage = None


def run():
    """
    Runs the linter and tests

    :return:
        A bool - if the linter and tests ran successfully
    """

    print('Python ' + sys.version.replace('\n', ''))

    oscrypto_path = os.path.join(build_root, 'oscrypto')
    if not os.path.exists(oscrypto_path):
        oscrypto_path = os.path.join(build_root, 'modularcrypto-deps', 'oscrypto')
    if not os.path.exists(oscrypto_path):
        print(
            'Unable to locate oscrypto.tests',
            file=sys.stderr
        )
        return False

    try:
        oscrypto_tests_module_info = imp.find_module('tests', [oscrypto_path])
    except ImportError:
        print(
            'Error loading oscrypto.tests from "%s"' % oscrypto_path,
            file=sys.stderr
        )
        return False
    oscrypto_tests = imp.load_module('oscrypto.tests', *oscrypto_tests_module_info)
    asn1crypto, oscrypto = oscrypto_tests.local_oscrypto()
    print(
        '\nasn1crypto: %s, %s' % (
            asn1crypto.__version__,
            os.path.dirname(asn1crypto.__file__)
        )
    )
    print(
        'oscrypto: %s backend, %s, %s' % (
            oscrypto.backend(),
            oscrypto.__version__,
            os.path.dirname(oscrypto.__file__)
        )
    )

    if run_lint:
        print('')
        lint_result = run_lint()
    else:
        lint_result = True

    if run_coverage:
        print('\nRunning tests (via coverage.py)')
        sys.stdout.flush()
        tests_result = run_coverage(ci=True)
    else:
        print('\nRunning tests')
        sys.stdout.flush()
        tests_result = run_tests(ci=True)
    sys.stdout.flush()

    return lint_result and tests_result
