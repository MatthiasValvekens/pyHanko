# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

if sys.version_info >= (2, 7):
    from .lint import run as run_lint
if sys.version_info < (3, 0) or sys.version_info >= (3, 3):
    from .coverage import run as run_coverage
else:
    from .tests import run as run_tests


def run():
    """
    Runs the linter and tests

    :return:
        A bool - if the linter and tests ran successfully
    """

    print('Python ' + sys.version.replace('\n', ''))
    if sys.version_info >= (2, 7):
        print('')
        lint_result = run_lint()
    else:
        lint_result = True

    if sys.version_info < (3, 0) or sys.version_info >= (3, 3):
        print('\nRunning tests (via coverage.py)')
        sys.stdout.flush()
        tests_result = run_coverage(write_xml=True)
    else:
        print('\nRunning tests')
        sys.stdout.flush()
        tests_result = run_tests()

    return lint_result and tests_result
