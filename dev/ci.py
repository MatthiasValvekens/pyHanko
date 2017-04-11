# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

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
        tests_result = run_tests()
    sys.stdout.flush()

    return lint_result and tests_result
