# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .tests import run as run_tests
from .lint import run as run_lint


def run():
    """
    Runs the linter and tests

    :return:
        A bool - if the linter and tests ran successfully
    """

    print('Python ' + sys.version.replace('\n', ''))
    print('')
    lint_result = run_lint()
    print('\nRunning tests')
    sys.stdout.flush()
    tests_result = run_tests()

    return lint_result and tests_result
