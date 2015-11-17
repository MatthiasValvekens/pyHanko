# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import coverage


def run():
    """
    Runs the tests while measuring coverage

    :return:
        A bool - if the tests ran successfully
    """

    cov = coverage.Coverage(include='certvalidator/*.py')
    cov.start()

    from .tests import run as run_tests
    result = run_tests()
    print()

    cov.stop()
    cov.save()

    cov.report(show_missing=False)

    return result
