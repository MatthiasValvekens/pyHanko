# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import site
import sys

from . import build_root, requires_oscrypto
from ._import import _preload

from .tests import run as run_tests


deps_dir = os.path.join(build_root, 'modularcrypto-deps')
if os.path.exists(deps_dir):
    site.addsitedir(deps_dir)


def run():
    """
    Runs tests

    :return:
        A bool - if tests ran successfully
    """

    _preload(requires_oscrypto, True)

    print('\nRunning tests')
    sys.stdout.flush()
    tests_result = run_tests(ci=True)
    sys.stdout.flush()

    return tests_result
