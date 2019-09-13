#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def show_usage():
    print('Usage: run.py (api_docs | lint | tests [regex] | coverage | deps '
        '| ci | stress_test | version | build | release)', file=sys.stderr)
    sys.exit(1)


def get_arg(num):
    if len(sys.argv) < num + 1:
        return None
    arg = sys.argv[num]
    if isinstance(arg, byte_cls):
        arg = arg.decode('utf-8')
    return arg


if len(sys.argv) < 2 or len(sys.argv) > 3:
    show_usage()

task = get_arg(1)

if task not in set(['api_docs', 'lint', 'tests', 'coverage', 'deps', 'ci',
        'stress_test', 'version', 'build', 'release']):
    show_usage()

if task != 'tests' and task != 'version' and len(sys.argv) == 3:
    show_usage()

params = []
if task == 'api_docs':
    from dev.api_docs import run

elif task == 'lint':
    from dev.lint import run

elif task == 'tests':
    from dev.tests import run
    matcher = get_arg(2)
    if matcher:
        params.append(matcher)

elif task == 'coverage':
    from dev.coverage import run

elif task == 'deps':
    from dev.deps import run

elif task == 'ci':
    from dev.ci import run

elif task == 'stress_test':
    from dev.stress_test import run

elif task == 'version':
    from dev.version import run
    if len(sys.argv) != 3:
        show_usage()
    pep440_version = get_arg(2)
    params.append(pep440_version)

elif task == 'build':
    from dev.build import run

elif task == 'release':
    from dev.release import run

result = run(*params)
sys.exit(int(not result))
