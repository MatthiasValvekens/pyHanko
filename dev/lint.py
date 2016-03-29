# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os

from flake8.engine import get_style_guide


cur_dir = os.path.dirname(__file__)
config_file = os.path.join(cur_dir, '..', 'tox.ini')


def run():
    """
    Runs flake8 lint

    :return:
        A bool - if flake8 did not find any errors
    """

    print('Running flake8')

    flake8_style = get_style_guide(config_file=config_file)

    paths = []
    for root, _, filenames in os.walk('certvalidator'):
        for filename in filenames:
            if not filename.endswith('.py'):
                continue
            paths.append(os.path.join(root, filename))
    report = flake8_style.check_files(paths)
    success = report.total_errors == 0
    if success:
        print('OK')
    return success
