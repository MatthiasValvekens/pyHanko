# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os


package_name = "pyhanko-pyhanko_certvalidator"
python_package_name = "pyhanko_certvalidator"

other_packages = []

task_keyword_args = []

requires_oscrypto = True
has_tests_package = False

package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
build_root = os.path.abspath(os.path.join(package_root, '..'))

md_source_map = {
    'docs/api.md': [
        'pyhanko_certvalidator/__init__.py',
        'pyhanko_certvalidator/context.py',
    ],
}

definition_replacements = {}
