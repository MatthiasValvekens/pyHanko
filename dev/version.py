# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import codecs
import os
import re

from . import package_root, package_name, has_tests_package


run_args = [
    {
        'name': 'pep440_version',
        'required': True
    },
]


def run(new_version):
    """
    Updates the package version in the various locations

    :param new_version:
        A unicode string of the new library version as a PEP 440 version

    :return:
        A bool - if the version number was successfully bumped
    """

    # We use a restricted form of PEP 440 versions
    version_match = re.match(
        r'(\d+)\.(\d+)\.(\d)+(?:\.((?:dev|a|b|rc)\d+))?$',
        new_version
    )
    if not version_match:
        raise ValueError('Invalid PEP 440 version: %s' % new_version)

    new_version_info = (
        int(version_match.group(1)),
        int(version_match.group(2)),
        int(version_match.group(3)),
    )
    if version_match.group(4):
        new_version_info += (version_match.group(4),)

    version_path = os.path.join(package_root, package_name, 'version.py')
    setup_path = os.path.join(package_root, 'setup.py')
    setup_tests_path = os.path.join(package_root, 'tests', 'setup.py')
    tests_path = os.path.join(package_root, 'tests', '__init__.py')

    file_paths = [version_path, setup_path]
    if has_tests_package:
        file_paths.extend([setup_tests_path, tests_path])

    for file_path in file_paths:
        orig_source = ''
        with codecs.open(file_path, 'r', encoding='utf-8') as f:
            orig_source = f.read()

        found = 0
        new_source = ''
        for line in orig_source.splitlines(True):
            if line.startswith('__version__ = '):
                found += 1
                new_source += '__version__ = %r\n' % new_version
            elif line.startswith('__version_info__ = '):
                found += 1
                new_source += '__version_info__ = %r\n' % (new_version_info,)
            elif line.startswith('PACKAGE_VERSION = '):
                found += 1
                new_source += 'PACKAGE_VERSION = %r\n' % new_version
            else:
                new_source += line

        if found == 0:
            raise ValueError('Did not find any versions in %s' % file_path)

        s = 's' if found > 1 else ''
        rel_path = file_path[len(package_root) + 1:]
        was_were = 'was' if found == 1 else 'were'
        if new_source != orig_source:
            print('Updated %d version%s in %s' % (found, s, rel_path))
            with codecs.open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_source)
        else:
            print('%d version%s in %s %s up-to-date' % (found, s, rel_path, was_were))

    return True
