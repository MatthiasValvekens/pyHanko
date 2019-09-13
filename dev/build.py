# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import tarfile
import zipfile

import setuptools.sandbox

from . import package_root, package_name, has_tests_package


def _list_zip(filename):
    """
    Prints all of the files in a .zip file
    """

    zf = zipfile.ZipFile(filename, 'r')
    for name in zf.namelist():
        print('     %s' % name)


def _list_tgz(filename):
    """
    Prints all of the files in a .tar.gz file
    """

    tf = tarfile.open(filename, 'r:gz')
    for name in tf.getnames():
        print('     %s' % name)


def run():
    """
    Creates a sdist .tar.gz and a bdist_wheel --univeral .whl

    :return:
        A bool - if the packaging process was successful
    """

    setup = os.path.join(package_root, 'setup.py')
    tests_root = os.path.join(package_root, 'tests')
    tests_setup = os.path.join(tests_root, 'setup.py')

    # Trying to call setuptools.sandbox.run_setup(setup, ['--version'])
    # resulted in a segfault, so we do this instead
    module_info = imp.find_module('version', [os.path.join(package_root, package_name)])
    version_mod = imp.load_module('%s.version' % package_name, *module_info)

    pkg_name_info = (package_name, version_mod.__version__)
    print('Building %s-%s' % pkg_name_info)

    sdist = '%s-%s.tar.gz' % pkg_name_info
    whl = '%s-%s-py2.py3-none-any.whl' % pkg_name_info
    setuptools.sandbox.run_setup(setup, ['-q', 'sdist'])
    print(' - created %s' % sdist)
    _list_tgz(os.path.join(package_root, 'dist', sdist))
    setuptools.sandbox.run_setup(setup, ['-q', 'bdist_wheel', '--universal'])
    print(' - created %s' % whl)
    _list_zip(os.path.join(package_root, 'dist', whl))
    setuptools.sandbox.run_setup(setup, ['-q', 'clean'])

    if has_tests_package:
        print('Building %s_tests-%s' % (package_name, version_mod.__version__))

        tests_sdist = '%s_tests-%s.tar.gz' % pkg_name_info
        tests_whl = '%s_tests-%s-py2.py3-none-any.whl' % pkg_name_info
        setuptools.sandbox.run_setup(tests_setup, ['-q', 'sdist'])
        print(' - created %s' % tests_sdist)
        _list_tgz(os.path.join(tests_root, 'dist', tests_sdist))
        setuptools.sandbox.run_setup(tests_setup, ['-q', 'bdist_wheel', '--universal'])
        print(' - created %s' % tests_whl)
        _list_zip(os.path.join(tests_root, 'dist', tests_whl))
        setuptools.sandbox.run_setup(tests_setup, ['-q', 'clean'])

        dist_dir = os.path.join(package_root, 'dist')
        tests_dist_dir = os.path.join(tests_root, 'dist')
        os.rename(
            os.path.join(tests_dist_dir, tests_sdist),
            os.path.join(dist_dir, tests_sdist)
        )
        os.rename(
            os.path.join(tests_dist_dir, tests_whl),
            os.path.join(dist_dir, tests_whl)
        )
        os.rmdir(tests_dist_dir)

    return True
