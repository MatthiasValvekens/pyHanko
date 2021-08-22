import codecs
import os
import shutil
import sys
import warnings

import setuptools
from setuptools import find_packages, setup, Command
from setuptools.command.egg_info import egg_info


PACKAGE_NAME = 'pyhanko-certvalidator'
EGG_NAME = PACKAGE_NAME.replace('-', '_')
PYTHON_PACKAGE_NAME = 'pyhanko_certvalidator'
PACKAGE_VERSION = '0.16.0'
PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))


# setuptools 38.6.0 and newer know about long_description_content_type, but
# distutils still complains about it, so silence the warning
sv = setuptools.__version__
svi = tuple(int(o) if o.isdigit() else o for o in sv.split('.'))
if svi >= (38, 6):
    warnings.filterwarnings(
        'ignore',
        "Unknown distribution option: 'long_description_content_type'",
        module='distutils.dist'
    )


# This allows us to send the LICENSE and docs when creating a sdist. Wheels
# automatically include the LICENSE, and don't need the docs. For these
# to be included, the command must be "python setup.py sdist".
package_data = {}
if sys.argv[1:] == ['sdist'] or sorted(sys.argv[1:]) == ['-q', 'sdist']:
    package_data[PYTHON_PACKAGE_NAME] = [
        '../LICENSE',
        '../*.md',
        '../docs/*.md',
    ]


# Ensures a copy of the LICENSE is included with the egg-info for
# install and bdist_egg commands
class EggInfoCommand(egg_info):
    def run(self):
        egg_info_path = os.path.join(
            PACKAGE_ROOT,
            '%s.egg-info' % EGG_NAME 
        )
        if not os.path.exists(egg_info_path):
            os.mkdir(egg_info_path)
        shutil.copy2(
            os.path.join(PACKAGE_ROOT, 'LICENSE'),
            os.path.join(egg_info_path, 'LICENSE')
        )
        egg_info.run(self)


class CleanCommand(Command):
    user_options = [
        ('all', 'a', '(Compatibility with original clean command)'),
    ]

    def initialize_options(self):
        self.all = False

    def finalize_options(self):
        pass

    def run(self):
        sub_folders = ['build', 'temp', '%s.egg-info' % EGG_NAME]
        if self.all:
            sub_folders.append('dist')
        for sub_folder in sub_folders:
            full_path = os.path.join(PACKAGE_ROOT, sub_folder)
            if os.path.exists(full_path):
                shutil.rmtree(full_path)
        for root, dirs, files in os.walk(os.path.join(PACKAGE_ROOT, PYTHON_PACKAGE_NAME)):
            for filename in files:
                if filename[-4:] == '.pyc':
                    os.unlink(os.path.join(root, filename))
            for dirname in list(dirs):
                if dirname == '__pycache__':
                    shutil.rmtree(os.path.join(root, dirname))


readme = ''
with codecs.open(os.path.join(PACKAGE_ROOT, 'README.md'), 'r', 'utf-8') as f:
    readme = f.read()


setup(
    name=PACKAGE_NAME,
    version=PACKAGE_VERSION,

    description='Validates X.509 certificates and paths; forked from wbond/certvalidator',
    long_description=readme,
    long_description_content_type='text/markdown',

    url='https://github.com/MatthiasValvekens/certvalidator',

    author='Matthias Valvekens',
    author_email='dev@mvalvekens.be',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',

        'Topic :: Security :: Cryptography',
    ],

    keywords='crypto pki x509 certificate crl ocsp',

    install_requires=[
        'requests>=2.24.0',
        'asn1crypto>=1.2.0',
        'oscrypto>=1.1.0',
        'cryptography>=3.3.1',
        'uritools>=3.0.1'
    ],
    packages=[PYTHON_PACKAGE_NAME],
    package_data=package_data,

    test_suite='tests.make_suite',

    cmdclass={
        'clean': CleanCommand,
        'egg_info': EggInfoCommand,
    }
)
