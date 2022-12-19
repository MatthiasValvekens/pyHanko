from os import path

from setuptools import setup

BASE_DIR = path.abspath(path.dirname(__file__))
with open(path.join(BASE_DIR, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


# based on https://packaging.python.org/guides/single-sourcing-package-version/
def get_version():
    version_file = path.join(BASE_DIR, 'pyhanko', 'version.py')
    with open(version_file, encoding='utf-8') as f:
        for line in f:
            if line.startswith('__version__'):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]
        raise RuntimeError("Unable to find version string.")


setup(
    name='pyHanko',
    version=get_version(),
    packages=[
        'pyhanko',
        'pyhanko.pdf_utils', 'pyhanko.pdf_utils.font',
        'pyhanko.pdf_utils.crypt', 'pyhanko.pdf_utils.metadata',
        'pyhanko.sign', 'pyhanko.sign.ades', 'pyhanko.sign.signers',
        'pyhanko.sign.diff_analysis', 'pyhanko.sign.diff_analysis.rules',
        'pyhanko.sign.timestamps', 'pyhanko.sign.validation'
    ],
    url='https://github.com/MatthiasValvekens/pyHanko',
    license='MIT',
    author='Matthias Valvekens',
    author_email='dev@mvalvekens.be',
    description='Tools for stamping and signing PDF files',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',

        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    entry_points={
        "console_scripts": [
            "pyhanko = pyhanko.__main__:launch"
        ]
    },
    install_requires=[
        'asn1crypto>=1.5.1',
        'pytz>=2020.1',
        'qrcode>=6.1',
        'tzlocal>=2.1',
        'pyhanko-certvalidator~=0.19.8',
        'click>=7.1.2',
        'requests>=2.24.0',
        'pyyaml>=5.3.1',
        'cryptography>=3.3.1'
    ],
    setup_requires=[
        'wheel', 'pytest-runner'
    ],
    extras_require={
        'extra_pubkey_algs': ['oscrypto>=1.2.1'],
        'xmp': ['defusedxml~=0.7.1'],
        'opentype': [
            'fonttools>=4.33.3',
            # uharfbuzz sometimes includes breaking changes, so
            # we set an explicit range
            'uharfbuzz>=0.25.0,<0.31.0'
        ],
        'image-support': [
            # Only tested systematically on 8.x,
            # but we allow 7.2.x to support system PIL on Ubuntu
            'Pillow>=7.2.0',
            'python-barcode==0.14.0',
        ],
        'pkcs11': ['python-pkcs11~=0.7.0'],
        'async_http': ['aiohttp~=3.8.0']
    },
    tests_require=[
        'pytest>=6.1.1', 'requests-mock>=1.8.0',
        'freezegun>=1.1.0', 'certomancer~=0.9.1',
        'aiohttp~=3.8.0', 'pytest-aiohttp~=1.0.4',
        'certomancer-csc-dummy==0.2.1'
    ],
    keywords="signature pdf pades digital-signature pkcs11"
)
