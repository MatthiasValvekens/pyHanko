from setuptools import setup

setup(
    name='pyHanko',
    version='0.0.1',
    packages=['pyhanko', 'pyhanko.sign', 'pyhanko.pdf_utils'],
    url='https://github.com/MatthiasValvekens/pdf-stamp',
    license='MIT License',
    author='Matthias Valvekens',
    author_email='dev@mvalvekens.be',
    description='Tools for stamping and signing PDF files',
    entry_points={
        "console_scripts": [
            "pyhanko = pyhanko.__main__:launch"
        ]
    }
)
