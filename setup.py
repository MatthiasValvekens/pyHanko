from setuptools import setup

setup(
    name='pdf-stamp',
    version='0.0.1',
    packages=['tests', 'pdfstamp', 'pdfstamp.sign', 'pdf_utils'],
    url='https://github.com/MatthiasValvekens/pdf-stamp',
    license='MIT License',
    author='Matthias Valvekens',
    author_email='dev@mvalvekens.be',
    description='Tools for stamping and signing PDF files',
    entry_points={
        "console_scripts": [
            "pdfstamp = pdfstamp.__main__:launch"
        ]
    }
)
