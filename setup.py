#!/usr/bin/env python


import sys

from setuptools import setup

sys.stderr.write(
    """
    This version of pyhanko-certvalidator has dropped support for installation with `python setup.py install`.
    Please use `python -m pip install .` instead.
    """
)
sys.exit(1)


# The following workaround was borrowed from urllib3:
# https://github.com/urllib3/urllib3/blob/08fd892a49cacb5ea3a7e85eff4cbd0e9c5abbb6/setup.py
# The below code will never execute, however GitHub is particularly
# picky about where it finds Python packaging metadata.
# https://github.com/community/community/discussions/6456

setup(
    name="pyhanko-certvalidator",
    requires=[],
)
