# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath('../pkgs/pyhanko/src'))

import sphinx_rtd_theme

def get_version():
    from os import path

    current_tag_output = subprocess.check_output(['git', 'tag', '--points-at', 'HEAD'])
    tags = [x for x in current_tag_output.decode('utf-8').splitlines() if x.startswith('v')]
    if not tags:
        version = "0.0.0.dev1"
    else:
        version = tags[0]

    return version

# -- Project information -----------------------------------------------------

project = 'pyHanko'
copyright = '2020-2025, Matthias Valvekens'
author = 'Matthias Valvekens'

# The full version, including alpha/beta/rc tags
release = get_version()
version = release.split('-')[0]  # strip the release tag


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ['sphinx.ext.autodoc', 'sphinx_rtd_theme']

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = []


# Order module/class members by source order.

autodoc_member_order = 'bysource'


# number figures
numfig = True
