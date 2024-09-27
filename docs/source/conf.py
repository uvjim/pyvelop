"""Sphinx configuration."""

import os
import sys

import sphinx_rtd_theme

sys.path.insert(0, os.path.abspath("../.."))

from pyvelop.const import _PACKAGE_AUTHOR, _PACKAGE_NAME

# -- Project information -----------------------------------------------------
project = _PACKAGE_NAME
copyright = f"2024, {_PACKAGE_AUTHOR}"
author = _PACKAGE_AUTHOR


# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_rtd_theme",
]

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
