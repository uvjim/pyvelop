"""Sphinx configuration."""

import os
import sys

import sphinx_rtd_theme

sys.path.insert(0, os.path.abspath("../.."))

PACKAGE_AUTHOR = "uvjim"

# -- Project information -----------------------------------------------------
project = __package__
copyright = f"2024, {PACKAGE_AUTHOR}"
author = PACKAGE_AUTHOR


# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_rtd_theme",
]

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
