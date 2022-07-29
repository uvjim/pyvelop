"""Sphinx configuration.

isort:skip_file
"""

import os
import sys

import sphinx_rtd_theme

sys.path.insert(0, os.path.abspath('../..'))

from pyvelop.const import (_PACKAGE_AUTHOR,  # noqa pylint: disable=import-error, wrong-import-position
                           _PACKAGE_NAME)

# -- Project information -----------------------------------------------------
project = _PACKAGE_NAME
copyright = f"2022, {_PACKAGE_AUTHOR}"  # pylint: disable=redefined-builtin
author = _PACKAGE_AUTHOR


# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_rtd_theme",
]

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"  # pylint: disable=invalid-name
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
