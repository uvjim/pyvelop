# noinspection PyUnresolvedReferences
import sphinx_rtd_theme

# -- Imports for package constants -------------------------------------------
# noinspection PyProtectedMember
from pyvelop.const import (
    _PACKAGE_AUTHOR,
    _PACKAGE_NAME,
)


# -- Project information -----------------------------------------------------
project = _PACKAGE_NAME
copyright = f"2021, {_PACKAGE_AUTHOR}"
author = _PACKAGE_AUTHOR


# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_rtd_theme",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = ['_static']
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
