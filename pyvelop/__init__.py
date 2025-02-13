"""The pyvelop module."""

# region #-- imports --#
from __future__ import annotations

import contextlib
from importlib.metadata import PackageNotFoundError, version

with contextlib.suppress(PackageNotFoundError):
    __version__ = version(__name__)

import re

# endregion


def camel_to_snake(to_convert: str) -> str:
    """Convert from camel case to snake case."""
    ret = re.sub("(.)([A-Z][a-z])+", r"\1_\2", to_convert)
    return ret.lower()
