"""The pyvelop module."""

# region #-- imports --#
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    pass

import re

# endregion


def camel_to_snake(to_convert: str) -> str:
    """Convert from camel case to snake case."""
    ret = re.sub("(.)([A-Z][a-z])+", r"\1_\2", to_convert)
    return ret.lower()


def signal_strength_to_text(rssi: int | None) -> str | None:
    """Convert the given RSSI value to a textual representation."""
    ret: str | None = None
    if rssi is not None:
        if rssi <= 0:
            ret = "Excellent"
        if rssi <= -50:
            ret = "Good"
        if rssi <= -60:
            ret = "Fair"
        if rssi <= -70:
            ret = "Weak"

    return ret
