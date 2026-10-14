"""The pyvelop module."""

# region #-- imports --#
from __future__ import annotations

import contextlib
from importlib.metadata import PackageNotFoundError, version

# endregion

__version__ = "from source"
with contextlib.suppress(PackageNotFoundError):
    __version__ = version(__name__)
