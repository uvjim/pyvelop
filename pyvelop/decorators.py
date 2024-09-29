"""Decorators."""

# region #-- imports --#
from __future__ import annotations

import functools

from .exceptions import MeshNeedsGatherDetails

# endregion


def needs_gather_details(func):
    """Ensure that async_gather_details has been executed."""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        """Wrap the required function."""
        if not getattr(self, "_Mesh__gather_details_executed", False):
            raise MeshNeedsGatherDetails from None
        ret = func(self, *args, **kwargs)
        return ret

    return wrapper
