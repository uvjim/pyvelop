"""Decorators."""

# region #-- imports --#
from __future__ import annotations

import functools

from .exceptions import MeshNeedsInitialise

# endregion


def needs_initialise(func):
    """Ensure that async_initialise has been executed."""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        """Wrap the required function."""
        if not getattr(self, "_Mesh__initialise_executed", False):
            raise MeshNeedsInitialise from None
        ret = func(self, *args, **kwargs)
        return ret

    return wrapper
