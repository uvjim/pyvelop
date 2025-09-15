"""Decorators."""

# region #-- imports --#
from __future__ import annotations

import functools
import logging

from .exceptions import MeshNeedsInitialise

# endregion


def deprecated(solution: str):
    """Mark a method as deprecated."""

    def deprecated_decorator(func):
        """Decorate the function."""

        @functools.wraps(func)
        def deprecated_wrapper(self, *args, **kwargs):
            """Wrap for the original function."""
            logger = logging.getLogger(func.__module__)
            log_formatter = getattr(self, "_log_formatter", None)
            if log_formatter is not None:
                logger.warning(
                    log_formatter.format(
                        "The %s method has been deprecated. %s",
                        include_caller=False,
                    ),
                    func.__name__,
                    solution,
                )

            return func(self, *args, **kwargs)

        return deprecated_wrapper

    return deprecated_decorator


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
