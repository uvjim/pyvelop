"""Decorators."""

# region #-- imports --#
from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any, Concatenate, ParamSpec, TypeVar, cast

from .exceptions import MeshNeedsInitialise

P = ParamSpec("P")
R = TypeVar("R")

# endregion


F = TypeVar("F", bound=Callable[..., Any])


def deprecated(solution: str) -> Callable[[F], F]:
    """Mark a method as deprecated."""

    def deprecated_decorator(func: F) -> F:
        """Decorate the function."""

        def deprecated_wrapper(*args: Any, **kwargs: Any) -> Any:
            """Wrap for the original function."""
            logger = logging.getLogger(func.__module__)
            log_formatter = getattr(args[0], "_log_formatter", None)
            if log_formatter is not None:
                logger.warning(
                    log_formatter.format(
                        "The %s method has been deprecated. %s",
                        include_caller=False,
                    ),
                    func.__name__,
                    solution,
                )

            return func(*args, **kwargs)

        return cast(F, functools.wraps(func)(deprecated_wrapper))

    return deprecated_decorator


def needs_initialise(
    func: Callable[Concatenate[Any, P], R],
) -> Callable[Concatenate[Any, P], R]:
    """Ensure that async_initialise has been executed."""

    def wrapper(self: Any, *args: P.args, **kwargs: P.kwargs) -> R:
        """Wrap the required function."""
        if not getattr(self, "_Mesh__initialise_executed", False):
            raise MeshNeedsInitialise from None
        return func(self, *args, **kwargs)

    return cast(Callable[Concatenate[Any, P], R], functools.wraps(func)(wrapper))
