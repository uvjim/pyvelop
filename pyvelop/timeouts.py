"""Utilities for async wait and timeout helpers."""

import asyncio
import functools
import time
from collections.abc import Awaitable, Callable
from typing import Any

_NO_DEFAULT = object()


async def wait_for_predicate(
    probe: Callable[[], Awaitable[bool]],
    *,
    timeout: float = 300.0,
    interval: float = 5.0,
    exc_cls: type[Exception] = TimeoutError,
) -> None:
    """Poll a predicate until it returns True or the timeout expires."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if await probe():
            return
        await asyncio.sleep(interval)

    raise exc_cls(f"predicate did not become true within {timeout}s")


def with_timeout(
    timeout: float,
    *,
    default: Any = _NO_DEFAULT,
    exc_cls: type[Exception] = TimeoutError,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap an async call and enforce a timeout.

    :param timeout: Maximum time in seconds to wait for the async call.
    :param default: Optional value to return if the call times out.
    :param exc_cls: Exception type to raise when no default is provided.
    :returns: A wrapped async function that enforces the timeout.
    """

    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Execute the wrapped coroutine with timeout enforcement."""
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
            except TimeoutError as exc:
                if default is not _NO_DEFAULT:
                    return default
                raise exc_cls(f"{func.__name__} timed out after {timeout}s") from exc

        return wrapper

    return decorator
