"""Utilities for async wait and timeout helpers."""

import asyncio
import functools
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

_NO_DEFAULT = object()


async def poll_with_yield[T](
    probe: Callable[[], Awaitable[T]],
    *,
    interval: float = 5.0,
    timeout: float = 300.0,
) -> AsyncIterator[T]:
    """Poll an asynchronous callable at regular intervals.

    The result of every probe call is yielded. Polling stops when `timeout`
    expires.

    :param probe: Asynchronous callable that retrieves the value to be polled.
    :param interval: Minimum delay between probe calls, in seconds.
    :param timeout: Maximum polling duration, in seconds.
    :raises ValueError: If `interval` is negative or `timeout` is not greater than zero.
    :raises TimeoutError: If the timeout expires before polling completes.
    :yields: The value returned by each invocation of ``probe``.
    """
    if interval < 0:
        raise ValueError("interval must be non-negative")

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    deadline = time.monotonic() + timeout

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            raise TimeoutError(f"probe did not complete within {timeout}s")

        value = await probe()
        yield value

        remaining = deadline - time.monotonic()

        if remaining <= 0:
            raise TimeoutError(f"probe did not complete within {timeout}s")

        await asyncio.sleep(min(interval, remaining))


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
