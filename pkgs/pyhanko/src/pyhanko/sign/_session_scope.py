"""
Internal helpers bounding the lifetime of implicitly provisioned HTTP
sessions.
"""

from collections.abc import Awaitable
from typing import TypeVar

from pyhanko_certvalidator import ValidationContext

__all__ = ['run_and_release']

T = TypeVar('T')


async def run_and_release(
    coro: Awaitable[T], *contexts: ValidationContext | None
) -> T:
    """
    Await a coroutine, then release the network resources that the given
    validation contexts provisioned for themselves.

    A synchronous entry point is one top-level operation, which is exactly how
    long a default session lives. The release happens inside the coroutine
    rather than around it, so that it runs while the event loop that opened the
    session is still there to close it.
    """

    try:
        return await coro
    finally:
        for validation_context in contexts:
            if validation_context is not None:
                await validation_context.aclose()
