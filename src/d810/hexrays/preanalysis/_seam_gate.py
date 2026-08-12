"""Shared policy gate for the pre-lift seam registries.

Each seam registry keeps its own handler dict and its own dispatch signature;
only the gating decision is shared, so this module stays a filter rather than a
framework.

The gate is applied at dispatch rather than at registration because a policy is
per function: the same handler is permitted for one function and suppressed for
the next, and registration happens once at plugin load.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from d810.core.normalization_policy import Seam, decide, handler_is_permitted

__all__ = ["RegisteredSeamHandler", "permitted_seam_handlers"]


@dataclass(frozen=True, slots=True)
class RegisteredSeamHandler:
    """A seam handler plus the one property the gate needs from it.

    ``read_only`` defaults to False so a handler that predates the gate, or one
    whose author did not think about it, is treated as a mutator. The safe
    default is the restrictive one.
    """

    handler: Callable[..., None]
    read_only: bool = False


def permitted_seam_handlers(
    seam: Seam,
    function_ea: int,
    handlers: Mapping[str, RegisteredSeamHandler],
) -> list[tuple[str, Callable[..., None]]]:
    """Return the ``(name, handler)`` pairs allowed to run for this function.

    The policy is consulted once per dispatch, not once per handler, so a
    registry cannot observe two different verdicts within a single seam
    invocation.
    """
    verdict = decide(function_ea, seam)
    return [
        (name, entry.handler)
        for name, entry in tuple(handlers.items())
        if handler_is_permitted(verdict, read_only=entry.read_only)
    ]
