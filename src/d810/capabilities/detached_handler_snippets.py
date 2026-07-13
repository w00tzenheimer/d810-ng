"""Portable capability seam for between-decompile snippet preparation.

The UI layer must be importable without IDA or Hex-Rays.  The concrete
computed-goto implementation therefore registers its preparer here when the
resolver is installed; UI actions invoke this facade without importing the
optimizer or its vendor backend dependencies.
"""

from __future__ import annotations

import threading

from d810.core.typing import Any, Protocol


class DetachedHandlerSnippetPreparer(Protocol):
    """Prepare detached handler templates between top-level decompilations."""

    def __call__(
        self,
        function_ea: int,
        *,
        live_mba: Any | None = None,
    ) -> int: ...


_lock = threading.Lock()
_preparer: DetachedHandlerSnippetPreparer | None = None


def register_detached_handler_snippet_preparer(
    preparer: DetachedHandlerSnippetPreparer,
) -> None:
    """Install the active high-layer implementation."""
    global _preparer
    with _lock:
        _preparer = preparer


def unregister_detached_handler_snippet_preparer(
    preparer: DetachedHandlerSnippetPreparer,
) -> None:
    """Remove ``preparer`` without clearing a newer replacement."""
    global _preparer
    with _lock:
        if _preparer is preparer:
            _preparer = None


def prepare_detached_handler_snippets(
    function_ea: int,
    *,
    live_mba: Any | None = None,
) -> int:
    """Run the registered preparer, or safely do nothing when absent."""
    with _lock:
        preparer = _preparer
    if preparer is None:
        return 0
    return int(preparer(int(function_ea), live_mba=live_mba))


def reset_detached_handler_snippet_preparer_for_tests() -> None:
    """Clear the capability registry for test isolation."""
    global _preparer
    with _lock:
        _preparer = None


__all__ = [
    "DetachedHandlerSnippetPreparer",
    "prepare_detached_handler_snippets",
    "register_detached_handler_snippet_preparer",
    "reset_detached_handler_snippet_preparer_for_tests",
    "unregister_detached_handler_snippet_preparer",
]
