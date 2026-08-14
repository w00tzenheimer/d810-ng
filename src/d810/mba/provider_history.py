"""Bounded, cursor-addressable storage for MBA provider outcomes.

Provider adapters are long-lived for an IDA session.  This utility keeps their
observability state bounded while letting corpus capture request an exact delta.
If a capture cursor is evicted, the caller must fail closed rather than report
an incomplete decompilation as complete evidence.
"""

from __future__ import annotations

from collections import deque

from d810.core.typing import Generic, TypeVar


T = TypeVar("T")


# A single native decompilation can revisit one rule across several maturity
# passes and the manifest corpus has observed more than 64 callbacks for one
# selected rule.  256 is still a hard per-provider bound; capture windows are
# cleared before each decompilation so it is never session-growing state.
DEFAULT_PROVIDER_OUTCOME_HISTORY_CAPACITY = 256


class ProviderOutcomeHistoryTruncated(ValueError):
    """A requested capture cursor predates the bounded history window."""


class ProviderOutcomeHistory(Generic[T]):
    """Fixed-capacity outcome history with stable, monotonic cursors."""

    def __init__(
        self, *, capacity: int = DEFAULT_PROVIDER_OUTCOME_HISTORY_CAPACITY
    ) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("provider outcome history capacity must be positive")
        self._capacity = capacity
        self._entries: deque[tuple[int, T]] = deque()
        self._next_cursor = 0

    @property
    def cursor(self) -> int:
        """Return the cursor immediately after the newest recorded outcome."""

        return self._next_cursor

    def clear(self) -> None:
        """Discard one completed capture window without reusing cursors."""

        self._entries.clear()

    def append(self, outcome: T) -> int:
        """Record one outcome and return its stable cursor."""

        cursor = self._next_cursor
        self._next_cursor += 1
        self._entries.append((cursor, outcome))
        if len(self._entries) > self._capacity:
            self._entries.popleft()
        return cursor

    def replace(self, cursor: int, outcome: T) -> None:
        """Replace the finalization state for one still-retained attempt."""

        for index, (entry_cursor, _entry) in enumerate(self._entries):
            if entry_cursor == cursor:
                self._entries[index] = (cursor, outcome)
                return
        raise ProviderOutcomeHistoryTruncated(
            "provider outcome was evicted before mutation finalization"
        )

    def outcomes(self) -> tuple[T, ...]:
        """Return the bounded retained history in observation order."""

        return tuple(outcome for _cursor, outcome in self._entries)

    def since(self, cursor: int) -> tuple[T, ...]:
        """Return outcomes at or after ``cursor``, rejecting evicted capture."""

        if type(cursor) is not int or cursor < 0 or cursor > self._next_cursor:
            raise ValueError("invalid provider outcome history cursor")
        first_cursor = self._entries[0][0] if self._entries else self._next_cursor
        if cursor < first_cursor:
            raise ProviderOutcomeHistoryTruncated(
                "provider outcome history was truncated after the capture cursor"
            )
        return tuple(
            outcome for entry_cursor, outcome in self._entries if entry_cursor >= cursor
        )


__all__ = [
    "DEFAULT_PROVIDER_OUTCOME_HISTORY_CAPACITY",
    "ProviderOutcomeHistory",
    "ProviderOutcomeHistoryTruncated",
]
