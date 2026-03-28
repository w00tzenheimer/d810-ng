"""Helpers for augmenting handler-state maps from dispatcher intervals."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from d810.core.typing import Mapping


@dataclass(frozen=True, slots=True)
class IntervalHandlerBackfill:
    """One uniquely-owned interval row promoted into ``handler_state_map``."""

    target: int
    lo: int
    hi: int


def collect_unique_interval_handler_backfills(
    handler_state_map: Mapping[int, int],
    dispatcher: object | None,
) -> tuple[IntervalHandlerBackfill, ...]:
    """Collect unique dispatcher rows that should augment ``handler_state_map``.

    This preserves the current LFG behavior: only rows whose target appears
    exactly once in the interval dispatcher are promoted. Multi-row targets are
    treated as catch-all/default blocks and skipped.
    """
    if dispatcher is None:
        return ()

    rows = tuple(getattr(dispatcher, "_rows", ()) or ())
    if not rows:
        return ()

    existing_handler_serials = set(int(serial) for serial in handler_state_map.keys())
    target_freq: dict[int, int] = Counter(
        int(row.target)
        for row in rows
        if getattr(row, "target", None) is not None
    )

    backfills: list[IntervalHandlerBackfill] = []
    for row in rows:
        target = getattr(row, "target", None)
        if target is None:
            continue
        target = int(target)
        if target in existing_handler_serials:
            continue
        if target_freq[target] > 1:
            continue
        backfills.append(
            IntervalHandlerBackfill(
                target=target,
                lo=int(row.lo),
                hi=int(row.hi),
            )
        )
    return tuple(backfills)


__all__ = [
    "IntervalHandlerBackfill",
    "collect_unique_interval_handler_backfills",
]
