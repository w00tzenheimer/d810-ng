"""Function-scoped terminal-tail layout priors.

These priors are explicit caller/project knowledge.  They are not inferred by
the Hodur runtime and are not generic terminal-tail policy.  Runtime mutation
code may consume them after checking the live CFG still matches the supplied
evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Iterable


@dataclass(frozen=True, slots=True)
class TerminalTailRowTargetOverride:
    """Redirect one byte row through another byte's terminal entry block."""

    byte_index: int
    target_entry_byte_index: int


@dataclass(frozen=True, slots=True)
class TerminalTailContinuationBridgePrior:
    """Bridge a byte source-loader on another byte's continuation path."""

    continuation_byte_index: int
    source_byte_index: int
    target_store_guard_byte_index: int
    max_depth: int = 8


@dataclass(frozen=True, slots=True)
class TerminalTailEqualityFrontierPriors:
    """Allowed terminal equality-frontier closure candidates."""

    return_frontier_byte_index: int
    row_byte_indices: tuple[int, ...] = ()
    shared_store_guard_byte_indices: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class TerminalTailEntryFrontierPriors:
    """Allowed terminal-tail entry closure candidate."""

    first_byte_index: int


@dataclass(frozen=True, slots=True)
class TerminalTailCascadeEgressPriors:
    """Explicit cascade-egress policy for one known function shape."""

    byte_indices: tuple[int, ...] = ()
    split_byte_indices: tuple[int, ...] = ()
    row_target_overrides: tuple[TerminalTailRowTargetOverride, ...] = ()
    continuation_bridges: tuple[TerminalTailContinuationBridgePrior, ...] = ()
    equality_frontier: TerminalTailEqualityFrontierPriors | None = None
    entry_frontier: TerminalTailEntryFrontierPriors | None = None

    @property
    def is_empty(self) -> bool:
        return (
            not self.byte_indices
            and not self.split_byte_indices
            and not self.row_target_overrides
            and not self.continuation_bridges
            and self.equality_frontier is None
            and self.entry_frontier is None
        )

    def merge(
        self,
        other: "TerminalTailCascadeEgressPriors | None",
    ) -> "TerminalTailCascadeEgressPriors":
        if other is None or other.is_empty:
            return self
        if self.is_empty:
            return other
        return TerminalTailCascadeEgressPriors(
            byte_indices=_merge_ints(self.byte_indices, other.byte_indices),
            split_byte_indices=_merge_ints(
                self.split_byte_indices,
                other.split_byte_indices,
            ),
            row_target_overrides=_merge_objects(
                self.row_target_overrides,
                other.row_target_overrides,
            ),
            continuation_bridges=_merge_objects(
                self.continuation_bridges,
                other.continuation_bridges,
            ),
            equality_frontier=other.equality_frontier or self.equality_frontier,
            entry_frontier=other.entry_frontier or self.entry_frontier,
        )


def _merge_ints(left: Iterable[int], right: Iterable[int]) -> tuple[int, ...]:
    return tuple(
        dict.fromkeys(
            [*(int(item) for item in left), *(int(item) for item in right)]
        )
    )


def _merge_objects(left: Iterable[object], right: Iterable[object]) -> tuple:
    return tuple(dict.fromkeys((*tuple(left), *tuple(right))))


__all__ = [
    "TerminalTailCascadeEgressPriors",
    "TerminalTailContinuationBridgePrior",
    "TerminalTailEntryFrontierPriors",
    "TerminalTailEqualityFrontierPriors",
    "TerminalTailRowTargetOverride",
]
