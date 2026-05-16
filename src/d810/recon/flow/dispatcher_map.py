"""Exact state-dispatcher row model.

This model is intentionally dispatcher-shape neutral. Equality chains,
interval trees, and future switch-table adapters can all provide the same
core relation: concrete state constant -> handler entry block.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.recon.flow.dispatcher_detection import DispatcherType


@dataclass(frozen=True, slots=True)
class StateDispatcherRow:
    """One exact dispatcher row: ``state_const`` routes to ``target_block``."""

    state_const: int
    target_block: int
    dispatcher_block: int
    compare_block: int
    branch_kind: str
    source: DispatcherType
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class StateDispatcherMap:
    """Exact dispatcher table for one dispatcher entry."""

    rows: tuple[StateDispatcherRow, ...]
    dispatcher_entry_block: int
    dispatcher_blocks: frozenset[int]
    state_var_stkoff: int | None
    state_var_lvar_idx: int | None
    source: DispatcherType
    initial_state: int | None = None

    def state_to_handler(self) -> dict[int, int]:
        """Return ``state_const -> handler_block``."""
        return {int(row.state_const): int(row.target_block) for row in self.rows}

    def handler_state_map(self) -> dict[int, int]:
        """Return ``handler_block -> state_const`` for DispatcherHandlerMap."""
        return {int(row.target_block): int(row.state_const) for row in self.rows}

    def resolve_target(self, state_value: int) -> int | None:
        """Resolve a concrete state value to a handler block."""
        return self.state_to_handler().get(int(state_value))

    def to_dispatcher_handler_map(self):
        """Convert to the existing dispatcher-agnostic handler map."""
        from d810.recon.flow.dispatcher_handler_map import DispatcherHandlerMap

        return DispatcherHandlerMap.from_state_dispatcher_map(self)


__all__ = [
    "StateDispatcherMap",
    "StateDispatcherRow",
]
