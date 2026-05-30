"""Exact state-dispatcher row model.

This model is intentionally dispatcher-shape neutral. Equality chains,
interval trees, and future switch-table adapters can all provide the same
core relation: concrete state constant -> handler entry block.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.analyses.control_flow.dispatcher_kind import DispatcherType


@dataclass(frozen=True, slots=True)
class StateDispatcherRow:
    """One exact dispatcher row: ``state_const`` routes to ``target_block``."""

    state_const: int
    target_block: int
    dispatcher_block: int
    compare_block: int | None
    branch_kind: str
    source: DispatcherType
    confidence: float = 1.0
    row_kind: str = "handler"
    payload: dict[str, object] = field(default_factory=dict)

    @property
    def is_handler_row(self) -> bool:
        """Whether this row names a semantic handler entry."""
        return self.row_kind in {"handler", "handler_alias"}

    @property
    def is_dispatcher_self_loop(self) -> bool:
        """Whether this exact state routes back to the dispatcher."""
        return self.row_kind == "dispatcher_self_loop"


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
    default_target_block: int | None = None
    default_row_kind: str | None = None

    def state_to_handler(self) -> dict[int, int]:
        """Return exact ``state_const -> target_block`` rows.

        This intentionally includes exact dispatcher self-loop rows: they are
        part of the state-machine table even though older handler-map adapters
        skip them.
        """
        return {int(row.state_const): int(row.target_block) for row in self.rows}

    def handler_state_map(self) -> dict[int, int]:
        """Return lossy ``handler_block -> first_state_const`` adapter rows.

        ``DispatcherHandlerMap`` cannot represent switch aliases or dispatcher
        self-loops. Keep those in ``StateDispatcherMap.rows`` and expose only a
        compatibility view here for existing consumers.
        """
        handler_map: dict[int, int] = {}
        for row in self.rows:
            if not row.is_handler_row:
                continue
            handler_map.setdefault(int(row.target_block), int(row.state_const))
        return handler_map

    def states_by_target(self) -> dict[int, tuple[int, ...]]:
        """Return every exact state value grouped by target block."""
        grouped: dict[int, list[int]] = {}
        for row in self.rows:
            grouped.setdefault(int(row.target_block), []).append(int(row.state_const))
        return {
            target: tuple(states)
            for target, states in grouped.items()
        }

    def resolve_target(self, state_value: int) -> int | None:
        """Resolve a concrete state value to a handler block."""
        return self.state_to_handler().get(int(state_value))

    def to_dispatcher_handler_map(self):
        """Convert to the existing dispatcher-agnostic handler map."""
        from d810.analyses.control_flow.dispatcher_handler_map import DispatcherHandlerMap

        return DispatcherHandlerMap.from_state_dispatcher_map(self)


__all__ = [
    "StateDispatcherMap",
    "StateDispatcherRow",
]
