"""Stable identity for a semantic state DAG node.

Lives in the portable `d810.ir` layer so both lowering code
(`d810.transforms.*`) and analysis code (`d810.analyses.*`) can reference the
same type without an upward import between those sibling portable-core packages.

`d810.analyses.control_flow.linearized_state_dag` re-exports `StateDagNodeKey` for
backwards compatibility with existing `from d810.analyses.control_flow.linearized_state_dag
import StateDagNodeKey` call sites.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StateDagNodeKey:
    """Stable identity for a state node."""

    handler_serial: int
    state_const: int | None = None
    range_lo: int | None = None
    range_hi: int | None = None


__all__ = ("StateDagNodeKey",)
