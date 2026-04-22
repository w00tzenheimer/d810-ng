"""Stable identity for a semantic state DAG node.

Lives in the cfg layer so both `d810.cfg.*` lowering code and `d810.recon.flow.*`
analysis code can reference the same type without creating an upward import
from cfg to recon (which the layered import-linter contract forbids).

`d810.recon.flow.linearized_state_dag` re-exports `StateDagNodeKey` for
backwards compatibility with existing `from d810.recon.flow.linearized_state_dag
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
