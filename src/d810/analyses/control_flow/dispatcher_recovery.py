"""Recover the state-machine dispatcher structure from a portable FlowGraph (§1a pass #1).

WORK-LIST / seam source: extract the portable detection currently trapped in
``optimizers/.../hodur/snapshot_builder.py`` (block-topology reachability + maturity gates,
routed through ``MicrocodeEvidenceProvider``) and ``engine/planner.py``. Until that seam lands
this is a behavior-neutral skeleton: it reads only the portable ``FlowGraph`` + validated facts
and is NOT wired into the live runtime (the live path remains ``HodurUnflattener``).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView


@dataclass(frozen=True, slots=True)
class DispatcherRecovery:
    """Portable result of dispatcher recovery: the dispatcher block + BST block set."""

    dispatcher_block_serial: int | None = None
    bst_block_serials: tuple[int, ...] = ()
    state_var_stkoff: int | None = None


def recover_dispatcher(graph: FlowGraph, facts: ValidatedFactView) -> DispatcherRecovery:
    """Locate the dispatcher + BST blocks over a portable ``FlowGraph``.

    Skeleton (seam pending): returns an empty recovery. Seam-extract from
    ``hodur/snapshot_builder`` + ``engine/planner``, pushing live ``mba`` reachability behind
    ``MicrocodeEvidenceProvider`` (graph-parameter, not mba-parameter).
    """
    return DispatcherRecovery()
