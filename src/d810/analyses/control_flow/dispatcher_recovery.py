"""Recover the state-machine dispatcher structure from a portable FlowGraph (§1a pass #1).

LLVM-analysis / LiSA-CFG style: an analysis pass that reads only the portable ``FlowGraph`` and
produces an immutable result (``DispatcherRecovery``) — no microcode patching, no live ``mba``.

First real body: forward reachability over the FlowGraph (the shared
``analyses.control_flow.reachability`` primitive, also used by the live snapshot policy). The
dispatcher-block + state-var identification is the remaining seam from ``hodur/snapshot_builder``
+ ``engine/planner`` (push the live state-machine detection behind ``MicrocodeEvidenceProvider``);
until then those fields stay ``None`` and only reachability is populated.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.reachability import reachable_from


@dataclass(frozen=True, slots=True)
class DispatcherRecovery:
    """Portable result of dispatcher recovery over a FlowGraph."""

    reachable_block_serials: frozenset[int] = frozenset()
    dispatcher_block_serial: int | None = None
    bst_block_serials: tuple[int, ...] = ()
    state_var_stkoff: int | None = None


def recover_dispatcher(
    graph: FlowGraph | None, facts: ValidatedFactView | None
) -> DispatcherRecovery:
    """Recover dispatcher structure over a portable ``FlowGraph``.

    Real today: blocks reachable from the entry (shared reachability primitive). Seam-pending:
    dispatcher-block + state-var identification from ``hodur/snapshot_builder`` + ``engine/planner``.
    """
    if graph is None:
        return DispatcherRecovery()
    adjacency = {serial: graph.successors(serial) for serial in graph.blocks}
    reachable = reachable_from(adjacency, graph.block_count, graph.entry_serial)
    return DispatcherRecovery(reachable_block_serials=reachable)
