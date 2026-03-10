"""InnerMergeDuplicationStrategy -- tail-duplicate DAG merge blocks.

After Hodur linearization, some blocks have 2+ predecessors from different
handler chains.  IDA's structurer cannot nest these DAG merge points and
emits gotos instead.  Tail-duplicating the merge block gives each
predecessor its own private copy, enabling IDA to inline the block into
each handler chain.

Safety gates:
 - Size budget: blocks with more than ``MAX_MERGE_INSNS`` instructions
   are skipped (too expensive to clone).
 - Loop guard: blocks inside SCCs are never duplicated (they are loop
   bodies/headers, not DAG merge points).
 - Infrastructure guard: dispatcher, BST, entry and stop blocks are
   excluded.
 - Total clone budget: at most ``MAX_TOTAL_CLONES`` duplications per
   function to bound code-size growth.
"""
from __future__ import annotations

from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    collect_state_machine_blocks,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_CLEANUP,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.inner_merge_duplication")

__all__ = ["InnerMergeDuplicationStrategy"]

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

MAX_MERGE_INSNS: int = 8
"""Maximum instruction count for a merge block to be eligible for cloning."""

MAX_CHAIN_DEPTH: int = 2
"""Reserved for future chained-merge detection (unused in v1)."""

MAX_TOTAL_CLONES: int = 12
"""Maximum total DuplicateBlock modifications emitted per function."""


# ---------------------------------------------------------------------------
# SCC computation (Tarjan's iterative)
# ---------------------------------------------------------------------------


def _compute_sccs(
    adj: dict[int, list[int]],
    all_nodes: set[int],
) -> list[frozenset[int]]:
    """Compute strongly connected components using iterative Tarjan's algorithm.

    Args:
        adj: Adjacency list (serial -> list of successor serials).
        all_nodes: Complete set of node serials in the graph.

    Returns:
        List of SCCs, each as a frozenset of block serials.
        Single-node SCCs without self-loops are included but filtered
        by callers.
    """
    index_counter = [0]
    node_index: dict[int, int] = {}
    node_lowlink: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[int] = []
    sccs: list[frozenset[int]] = []

    for node in sorted(all_nodes):
        if node in node_index:
            continue
        # Iterative DFS using an explicit work stack.
        # Each frame is (node, successor_iterator, is_root_call).
        work: list[tuple[int, int]] = []  # (node, succ_index)
        work.append((node, 0))
        node_index[node] = index_counter[0]
        node_lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)

        while work:
            v, si = work[-1]
            succs = adj.get(v, [])
            if si < len(succs):
                work[-1] = (v, si + 1)
                w = succs[si]
                if w not in node_index:
                    # Tree edge: push w
                    node_index[w] = index_counter[0]
                    node_lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, 0))
                elif w in on_stack:
                    node_lowlink[v] = min(node_lowlink[v], node_index[w])
            else:
                # All successors processed; check if v is SCC root.
                if node_lowlink[v] == node_index[v]:
                    scc_members: list[int] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        scc_members.append(w)
                        if w == v:
                            break
                    sccs.append(frozenset(scc_members))
                # Pop frame and propagate lowlink to parent.
                work.pop()
                if work:
                    parent = work[-1][0]
                    node_lowlink[parent] = min(
                        node_lowlink[parent], node_lowlink[v]
                    )

    return sccs


def _blocks_in_nontrivial_sccs(
    adj: dict[int, list[int]],
    all_nodes: set[int],
) -> frozenset[int]:
    """Return the set of block serials that belong to non-trivial SCCs.

    A non-trivial SCC is one with more than one node, OR a single node
    with a self-loop.

    Args:
        adj: Adjacency list.
        all_nodes: Complete set of node serials.

    Returns:
        Frozenset of block serials inside loops.
    """
    sccs = _compute_sccs(adj, all_nodes)
    in_loop: set[int] = set()
    for scc in sccs:
        if len(scc) > 1:
            in_loop.update(scc)
        elif len(scc) == 1:
            (sole,) = scc
            if sole in adj.get(sole, []):
                in_loop.add(sole)
    return frozenset(in_loop)


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------


class InnerMergeDuplicationStrategy:
    """Tail-duplicate small DAG merge blocks to eliminate structurer gotos.

    Runs after direct linearization (FAMILY_CLEANUP).  For each non-loop
    block with >= 2 predecessors that is small enough, emits
    :class:`~d810.cfg.graph_modification.DuplicateBlock` modifications so
    that each predecessor except the lowest-serial one gets a private copy.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "inner_merge_duplication"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when direct linearization has already run.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if ``pass_number >= 1`` and the flow graph is available.
        """
        if snapshot.pass_number < 1:
            return False
        if snapshot.flow_graph is None:
            return False
        if snapshot.bst_result is None:
            return False
        if snapshot.state_machine is None:
            return False
        return True

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with DuplicateBlock edits for merge points.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with DuplicateBlock modifications, or ``None``
            when the strategy has nothing to contribute.
        """
        if not self.is_applicable(snapshot):
            return None

        fg: FlowGraph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        state_machine = snapshot.state_machine

        # ---- Build infrastructure exclusion set ----
        sm_blocks = collect_state_machine_blocks(state_machine)
        bst_node_blocks: set[int] = set(
            getattr(bst_result, "bst_node_blocks", set()) or set()
        )
        bst_node_blocks.add(dispatcher_serial)

        # Entry and stop block
        entry_serial = fg.entry_serial
        max_serial = max(fg.blocks.keys()) if fg.blocks else -1
        stop_serial = max_serial  # BLT_STOP is always the last block

        full_infra: frozenset[int] = frozenset(
            bst_node_blocks
            | sm_blocks
            | {entry_serial, stop_serial}
        )

        # ---- Build adjacency list and compute SCC membership ----
        adj = fg.as_adjacency_dict()
        all_nodes = set(fg.blocks.keys())
        loop_blocks = _blocks_in_nontrivial_sccs(adj, all_nodes)

        # ---- Identify eligible merge blocks ----
        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        total_clones = 0

        for serial, blk in sorted(fg.blocks.items()):
            if blk.npred < 2:
                continue
            if serial in full_infra:
                continue
            if serial in loop_blocks:
                continue
            # Size gate
            insn_count = len(blk.insn_snapshots)
            if insn_count > MAX_MERGE_INSNS:
                continue
            # Budget gate
            needed_clones = blk.npred - 1
            if total_clones + needed_clones > MAX_TOTAL_CLONES:
                logger.info(
                    "[inner-merge] skipping blk[%d] (npred=%d): would exceed "
                    "clone budget (%d + %d > %d)",
                    serial,
                    blk.npred,
                    total_clones,
                    needed_clones,
                    MAX_TOTAL_CLONES,
                )
                continue

            # Emit DuplicateBlock for each predecessor except the first
            # (lowest serial keeps the original block).
            sorted_preds = sorted(blk.preds)
            keep_pred = sorted_preds[0]

            for pred_serial in sorted_preds[1:]:
                mod = builder.duplicate_block(
                    source_block=serial,
                    target_block=None,
                    pred_serial=pred_serial,
                    patch_kind="inner_merge",
                )
                modifications.append(mod)
                owned_edges.add((pred_serial, serial))
                total_clones += 1

            owned_blocks.add(serial)
            logger.info(
                "[inner-merge] blk[%d] npred=%d insns=%d clones=%d "
                "keep_pred=%d",
                serial,
                blk.npred,
                insn_count,
                needed_clones,
                keep_pred,
            )

        if not modifications:
            return None

        logger.info(
            "[inner-merge] emitting %d DuplicateBlock modifications "
            "(%d merge blocks, %d total clones)",
            len(modifications),
            len(owned_blocks),
            total_clones,
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset(owned_edges),
                transitions=frozenset(),
            ),
            prerequisites=["direct_handler_linearization"],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.2,
            metadata={
                "safeguard_min_required": len(modifications),
                "total_clones": total_clones,
                "merge_blocks": sorted(owned_blocks),
            },
        )
