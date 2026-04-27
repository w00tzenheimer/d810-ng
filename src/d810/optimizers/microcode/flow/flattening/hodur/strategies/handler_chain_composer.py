"""HandlerChainComposerStrategy -- region-based body composition (option β).

Ticket: ``uee-b7ze``.

Motivation
----------
After ``DirectLinearization``, byte-handler producers/consumers are placed
on diverging execution paths.  IDA's data-flow optimizer determines that
defs no longer dominate uses and DCEs them.  Empirical case on
``sub_7FFD3338C040``: bytes 1, 2, 4, 5 are written by handlers but wiped
from AFTER pseudocode despite being intact in our ``post_pipeline``
snapshot.

Strategy (region-based, NOT per-chain)
--------------------------------------
The previous per-chain implementation re-introduced the same use-def
severance problem we are trying to solve, because each per-chain
``InsertBlock`` lives in its own block: chain ``N``'s def lives in chain
``N``'s inserted block but is consumed by chain ``N+1``'s inserted block,
which is a different block, so dominance is again non-trivial.

This rewrite collapses an *entire DAG region* — a maximal linear path
through the recon ``LinearizedStateDag`` — into ONE composed straight-line
``InsertBlock``.  Within a single block, def→use dominance is trivially
preserved (instruction order = dominance order).

Region definition
-----------------
Walk the recon DAG (``snapshot.discovery.dag`` if available, otherwise
build live).  A region is a maximal linear path::

    state_0 --TRANSITION--> state_1 --TRANSITION--> ... --TRANSITION--> state_n

where each ``state_i`` has exactly ONE outgoing TRANSITION edge AND the
target node has exactly ONE incoming TRANSITION edge.  Branching states
or terminal states close the region.

Body composition
----------------
For each ``StateDagNode`` in the region, walk live ``mblock_t`` for
``node.entry_anchor`` and capture all instructions EXCEPT:
* the state-write ``m_mov #STATE, %var_<state_var_stkoff>`` — we are
  collapsing the state machine, no need to write the next state;
* trailing ``m_goto`` / ``m_nop`` — we are replacing the chain entirely,
  not redirecting through the dispatcher.

Concatenate per-node captured instructions into ``tuple[InsnSnapshot, ...]``.

Emission
--------
ONE ``InsertBlock`` per region.  ``pred_serial`` = the in-CFG predecessor
that flows into the FIRST handler of the region (resolved via the live
mblock).  ``succ_serial`` = the entry block of the region's exit target
(the block following the LAST handler) — looked up via the DAG's outgoing
edge from the last node, falling back to the live mblock's successor when
the DAG does not record an exit edge.

Default-OFF
-----------
Behavior is gated on
``HandlerChainComposerStrategy.HANDLER_CHAIN_COMPOSER_ENABLED`` (class
flag, defaults to ``False``).  When disabled, ``plan()`` returns ``None``
and emits no modifications.  Set ``D810_ENABLE_HANDLER_CHAIN_COMPOSER=1``
to opt in.

Family: ``FAMILY_DIRECT``.
Prerequisites: ``["direct_handler_linearization"]`` -- region detection
relies on the linearized DAG that ``StateWriteReconstructionStrategy``
produces.
"""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass

from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import logging
from d810.cfg.flowgraph import InsnSnapshot
from d810.cfg.graph_modification import InsertBlock
from d810.hexrays.mutation.ir_translator import capture_insn_snapshot
from d810.hexrays.mutation.insn_snapshot_materializer import (
    validate_insn_snapshots,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    StateDagNode,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.handler_chain_composer")

__all__ = [
    "HandlerChainCandidate",
    "HandlerChainComposerStrategy",
]


@dataclass(frozen=True, slots=True)
class HandlerChainCandidate:
    """A detected DAG region ready for body composition.

    The name is preserved from the previous chain-based implementation
    for backward compatibility with system tests; semantically this is
    now a *region* (a linear DAG path), not a "chain" of CFG blocks.
    """

    handler_serials: tuple[int, ...]
    """Ordered handler-entry block serials in the region (s0..sn)."""

    pred_serial: int
    """Predecessor block (region anchor) feeding the first handler entry."""

    succ_serial: int
    """Successor block reached after the region exits."""

    composed_instructions: tuple[InsnSnapshot, ...]
    """Concatenated composable snapshots in region order."""

    state_values: tuple[int, ...]
    """State constants attached to each handler in the region (informational)."""


# Opcodes that abort composition because their effects are hard to
# preserve in a relocated InsertBlock body: external side effects
# (calls), control-flow termination (ret), assembly escape (ext), and
# indirect jumps (jtbl/ijmp) that change CFG topology.  Everything else
# — arithmetic, flag setters, conditional branches, byte loads/stores
# — is composable.
_FORBIDDEN_COMPOSITION_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_call,   # external side effects
        ida_hexrays.m_icall,  # external side effects (indirect)
        ida_hexrays.m_ret,    # control-flow termination
        ida_hexrays.m_ext,    # extended assembly escape
        ida_hexrays.m_jtbl,   # indirect jump (jump-table)
        ida_hexrays.m_ijmp,   # indirect jump (computed)
    }
)


def _resolve_state_var_stkoff(snapshot: "AnalysisSnapshot") -> int | None:
    """Best-effort state-var stack offset resolution.

    Mirrors the pattern used by ``StateConstantReturnFixupStrategy`` and
    ``DeadStateVariableEliminationStrategy``.  Returns ``None`` when
    neither the detector nor the state-machine expose a ``mop_S`` state
    variable.
    """
    detector = getattr(snapshot, "detector", None)
    if detector is not None:
        try:
            from d810.recon.flow.transition_builder import _get_state_var_stkoff

            stkoff = _get_state_var_stkoff(detector)
            if stkoff is not None:
                return int(stkoff)
        except Exception:
            pass
    sm = getattr(snapshot, "state_machine", None)
    if sm is not None:
        sv = getattr(sm, "state_var", None)
        if sv is not None:
            try:
                if sv.t == ida_hexrays.mop_S:
                    return int(sv.s.off)
            except Exception:
                pass
    # Last-resort: discovery DAG carries it.
    discovery = getattr(snapshot, "discovery", None)
    if discovery is not None:
        dag = getattr(discovery, "dag", None)
        if dag is not None:
            stkoff = getattr(dag, "state_var_stkoff", None)
            if isinstance(stkoff, int):
                return int(stkoff)
    return None


def _is_state_write(insn: object, state_var_stkoff: int | None) -> bool:
    """Return True if ``insn`` writes a state constant to the state var.

    State writes are dropped from composed bodies because the composed
    region replaces the dispatcher's state-machine progression.

    Recognized shape: ``m_mov #N, %var_<state_var_stkoff>`` where the
    destination is a stack mop (``mop_S``) at exactly the state-var
    offset.  When ``state_var_stkoff`` is ``None`` we cannot identify
    state writes; fall through (do not drop).
    """
    if state_var_stkoff is None:
        return False
    try:
        opcode = int(insn.opcode)
    except Exception:
        return False
    if opcode != ida_hexrays.m_mov:
        return False
    dst = getattr(insn, "d", None)
    if dst is None:
        return False
    try:
        if dst.t != ida_hexrays.mop_S:
            return False
        return int(dst.s.off) == int(state_var_stkoff)
    except Exception:
        return False


class HandlerChainComposerStrategy:
    """Compose body of a DAG region into a single straight-line block.

    See module docstring for the full design rationale.

    Class flag
    ----------
    ``HANDLER_CHAIN_COMPOSER_ENABLED`` (bool, default ``False``).  When
    ``False`` (the default), ``plan()`` always returns ``None`` and the
    strategy emits no modifications.  Set to ``True`` only for targeted
    experiments.
    """

    # CLASS-LEVEL GATE: keep behavior off by default.  Same pattern as
    # ``HodurUnflattener.MBL_KEEP_ENABLED``.  Set via env var
    # ``D810_ENABLE_HANDLER_CHAIN_COMPOSER=1`` to opt in.
    HANDLER_CHAIN_COMPOSER_ENABLED: bool = bool(
        int(os.environ.get("D810_ENABLE_HANDLER_CHAIN_COMPOSER", "0"))
    )

    @property
    def name(self) -> str:
        return "handler_chain_composer"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        """Return True when the gate is on and we have a state machine."""
        if not self.HANDLER_CHAIN_COMPOSER_ENABLED:
            return False
        if snapshot.mba is None:
            return False
        if snapshot.state_machine is None:
            return False
        if not getattr(snapshot.state_machine, "handlers", None):
            return False
        return True

    def plan(
        self, snapshot: "AnalysisSnapshot"
    ) -> "PlanFragment | None":
        """Detect regions, compose bodies, and emit ONE InsertBlock per region.

        Returns ``None`` when the strategy is disabled, no regions are
        detected, or composition fails for every region.
        """
        if not self.is_applicable(snapshot):
            return None

        candidates = self.detect_chains(snapshot)
        if not candidates:
            logger.info(
                "HandlerChainComposer: no candidate regions detected"
            )
            return None

        modifications: list = []
        owned_blocks: set[int] = set()
        emitted = 0

        for candidate in candidates:
            if not candidate.composed_instructions:
                logger.info(
                    "HandlerChainComposer: region pred=%d succ=%d has no"
                    " composable instructions; skipping",
                    candidate.pred_serial,
                    candidate.succ_serial,
                )
                continue
            reason = validate_insn_snapshots(candidate.composed_instructions)
            if reason is not None:
                logger.warning(
                    "HandlerChainComposer: snapshot validation failed for"
                    " region pred=%d succ=%d: %s",
                    candidate.pred_serial,
                    candidate.succ_serial,
                    reason,
                )
                continue
            # ``old_target_serial`` tells the backend which existing
            # edge to replace.  We are splicing ``pred -> region[0] ->
            # ... -> region[n] -> succ`` into ``pred -> composed_block
            # -> succ``.  The existing edge being replaced is ``pred ->
            # region[0]``; the new block routes to ``succ_serial``.
            modifications.append(
                InsertBlock(
                    pred_serial=candidate.pred_serial,
                    succ_serial=candidate.succ_serial,
                    instructions=candidate.composed_instructions,
                    old_target_serial=int(candidate.handler_serials[0]),
                )
            )
            owned_blocks.update(candidate.handler_serials)
            owned_blocks.add(candidate.pred_serial)
            emitted += 1
            logger.info(
                "HandlerChainComposer: composed region pred=%d succ=%d"
                " handlers=%s ninsns=%d states=%s",
                candidate.pred_serial,
                candidate.succ_serial,
                candidate.handler_serials,
                len(candidate.composed_instructions),
                candidate.state_values,
            )

        if not modifications:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=len(owned_blocks),
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.5,
            metadata={
                "handler_chain_composer_emitted": emitted,
                # Other focused strategies emit a single InsertBlock per
                # opportunity; reuse the same safeguard precedent.
                "safeguard_min_required": 1,
                "safeguard_profile": "engine",
            },
        )

    # ------------------------------------------------------------------
    # Region detection (DAG-driven)
    # ------------------------------------------------------------------

    def detect_chains(
        self, snapshot: "AnalysisSnapshot"
    ) -> list[HandlerChainCandidate]:
        """Detect maximal linear regions in the recon DAG.

        A region is a maximal linear sequence of state nodes ``s0 -> s1
        -> ... -> sn`` connected by ``TRANSITION`` (or
        ``CONDITIONAL_TRANSITION``) edges where each ``s_i`` (i < n) has
        exactly one outgoing TRANSITION edge and each ``s_i`` (i > 0)
        has exactly one incoming TRANSITION edge.  Branching/joining
        states close the region.

        The method preserves its old name (``detect_chains``) for
        backward-compat with system tests.
        """
        mba = snapshot.mba
        if mba is None:
            return []

        dag = self._resolve_dag(snapshot)
        if dag is None or not dag.nodes:
            logger.info(
                "HandlerChainComposer: no DAG available; skipping"
            )
            return []

        state_var_stkoff = _resolve_state_var_stkoff(snapshot)
        if state_var_stkoff is None:
            logger.info(
                "HandlerChainComposer: state_var_stkoff unresolved;"
                " composed bodies will retain state-var writes"
            )

        regions = self._detect_dag_regions(dag)
        logger.info(
            "HandlerChainComposer: detected %d region(s) from DAG"
            " (nodes=%d edges=%d)",
            len(regions),
            len(dag.nodes),
            len(dag.edges),
        )
        if not regions:
            return []

        candidates: list[HandlerChainCandidate] = []
        for region_nodes in regions:
            candidate = self._compose_region(
                mba=mba,
                dag=dag,
                region_nodes=region_nodes,
                state_var_stkoff=state_var_stkoff,
            )
            if candidate is not None:
                candidates.append(candidate)

        return candidates

    @staticmethod
    def _resolve_dag(
        snapshot: "AnalysisSnapshot",
    ) -> LinearizedStateDag | None:
        """Return the recon DAG when available on the snapshot.

        Falls through to ``None`` for legacy snapshots without
        ``discovery`` or where the DAG was not built (e.g., families
        that don't run the round-discovery context yet).
        """
        discovery = getattr(snapshot, "discovery", None)
        if discovery is None:
            return None
        dag = getattr(discovery, "dag", None)
        if dag is None:
            return None
        return dag if isinstance(dag, LinearizedStateDag) else None

    @staticmethod
    def _detect_dag_regions(
        dag: LinearizedStateDag,
    ) -> list[tuple[StateDagNode, ...]]:
        """Return maximal linear paths through the DAG.

        Walks ``dag.nodes`` and ``dag.edges`` to build:
        * ``out_by_src``: for each node key, the set of TRANSITION-kind
          successors.
        * ``in_count``: for each target entry anchor, the count of
          TRANSITION-kind incoming edges.

        Then for each starting node (one with no in-region predecessor
        in TRANSITION edges, or one whose pred has more than one
        outgoing TRANSITION) extends forward while the linearity
        invariants hold.
        """
        # Map node-key -> StateDagNode for O(1) lookup.
        node_by_key = {node.key: node for node in dag.nodes}

        # Build forward adjacency (only TRANSITION-kind edges qualify
        # as "linear" successors; CONDITIONAL_TRANSITION and others
        # break linearity).
        out_by_src: dict[object, list[StateDagNode]] = defaultdict(list)
        in_count: dict[object, int] = defaultdict(int)
        for edge in dag.edges:
            if edge.kind is not SemanticEdgeKind.TRANSITION:
                continue
            target_node: StateDagNode | None = None
            if edge.target_key is not None:
                target_node = node_by_key.get(edge.target_key)
            if target_node is None:
                continue
            out_by_src[edge.source_key].append(target_node)
            in_count[edge.target_key] = in_count.get(edge.target_key, 0) + 1

        # Identify starting nodes: any node with in_count != 1, OR
        # whose predecessor has more than one outgoing TRANSITION edge.
        # Equivalent characterization: a node is a region start iff it
        # has zero or multiple TRANSITION preds (zero = entry-state,
        # multiple = join), OR exactly one pred but that pred branches.
        is_region_start: set[object] = set()
        for node in dag.nodes:
            n_in = in_count.get(node.key, 0)
            if n_in != 1:
                is_region_start.add(node.key)

        # Also: any node whose unique pred has multiple out edges starts
        # a new region (because the pred itself terminates a region).
        # We model this implicitly: when extending a region, we stop at
        # the current node if it has != 1 outgoing TRANSITION; the
        # successor then becomes a region start.
        # To find such successor starts: collect them as we walk.
        visited: set[object] = set()
        regions: list[tuple[StateDagNode, ...]] = []

        # Deterministic ordering: sort by (entry_anchor, state_label).
        ordered_nodes = sorted(
            dag.nodes,
            key=lambda n: (int(n.entry_anchor), str(n.state_label)),
        )

        for node in ordered_nodes:
            if node.key in visited:
                continue
            if node.key not in is_region_start:
                # Not a starting node; will be picked up as part of a
                # region rooted earlier.
                continue
            path = [node]
            visited.add(node.key)
            cur = node
            # Extend forward while:
            # * cur has exactly 1 outgoing TRANSITION edge
            # * the target has exactly 1 incoming TRANSITION edge
            # * the target is unvisited (defense against cycles)
            depth = 0
            while depth < 4096:  # defensive cap
                outs = out_by_src.get(cur.key, [])
                if len(outs) != 1:
                    break
                nxt = outs[0]
                if in_count.get(nxt.key, 0) != 1:
                    break
                if nxt.key in visited:
                    break
                path.append(nxt)
                visited.add(nxt.key)
                cur = nxt
                depth += 1
            # Even singleton regions are kept — option (β)'s value
            # comes from use-def preservation, not compaction.
            regions.append(tuple(path))

        return regions

    def _compose_region(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        region_nodes: tuple[StateDagNode, ...],
        state_var_stkoff: int | None,
    ) -> HandlerChainCandidate | None:
        """Compose one region into a HandlerChainCandidate, or None.

        The composition walks each node's ``entry_anchor`` block live
        and concatenates composable instructions.  ``pred_serial`` is
        the live predecessor of the first node; ``succ_serial`` is the
        target of the last node's outgoing edge (DAG first, live mblock
        fallback).
        """
        if not region_nodes:
            return None

        first_anchor = int(region_nodes[0].entry_anchor)
        first_blk = self._safe_get_mblock(mba, first_anchor)
        if first_blk is None:
            return None

        # Resolve pred_serial.  Region's first handler must have at
        # least one predecessor we can splice on.  For multi-pred
        # cases, prefer a pred outside the region (the dispatcher /
        # state-setter); when ambiguous, fall back to the first pred.
        pred_serial = self._resolve_first_pred(
            mba=mba,
            blk=first_blk,
            region_anchors={int(n.entry_anchor) for n in region_nodes},
        )
        if pred_serial is None:
            logger.info(
                "HandlerChainComposer: region first=%d has no usable pred",
                first_anchor,
            )
            return None

        # Resolve succ_serial via DAG outgoing edge of last node, then
        # fallback to live mblock.
        last_node = region_nodes[-1]
        succ_serial = self._resolve_region_exit(
            mba=mba, dag=dag, last_node=last_node,
        )
        if succ_serial is None:
            logger.info(
                "HandlerChainComposer: region last=%d has no exit successor",
                int(last_node.entry_anchor),
            )
            return None

        # Compose bodies.  Drop state-writes and trailing m_goto/m_nop
        # per node; bail entirely if any node contains a forbidden
        # opcode (m_call, m_ret, etc.).
        composed: list[InsnSnapshot] = []
        handler_serials: list[int] = []
        state_values: list[int] = []
        for node in region_nodes:
            anchor = int(node.entry_anchor)
            blk = self._safe_get_mblock(mba, anchor)
            if blk is None:
                logger.info(
                    "HandlerChainComposer: region node anchor=%d missing"
                    " in live mba; aborting region",
                    anchor,
                )
                return None
            insns = self._capture_block_composable_instructions(
                blk, state_var_stkoff=state_var_stkoff,
            )
            if insns is None:
                logger.info(
                    "HandlerChainComposer: region node anchor=%d has"
                    " forbidden opcode; aborting region",
                    anchor,
                )
                return None
            composed.extend(insns)
            handler_serials.append(anchor)
            state_values.append(0)  # state value annotation reserved

        return HandlerChainCandidate(
            handler_serials=tuple(handler_serials),
            pred_serial=int(pred_serial),
            succ_serial=int(succ_serial),
            composed_instructions=tuple(composed),
            state_values=tuple(state_values),
        )

    @staticmethod
    def _safe_get_mblock(mba: object, serial: int) -> object | None:
        try:
            return mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            return None

    @staticmethod
    def _resolve_first_pred(
        *,
        mba: object,
        blk: object,
        region_anchors: set[int],
    ) -> int | None:
        """Pick the splice predecessor for the region's first handler.

        ``InsertBlock`` requires the pred to be 1-way (single
        successor) — emulated_dispatcher_family.py treats this as a
        hard precondition.  Multi-way preds raise ``CFG_50856_BAD_NSUCC``
        because splicing through a 2-way block adds a third successor.

        Selection rules, in order:
        1. Predecessor must NOT be a region anchor (so we do not
           splice an internal region edge).
        2. Predecessor must be 1-way (``nsucc() == 1``).
        3. Among qualifying preds, prefer smallest serial for
           determinism.

        Returns ``None`` when no pred meets these constraints; the
        region is then skipped.
        """
        try:
            n = int(blk.npred())  # type: ignore[attr-defined]
        except Exception:
            return None
        if n == 0:
            return None
        eligible: list[int] = []
        try:
            for i in range(n):
                p = int(blk.pred(i))  # type: ignore[attr-defined]
                if p in region_anchors:
                    continue
                pred_blk = HandlerChainComposerStrategy._safe_get_mblock(mba, p)
                if pred_blk is None:
                    continue
                try:
                    if int(pred_blk.nsucc()) != 1:  # type: ignore[attr-defined]
                        continue
                except Exception:
                    continue
                eligible.append(p)
        except Exception:
            return None
        if not eligible:
            return None
        return min(eligible)

    def _resolve_region_exit(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        last_node: StateDagNode,
    ) -> int | None:
        """Find the block to wire the inserted region's tail into.

        Strategy:
        1. Look at the DAG's outgoing edges from ``last_node`` -- pick
           any TRANSITION edge whose target_entry_anchor exists in the
           live CFG.  If multiple, prefer the smallest serial for
           determinism.
        2. Fallback to the live mblock's first successor (filter
           anchors that are themselves part of the region's prefix).
        """
        # DAG-first lookup.
        candidates: list[int] = []
        for edge in dag.edges:
            if edge.source_key != last_node.key:
                continue
            if edge.target_entry_anchor is None:
                continue
            candidates.append(int(edge.target_entry_anchor))
        if candidates:
            return min(candidates)

        # Live CFG fallback.
        blk = self._safe_get_mblock(mba, int(last_node.entry_anchor))
        if blk is None:
            return None
        try:
            if int(blk.nsucc()) >= 1:  # type: ignore[attr-defined]
                return int(blk.succ(0))  # type: ignore[attr-defined]
        except Exception:
            return None
        return None

    @staticmethod
    def _capture_block_composable_instructions(
        blk: object,
        *,
        state_var_stkoff: int | None = None,
    ) -> list[InsnSnapshot] | None:
        """Walk ``blk.head`` and capture composable instructions, or None.

        Returns None if any instruction has a non-whitelisted opcode
        (we cannot safely compose unknown side-effects).  Trailing
        ``m_goto`` / ``m_nop`` and state-writes are silently dropped.
        """
        out: list[InsnSnapshot] = []
        try:
            insn = blk.head  # type: ignore[attr-defined]
        except Exception:
            return None
        while insn is not None:
            opcode = int(insn.opcode)
            if opcode in (ida_hexrays.m_goto, ida_hexrays.m_nop):
                insn = insn.next
                continue
            if opcode in _FORBIDDEN_COMPOSITION_OPCODES:
                return None
            if _is_state_write(insn, state_var_stkoff):
                # Drop the state machine progression — the composed
                # region replaces it.
                insn = insn.next
                continue
            try:
                snap = capture_insn_snapshot(insn)
            except Exception as exc:
                logger.warning(
                    "HandlerChainComposer: capture_insn_snapshot failed at"
                    " ea=0x%x opcode=%d: %s",
                    int(getattr(insn, "ea", 0)),
                    opcode,
                    exc,
                )
                return None
            out.append(snap)
            insn = insn.next
        return out
