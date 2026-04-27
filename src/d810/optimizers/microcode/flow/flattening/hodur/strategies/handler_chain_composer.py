"""HandlerChainComposerStrategy -- linearizer + region-collapse strategy.

Ticket: ``uee-b7ze``.

Motivation
----------
After ``DirectLinearization``, byte-handler producers/consumers are placed
on diverging execution paths.  IDA's data-flow optimizer determines that
defs no longer dominate uses and DCEs them.  Empirical case on
``sub_7FFD3338C040``: bytes 1, 2, 4, 5 are written by handlers but wiped
from AFTER pseudocode despite being intact in our ``post_pipeline``
snapshot.

This strategy is the sole linearizer + region-collapse driver under the
``D810_RECON_SKIP_SRW_STRATEGY=1`` flag.  It absorbs the orchestration
that ``StateWriteReconstructionStrategy`` (SWR) used to perform, and
adds a region-collapse step on top that preserves use-def dominance by
folding maximal linear DAG regions into a single ``InsertBlock``.

Strategy
--------
``plan()`` runs in two phases:

  1. **SWR-style orchestration** -- copied verbatim from SWR's plan body.
     Drives semantic-corridor reconstruction: build live DAG → run
     constant fixpoint → discover structured regions → build candidates
     per edge → group by shared block → plan direct/passthrough mods →
     execute primary → execute shared-group → postprocess.

  2. **Region collapse** -- detect maximal linear DAG regions (via
     ``detect_chains`` / ``_detect_dag_regions`` / ``_compose_region``)
     and emit ONE ``InsertBlock`` per region containing the composed
     bodies of every handler in that region.  Within a single block,
     def→use dominance is trivially preserved (instruction order =
     dominance order).

The two phases are merged into ONE ``PlanFragment``.  SWR-style mods
that touch a region-collapse anchor are dropped (the ``InsertBlock``
makes them redundant).

Region definition
-----------------
A region is a maximal linear path through the recon DAG::

    state_0 --TRANSITION--> state_1 --TRANSITION--> ... --TRANSITION--> state_n

where each ``state_i`` has exactly ONE outgoing TRANSITION edge AND the
target node has exactly ONE incoming TRANSITION edge.  Branching states
or terminal states close the region.

Body composition
----------------
For each ``StateDagNode`` in the region, walk live ``mblock_t`` for
``node.entry_anchor`` and capture all instructions EXCEPT:
* the state-write ``m_mov #STATE, %var_<state_var_stkoff>``;
* trailing ``m_goto`` / ``m_nop``.

Default-OFF
-----------
Behavior is gated on
``HandlerChainComposerStrategy.HANDLER_CHAIN_COMPOSER_ENABLED`` (class
flag, defaults to ``False``).  Set ``D810_ENABLE_HANDLER_CHAIN_COMPOSER=1``
to opt in.  When the flag is False, ``plan()`` returns ``None`` and emits
no modifications.

Family: ``FAMILY_DIRECT``.
Prerequisites: ``[]`` -- this strategy IS the linearizer.
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, replace

from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.flowgraph import InsnSnapshot
from d810.cfg.frontier_override_emission import emit_frontier_overrides
from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateAndRedirect,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.modification_builder import ModificationBuilder
from d810.cfg.reconstruction_emission import (
    apply_shared_group_reachability_fallback,
    execute_primary_reconstruction_modifications,
)
from d810.cfg.reconstruction_postprocess_emission import (
    execute_reconstruction_postprocess,
)
from d810.cfg.reconstruction_recording import RoundAcceptLedger
from d810.cfg.state_edge_pair import state_edge_pair
from d810.hexrays.mutation.ir_translator import capture_insn_snapshot
from d810.hexrays.mutation.insn_snapshot_materializer import (
    validate_insn_snapshots,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._reconstruction_reporting import (
    log_reconstruction_postprocess_result,
    snapshot_reconstruction_dag,
    snapshot_reconstruction_post_apply,
)
from d810.optimizers.microcode.flow.flattening.hodur.reconstruction_fragment_builder import (
    finalize_reconstruction_fragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.conditional_arm_canonicalization import (
    canonicalize_same_target_conditional_candidates,
)
from d810.recon.flow.edge_metadata import edge_kind_name, make_edge_metadata
from d810.recon.flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.recon.flow.frontier_override_discovery import (
    discover_frontier_overrides,
)
from d810.recon.flow.full_coverage_chain_probe import log_chain_coverage
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    StateDagNode,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.narrow_branch_local_discovery import (
    discover_narrow_branch_local_reconstruction_candidates,
)
from d810.recon.flow.reconstruction_candidate_builder import (
    ReconstructionCandidate,
    build_reconstruction_candidate,
)
from d810.recon.flow.reconstruction_diagnostics import (
    log_reconstruction_candidate_probe,
    log_reconstruction_phase_probe,
)
from d810.recon.flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
    resolve_state_var_stkoff,
)
from d810.recon.flow.reconstruction_discovery_indexes import (
    build_reconstruction_discovery_indexes,
)
from d810.recon.flow.residual_alias_discovery import (
    discover_residual_alias_overrides,
)
from d810.recon.flow.return_corridor_discovery import (
    collect_common_return_corridor,
)
from d810.recon.flow.shared_group_bucketing import (
    group_candidates_by_shared_block,
)
from d810.recon.flow.state_machine_analysis import run_snapshot_constant_fixpoint
from d810.recon.flow.terminal_family_collection import (
    collect_terminal_family_report,
)
from d810.recon.flow.transition_builder import (
    build_transition_result_from_state_machine,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.handler_chain_composer",
    logging.DEBUG,
)

__all__ = [
    "HandlerChainCandidate",
    "HandlerChainComposerStrategy",
]


# ---------------------------------------------------------------------------
# SWR sub_7FFD-specific constants (carried verbatim from SWR for byte-handler
# corridor recovery).  Kept private to this module.
# ---------------------------------------------------------------------------
_SUB7FFD_INITIAL_REGION_NAME = "sub7ffd_initial_semantic_region"
_SUB7FFD_INITIAL_FORCE_EDGE = (0x139F2922, 0x63F502FA)
_SUB7FFD_DOWNSTREAM_REGION_NAME = "sub7ffd_downstream_chain_region"
_SUB7FFD_DOWNSTREAM_FORCE_EDGE = (0x32FCD904, 0x2E6C61F3)
_SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE = (0x2E6C61F3, 0x652D7A98)
_SUB7FFD_RETRY_CHAIN_REGION_NAME = "sub7ffd_retry_chain_region"
_SUB7FFD_RETRY_CHAIN_FORCE_EDGES = (
    (0x37B42A40, 0x63D54755),
    (0x63D54755, 0x57BE6FD0),
    (0x57BE6FD0, 0x03E42B03),
    (0x03E42B03, 0x610BB4D9),
)
_SUB7FFD_FORCED_REGION_EDGES: dict[str, tuple[tuple[int, int], ...]] = {
    _SUB7FFD_INITIAL_REGION_NAME: (_SUB7FFD_INITIAL_FORCE_EDGE,),
    _SUB7FFD_DOWNSTREAM_REGION_NAME: (
        _SUB7FFD_DOWNSTREAM_FORCE_EDGE,
        _SUB7FFD_DOWNSTREAM_HEAD_FORCE_EDGE,
    ),
    _SUB7FFD_RETRY_CHAIN_REGION_NAME: _SUB7FFD_RETRY_CHAIN_FORCE_EDGES,
}
_ENABLE_STRUCTURED_REGION_OVERLAY = False


# ---------------------------------------------------------------------------
# SWR env-var parsers (carried verbatim).
# ---------------------------------------------------------------------------
def _parse_relaxed_lateclone_shared_blocks() -> frozenset[int]:
    raw_value = os.getenv("D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS", "").strip()
    if not raw_value:
        return frozenset()
    relaxed: set[int] = set()
    for token in raw_value.replace(",", " ").split():
        try:
            relaxed.add(int(token, 0))
        except ValueError:
            logger.info(
                "RECON DAG: ignoring invalid late-clone relaxation token=%r",
                token,
            )
    return frozenset(relaxed)


def _parse_force_keep_per_pred_shared_blocks() -> frozenset[int]:
    raw_value = os.getenv("D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS", "").strip()
    if not raw_value:
        return frozenset()
    keep: set[int] = set()
    for token in raw_value.replace(",", " ").split():
        try:
            keep.add(int(token, 0))
        except ValueError:
            logger.info(
                "RECON DAG: ignoring invalid force-keep per-pred token=%r",
                token,
            )
    return frozenset(keep)


def _parse_force_clone_primary_shared_blocks() -> frozenset[int]:
    raw_value = os.getenv("D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS", "").strip()
    if not raw_value:
        return frozenset()
    forced: set[int] = set()
    for token in raw_value.replace(",", " ").split():
        try:
            forced.add(int(token, 0))
        except ValueError:
            logger.info(
                "RECON DAG: ignoring invalid primary force-clone token=%r",
                token,
            )
    return frozenset(forced)


# ---------------------------------------------------------------------------
# SWR helper functions (carried verbatim, made module-private).
# ---------------------------------------------------------------------------
def _collect_accepted_reconstruction_candidates(run) -> list[object]:
    accepted_candidates = [
        result.candidate for result in getattr(run, "conditional_results", ())
    ]
    accepted_candidates.extend(
        result.accepted_candidate
        for result in getattr(run, "direct_results", ())
        if getattr(result, "accepted_candidate", None) is not None
    )
    for result in getattr(run, "shared_group_results", ()):
        accepted_candidates.extend(getattr(result, "accepted_candidates", ()))
    return accepted_candidates


def _record_accept_metadata(metadata, candidate) -> None:
    metadata.append(
        make_edge_metadata(
            candidate.edge,
            horizon_block=candidate.horizon_block,
            site=candidate.site,
            target_entry=candidate.target_entry,
            first_shared_block=candidate.first_shared_block,
            via_pred=candidate.via_pred,
            emission_mode=candidate.emission_mode,
        )
    )


def _collect_rejected_reconstruction_candidates(run) -> list[object]:
    rejected: list[object] = []
    for result in getattr(run, "direct_results", ()):
        rejected.extend(getattr(result, "rejected_candidates", ()))
    for result in getattr(run, "shared_group_results", ()):
        rejected.extend(getattr(result, "rejected_candidates", ()))
    return rejected


def _build_execution_probe_metadata(
    run,
) -> tuple[list[dict[str, int | str | None]], list[dict[str, int | str | None]]]:
    accepted_metadata: list[dict[str, int | str | None]] = []
    rejected_metadata: list[dict[str, int | str | None]] = []
    for result in getattr(run, "conditional_results", ()):
        _record_accept_metadata(accepted_metadata, result.candidate)
    for result in getattr(run, "direct_results", ()):
        accepted_candidate = getattr(result, "accepted_candidate", None)
        if accepted_candidate is not None:
            _record_accept_metadata(accepted_metadata, accepted_candidate)
        for candidate in getattr(result, "rejected_candidates", ()):
            rejected_metadata.append(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=result.rejection_reason,
                )
            )
    for result in getattr(run, "shared_group_results", ()):
        for candidate in getattr(result, "accepted_candidates", ()):
            _record_accept_metadata(accepted_metadata, candidate)
        for candidate in getattr(result, "rejected_candidates", ()):
            rejected_metadata.append(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=result.rejection_reason,
                )
            )
    return accepted_metadata, rejected_metadata


# ---------------------------------------------------------------------------
# Region-collapse types and helpers.
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class HandlerChainCandidate:
    """A detected DAG region ready for body composition."""

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
# preserve in a relocated InsertBlock body.
_FORBIDDEN_COMPOSITION_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_call,
        ida_hexrays.m_icall,
        ida_hexrays.m_ret,
        ida_hexrays.m_ext,
        ida_hexrays.m_jtbl,
        ida_hexrays.m_ijmp,
    }
)


def _resolve_state_var_stkoff_loose(snapshot: "AnalysisSnapshot") -> int | None:
    """Best-effort state-var stack offset resolution.

    Mirrors the pattern used by ``StateConstantReturnFixupStrategy`` and
    ``DeadStateVariableEliminationStrategy``.  Falls back to the discovery
    DAG when neither the detector nor the state-machine expose a ``mop_S``
    state variable.  Used only by the region-collapse path; the SWR
    orchestration path uses the strict ``resolve_state_var_stkoff``
    helper from ``recon.flow.reconstruction_discovery``.
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
    discovery = getattr(snapshot, "discovery", None)
    if discovery is not None:
        dag = getattr(discovery, "dag", None)
        if dag is not None:
            stkoff = getattr(dag, "state_var_stkoff", None)
            if isinstance(stkoff, int):
                return int(stkoff)
    return None


def _is_state_write(insn: object, state_var_stkoff: int | None) -> bool:
    """Return True if ``insn`` writes a state constant to the state var."""
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


# ---------------------------------------------------------------------------
# Strategy.
# ---------------------------------------------------------------------------
@algorithm_metadata(
    algorithm_id="hodur.handler_chain_composer",
    family="structured_semantic_region_lowering",
    summary=(
        "Combined linearizer + region-collapse: runs SWR-style semantic-corridor"
        " reconstruction and folds maximal linear DAG regions into single"
        " InsertBlocks to preserve def-dominates-use after CFG restructuring."
    ),
    use_cases=(
        "Drive semantic-handoff reconstruction without registering SWR.",
        "Collapse linear DAG regions to preserve byte-handler use-def chains"
        " across IDA's MMAT_GLBOPT1 cleanup.",
    ),
    examples=(
        "On sub_7FFD3338C040, recover bytes 1, 2, 4, 5 by composing handler"
        " bodies into single straight-line blocks.",
    ),
    tags=("reconstruction", "region-collapse", "use-def-preservation"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/handler_chain_composer.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/reconstruction.py",
    ),
)
class HandlerChainComposerStrategy:
    """Combined linearizer + region-collapse strategy.

    See module docstring for the full design rationale.

    Class flag
    ----------
    ``HANDLER_CHAIN_COMPOSER_ENABLED`` (bool, default ``False``).  When
    ``False`` (the default), ``plan()`` always returns ``None`` and the
    strategy emits no modifications.  Set to ``True`` only for targeted
    experiments.
    """

    # CLASS-LEVEL GATE: keep behavior off by default.
    HANDLER_CHAIN_COMPOSER_ENABLED: bool = bool(
        int(os.environ.get("D810_ENABLE_HANDLER_CHAIN_COMPOSER", "0"))
    )

    prerequisites: list[str] = []

    def __init__(self):
        # Caches mirror SWR's per-round caches.
        self._cached_structured_regions_by_round: dict[
            tuple[int, int], tuple[object, ...]
        ] = {}
        self._cached_force_edge_direct_overrides_by_round: dict[
            tuple[int, int, tuple[int, int]], tuple[int, int, tuple[int, ...]]
        ] = {}

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

    # ------------------------------------------------------------------
    # plan(): combined SWR orchestration + region collapse.
    # ------------------------------------------------------------------
    def plan(
        self, snapshot: "AnalysisSnapshot"
    ) -> "PlanFragment | None":
        """Run SWR-style orchestration + region collapse, emit one fragment."""
        if not self.is_applicable(snapshot):
            return None

        # Phase 1: detect region-collapse candidates (stub-snapshot safe).
        candidates = self.detect_chains(snapshot)

        # Phase 2: run SWR-style orchestration when full snapshot is
        # available; otherwise return only the region-collapse fragment
        # (preserves stub-snapshot test contract).
        swr_result = self._run_swr_orchestration(snapshot)

        # Region-collapse anchor sets used to filter overlapping SWR mods.
        region_anchor_blocks: set[int] = set()
        region_pred_serials: set[int] = set()
        region_succ_serials: set[int] = set()
        validated_candidates: list[HandlerChainCandidate] = []
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
            validated_candidates.append(candidate)
            region_anchor_blocks.update(candidate.handler_serials)
            region_pred_serials.add(candidate.pred_serial)
            region_succ_serials.add(candidate.succ_serial)

        # Filter SWR mods that touch any region-collapse anchor
        # (the InsertBlock makes such redirects redundant).
        if swr_result is not None:
            swr_result = self._filter_swr_against_regions(
                swr_result,
                region_anchor_blocks=region_anchor_blocks,
                region_pred_serials=region_pred_serials,
            )

        # Build region-collapse modifications.
        # Dedup by (pred_serial, old_target) — the same edge may surface
        # multiple times when several DAG paths reach the same region.
        # Two InsertBlocks targeting the same pred edge would project
        # an over-saturated CFG (CFG_50856_BAD_NSUCC).
        region_modifications: list = []
        region_owned_blocks: set[int] = set()
        emitted = 0
        emitted_edges: set[tuple[int, int]] = set()
        for candidate in validated_candidates:
            pred_serial = int(candidate.pred_serial)
            old_target = int(candidate.handler_serials[0])
            edge_key = (pred_serial, old_target)
            if edge_key in emitted_edges:
                logger.info(
                    "HandlerChainComposer: skipping duplicate region for"
                    " edge pred=%d old_target=%d (already emitted)",
                    pred_serial,
                    old_target,
                )
                continue
            emitted_edges.add(edge_key)
            region_modifications.append(
                InsertBlock(
                    pred_serial=pred_serial,
                    succ_serial=candidate.succ_serial,
                    instructions=candidate.composed_instructions,
                    old_target_serial=old_target,
                )
            )
            region_owned_blocks.update(candidate.handler_serials)
            region_owned_blocks.add(pred_serial)
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

        # Combine SWR + region-collapse into a single fragment.
        if swr_result is None and not region_modifications:
            return None

        # When SWR ran and produced mods (or has its full metadata
        # plumbing), use finalize_reconstruction_fragment so the SWR
        # conflict filters / DAG arbiter / metadata key all apply, then
        # extend with region-collapse mods + ownership.
        if swr_result is not None:
            # Append region-collapse mods into the SWR modifications list
            # before finalize so the DAG-arbiter / dup-conflict filters
            # can also reason about them as a single batch.  The filters
            # only target redirect-shaped mods; InsertBlock passes
            # through untouched.
            combined_modifications = list(swr_result["modifications"])
            combined_modifications.extend(region_modifications)
            combined_owned_blocks = set(swr_result["owned_blocks"])
            combined_owned_blocks.update(region_owned_blocks)
            combined_owned_edges = set(swr_result["owned_edges"])

            fragment = finalize_reconstruction_fragment(
                strategy_name=self.name,
                modifications=combined_modifications,
                owned_blocks=combined_owned_blocks,
                owned_edges=combined_owned_edges,
                accepted_metadata=swr_result["accepted_metadata"],
                rejected_metadata=swr_result["rejected_metadata"],
                allow_post_apply_bst_cleanup=swr_result[
                    "allow_post_apply_bst_cleanup"
                ],
                post_apply_bst_cleanup_reason=swr_result[
                    "post_apply_bst_cleanup_reason"
                ],
                residual_dispatcher_preds=swr_result[
                    "residual_dispatcher_preds"
                ],
                structured_region_fidelity=swr_result[
                    "structured_region_fidelity"
                ],
                cumulative_planner_view=getattr(
                    snapshot, "cumulative_planner_view", None
                ),
            )
            # Annotate metadata with HCC-specific counts for diagnostics.
            fragment.metadata["handler_chain_composer_emitted"] = emitted
            fragment.metadata["handler_chain_composer_region_anchors"] = tuple(
                sorted(region_anchor_blocks)
            )
            # Snapshot AFTER finalize — match SWR ordering so the diag DB
            # reflects the post-filter state.
            snapshot_reconstruction_post_apply(
                logger,
                dag=swr_result["dag"],
                modifications=fragment.modifications,
                mba=snapshot.mba,
                strategy_name=self.name,
            )
            return fragment

        # Region-collapse-only path (SWR orchestration was a no-op).
        if not region_modifications:
            return None
        ownership = OwnershipScope(
            blocks=frozenset(region_owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=len(region_owned_blocks),
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=region_modifications,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.5,
            metadata={
                "handler_chain_composer_emitted": emitted,
                "safeguard_min_required": 1,
                "safeguard_profile": "engine",
            },
        )

    # ------------------------------------------------------------------
    # SWR orchestration -- copied verbatim from SWR.plan() body.
    # ------------------------------------------------------------------
    def _run_swr_orchestration(
        self, snapshot: "AnalysisSnapshot"
    ) -> dict | None:
        """Run SWR-style orchestration when full snapshot is available.

        Returns a dict packaging the modifications, ownership sets,
        accepted/rejected metadata, postprocess-derived flags, and the
        DAG used for snapshotting.  Returns ``None`` when the snapshot
        lacks ``flow_graph`` / ``bst_result`` / a resolvable
        ``state_var_stkoff`` (which is the case for unit-test stubs).
        """
        sm = snapshot.state_machine
        bst_result = getattr(snapshot, "bst_result", None)
        flow_graph = getattr(snapshot, "flow_graph", None)
        mba = snapshot.mba
        if sm is None or bst_result is None or flow_graph is None or mba is None:
            return None
        if not sm.handlers:
            return None
        state_var_stkoff = resolve_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        )
        if state_var_stkoff is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        transition_result = build_transition_result_from_state_machine(
            sm,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
        )
        _corrected_dag_out: list = []
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=sm.initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(
                sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
            ),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
            corrected_dag_out=_corrected_dag_out,
        )
        corrected_dag = _corrected_dag_out[0] if _corrected_dag_out else dag
        log_chain_coverage(corrected_dag, context_label="HCC corrected_dag")

        constant_result = run_snapshot_constant_fixpoint(
            flow_graph,
            state_var_stkoff,
        )
        structured_regions: tuple = ()
        cache_key = (
            int(getattr(mba, "entry_ea", 0) or 0),
            int(getattr(mba, "maturity", 0) or 0),
        )
        indexes = build_reconstruction_discovery_indexes(
            dag=dag,
            corrected_dag=corrected_dag,
            structured_regions=structured_regions,
        )
        structured_region_edge_pairs = indexes.structured_region_edge_pairs
        structured_region_source_blocks = indexes.structured_region_source_blocks
        dispatcher_region = indexes.dispatcher_region
        shared_suffix_blocks = indexes.shared_suffix_blocks
        corrected_boundary_shared_blocks = indexes.corrected_boundary_shared_blocks
        node_by_key = indexes.node_by_key
        dispatcher_serial = indexes.dispatcher_serial

        snapshot_reconstruction_dag(
            logger,
            dag=dag,
            mba=mba,
            strategy_name=self.name,
        )

        raw_candidates: list[ReconstructionCandidate] = []
        rejected_metadata: list[dict[str, int | str | None]] = []
        structured_region_candidate_counts: Counter[str] = Counter()
        structured_region_candidate_pairs: dict[str, list[tuple[int, int]]] = (
            defaultdict(list)
        )
        structured_region_candidates_by_pair: dict[
            tuple[int, int], list[ReconstructionCandidate]
        ] = defaultdict(list)
        structured_region_edges_by_pair: dict[tuple[int, int], list[object]] = (
            defaultdict(list)
        )
        corrected_region_edges_by_pair: dict[tuple[int, int], list[object]] = (
            defaultdict(list)
        )
        edge_kind_counts = Counter(edge_kind_name(e) for e in dag.edges)
        logger.info(
            "RECON DAG: edge distribution: %s",
            ", ".join(f"{k}={v}" for k, v in edge_kind_counts.most_common()),
        )
        for edge in dag.edges:
            pair = state_edge_pair(edge)
            if pair is not None:
                structured_region_edges_by_pair[pair].append(edge)
            candidate, rejection = build_reconstruction_candidate(
                edge,
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                state_var_stkoff=state_var_stkoff,
                constant_result=constant_result,
                shared_suffix_blocks=shared_suffix_blocks,
                dispatcher_region=dispatcher_region,
            )
            if candidate is not None:
                raw_candidates.append(candidate)
                if pair is not None:
                    structured_region_candidates_by_pair[pair].append(candidate)
                    for region_name, source_state, target_state in (
                        structured_region_edge_pairs
                    ):
                        if pair == (source_state, target_state):
                            structured_region_candidate_counts[region_name] += 1
                            structured_region_candidate_pairs[region_name].append(
                                pair
                            )
            elif rejection is not None:
                rejected_metadata.append(rejection)
        for edge in corrected_dag.edges:
            pair = state_edge_pair(edge)
            if pair is not None:
                corrected_region_edges_by_pair[pair].append(edge)

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        ledger = RoundAcceptLedger()
        accepted_metadata = ledger.accepted_metadata
        structured_region_accepted_counts = ledger.structured_region_accepted_counts
        structured_region_accepted_pairs = ledger.structured_region_accepted_pairs
        shared_group_candidates_by_block = group_candidates_by_shared_block(
            raw_candidates
        )

        if not raw_candidates:
            logger.info(
                "RECON DAG: no proven corridors across %d semantic edges (rejections=%d)",
                len(dag.edges),
                len(rejected_metadata),
            )

        raw_candidates, collapsed_same_target_conditionals = (
            canonicalize_same_target_conditional_candidates(raw_candidates)
        )
        if collapsed_same_target_conditionals:
            logger.info(
                "RECON DAG: collapsed %d same-target conditional candidate(s) into direct handoffs",
                int(collapsed_same_target_conditionals),
            )
        force_clone_primary_shared_blocks = _parse_force_clone_primary_shared_blocks()
        log_reconstruction_candidate_probe(
            phase="pre_primary_execution",
            raw_candidates=tuple(raw_candidates),
        )

        run = execute_primary_reconstruction_modifications(
            raw_candidates=list(raw_candidates),
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            force_clone_shared_blocks=force_clone_primary_shared_blocks,
        )
        primary_probe_accepted_candidates = _collect_accepted_reconstruction_candidates(
            run
        )
        primary_probe_rejected_candidates = _collect_rejected_reconstruction_candidates(
            run
        )
        log_reconstruction_candidate_probe(
            phase="post_primary_execution",
            raw_candidates=tuple(raw_candidates),
            accepted_candidates=tuple(primary_probe_accepted_candidates),
            rejected_candidates=tuple(primary_probe_rejected_candidates),
        )
        (
            primary_probe_accepted_metadata,
            primary_probe_rejected_metadata,
        ) = _build_execution_probe_metadata(run)
        log_reconstruction_phase_probe(
            phase="post_primary_execution",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=primary_probe_accepted_metadata,
            rejected_metadata=primary_probe_rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(run.shared_group_results),
        )
        for result in run.conditional_results:
            candidate = result.candidate
            ledger.record_accept(
                candidate,
                structured_region_edge_pairs=structured_region_edge_pairs,
                edge_metadata_fn=make_edge_metadata,
                state_edge_pair_fn=state_edge_pair,
            )
            logger.info(
                "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                blk_label(mba, candidate.horizon_block),
                candidate.site.state_value & 0xFFFFFFFF,
                blk_label(mba, candidate.target_entry),
                candidate.edge.source_anchor.branch_arm or 0,
                result.redirect_count,
                result.passthrough_count,
            )

        for result in run.direct_results:
            if result.accepted_candidate is not None:
                candidate = result.accepted_candidate
                ledger.record_accept(
                    candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
                logger.info(
                    "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
                    blk_label(mba, candidate.horizon_block),
                    candidate.site.state_value & 0xFFFFFFFF,
                    blk_label(mba, candidate.target_entry),
                    1,
                )
                continue

            rejected_metadata.extend(
                make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    rejection_reason=result.rejection_reason,
                )
                for candidate in result.rejected_candidates
            )

        shared_group_results = list(run.shared_group_results)
        unresolved_branch_local_edges = tuple(
            edge
            for region_name, source_state, target_state in structured_region_edge_pairs
            if (source_state, target_state)
            not in structured_region_accepted_pairs.get(region_name, set())
            for edge in structured_region_edges_by_pair.get(
                (source_state, target_state), ()
            )
        )
        narrow_branch_local_candidates = (
            discover_narrow_branch_local_reconstruction_candidates(
                unresolved_edges=unresolved_branch_local_edges,
                flow_graph=flow_graph,
            )
        )
        if narrow_branch_local_candidates:
            narrow_branch_local_candidates, _collapsed = (
                canonicalize_same_target_conditional_candidates(
                    list(narrow_branch_local_candidates)
                )
            )
            fallback_run = execute_primary_reconstruction_modifications(
                raw_candidates=list(narrow_branch_local_candidates),
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                dispatcher_serial=dispatcher_serial,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
            )
            for result in fallback_run.conditional_results:
                candidate = result.candidate
                ledger.record_accept(
                    candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
            for result in fallback_run.direct_results:
                if result.accepted_candidate is None:
                    continue
                candidate = result.accepted_candidate
                ledger.record_accept(
                    candidate,
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )
            for result in fallback_run.shared_group_results:
                shared_group_results.append(result)
                for candidate in result.accepted_candidates:
                    ledger.record_accept(
                        candidate,
                        structured_region_edge_pairs=structured_region_edge_pairs,
                        edge_metadata_fn=make_edge_metadata,
                        state_edge_pair_fn=state_edge_pair,
                    )

        frontier_override_plans = discover_frontier_overrides(
            dag=dag,
            flow_graph=flow_graph,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            structured_regions=structured_regions,
            structured_region_candidate_pairs=structured_region_candidate_pairs,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
        )
        _frontier_claimed_sources, _frontier_claimed_targets = collect_mod_claims(
            modifications
        )
        _frontier_claimed_sources.update(
            int(block_serial) for block_serial in owned_blocks
        )
        structured_frontier_overrides = emit_frontier_overrides(
            frontier_override_plans,
            builder=builder,
            modifications=modifications,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            claimed_sources=_frontier_claimed_sources,
            claimed_targets=_frontier_claimed_targets,
        )
        log_reconstruction_phase_probe(
            phase="pre_postprocess",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(shared_group_results),
        )

        postprocess = execute_reconstruction_postprocess(
            dag=dag,
            corrected_dag=corrected_dag,
            flow_graph=flow_graph,
            modifications=modifications,
            builder=builder,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
            bst_result=bst_result,
            state_machine=sm,
            state_var_stkoff=state_var_stkoff,
            constant_result=constant_result,
            node_by_key=node_by_key,
            rejected_metadata=rejected_metadata,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            collect_entry_island_rescue_seeds=collect_entry_island_rescue_seeds,
            collect_late_entry_island_diagnostics=collect_late_entry_island_diagnostics,
            collect_late_entry_island_rescue_seeds=collect_late_entry_island_rescue_seeds,
            collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
            compute_reachable_blocks=compute_reachable_blocks,
            classify_artifact_return_blocks=classify_artifact_return_blocks,
            collect_common_return_corridor=collect_common_return_corridor,
            collect_terminal_family_report=collect_terminal_family_report,
            build_reconstruction_candidate=build_reconstruction_candidate,
            discover_residual_alias_overrides_fn=discover_residual_alias_overrides,
        )
        log_reconstruction_postprocess_result(
            logger,
            result=postprocess,
            dag=dag,
            mba=mba,
        )
        structured_region_fidelity = {}
        projected_flow_graph = postprocess.projected_flow_graph  # noqa: F841
        residual_dispatcher_preds = postprocess.residual_dispatcher_preds
        allow_post_apply_bst_cleanup = postprocess.allow_post_apply_bst_cleanup
        post_apply_bst_cleanup_reason = postprocess.post_apply_bst_cleanup_reason
        relaxed_lateclone_shared_blocks = _parse_relaxed_lateclone_shared_blocks()
        force_keep_per_pred_shared_blocks = _parse_force_keep_per_pred_shared_blocks()
        log_reconstruction_phase_probe(
            phase="pre_late_shared_fallback",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(shared_group_results),
        )
        final_shared_group_results = apply_shared_group_reachability_fallback(
            shared_group_results=tuple(shared_group_results),
            shared_groups=shared_group_candidates_by_block,
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            handler_entries=tuple(int(node.entry_anchor) for node in dag.nodes),
            compute_reachable_blocks=compute_reachable_blocks,
            force_clone_shared_blocks=frozenset(
                int(result.shared_block)
                for result in shared_group_results
                if result.emission_mode == "per_pred_redirect"
                and int(result.shared_block) in corrected_boundary_shared_blocks
                and int(result.shared_block) not in relaxed_lateclone_shared_blocks
                and int(result.shared_block) not in force_keep_per_pred_shared_blocks
            ),
            force_keep_per_pred_shared_blocks=force_keep_per_pred_shared_blocks,
        )
        log_reconstruction_phase_probe(
            phase="post_late_shared_fallback",
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            accepted_metadata=accepted_metadata,
            rejected_metadata=rejected_metadata,
            compute_reachable_blocks=compute_reachable_blocks,
            shared_group_results=tuple(final_shared_group_results),
        )

        for result in final_shared_group_results:
            if result.rejected_candidates:
                rejected_metadata.extend(
                    make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=result.shared_block,
                        via_pred=candidate.via_pred,
                        rejection_reason=result.rejection_reason,
                    )
                    for candidate in result.rejected_candidates
                )
                continue
            if not result.accepted_candidates:
                continue
            for candidate in result.accepted_candidates:
                ledger.record_accept(
                    replace(candidate, emission_mode=result.emission_mode),
                    structured_region_edge_pairs=structured_region_edge_pairs,
                    edge_metadata_fn=make_edge_metadata,
                    state_edge_pair_fn=state_edge_pair,
                )

        return {
            "modifications": modifications,
            "owned_blocks": owned_blocks,
            "owned_edges": owned_edges,
            "accepted_metadata": accepted_metadata,
            "rejected_metadata": rejected_metadata,
            "allow_post_apply_bst_cleanup": allow_post_apply_bst_cleanup,
            "post_apply_bst_cleanup_reason": post_apply_bst_cleanup_reason,
            "residual_dispatcher_preds": residual_dispatcher_preds,
            "structured_region_fidelity": structured_region_fidelity,
            "dag": dag,
        }

    @staticmethod
    def _filter_swr_against_regions(
        swr_result: dict,
        *,
        region_anchor_blocks: set[int],
        region_pred_serials: set[int],
    ) -> dict:
        """Drop SWR-style mods that overlap region-collapse anchors.

        The InsertBlock for a region replaces the dispatcher-routed
        progression through ``handler_serials``; any SWR-style redirect
        that targets one of those handlers (or whose source is the
        region's predecessor) is now redundant and would conflict with
        the InsertBlock's edge rewiring.
        """
        if not region_anchor_blocks and not region_pred_serials:
            return swr_result
        kept_mods: list = []
        dropped = 0
        for mod in swr_result["modifications"]:
            if HandlerChainComposerStrategy._mod_touches_region(
                mod,
                region_anchor_blocks=region_anchor_blocks,
                region_pred_serials=region_pred_serials,
            ):
                dropped += 1
                continue
            kept_mods.append(mod)
        if dropped:
            logger.info(
                "HandlerChainComposer: dropped %d SWR-style mod(s) overlapping"
                " region-collapse anchors=%s preds=%s",
                dropped,
                sorted(region_anchor_blocks),
                sorted(region_pred_serials),
            )
        return {**swr_result, "modifications": kept_mods}

    @staticmethod
    def _mod_touches_region(
        mod: object,
        *,
        region_anchor_blocks: set[int],
        region_pred_serials: set[int],
    ) -> bool:
        """Return True when ``mod`` targets a region-collapse anchor."""
        if isinstance(mod, RedirectGoto):
            if int(mod.from_serial) in region_pred_serials:
                return True
            if int(mod.new_target) in region_anchor_blocks:
                return True
            if int(mod.from_serial) in region_anchor_blocks:
                return True
            return False
        if isinstance(mod, RedirectBranch):
            if int(mod.from_serial) in region_pred_serials:
                return True
            if int(mod.new_target) in region_anchor_blocks:
                return True
            if int(mod.from_serial) in region_anchor_blocks:
                return True
            return False
        if isinstance(mod, ConvertToGoto):
            if int(mod.block_serial) in region_pred_serials:
                return True
            if int(mod.goto_target) in region_anchor_blocks:
                return True
            if int(mod.block_serial) in region_anchor_blocks:
                return True
            return False
        if isinstance(mod, DuplicateAndRedirect):
            if int(mod.source_serial) in region_anchor_blocks:
                return True
            if int(mod.source_serial) in region_pred_serials:
                return True
            return False
        # Other mod kinds (NopInstructions, ZeroStateWrite, etc.) leave the
        # CFG topology intact, so they coexist safely with InsertBlock.
        return False

    # ------------------------------------------------------------------
    # Region detection (DAG-driven). Same logic as before.
    # ------------------------------------------------------------------
    def detect_chains(
        self, snapshot: "AnalysisSnapshot"
    ) -> list[HandlerChainCandidate]:
        """Detect maximal linear regions in the recon DAG."""
        mba = snapshot.mba
        if mba is None:
            return []

        dag = self._resolve_dag(snapshot)
        if dag is None or not dag.nodes:
            logger.info(
                "HandlerChainComposer: no DAG available; skipping"
            )
            return []

        state_var_stkoff = _resolve_state_var_stkoff_loose(snapshot)
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
        """Return maximal linear paths through the DAG."""
        node_by_key = {node.key: node for node in dag.nodes}

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

        is_region_start: set[object] = set()
        for node in dag.nodes:
            n_in = in_count.get(node.key, 0)
            if n_in != 1:
                is_region_start.add(node.key)

        visited: set[object] = set()
        regions: list[tuple[StateDagNode, ...]] = []

        ordered_nodes = sorted(
            dag.nodes,
            key=lambda n: (int(n.entry_anchor), str(n.state_label)),
        )

        for node in ordered_nodes:
            if node.key in visited:
                continue
            if node.key not in is_region_start:
                continue
            path = [node]
            visited.add(node.key)
            cur = node
            depth = 0
            while depth < 4096:
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
        if not region_nodes:
            return None

        first_anchor = int(region_nodes[0].entry_anchor)
        first_blk = self._safe_get_mblock(mba, first_anchor)
        if first_blk is None:
            return None

        pred_serial = self._resolve_first_pred(
            mba=mba,
            blk=first_blk,
            region_anchors={int(n.entry_anchor) for n in region_nodes},
            first_anchor=first_anchor,
        )
        if pred_serial is None:
            logger.info(
                "HandlerChainComposer: region first=%d has no usable pred",
                first_anchor,
            )
            return None

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
            state_values.append(0)

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
        first_anchor: int,
    ) -> int | None:
        """Pick the splice predecessor for the region's first handler.

        Accepts 1-way preds and 2-way preds whose conditional (taken) arm
        currently targets the region's first handler. Fallthrough-arm
        edges and non-conditional 2-way tails are skipped because the
        downstream backend cannot rewrite them via create-and-redirect
        without violating physical adjacency invariants.
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
                    nsucc = int(pred_blk.nsucc())  # type: ignore[attr-defined]
                except Exception:
                    continue
                if nsucc == 1:
                    eligible.append(p)
                    continue
                if nsucc != 2:
                    continue
                # 2-way pred: only allow when the conditional arm
                # (tail.d.b) currently targets the region's first
                # handler. The fallthrough arm cannot be safely
                # redirected via create-and-redirect.
                tail = getattr(pred_blk, "tail", None)
                if tail is None:
                    continue
                try:
                    if not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
                        continue
                    cond_target = int(tail.d.b)
                except Exception:
                    continue
                if cond_target != int(first_anchor):
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
        candidates: list[int] = []
        for edge in dag.edges:
            if edge.source_key != last_node.key:
                continue
            if edge.target_entry_anchor is None:
                continue
            candidates.append(int(edge.target_entry_anchor))
        if candidates:
            return min(candidates)

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
        """Walk ``blk.head`` and capture composable instructions, or None."""
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
            try:
                if ida_hexrays.is_mcode_jcond(opcode):
                    return None
            except Exception:
                return None
            if _is_state_write(insn, state_var_stkoff):
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
