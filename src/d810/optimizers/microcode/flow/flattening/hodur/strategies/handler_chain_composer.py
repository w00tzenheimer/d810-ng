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

This strategy is the live linearizer + region-collapse driver.  It absorbs
the orchestration that ``StateWriteReconstructionStrategy`` (SWR) used to
perform, and adds a region-collapse step on top that preserves use-def
dominance by folding maximal linear DAG regions into a single
``InsertBlock``.  The old standalone SRW strategy is opt-in only via
``D810_RECON_ENABLE_STANDALONE_SRW=1``.

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

Default behavior
----------------
HCC is the default live Hodur reconstruction path.  Disable it only for
archaeology or regression isolation with
``D810_DISABLE_HANDLER_CHAIN_COMPOSER=1`` or
``D810_ENABLE_HANDLER_CHAIN_COMPOSER=0``.

See ``docs/hodur/env_flags.md`` for the full Hodur/unflattening env-var
manifest.  When the class flag is False, ``plan()`` returns ``None`` and
emits no modifications.

Family: ``FAMILY_DIRECT``.
Prerequisites: ``[]`` -- this strategy IS the linearizer.
"""
from __future__ import annotations

import enum
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, replace

from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.block_identity import (
    block_label as flow_block_label,
    edge_label as flow_edge_label,
    flow_graph_context_label,
)
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
from d810.optimizers.microcode.flow.flattening.use_def_dominance import (
    check_redirect_severs_use_def,
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
    detect_side_effect_corridors,
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
from d810.recon.flow.round_discovery_context import (
    DagLocalFacts,
    _build_dag_local_facts,
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


# uee-b7ze Step 2: refinement of _FORBIDDEN_COMPOSITION_OPCODES into:
#   - _CLOSING_FORBIDDEN: structurally-positional opcodes that genuinely
#     close a block (return/branch tables/external/indirect jumps).  These
#     never become opaque-call anchors.
#   - _CALL_FORBIDDEN: side-effecting call opcodes.  When a region's
#     anchor block contains EXACTLY one of these, it is a candidate to
#     become an "opaque call anchor": the original block stays in the
#     CFG (calls untouched), and surrounding flow rewires AROUND it.
_CLOSING_FORBIDDEN: frozenset[int] = frozenset(
    {
        ida_hexrays.m_ret,
        ida_hexrays.m_jtbl,
        ida_hexrays.m_ijmp,
        ida_hexrays.m_ext,
    }
)

_CALL_FORBIDDEN: frozenset[int] = frozenset(
    {
        ida_hexrays.m_call,
        ida_hexrays.m_icall,
    }
)


def _env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip() == "1"


def _block_contains_call_opcode(mba: object, serial: int) -> bool:
    """Return whether ``serial`` currently contains an m_call/m_icall."""
    try:
        blk = mba.get_mblock(int(serial))  # type: ignore[attr-defined]
    except Exception:
        return False
    if blk is None:
        return False
    try:
        cur = blk.head
    except Exception:
        return False
    while cur is not None:
        try:
            if int(cur.opcode) in _CALL_FORBIDDEN:
                return True
            cur = cur.next
        except Exception:
            return False
    return False


@dataclass(frozen=True, slots=True)
class _CaptureResult:
    """Richer return type for ``_capture_block_composable_instructions``.

    ``kind`` is one of:
      * ``"composable"``: block has only whitelisted instructions; the
        ``snapshots`` field carries the captured composable body.
      * ``"closing_abort"``: block contains a closing-forbidden opcode
        (return/jtbl/ijmp/ext); ``abort_reason`` describes which.
      * ``"opaque_call_anchor"``: block contains exactly ONE call/icall
        and otherwise composable (or composable-after-call) body.
        ``call_ea``, ``is_indirect``, ``pre_call_count``, and
        ``post_call_count`` describe the call's location.

    For the legacy behaviour, callers can treat ``"composable"`` as the
    success case and any other ``kind`` as composition refusal.
    """

    kind: str
    snapshots: tuple[InsnSnapshot, ...] | None = None
    abort_reason: str | None = None
    call_ea: int | None = None
    is_indirect: bool | None = None
    pre_call_count: int | None = None
    post_call_count: int | None = None


@dataclass(frozen=True, slots=True)
class _WalkBackChunk:
    """One body prepended by chained-call recursive walk-back."""

    writer_serial: int
    target_stkoff: int
    ninsns: int


@dataclass(frozen=True, slots=True)
class _WalkBackResult:
    """Recursive walk-back result with enough provenance to retarget safely."""

    body: tuple[InsnSnapshot, ...]
    prepended_chunks: tuple[_WalkBackChunk, ...]


# ---------------------------------------------------------------------------
# Logging-only DAG-edge-driven entry resolver (uee-b7ze Step 1).
#
# This resolver runs alongside the existing physical-CFG-predecessor splice
# (``_resolve_first_pred``) and emits a structured ``REGION_LOWERING_CANDIDATE``
# log line per detected region.  It DOES NOT change emission behavior --
# ``InsertBlock.pred_serial`` continues to come from ``_resolve_first_pred``.
#
# Goal: collect data on (a) how often the new resolver agrees with the old
# one, (b) how often ``source_covered_by_other_region`` triggers, and (c) the
# per-eligibility distribution.  Step 2 (call-barrier segmentation) is OUT
# OF SCOPE here.
# ---------------------------------------------------------------------------


class EntryEligibility(str, enum.Enum):
    """Why a region head's semantic incoming edge is/isn't usable as a splice.

    Logging-only.  No emission decision currently consumes this enum.
    """

    NO_TRANSITION_INCOMING = "NO_TRANSITION_INCOMING"
    MULTIPLE_DISTINCT_SPLICE_SOURCES = "MULTIPLE_DISTINCT_SPLICE_SOURCES"
    SOURCE_DEAD = "SOURCE_DEAD"
    SOURCE_INSIDE_REGION = "SOURCE_INSIDE_REGION"
    SOURCE_NOT_1WAY = "SOURCE_NOT_1WAY"
    SOURCE_OLD_TARGET_UNREADABLE = "SOURCE_OLD_TARGET_UNREADABLE"
    UNCONDITIONAL_1WAY = "UNCONDITIONAL_1WAY"


@dataclass(frozen=True, slots=True)
class SemanticEntryCandidate:
    """Logging-only candidate for splicing a region via its DAG TRANSITION edge.

    Fields:
        head_state: ``state_const`` of the region head node (or 0 if absent).
        head_entry: Entry anchor block serial of the region head node.
        splice_source_block: The unique TRANSITION source block (when
            classification reaches the per-source check), else ``None``.
        splice_old_target: Existing single successor of ``splice_source_block``
            (the outgoing edge that would be replaced), else ``None``.
        transition_source_blocks: All distinct TRANSITION source blocks for
            edges incoming to the region head, ordered ascending.
        nontransition_source_blocks: All distinct non-TRANSITION (e.g.
            CONDITIONAL_TRANSITION) source blocks for edges incoming to the
            region head, ordered ascending.  Informational only -- never
            blocks ``UNCONDITIONAL_1WAY`` classification.
        eligibility: The classification (see ``EntryEligibility``).
        reason: Human-readable explanation of the classification.
    """

    head_state: int
    head_entry: int
    splice_source_block: int | None
    splice_old_target: int | None
    transition_source_blocks: tuple[int, ...]
    nontransition_source_blocks: tuple[int, ...]
    eligibility: EntryEligibility
    reason: str


def _resolve_semantic_entry_candidate(
    *,
    dag: LinearizedStateDag,
    region_head_node: StateDagNode,
    region_anchors: frozenset[int],
    mba: object,
) -> SemanticEntryCandidate:
    """Logging-only resolver for the semantic incoming edge of a region.

    Algorithm (per spec):
      1. Collect all ``dag.edges`` where ``target_key == region_head_node.key``.
      2. Partition by ``edge.kind``: TRANSITION vs everything else.
      3. If no TRANSITION edges -> ``NO_TRANSITION_INCOMING``.
      4. Group TRANSITION edges by source block (using
         ``edge.source_anchor.block_serial`` -- there is no separate
         ``source_block`` field on the edge dataclass).  If multiple distinct
         source blocks -> ``MULTIPLE_DISTINCT_SPLICE_SOURCES``.
      5. With a single source block:
           - ``mba.get_mblock(source_block)``; if ``None`` -> ``SOURCE_DEAD``
           - if ``source_block in region_anchors`` -> ``SOURCE_INSIDE_REGION``
           - if ``nsucc() != 1`` -> ``SOURCE_NOT_1WAY``
           - else: read ``succ(0)`` as ``splice_old_target``; on any failure
             -> ``SOURCE_OLD_TARGET_UNREADABLE``.  Otherwise:
             ``UNCONDITIONAL_1WAY``.

    Conditional-kind edges are NEVER allowed to block ``UNCONDITIONAL_1WAY``.
    They appear in ``nontransition_source_blocks`` for diagnostics only.
    """
    head_key = region_head_node.key
    head_state = int(getattr(head_key, "state_const", 0) or 0)
    head_entry = int(region_head_node.entry_anchor)

    transition_sources: list[int] = []
    nontransition_sources: list[int] = []
    for edge in dag.edges:
        if edge.target_key != head_key:
            continue
        try:
            src = int(edge.source_anchor.block_serial)
        except Exception:
            continue
        if edge.kind is SemanticEdgeKind.TRANSITION:
            transition_sources.append(src)
        else:
            nontransition_sources.append(src)

    transition_unique = tuple(sorted(set(transition_sources)))
    nontransition_unique = tuple(sorted(set(nontransition_sources)))

    if not transition_unique:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=None,
            splice_old_target=None,
            transition_source_blocks=(),
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.NO_TRANSITION_INCOMING,
            reason="no TRANSITION edges target region head",
        )

    if len(transition_unique) > 1:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=None,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.MULTIPLE_DISTINCT_SPLICE_SOURCES,
            reason=(
                "TRANSITION edges to region head originate from "
                f"{len(transition_unique)} distinct source blocks"
            ),
        )

    splice_source = int(transition_unique[0])

    src_blk = HandlerChainComposerStrategy._safe_get_mblock(mba, splice_source)
    if src_blk is None:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_DEAD,
            reason=f"mba.get_mblock({splice_source}) returned None",
        )

    if splice_source in region_anchors:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_INSIDE_REGION,
            reason=f"source block blk[{splice_source}] is itself a region anchor",
        )

    try:
        nsucc = int(src_blk.nsucc())  # type: ignore[attr-defined]
    except Exception:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_NOT_1WAY,
            reason=f"blk[{splice_source}].nsucc() raised",
        )

    if nsucc != 1:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_NOT_1WAY,
            reason=f"blk[{splice_source}].nsucc()={nsucc}, expected 1",
        )

    try:
        old_target = int(src_blk.succ(0))  # type: ignore[attr-defined]
    except Exception:
        return SemanticEntryCandidate(
            head_state=head_state,
            head_entry=head_entry,
            splice_source_block=splice_source,
            splice_old_target=None,
            transition_source_blocks=transition_unique,
            nontransition_source_blocks=nontransition_unique,
            eligibility=EntryEligibility.SOURCE_OLD_TARGET_UNREADABLE,
            reason=f"blk[{splice_source}].succ(0) raised",
        )

    return SemanticEntryCandidate(
        head_state=head_state,
        head_entry=head_entry,
        splice_source_block=splice_source,
        splice_old_target=old_target,
        transition_source_blocks=transition_unique,
        nontransition_source_blocks=nontransition_unique,
        eligibility=EntryEligibility.UNCONDITIONAL_1WAY,
        reason="single TRANSITION source is a 1-way block; semantic splice eligible",
    )


def _format_blk_list(serials: tuple[int, ...]) -> str:
    """Render ``(1, 2, 3)`` as ``[blk[1], blk[2], blk[3]]``."""
    if not serials:
        return "[]"
    return "[" + ", ".join(f"blk[{int(s)}]" for s in serials) + "]"


# ---------------------------------------------------------------------------
# Pre-compose raw-region table (uee-b7ze A0).
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _RawRegionInfo:
    """Best-effort observation about one raw region.

    Built once per ``detect_chains()`` invocation, BEFORE any region is
    handed to ``_compose_region``.  Fields that depend on the live mba may
    be ``None`` if the corresponding probe failed -- this object never
    aborts collection of the rest.

    ``composed_candidate`` carries the result of speculatively running
    ``_compose_region`` on this region.  When non-None, this region is
    "compose-viable" -- i.e. it has a usable physical predecessor, a
    resolvable exit successor, and a clean composable body.  This is the
    sole gate consulted by ``_classify_yes_handlers_subclass`` to decide
    whether a covering region (R1) is fit to be the front half of a
    fusion pair.  It does NOT depend on R1's ``SemanticEntryCandidate``
    eligibility flavor.
    """

    region_nodes: tuple[StateDagNode, ...]
    head_node: StateDagNode
    tail_node: StateDagNode
    head_anchor: int
    tail_anchor: int
    region_anchors: frozenset[int]
    old_physical_pred: int | None
    proposed_exit: int | None
    candidate: SemanticEntryCandidate
    composed_candidate: "HandlerChainCandidate | None" = None
    # uee-b7ze Step 2 (call-barrier segmentation): when one of the
    # region's anchor blocks contains exactly one m_call/m_icall and
    # otherwise has a clean composable body, record it here as
    # ``(block_serial, call_ea, is_indirect)``.  Phase A populates this
    # for diagnostics; Phase B (gated on
    # ``HCC_CALL_BARRIER_ENABLED``) consumes it to emit RedirectGoto
    # pairs that wire flow AROUND the anchor without relocating the
    # call instruction.
    opaque_call_anchor: tuple[int, int, bool] | None = None
    # Body shape diagnostics for the opaque-call anchor.  Populated only
    # when ``opaque_call_anchor`` is set.  ``pre_call_count`` and
    # ``post_call_count`` are the captured composable instruction counts
    # before and after the call.  ``shape`` is "SIMPLE_1WAY_OUT" when
    # the candidate satisfies the Phase B prerequisites, "OTHER"
    # otherwise.
    opaque_call_pre_count: int | None = None
    opaque_call_post_count: int | None = None
    opaque_call_shape: str | None = None


def _classify_source_covered_by_other_region(
    *,
    self_info: _RawRegionInfo,
    raw_region_table: tuple[_RawRegionInfo, ...],
) -> tuple[str, tuple[str, ...]]:
    """Return ``(label, all_reasons)`` cross-referenced against ALL raw regions.

    Computes coverage of the candidate's ``splice_source_block`` against the
    complete raw region set built during the pre-pass (NOT just regions
    iterated earlier).  Three independent reasons can apply:

      * ``YES_HANDLERS``       -- source appears in another region's
        ``region_anchors`` (i.e. another region's ``handlers=`` list).
      * ``YES_PHYSICAL_PRED``  -- source equals another region's
        ``old_physical_pred`` (i.e. another region's planned ``pred=``).
      * ``YES_COLLISION``      -- another region's
        ``candidate.splice_source_block`` equals this region's source
        (two semantic candidates claim the same source -- the second
        replacer would have stale ``old_target``).

    The returned ``label`` is the most-significant single matching reason
    using order ``COLLISION > HANDLERS > PHYSICAL_PRED``.  ``all_reasons``
    contains every matching reason in that priority order.
    """
    src = self_info.candidate.splice_source_block
    if src is None:
        return ("NO", ())
    src_int = int(src)
    self_id = id(self_info)

    has_collision = False
    has_handlers = False
    has_physical_pred = False
    for other in raw_region_table:
        if id(other) == self_id:
            continue
        other_src = other.candidate.splice_source_block
        if other_src is not None and int(other_src) == src_int:
            has_collision = True
        if src_int in other.region_anchors:
            has_handlers = True
        if (
            other.old_physical_pred is not None
            and src_int == int(other.old_physical_pred)
        ):
            has_physical_pred = True

    reasons: list[str] = []
    if has_collision:
        reasons.append("YES_COLLISION")
    if has_handlers:
        reasons.append("YES_HANDLERS")
    if has_physical_pred:
        reasons.append("YES_PHYSICAL_PRED")
    if not reasons:
        return ("NO", ())
    return (reasons[0], tuple(reasons))


# ---------------------------------------------------------------------------
# YES_HANDLERS sub-classification (uee-b7ze Step 1+2).
# ---------------------------------------------------------------------------
def _find_cover_regions(
    *,
    self_info: _RawRegionInfo,
    raw_region_table: tuple[_RawRegionInfo, ...],
) -> tuple[_RawRegionInfo, ...]:
    """Return raw-region records whose ``region_anchors`` contain
    ``self_info``'s splice source.

    Used to drive ``yes_handlers_subclass`` classification.
    """
    src = self_info.candidate.splice_source_block
    if src is None:
        return ()
    src_int = int(src)
    self_id = id(self_info)
    covers: list[_RawRegionInfo] = []
    for other in raw_region_table:
        if id(other) == self_id:
            continue
        if src_int in other.region_anchors:
            covers.append(other)
    return tuple(covers)


def _classify_yes_handlers_subclass(
    *,
    self_info: _RawRegionInfo,
    raw_region_table: tuple[_RawRegionInfo, ...],
) -> str | None:
    """Classify a YES_HANDLERS region into one of four sub-categories.

    Relaxed rule (revised in continuation patch): the cover-region
    ``R1``'s eligibility flavor is irrelevant -- the only thing that
    matters is whether ``R1`` actually produces a valid composed
    ``HandlerChainCandidate`` under current HCC rules.  If R1 composes,
    R1 has a usable physical pred + exit, which is all fusion needs.

    Returns one of:
      * ``"FUSABLE_LINEAR"``       -- exactly one cover region R1 exists,
        ``R1.composed_candidate`` is not None (R1 produced a valid
        candidate), ``R1.proposed_exit == self.head_anchor``, R1 and
        self do not share any handler anchors (no doubled-handler
        cycle), and R1's splice source is not claimed by yet another
        candidate.
      * ``"FUSABLE_RECURSIVE"``    -- reserved for future patches; not
        emitted by the current relaxed rule (recursive chain fusion is
        out of scope).
      * ``"NOT_FUSABLE_BRANCH"``   -- exactly one cover region R1 exists
        but ``R1.proposed_exit`` does NOT equal ``self.head_anchor``.
        R1 doesn't cleanly precede us; would require diamond reasoning.
      * ``"CONFLICT"``             -- splice-source collision with another
        candidate, handler-set overlap (cycle), R1 fails to compose,
        multiple cover regions, or cover not findable.

    Returns ``None`` only when ``self_info`` is not actually a
    YES_HANDLERS candidate (caller invariant).
    """
    covers = _find_cover_regions(
        self_info=self_info, raw_region_table=raw_region_table,
    )
    if not covers:
        # YES_HANDLERS was set, but we can't reproduce the cover here.
        # Treat as conflict (conservative).
        return "CONFLICT"

    # Multiple covers -> conflict.
    if len(covers) > 1:
        return "CONFLICT"

    cover = covers[0]

    # Compose-viability gate: R1 must have produced a valid candidate
    # under the regular per-region pass.  Without a composed candidate,
    # R1 has no usable pred/exit/body -- there is nothing to fuse with.
    if cover.composed_candidate is None:
        return "CONFLICT"

    # Splice-source collision: another raw region claims the same
    # ``splice_source_block`` as the cover.  This would race with the
    # fused emission for the same physical pred edge.
    cover_src = cover.candidate.splice_source_block
    if cover_src is not None:
        cover_src_int = int(cover_src)
        for other in raw_region_table:
            if id(other) == id(cover) or id(other) == id(self_info):
                continue
            other_src = other.candidate.splice_source_block
            if other_src is not None and int(other_src) == cover_src_int:
                return "CONFLICT"

    # Handler-set overlap guard: R1.handlers and R2.handlers must be
    # disjoint.  Overlap would produce a doubled handler in the fused
    # output (a cycle in handler-anchor order).
    if not self_info.region_anchors.isdisjoint(cover.region_anchors):
        return "CONFLICT"

    # Linear / branch distinction.  Cover's exit must land exactly at
    # self's head for the fused composition to be a contiguous chain.
    cover_exit = cover.proposed_exit
    self_head = self_info.head_anchor
    if cover_exit is not None and int(cover_exit) == int(self_head):
        return "FUSABLE_LINEAR"

    return "NOT_FUSABLE_BRANCH"


# ---------------------------------------------------------------------------
# FUSABLE_LOCAL_CONVERGENCE -- convergence-aware variant of fusion.
# ---------------------------------------------------------------------------
#
# Plain FUSABLE_LINEAR assumes R2's splice_source_block is a 1-way pred
# (npred==1).  When it is actually a multi-pred convergence point inside
# R1's owning state's local CFG, single-edge emission is wrong: only one
# of the convergence preds gets the spliced body.  ``FUSABLE_LOCAL_CONVERGENCE``
# detects this shape and (when ``HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION_ENABLED`` is set)
# emits ONE ``InsertBlock`` per incoming edge, all sharing the same
# composed body, all-or-nothing.

# Sub-labels reported via REGION_LOWERING_CANDIDATE when convergence
# is rejected for a structural reason.  These are NOT fall-through to
# FUSABLE_LINEAR -- they are explicit failure modes so the diagnostic
# is auditable.
_CONVERGENCE_UNSUPPORTED_LABELS: tuple[str, ...] = (
    "CONVERGENCE_UNSUPPORTED_EXTERNAL_PRED",
    "CONVERGENCE_UNSUPPORTED_PRED_SHAPE",
    "CONVERGENCE_UNSUPPORTED_FALLTHROUGH_2WAY",
    "CONVERGENCE_FORBIDDEN_BODY",
)


@dataclass(frozen=True, slots=True)
class _ConvergenceIncomingEdge:
    """One supported incoming edge feeding a convergence block."""

    pred: int
    kind: str  # "conditional" or "one_way"
    old_target: int
    edge_validation: str


@dataclass(frozen=True, slots=True)
class _ConvergencePlan:
    """All-or-nothing per-pred plan for FUSABLE_LOCAL_CONVERGENCE.

    Built only when EVERY live pred of ``convergence_block`` validates
    cleanly inside the same owning state.  Carries the per-pred edges
    that ``_apply_fusable_local_convergence_fusion`` will materialize
    as one ``InsertBlock`` each.
    """

    convergence_block: int
    incoming_edges: tuple[_ConvergenceIncomingEdge, ...]
    owning_state_anchor: int  # entry_anchor of the owning StateDagNode


@dataclass(frozen=True, slots=True)
class _TailExtensionPlan:
    """All-or-nothing plan for FUSABLE_TAIL_EXTENSION.

    Built when R2's ``splice_source_block`` (the ``convergence_block``
    in the convergence-classifier vocabulary) is a multi-pred local
    convergence inside R1's owning state's local CFG.  Instead of
    cloning the convergence per-incoming-edge (the ``_ConvergencePlan``
    behavior, which broke SSA versioning), this plan preserves the
    original convergence and redirects only the convergence's
    outgoing dispatcher edge through a single InsertBlock that
    carries R2's composable instructions and lands at R2's exit.

    Fields:
      convergence_block: The shared convergence block (R2's
        ``splice_source_block``).  Preserved as-is in the live CFG
        so its preds remain intact and SSA versioning is undisturbed.
      splice_old_target: The convergence's current outgoing successor
        (the dispatcher / R2's ``splice_old_target``).  This is the
        edge replaced by the tail-extension InsertBlock.
      exit_target: R2's exit successor block (where the tail-extension
        InsertBlock body lands after running R2's instructions).
      owning_state_anchor: ``entry_anchor`` of the convergence's
        owning ``StateDagNode``.  Logged for cross-reference.
    """

    convergence_block: int
    splice_old_target: int
    exit_target: int
    owning_state_anchor: int


def _find_owning_state_node(
    *,
    local_facts: DagLocalFacts,
    block: int,
) -> StateDagNode | None:
    """Return the ``StateDagNode`` whose local CFG contains ``block``.

    Uses ``DagLocalFacts.node_by_any_local_block`` — the broad "any local
    block" mapping built by recon's chunk-6 bundle — so shared-suffix
    corridor blocks resolve to their owning state correctly.  Strict
    ``owned_blocks ∪ exclusive_blocks`` checks miss shared-suffix blocks
    and cause legitimate convergence sites to misclassify as
    ``CONVERGENCE_UNSUPPORTED_EXTERNAL_PRED``.
    """
    return local_facts.node_by_any_local_block.get(int(block))


def _state_node_owns_block(
    *, local_facts: DagLocalFacts, owner: StateDagNode, block: int,
) -> bool:
    """Return True when ``block`` is part of ``owner``'s local CFG.

    Looks up ``block`` in ``DagLocalFacts.node_by_any_local_block`` and
    compares identity against ``owner``.  This mirrors the broad
    "any local block" semantics of :func:`_find_owning_state_node`.
    """
    found = local_facts.node_by_any_local_block.get(int(block))
    return found is owner


def _classify_convergence_or_linear(
    *,
    self_info: _RawRegionInfo,
    raw_region_table: tuple[_RawRegionInfo, ...],
    dag: LinearizedStateDag,
    local_facts: DagLocalFacts,
    mba: object,
) -> tuple[str, _ConvergencePlan | _TailExtensionPlan | None]:
    """Try ``FUSABLE_TAIL_EXTENSION`` first; on failure fall back.

    Order of precedence (per uee-tail-extension):
      1. ``FUSABLE_TAIL_EXTENSION`` -- multi-pred local convergence with
         all preds inside the same owning state's local CFG.  Returns
         ``("FUSABLE_TAIL_EXTENSION", _TailExtensionPlan(...))``.  This
         supersedes the older per-edge convergence-duplication path,
         which broke SSA versioning by cloning the convergence block.
      2. ``FUSABLE_LOCAL_CONVERGENCE`` -- DORMANT: now subsumed by
         ``FUSABLE_TAIL_EXTENSION``.  Kept in the type signature for
         backward compat but never returned by this function.  The
         existing ``_apply_fusable_local_convergence_fusion`` machinery
         stays in place behind ``HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION_ENABLED``
         but will not see any candidates labeled this way.
      3. Otherwise returns one of the explicit ``CONVERGENCE_UNSUPPORTED_*``
         labels (with ``None``) when the shape *is* multi-pred but
         unsupported, OR delegates to ``_classify_yes_handlers_subclass``
         for the linear/branch/conflict triage when the shape is
         single-pred.
    """
    # Reproduce the basic guards from _classify_yes_handlers_subclass:
    # only proceed when there is exactly one cover region whose
    # composed_candidate is non-None.
    covers = _find_cover_regions(
        self_info=self_info, raw_region_table=raw_region_table,
    )
    if len(covers) != 1:
        return _classify_yes_handlers_subclass(
            self_info=self_info, raw_region_table=raw_region_table,
        ) or "CONFLICT", None

    cover = covers[0]
    if cover.composed_candidate is None:
        return _classify_yes_handlers_subclass(
            self_info=self_info, raw_region_table=raw_region_table,
        ) or "CONFLICT", None

    # The convergence candidate is R2's splice_source_block.  When it
    # can't be resolved or is single-pred, fall back to linear.
    splice_source = self_info.candidate.splice_source_block
    if splice_source is None:
        return _classify_yes_handlers_subclass(
            self_info=self_info, raw_region_table=raw_region_table,
        ) or "CONFLICT", None
    convergence = int(splice_source)

    convergence_blk = HandlerChainComposerStrategy._safe_get_mblock(
        mba, convergence,
    )
    if convergence_blk is None:
        return _classify_yes_handlers_subclass(
            self_info=self_info, raw_region_table=raw_region_table,
        ) or "CONFLICT", None

    try:
        npred = int(convergence_blk.npred())  # type: ignore[attr-defined]
    except Exception:
        return _classify_yes_handlers_subclass(
            self_info=self_info, raw_region_table=raw_region_table,
        ) or "CONFLICT", None

    if npred < 2:
        # Single-pred shape -- defer entirely to the existing classifier.
        return _classify_yes_handlers_subclass(
            self_info=self_info, raw_region_table=raw_region_table,
        ) or "CONFLICT", None

    # Multi-pred convergence detected.  Apply convergence-specific
    # validation rules; do NOT fall back to FUSABLE_LINEAR for these
    # cases -- that would reproduce the single-edge bug.

    # Rule (5): R2.composed_candidate must be present (otherwise R2's
    # body has forbidden opcodes / unrenderable instructions).
    if self_info.composed_candidate is None:
        return "CONVERGENCE_FORBIDDEN_BODY", None

    # Rule (2): convergence block must have an owning state in the DAG.
    # Lookup uses DagLocalFacts.node_by_any_local_block, which covers
    # owned/exclusive AND shared-suffix corridor blocks.
    owner = _find_owning_state_node(local_facts=local_facts, block=convergence)
    if owner is None:
        return "CONVERGENCE_UNSUPPORTED_EXTERNAL_PRED", None

    # Rules (3) + (4): every live pred must be inside the owning
    # state's local CFG AND cleanly redirectable.
    incoming: list[_ConvergenceIncomingEdge] = []
    try:
        pred_serials = [
            int(convergence_blk.pred(i))  # type: ignore[attr-defined]
            for i in range(npred)
        ]
    except Exception:
        return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None

    for p in pred_serials:
        if not _state_node_owns_block(
            local_facts=local_facts, owner=owner, block=p,
        ):
            return "CONVERGENCE_UNSUPPORTED_EXTERNAL_PRED", None
        pred_blk = HandlerChainComposerStrategy._safe_get_mblock(mba, p)
        if pred_blk is None:
            return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
        try:
            pn = int(pred_blk.nsucc())  # type: ignore[attr-defined]
        except Exception:
            return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
        if pn == 1:
            try:
                s0 = int(pred_blk.succ(0))  # type: ignore[attr-defined]
            except Exception:
                return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
            if s0 != convergence:
                return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
            incoming.append(
                _ConvergenceIncomingEdge(
                    pred=p,
                    kind="one_way",
                    old_target=convergence,
                    edge_validation="ok_one_way",
                )
            )
            continue
        if pn == 2:
            tail = getattr(pred_blk, "tail", None)
            if tail is None:
                return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
            try:
                if not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
                    return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
                cond_target = int(tail.d.b)
            except Exception:
                return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None
            if cond_target == convergence:
                incoming.append(
                    _ConvergenceIncomingEdge(
                        pred=p,
                        kind="conditional",
                        old_target=convergence,
                        edge_validation="ok_taken_arm",
                    )
                )
                continue
            # 2-way pred whose taken arm is NOT the convergence
            # block -- convergence reached via fallthrough is not
            # safely redirectable.
            return "CONVERGENCE_UNSUPPORTED_FALLTHROUGH_2WAY", None
        # 0-way / 3+-way / unknown shape.
        return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None

    # Tail-extension shape matched: replace per-edge convergence
    # duplication (FUSABLE_LOCAL_CONVERGENCE) with a single
    # InsertBlock that redirects only the convergence block's
    # outgoing edge.  R2's exit_target is the candidate's
    # ``proposed_exit`` (resolved via ``_resolve_region_exit``).
    if self_info.proposed_exit is None:
        # Defensive: if R2 has no resolvable exit, the splice has
        # nowhere to land.  Treat as unsupported.
        return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None

    splice_old_target = self_info.candidate.splice_old_target
    if splice_old_target is None:
        return "CONVERGENCE_UNSUPPORTED_PRED_SHAPE", None

    tail_plan = _TailExtensionPlan(
        convergence_block=convergence,
        splice_old_target=int(splice_old_target),
        exit_target=int(self_info.proposed_exit),
        owning_state_anchor=int(owner.entry_anchor),
    )
    return "FUSABLE_TAIL_EXTENSION", tail_plan


def _find_r1_to_suppress(
    *,
    splice_source_block: int,
    raw_region_table: tuple[_RawRegionInfo, ...],
    consumed_ids: set[int],
) -> _RawRegionInfo | None:
    """Surgical R1 suppression: locate the unique cover region whose
    ``composed_candidate.handler_serials`` contains ``splice_source_block``.

    Returns the matching ``_RawRegionInfo`` ONLY when exactly one cover
    region has the splice source in its composed candidate's handler
    list.  Returns ``None`` if zero or multiple matches exist (caller
    should reject with ``r1_not_uniquely_identified``).

    ``consumed_ids`` is the set of region ids already claimed in this
    batch; matching regions in this set are excluded so we do not
    "re-claim" an R1 that another tail-extension candidate already
    suppressed.
    """
    matches: list[_RawRegionInfo] = []
    for info in raw_region_table:
        if id(info) in consumed_ids:
            continue
        composed = info.composed_candidate
        if composed is None:
            continue
        try:
            handler_serials = tuple(int(s) for s in composed.handler_serials)
        except Exception:
            continue
        if splice_source_block in handler_serials:
            matches.append(info)
    if len(matches) != 1:
        return None
    return matches[0]


def _classify_yes_handlers_with_convergence(
    *,
    info: _RawRegionInfo,
    raw_region_table: tuple[_RawRegionInfo, ...],
    dag: LinearizedStateDag | None,
    local_facts: DagLocalFacts | None,
    mba: object | None,
) -> str | None:
    """Wrapper that prefers convergence detection when ``dag``/``mba``/
    ``local_facts`` are all provided.  Falls back to the linear-only
    classifier otherwise.
    """
    if dag is None or mba is None or local_facts is None:
        return _classify_yes_handlers_subclass(
            self_info=info, raw_region_table=raw_region_table,
        )
    label, _plan = _classify_convergence_or_linear(
        self_info=info,
        raw_region_table=raw_region_table,
        dag=dag,
        local_facts=local_facts,
        mba=mba,
    )
    return label


# ---------------------------------------------------------------------------
# uee-b7ze Step 2.1: refined opaque-call anchor classification + per-anchor
# diagnostic context.  Helpers below do NOT change emission behavior; they
# augment HCC_CALL_BARRIER_CANDIDATE / REGION_LOWERING_SUMMARY logs with
# structured shape sub-labels and (when the diag DB is reachable at plan
# time) per-anchor liveness across snapshots so the user can pinpoint the
# earliest kill point for an anchor block.
# ---------------------------------------------------------------------------

# Refined opaque-call anchor shape labels. Priority order (most specific
# first); the first matching label wins per ``_refine_opaque_call_shape``.
_OPAQUE_CALL_SHAPE_KEYS: tuple[str, ...] = (
    "SIMPLE_1WAY_OUT",
    "CHAINED_CALL_ANCHOR",
    "SHARED_SUFFIX_CALL_ANCHOR",
    "ANCHOR_OUT_BRANCH",
    "ANCHOR_MULTI_PRED",
    "OTHER",
)

# Snapshot labels we walk to compute the earliest kill point. Order is
# pipeline-temporal: anchors disappearing at an earlier label than the
# final IDA cleanup are dying inside our pipeline.
_KILL_POINT_SNAPSHOT_ORDER: tuple[str, ...] = (
    "maturity_MMAT_GLBOPT1_pre_d810",
    "handler_chain_composer_post_apply",
    "post_pipeline",
    "maturity_MMAT_GLBOPT1_post_d810",
)


def _format_serial_list(items) -> str:
    """Render an iterable of ints as ``[blk[a], blk[b], ...]`` (sorted)."""
    try:
        sorted_items = sorted({int(s) for s in items})
    except Exception:
        return "[]"
    if not sorted_items:
        return "[]"
    return "[" + ", ".join(f"blk[{s}]" for s in sorted_items) + "]"


def _refine_opaque_call_shape(
    *,
    base_shape: str,
    region_nodes: tuple[StateDagNode, ...],
    opaque_call_anchor: tuple[int, int, bool] | None,
    dag: LinearizedStateDag | None,
    local_facts: DagLocalFacts | None,
    mba: object | None,
    state_var_stkoff: int | None = None,
) -> str:
    """Return ONE refined shape label for an opaque-call anchor.

    Priority order (first match wins):
        SIMPLE_1WAY_OUT > CHAINED_CALL_ANCHOR > SHARED_SUFFIX_CALL_ANCHOR
        > ANCHOR_OUT_BRANCH > ANCHOR_MULTI_PRED > OTHER

    The ``base_shape`` argument is the legacy classifier's output. When
    it is ``SIMPLE_1WAY_OUT`` we honor it unchanged (priority preserved).
    Otherwise we walk the refinement checks below.

    All probes are best-effort: a raised exception or missing input
    falls through to the next check (and ultimately ``OTHER``).
    """
    if base_shape == "SIMPLE_1WAY_OUT":
        return "SIMPLE_1WAY_OUT"
    if opaque_call_anchor is None:
        return "OTHER"
    anchor_serial = int(opaque_call_anchor[0])

    # CHAINED_CALL_ANCHOR: handler is the LAST node of a multi-node region
    # whose preceding nodes are all "composable" (no forbidden opcodes).
    try:
        if (
            len(region_nodes) > 1
            and int(region_nodes[-1].entry_anchor) == anchor_serial
            and mba is not None
        ):
            all_pre_composable = True
            for node in region_nodes[:-1]:
                node_serial = int(node.entry_anchor)
                node_blk = HandlerChainComposerStrategy._safe_get_mblock(
                    mba, node_serial,
                )
                if node_blk is None:
                    all_pre_composable = False
                    break
                cap = (
                    HandlerChainComposerStrategy
                    ._capture_block_composable_instructions_v2(
                        node_blk, state_var_stkoff=state_var_stkoff,
                    )
                )
                if cap.kind != "composable":
                    all_pre_composable = False
                    break
            if all_pre_composable:
                return "CHAINED_CALL_ANCHOR"
    except Exception:
        pass

    # SHARED_SUFFIX_CALL_ANCHOR: handler block lives in some state's
    # shared_suffix_blocks per DagLocalFacts reverse-lookup.
    try:
        if local_facts is not None:
            for entry, suffix_blocks in (
                local_facts.shared_suffix_by_entry.items()
            ):
                if anchor_serial in suffix_blocks:
                    return "SHARED_SUFFIX_CALL_ANCHOR"
    except Exception:
        pass

    # ANCHOR_OUT_BRANCH: 1-way handler whose successor is a 2-way block
    # whose conditional arms diverge into different states.
    try:
        if mba is not None:
            anchor_blk = HandlerChainComposerStrategy._safe_get_mblock(
                mba, anchor_serial,
            )
            if anchor_blk is not None and int(anchor_blk.nsucc()) == 1:
                succ_serial = int(anchor_blk.succ(0))
                succ_blk = HandlerChainComposerStrategy._safe_get_mblock(
                    mba, succ_serial,
                )
                if succ_blk is not None and int(succ_blk.nsucc()) == 2:
                    arm_a = int(succ_blk.succ(0))
                    arm_b = int(succ_blk.succ(1))
                    if arm_a != arm_b and dag is not None:
                        # Confirm the arms map to different DAG nodes
                        # (different downstream states).  Pure local
                        # node-by-block lookup; absent index falls back
                        # to "different serials" as the only signal.
                        node_a = None
                        node_b = None
                        if local_facts is not None:
                            node_a = local_facts.node_by_any_local_block.get(
                                arm_a,
                            )
                            node_b = local_facts.node_by_any_local_block.get(
                                arm_b,
                            )
                        if node_a is None or node_b is None:
                            return "ANCHOR_OUT_BRANCH"
                        if node_a.key != node_b.key:
                            return "ANCHOR_OUT_BRANCH"
    except Exception:
        pass

    # ANCHOR_MULTI_PRED: handler block has npred() > 1 in the live CFG.
    try:
        if mba is not None:
            anchor_blk = HandlerChainComposerStrategy._safe_get_mblock(
                mba, anchor_serial,
            )
            if anchor_blk is not None and int(anchor_blk.npred()) > 1:
                return "ANCHOR_MULTI_PRED"
    except Exception:
        pass

    return "OTHER"


def _open_diag_db_readonly() -> object | None:
    """Return a sqlite3 Connection to a diag DB usable for cross-snapshot
    queries, or ``None``.

    The diag subsystem is per-decompilation: the active session's DB
    only contains snapshots taken so far in this run, so ``post_pipeline``
    / ``maturity_MMAT_GLBOPT1_post_d810`` from this run's GLBOPT1 plan
    pass aren't there yet.  For "earliest kill point" diagnostics we
    look at the most recent diag DB on disk that already has the full
    snapshot timeline for the same function.

    Falls back to ``None`` when no usable DB is found.
    """
    try:
        from d810.core.settings import get_settings
    except Exception:
        return None
    try:
        if not get_settings().diag_snapshots:
            return None
    except Exception:
        return None
    # Walk DB files newest-first; pick the first one that has the
    # late post-pipeline / GLBOPT1-post-d810 snapshots we need.
    try:
        import os as _os
        import sqlite3 as _sqlite3
        from pathlib import Path as _Path
        log_dir = _Path(_os.path.expanduser("~/.idapro/logs/d810_logs"))
        if not log_dir.exists():
            return None
        candidates = sorted(
            log_dir.glob("*.diag.sqlite3"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in candidates:
            try:
                conn = _sqlite3.connect(str(path))
            except Exception:
                continue
            try:
                has_post_pipeline = conn.execute(
                    "SELECT 1 FROM snapshots WHERE label = ? LIMIT 1",
                    ("post_pipeline",),
                ).fetchone()
                has_glbopt1_post = conn.execute(
                    "SELECT 1 FROM snapshots WHERE label = ? LIMIT 1",
                    ("maturity_MMAT_GLBOPT1_post_d810",),
                ).fetchone()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            if (
                has_post_pipeline is not None
                and has_glbopt1_post is not None
            ):
                return conn
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        return None
    return None


def _query_block_state_in_snapshot(
    conn,
    snapshot_label: str,
    block_serial: int,
) -> dict[str, object] | None:
    """Return ``{'preds': [...], 'succs': [...], 'reachable_from_0': YES|NO}``
    for ``block_serial`` in the latest snapshot with ``snapshot_label``,
    or ``None`` when the snapshot is missing or the block is missing in
    that snapshot.

    Snapshot label resolution: prefer the highest snapshot id with the
    given label (most recent run).  Reachability uses BFS over
    ``blocks.succs`` JSON.
    """
    try:
        row = conn.execute(
            "SELECT id FROM snapshots WHERE label = ? ORDER BY id DESC LIMIT 1",
            (snapshot_label,),
        ).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    snapshot_id = int(row[0])
    try:
        blk_row = conn.execute(
            "SELECT preds, succs FROM blocks WHERE snapshot_id = ? AND serial = ?",
            (snapshot_id, block_serial),
        ).fetchone()
    except Exception:
        return None
    if blk_row is None:
        return {"preds": None, "succs": None, "reachable_from_0": "NO"}
    import json as _json
    try:
        preds = _json.loads(blk_row[0]) if blk_row[0] else []
        succs = _json.loads(blk_row[1]) if blk_row[1] else []
    except Exception:
        preds, succs = [], []
    # BFS from blk[0] over succs to determine reachability.
    reachable = "UNKNOWN"
    try:
        all_rows = conn.execute(
            "SELECT serial, succs FROM blocks WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchall()
        succ_map: dict[int, list[int]] = {}
        for serial, succs_blob in all_rows:
            try:
                succ_map[int(serial)] = (
                    _json.loads(succs_blob) if succs_blob else []
                )
            except Exception:
                succ_map[int(serial)] = []
        visited: set[int] = set()
        stack = [0]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            for nxt in succ_map.get(cur, ()):
                stack.append(int(nxt))
        reachable = "YES" if int(block_serial) in visited else "NO"
    except Exception:
        reachable = "UNKNOWN"
    return {
        "preds": [int(p) for p in preds],
        "succs": [int(s) for s in succs],
        "reachable_from_0": reachable,
    }


def _collect_anchor_diag_context(
    *,
    anchor_serial: int,
    mba: object | None,
    local_facts: DagLocalFacts | None,
) -> dict[str, object]:
    """Collect per-anchor diagnostic context for HCC_CALL_BARRIER_CANDIDATE.

    Returned dict keys:
        owning_states_via_local_facts:  list[str]  -- "STATE_X (role=...)"
        preds_pre_pipeline:             str        -- "[blk[a], blk[b]]"
        preds_post_hcc:                 str
        preds_post_pipeline:            str
        succs_pre_pipeline:             str
        succs_post_hcc:                 str
        succs_post_pipeline:            str
        reachable_from_entry_post_pipeline: "YES" | "NO" | "UNKNOWN"
        survives_glbopt1_post_d810:     "YES" | "NO" | "UNKNOWN"
        earliest_kill_point:            str

    All snapshot lookups are best-effort.  When the diag DB is not
    reachable, snapshot-derived fields are set to ``"UNKNOWN"`` and
    ``earliest_kill_point`` is ``"unknown"``.
    """
    # Owning states via local_facts.  An anchor is OWNED by a state when
    # it appears in ``owned_blocks_by_entry[entry]``; SHARED_SUFFIX when
    # it appears in ``shared_suffix_by_entry[entry]``.
    owning_descriptions: list[str] = []
    if local_facts is not None:
        try:
            for entry, owned_blocks in local_facts.owned_blocks_by_entry.items():
                if anchor_serial in owned_blocks:
                    node = local_facts.node_by_entry.get(entry)
                    state_const = (
                        int(getattr(node.key, "state_const", 0) or 0)
                        if node is not None
                        else 0
                    )
                    owning_descriptions.append(
                        f"STATE_0x{state_const:08X} (role=owned, entry=blk[{int(entry)}])"
                    )
            for entry, suffix_blocks in (
                local_facts.shared_suffix_by_entry.items()
            ):
                if anchor_serial in suffix_blocks:
                    node = local_facts.node_by_entry.get(entry)
                    state_const = (
                        int(getattr(node.key, "state_const", 0) or 0)
                        if node is not None
                        else 0
                    )
                    owning_descriptions.append(
                        f"STATE_0x{state_const:08X} (role=shared_suffix, entry=blk[{int(entry)}])"
                    )
        except Exception:
            pass

    # Snapshot probes.
    conn = _open_diag_db_readonly()
    snapshot_results: dict[str, dict[str, object] | None] = {}
    if conn is not None:
        for label in _KILL_POINT_SNAPSHOT_ORDER:
            try:
                snapshot_results[label] = _query_block_state_in_snapshot(
                    conn, label, anchor_serial,
                )
            except Exception:
                snapshot_results[label] = None
        try:
            conn.close()
        except Exception:
            pass

    def _fmt(label: str, key: str) -> str:
        snap = snapshot_results.get(label)
        if snap is None or snap.get(key) is None:
            return "UNKNOWN"
        return _format_serial_list(snap.get(key) or ())

    pre_pipeline_lbl = "maturity_MMAT_GLBOPT1_pre_d810"
    post_hcc_lbl = "handler_chain_composer_post_apply"
    post_pipeline_lbl = "post_pipeline"
    post_glbopt1_lbl = "maturity_MMAT_GLBOPT1_post_d810"

    reach_post_pipeline = "UNKNOWN"
    snap_post = snapshot_results.get(post_pipeline_lbl)
    if snap_post is not None:
        v = snap_post.get("reachable_from_0")
        if isinstance(v, str):
            reach_post_pipeline = v

    survives_glbopt1 = "UNKNOWN"
    snap_glbopt1 = snapshot_results.get(post_glbopt1_lbl)
    if snap_glbopt1 is None:
        survives_glbopt1 = "UNKNOWN"
    else:
        # Block missing at snapshot => preds=None, reachable_from_0=NO.
        if snap_glbopt1.get("preds") is None:
            survives_glbopt1 = "NO"
        else:
            survives_glbopt1 = "YES"

    # earliest_kill_point: walk in pipeline-temporal order, first label
    # where the block has been removed wins. ``preds is None`` is the
    # canonical "missing in this snapshot" signal from
    # ``_query_block_state_in_snapshot``.
    earliest_kill_point = "NEVER"
    if conn is None and not snapshot_results:
        earliest_kill_point = "unknown"
    else:
        # Was the block alive in the FIRST snapshot at all?  If not,
        # we cannot really declare a kill point.
        first_snap = snapshot_results.get(_KILL_POINT_SNAPSHOT_ORDER[0])
        if first_snap is None or first_snap.get("preds") is None:
            earliest_kill_point = "unknown"
        else:
            for label in _KILL_POINT_SNAPSHOT_ORDER:
                snap = snapshot_results.get(label)
                if snap is None:
                    # snapshot itself missing -> can't conclude
                    continue
                if snap.get("preds") is None:
                    earliest_kill_point = label
                    break

    return {
        "owning_states_via_local_facts": owning_descriptions,
        "preds_pre_pipeline": _fmt(pre_pipeline_lbl, "preds"),
        "preds_post_hcc": _fmt(post_hcc_lbl, "preds"),
        "preds_post_pipeline": _fmt(post_pipeline_lbl, "preds"),
        "succs_pre_pipeline": _fmt(pre_pipeline_lbl, "succs"),
        "succs_post_hcc": _fmt(post_hcc_lbl, "succs"),
        "succs_post_pipeline": _fmt(post_pipeline_lbl, "succs"),
        "reachable_from_entry_post_pipeline": reach_post_pipeline,
        "survives_glbopt1_post_d810": survives_glbopt1,
        "earliest_kill_point": earliest_kill_point,
    }


def _log_region_lowering_candidate(
    *,
    info: _RawRegionInfo,
    raw_region_table: tuple[_RawRegionInfo, ...],
    dag: LinearizedStateDag | None = None,
    local_facts: DagLocalFacts | None = None,
    mba: object | None = None,
) -> None:
    """Emit the structured ``REGION_LOWERING_CANDIDATE`` log line.

    Runs in the pre-pass: every raw region produces exactly one log line
    regardless of whether ``_compose_region`` would later succeed.
    """
    candidate = info.candidate
    tail_state = int(getattr(info.tail_node.key, "state_const", 0) or 0)
    handler_block_list = tuple(int(n.entry_anchor) for n in info.region_nodes)
    if info.old_physical_pred is None:
        old_physical_pred_label = "None"
        divergence = "UNKNOWN"
    else:
        old_physical_pred_label = f"blk[{int(info.old_physical_pred)}]"
        divergence = (
            "YES"
            if (
                candidate.splice_source_block is not None
                and int(candidate.splice_source_block)
                != int(info.old_physical_pred)
            )
            else "NO"
        )
    if info.proposed_exit is None:
        exit_target_label = "None"
    else:
        exit_target_label = f"blk[{int(info.proposed_exit)}]"
    covered_label, covered_reasons = _classify_source_covered_by_other_region(
        self_info=info,
        raw_region_table=raw_region_table,
    )
    if (
        candidate.eligibility is EntryEligibility.UNCONDITIONAL_1WAY
        and candidate.splice_source_block is not None
        and candidate.splice_old_target is not None
        and info.proposed_exit is not None
    ):
        proposed = (
            f"blk[{int(candidate.splice_source_block)}] "
            f"--replace {int(candidate.splice_source_block)}->"
            f"{int(candidate.splice_old_target)}--> "
            f"inserted(copy handlers={_format_blk_list(handler_block_list)}) "
            f"-> blk[{int(info.proposed_exit)}]"
        )
    else:
        proposed = "NONE"
    covered_field = covered_label
    if covered_reasons and len(covered_reasons) > 1:
        covered_field = (
            f"{covered_label} (matches={','.join(covered_reasons)})"
        )
    # uee-b7ze Step 2: classify YES_HANDLERS into sub-categories.
    yes_handlers_subclass: str | None = None
    if "YES_HANDLERS" in covered_reasons:
        try:
            yes_handlers_subclass = _classify_yes_handlers_with_convergence(
                info=info,
                raw_region_table=raw_region_table,
                dag=dag,
                local_facts=local_facts,
                mba=mba,
            )
        except Exception:  # pragma: no cover - diagnostic only
            yes_handlers_subclass = None
    yes_handlers_subclass_field = (
        yes_handlers_subclass if yes_handlers_subclass is not None else "N/A"
    )
    logger.info(
        "REGION_LOWERING_CANDIDATE\n"
        "  phase=PRE_COMPOSE\n"
        "  head_state=0x%08X head_entry=blk[%d]\n"
        "  tail_state=0x%08X exit_target=%s\n"
        "  old_physical_pred=%s\n"
        "  transition_sources=%s\n"
        "  nontransition_sources=%s\n"
        "  splice_source_block=%s\n"
        "  splice_old_target=%s\n"
        "  proposed_splice=%s\n"
        "  eligibility=%s\n"
        "  reason=%r\n"
        "  divergence_from_old=%s\n"
        "  same_batch_regions_total=%d\n"
        "  source_covered_by_other_region=%s\n"
        "  yes_handlers_subclass=%s",
        candidate.head_state & 0xFFFFFFFF,
        candidate.head_entry,
        tail_state & 0xFFFFFFFF,
        exit_target_label,
        old_physical_pred_label,
        _format_blk_list(candidate.transition_source_blocks),
        _format_blk_list(candidate.nontransition_source_blocks),
        (
            f"blk[{int(candidate.splice_source_block)}]"
            if candidate.splice_source_block is not None
            else "None"
        ),
        (
            f"blk[{int(candidate.splice_old_target)}]"
            if candidate.splice_old_target is not None
            else "None"
        ),
        proposed,
        candidate.eligibility.value,
        candidate.reason,
        divergence,
        len(raw_region_table),
        covered_field,
        yes_handlers_subclass_field,
    )

    # uee-b7ze Step 2: emit HCC_CALL_BARRIER_CANDIDATE alongside the
    # REGION_LOWERING_CANDIDATE when this region carries an opaque-call
    # anchor.  Logging-only (Phase A); Phase B emits the corresponding
    # ACCEPTED/REJECTED lines when the gate is on.
    if info.opaque_call_anchor is not None:
        anchor_serial, call_ea, is_indirect = info.opaque_call_anchor
        call_type = "m_icall" if is_indirect else "m_call"
        next_semantic_target_label: str
        if info.proposed_exit is not None:
            next_semantic_target_label = f"blk[{int(info.proposed_exit)}]"
        else:
            next_semantic_target_label = "None"
        block_outgoing_edge_label: str = "None"
        if mba is not None:
            try:
                anchor_blk = HandlerChainComposerStrategy._safe_get_mblock(
                    mba, anchor_serial,
                )
                if anchor_blk is not None and int(anchor_blk.nsucc()) >= 1:
                    block_outgoing_edge_label = (
                        f"blk[{int(anchor_blk.succ(0))}]"
                    )
            except Exception:  # pragma: no cover - diagnostic only
                pass
        if candidate.splice_source_block is not None:
            semantic_pred_source_label = (
                f"blk[{int(candidate.splice_source_block)}]"
            )
        else:
            semantic_pred_source_label = "None"
        region_pred_label = (
            f"blk[{int(info.old_physical_pred)}]"
            if info.old_physical_pred is not None
            else "None"
        )
        # uee-b7ze Step 2.1: per-anchor diagnostic context (best-effort
        # snapshot probe + local_facts owning-state classification).
        try:
            diag_ctx = _collect_anchor_diag_context(
                anchor_serial=int(anchor_serial),
                mba=mba,
                local_facts=local_facts,
            )
        except Exception:  # pragma: no cover - diagnostic only
            diag_ctx = {
                "owning_states_via_local_facts": [],
                "preds_pre_pipeline": "UNKNOWN",
                "preds_post_hcc": "UNKNOWN",
                "preds_post_pipeline": "UNKNOWN",
                "succs_pre_pipeline": "UNKNOWN",
                "succs_post_hcc": "UNKNOWN",
                "succs_post_pipeline": "UNKNOWN",
                "reachable_from_entry_post_pipeline": "UNKNOWN",
                "survives_glbopt1_post_d810": "UNKNOWN",
                "earliest_kill_point": "unknown",
            }
        owning_states_text = (
            "[" + ", ".join(diag_ctx.get("owning_states_via_local_facts", []))
            + "]"
            if diag_ctx.get("owning_states_via_local_facts")
            else "[]"
        )
        logger.info(
            "HCC_CALL_BARRIER_CANDIDATE\n"
            "  handler_block=blk[%d]\n"
            "  call_type=%s\n"
            "  call_ea=0x%x\n"
            "  region_handlers=%s\n"
            "  region_pred_via_resolve_first_pred=%s\n"
            "  region_succ_via_resolve_region_exit=%s\n"
            "  semantic_pred_source=%s\n"
            "  semantic_pred_eligibility=%s\n"
            "  block_outgoing_edge=%s\n"
            "  body_pre_call_insn_count=%d\n"
            "  body_post_call_insn_count=%d\n"
            "  shape=%s\n"
            "  owning_states_via_local_facts=%s\n"
            "  preds_pre_pipeline=%s\n"
            "  preds_post_hcc=%s\n"
            "  preds_post_pipeline=%s\n"
            "  succs_pre_pipeline=%s\n"
            "  succs_post_hcc=%s\n"
            "  succs_post_pipeline=%s\n"
            "  reachable_from_entry_post_pipeline=%s\n"
            "  survives_glbopt1_post_d810=%s\n"
            "  earliest_kill_point=%s",
            int(anchor_serial),
            call_type,
            int(call_ea),
            handler_block_list,
            region_pred_label,
            next_semantic_target_label,
            semantic_pred_source_label,
            candidate.eligibility.value,
            block_outgoing_edge_label,
            int(info.opaque_call_pre_count or 0),
            int(info.opaque_call_post_count or 0),
            info.opaque_call_shape or "OTHER",
            owning_states_text,
            diag_ctx.get("preds_pre_pipeline", "UNKNOWN"),
            diag_ctx.get("preds_post_hcc", "UNKNOWN"),
            diag_ctx.get("preds_post_pipeline", "UNKNOWN"),
            diag_ctx.get("succs_pre_pipeline", "UNKNOWN"),
            diag_ctx.get("succs_post_hcc", "UNKNOWN"),
            diag_ctx.get("succs_post_pipeline", "UNKNOWN"),
            diag_ctx.get("reachable_from_entry_post_pipeline", "UNKNOWN"),
            diag_ctx.get("survives_glbopt1_post_d810", "UNKNOWN"),
            diag_ctx.get("earliest_kill_point", "unknown"),
        )


def _log_region_lowering_summary(
    raw_region_table: tuple[_RawRegionInfo, ...],
    *,
    dag: LinearizedStateDag | None = None,
    local_facts: DagLocalFacts | None = None,
    mba: object | None = None,
) -> None:
    """Emit ONE end-of-pass ``REGION_LOWERING_SUMMARY`` line."""
    eligibility_dist: Counter = Counter()
    divergence_yes = 0
    covered_handlers = 0
    covered_physical_pred = 0
    covered_collision = 0
    # uee-b7ze Step 2: aggregate yes_handlers_subclass distribution.
    subclass_dist: Counter = Counter()
    fusable_linear_pairs: list[tuple[int, int]] = []
    # source_block -> sorted list of (head_state, head_entry) claiming it
    collisions: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for info in raw_region_table:
        eligibility_dist[info.candidate.eligibility.value] += 1
        if (
            info.old_physical_pred is not None
            and info.candidate.splice_source_block is not None
            and int(info.candidate.splice_source_block)
            != int(info.old_physical_pred)
        ):
            divergence_yes += 1
        _label, reasons = _classify_source_covered_by_other_region(
            self_info=info,
            raw_region_table=raw_region_table,
        )
        if "YES_HANDLERS" in reasons:
            covered_handlers += 1
            try:
                sub = _classify_yes_handlers_with_convergence(
                    info=info,
                    raw_region_table=raw_region_table,
                    dag=dag,
                    local_facts=local_facts,
                    mba=mba,
                )
            except Exception:  # pragma: no cover - diagnostic only
                sub = None
            if sub is not None:
                subclass_dist[sub] += 1
                if sub == "FUSABLE_LINEAR":
                    covers = _find_cover_regions(
                        self_info=info, raw_region_table=raw_region_table,
                    )
                    if covers:
                        cov_state = int(covers[0].candidate.head_state) & 0xFFFFFFFF
                        self_state = int(info.candidate.head_state) & 0xFFFFFFFF
                        fusable_linear_pairs.append(
                            (cov_state, self_state)
                        )
        if "YES_PHYSICAL_PRED" in reasons:
            covered_physical_pred += 1
        if "YES_COLLISION" in reasons:
            covered_collision += 1
        if info.candidate.splice_source_block is not None:
            collisions[int(info.candidate.splice_source_block)].append(
                (
                    int(info.candidate.head_state) & 0xFFFFFFFF,
                    int(info.candidate.head_entry),
                )
            )
    # Filter to true collisions (more than one region claims the source).
    collision_summary: list[tuple[int, tuple[tuple[int, int], ...]]] = []
    for src, claimants in sorted(collisions.items()):
        if len(claimants) > 1:
            collision_summary.append(
                (int(src), tuple(sorted(claimants)))
            )

    eligibility_text = ", ".join(
        f"{kind}={count}" for kind, count in sorted(eligibility_dist.items())
    )
    if collision_summary:
        collision_text_parts: list[str] = []
        for src, claimants in collision_summary:
            heads = ", ".join(
                f"(head_state=0x{state:08X}, head_entry=blk[{entry}])"
                for state, entry in claimants
            )
            collision_text_parts.append(
                f"blk[{src}] -> [{heads}]"
            )
        collision_text = " | ".join(collision_text_parts)
    else:
        collision_text = "[]"

    # Always render the sub-categories explicitly so callers can rely
    # on a stable shape even when zero counts.  ``FUSABLE_LOCAL_CONVERGENCE``
    # and the four ``CONVERGENCE_UNSUPPORTED_*`` labels are reported
    # alongside the legacy linear/branch/conflict triage.
    subclass_keys = (
        "FUSABLE_LINEAR",
        "FUSABLE_RECURSIVE",
        "NOT_FUSABLE_BRANCH",
        "CONFLICT",
        "FUSABLE_LOCAL_CONVERGENCE",
        "FUSABLE_TAIL_EXTENSION",
        "CONVERGENCE_UNSUPPORTED_EXTERNAL_PRED",
        "CONVERGENCE_UNSUPPORTED_PRED_SHAPE",
        "CONVERGENCE_UNSUPPORTED_FALLTHROUGH_2WAY",
        "CONVERGENCE_FORBIDDEN_BODY",
    )
    subclass_text = ", ".join(
        f"{key}={subclass_dist.get(key, 0)}" for key in subclass_keys
    )
    if fusable_linear_pairs:
        fusable_text = ", ".join(
            f"(cov=0x{cov:08X}, self=0x{slf:08X})"
            for cov, slf in fusable_linear_pairs
        )
        fusable_field = f"[{fusable_text}]"
    else:
        fusable_field = "[]"

    # uee-b7ze Step 2.1: refined opaque-call anchor distribution.  All
    # six shape labels render explicitly (zero-fill) so the structured
    # consumer doesn't have to special-case missing keys.
    opaque_call_dist: Counter = Counter()
    for info in raw_region_table:
        if info.opaque_call_anchor is None:
            opaque_call_dist["NONE"] += 1
            continue
        shape = info.opaque_call_shape or "OTHER"
        opaque_call_dist[shape] += 1
    opaque_call_dist_keys = _OPAQUE_CALL_SHAPE_KEYS + ("NONE",)
    opaque_call_text = ", ".join(
        f"{key}={opaque_call_dist.get(key, 0)}"
        for key in opaque_call_dist_keys
    )

    # uee-b7ze Step 2.1: kill-point summary across opaque-call anchors.
    # Tells the user whether anchors are dying inside our pipeline or
    # only at IDA's GLBOPT1 cleanup.
    kill_dist: Counter = Counter()
    for info in raw_region_table:
        if info.opaque_call_anchor is None:
            continue
        anchor_serial = int(info.opaque_call_anchor[0])
        try:
            ctx = _collect_anchor_diag_context(
                anchor_serial=anchor_serial,
                mba=mba,
                local_facts=local_facts,
            )
        except Exception:  # pragma: no cover - diagnostic only
            ctx = {"earliest_kill_point": "unknown"}
        kill_label = str(ctx.get("earliest_kill_point", "unknown"))
        kill_dist[kill_label] += 1
    kill_summary_keys = (
        "NEVER",
        "post_pipeline",
        "maturity_MMAT_GLBOPT1_post_d810",
        "handler_chain_composer_post_apply",
        "maturity_MMAT_GLBOPT1_pre_d810",
        "unknown",
    )
    kill_summary_text = ", ".join(
        f"{key}={kill_dist.get(key, 0)}" for key in kill_summary_keys
    )

    logger.info(
        "REGION_LOWERING_SUMMARY\n"
        "  raw_regions_total=%d\n"
        "  candidates_emitted=%d\n"
        "  eligibility_distribution={%s}\n"
        "  divergence_from_old_yes=%d\n"
        "  source_covered_yes_handlers=%d\n"
        "  source_covered_yes_physical_pred=%d\n"
        "  source_covered_yes_collision=%d\n"
        "  yes_handlers_subclass_distribution={%s}\n"
        "  fusable_linear_pairs=%s\n"
        "  splice_source_collisions=%s\n"
        "  opaque_call_anchor_distribution={%s}\n"
        "  opaque_call_anchor_kill_summary={%s}",
        len(raw_region_table),
        len(raw_region_table),
        eligibility_text,
        divergence_yes,
        covered_handlers,
        covered_physical_pred,
        covered_collision,
        subclass_text,
        fusable_field,
        collision_text,
        opaque_call_text,
        kill_summary_text,
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


def _block_has_non_state_payload(
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
) -> bool:
    """Return True when a block has real payload beyond state write/goto glue."""
    try:
        blk = mba.get_mblock(int(block_serial))
    except Exception:
        return False
    if blk is None:
        return False
    insn = getattr(blk, "head", None)
    while insn is not None:
        try:
            opcode = int(insn.opcode)
        except Exception:
            return True
        if opcode in {ida_hexrays.m_nop, ida_hexrays.m_goto}:
            insn = getattr(insn, "next", None)
            continue
        if _is_state_write(insn, state_var_stkoff):
            insn = getattr(insn, "next", None)
            continue
        return True
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
    ``HANDLER_CHAIN_COMPOSER_ENABLED`` (bool, default ``True``).  HCC owns the
    live Hodur reconstruction path; set ``D810_DISABLE_HANDLER_CHAIN_COMPOSER``
    or ``D810_ENABLE_HANDLER_CHAIN_COMPOSER=0`` only for archaeology or
    regression isolation.
    """

    # CLASS-LEVEL GATE: HCC is the default live Hodur reconstruction path.
    # Feature flags remain accepted so older reproducer commands keep working,
    # while explicit disable flags give us an escape hatch for bisects.
    HANDLER_CHAIN_COMPOSER_ENABLED: bool = (
        not _env_flag("D810_DISABLE_HANDLER_CHAIN_COMPOSER")
        and (
            os.environ.get("D810_ENABLE_HANDLER_CHAIN_COMPOSER", "").strip() != "0"
            or _env_flag("D810_HCC_REGION_FUSION")
            or _env_flag("D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION")
            or _env_flag("D810_HCC_TAIL_EXTENSION")
            or _env_flag("D810_HCC_CALL_BARRIER")
            or _env_flag("D810_HCC_CHAINED_GUARDED_SOURCE")
        )
    )

    # uee-b7ze Step 2: opt-in flag for FUSABLE_LINEAR region fusion.
    # When False (default), fusion logic is dormant and behavior matches
    # the pre-Step-2 emission (logging-only).
    HCC_REGION_FUSION_ENABLED: bool = bool(
        int(os.environ.get("D810_HCC_REGION_FUSION", "0"))
    )

    # FUSABLE_LOCAL_CONVERGENCE (DEMOTED -> experimental).
    # Per-pred body cloning of a multi-pred local convergence is
    # **SSA-hostile** -- the cloned ``mov %var_X.{N}, ...`` references
    # a value version that was joined at the original convergence and
    # is no longer well-defined in either clone.  IDA's GLBOPT
    # subsequently DCEs the resulting island.  This mode is retained
    # for **experimental evidence only** and MUST NOT be treated as a
    # viable fallback architecture.  The intended replacement for
    # multi-pred local convergence shapes is ``FUSABLE_TAIL_EXTENSION``
    # (preserve the join, redirect only the semantic exit).
    HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION_ENABLED: bool = bool(
        int(os.environ.get(
            "D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION", "0",
        ))
    )

    # FUSABLE_TAIL_EXTENSION: independent flag that enables tail-extension
    # lowering -- a correction to the per-edge convergence-duplication
    # approach.  Instead of cloning the convergence block (which broke
    # SSA versioning), we preserve the original convergence and redirect
    # only its outgoing edge through a single InsertBlock that carries
    # R2's body and lands at R2's exit.  Default on for the live HCC pipeline.
    HCC_TAIL_EXTENSION_ENABLED: bool = bool(
        int(os.environ.get("D810_HCC_TAIL_EXTENSION", "1"))
    )

    # uee-b7ze Step 2: call-barrier segmentation.  Handlers whose bodies
    # contain m_call/m_icall must be PRESERVED as anchors (their
    # original blocks stay in the CFG, calls untouched), with
    # surrounding semantic flow rewired around them via RedirectGoto
    # pairs ONLY.  Runs ON TOP OF FUSABLE_TAIL_EXTENSION.  Default on for the
    # live HCC pipeline.
    HCC_CALL_BARRIER_ENABLED: bool = bool(
        int(os.environ.get("D810_HCC_CALL_BARRIER", "1"))
    )

    # Experimental semantic-equivalence guard for CHAINED_CALL_ANCHOR.
    # The BST-only fallback can synthesize upstream constant writers into
    # a later InsertBlock.  That preserves reaching defs but can erase the
    # original conditional guard that made the writer reachable.  When this
    # flag is set, a single guarded walk-back writer is kept in the real CFG
    # and becomes the InsertBlock predecessor instead of being copied.  Default
    # on for the live HCC pipeline.
    HCC_CHAINED_GUARDED_SOURCE_ENABLED: bool = bool(
        int(os.environ.get("D810_HCC_CHAINED_GUARDED_SOURCE", "1"))
    )

    # Planner-level use-def veto for direct reconstruction redirects.  This is
    # intentionally reject-only; previous generalized repair attempts expanded
    # this into broad split/copy emission and regressed the recovered shape.
    HCC_USE_DEF_VETO_ENABLED: bool = os.environ.get(
        "D810_HCC_USE_DEF_VETO",
        "1",
    ).strip() != "0"

    prerequisites: list[str] = []

    def __init__(self):
        # Caches mirror SWR's per-round caches.
        self._cached_structured_regions_by_round: dict[
            tuple[int, int], tuple[object, ...]
        ] = {}
        self._cached_force_edge_direct_overrides_by_round: dict[
            tuple[int, int, tuple[int, int]], tuple[int, int, tuple[int, ...]]
        ] = {}
        # uee-b7ze Step 2: stash for the most recent raw_region_table so
        # plan() can drive ``_apply_call_barrier_segmentation`` without
        # re-running the full detect_chains pipeline.  Cleared on each
        # detect_chains() call.
        self._last_raw_region_table: tuple[_RawRegionInfo, ...] = ()
        self._last_dag_for_call_barrier: LinearizedStateDag | None = None
        # uee-b7ze Step 2 (CHAINED_CALL_ANCHOR emit path): the chained
        # emitter needs ``state_var_stkoff`` and ``local_facts`` to call
        # ``_capture_block_composable_instructions`` on the pre-anchor
        # body.  Stashed alongside ``_last_raw_region_table``.
        self._last_state_var_stkoff_for_call_barrier: int | None = None
        self._last_local_facts_for_call_barrier: DagLocalFacts | None = None

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

        # Reset the per-invocation stash before detect_chains runs.
        self._last_raw_region_table = ()
        self._last_dag_for_call_barrier = None
        self._last_state_var_stkoff_for_call_barrier = None
        self._last_local_facts_for_call_barrier = None

        # Phase 1: detect region-collapse candidates (stub-snapshot safe).
        candidates = self.detect_chains(snapshot)

        # uee-b7ze Step 2: call-barrier segmentation (Phase B).  Runs
        # AFTER detect_chains has built and stashed raw_region_table.
        # When the gate is off, the list is empty and behavior is
        # unchanged.  When on, the strategy emits per-anchor RedirectGoto
        # pairs (SIMPLE_1WAY_OUT) and (InsertBlock + RedirectGoto)
        # bundles (CHAINED_CALL_ANCHOR) alongside the standard
        # InsertBlock-based composition.
        call_barrier_modifications: list = []
        if (
            self.HCC_CALL_BARRIER_ENABLED
            and self._last_raw_region_table
            and self._last_dag_for_call_barrier is not None
            and snapshot.mba is not None
        ):
            try:
                _bst_result = getattr(snapshot, "bst_result", None)
                # Forward the full BSTAnalysisResult so the BST-only
                # chained resolver can run state-write scans via
                # ``resolve_target_via_bst`` when the recon DAG lacks
                # an inbound TRANSITION edge for range-backed handler
                # entries.
                _bst_blocks: frozenset[int] = frozenset(
                    int(b) for b in (
                        getattr(_bst_result, "bst_node_blocks", set())
                        if _bst_result is not None else set()
                    )
                )
                _dispatcher_serial = int(
                    getattr(snapshot, "bst_dispatcher_serial", -1) or -1
                )
                call_barrier_modifications = (
                    self._apply_call_barrier_segmentation(
                        mba=snapshot.mba,
                        flow_graph=getattr(snapshot, "flow_graph", None),
                        dag=self._last_dag_for_call_barrier,
                        raw_region_table=self._last_raw_region_table,
                        state_var_stkoff=(
                            self._last_state_var_stkoff_for_call_barrier
                        ),
                        local_facts=(
                            self._last_local_facts_for_call_barrier
                        ),
                        bst_node_blocks=_bst_blocks,
                        dispatcher_serial=_dispatcher_serial,
                        bst_result=_bst_result,
                    )
                )
            except Exception as exc:  # pragma: no cover - diagnostic only
                logger.warning(
                    "HandlerChainComposer: call-barrier segmentation"
                    " raised: %s",
                    exc,
                )
                call_barrier_modifications = []

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
            bst_result_for_filter = getattr(snapshot, "bst_result", None)
            filter_bst_node_blocks = frozenset(
                int(block)
                for block in (
                    getattr(bst_result_for_filter, "bst_node_blocks", set())
                    if bst_result_for_filter is not None
                    else set()
                )
            )
            filter_dispatcher_serial = int(
                getattr(snapshot, "bst_dispatcher_serial", -1) or -1
            )
            filter_state_var_stkoff = _resolve_state_var_stkoff_loose(snapshot)
            preserve_redirect_sources = (
                self._payload_intermediate_feeder_sources(
                    list(swr_result["modifications"]),
                    mba=snapshot.mba,
                    dispatcher_serial=filter_dispatcher_serial,
                    bst_node_blocks=filter_bst_node_blocks,
                    state_var_stkoff=filter_state_var_stkoff,
                    region_anchor_blocks=region_anchor_blocks,
                    region_pred_serials=region_pred_serials,
                )
            )
            swr_result = self._filter_swr_against_regions(
                swr_result,
                region_anchor_blocks=region_anchor_blocks,
                region_pred_serials=region_pred_serials,
                preserve_redirect_sources=preserve_redirect_sources,
                mba=snapshot.mba,
                flow_graph=getattr(snapshot, "flow_graph", None),
                state_var_stkoff=filter_state_var_stkoff,
                veto_nonpreserved_use_def_severance=False,
                use_def_veto_sources=swr_result.get(
                    "fixpoint_feeder_sources",
                    frozenset(),
                ),
            )

        # Build region-collapse modifications.
        # Dedup by (pred_serial, old_target) — the same edge may surface
        # multiple times when several DAG paths reach the same region.
        # Two InsertBlocks targeting the same pred edge would project
        # an over-saturated CFG (CFG_50856_BAD_NSUCC).
        call_barrier_redirect_edges: set[tuple[int, int]] = set()
        for cb_mod in call_barrier_modifications:
            if isinstance(cb_mod, (RedirectGoto, RedirectBranch)):
                call_barrier_redirect_edges.add(
                    (int(cb_mod.from_serial), int(cb_mod.old_target))
                )
            elif isinstance(cb_mod, InsertBlock):
                call_barrier_redirect_edges.add(
                    (int(cb_mod.pred_serial), int(cb_mod.old_target_serial))
                )
        region_modifications: list = []
        region_owned_blocks: set[int] = set()
        emitted = 0
        emitted_edges: set[tuple[int, int]] = set()
        for candidate in validated_candidates:
            pred_serial = int(candidate.pred_serial)
            old_target = int(candidate.handler_serials[0])
            edge_key = (pred_serial, old_target)
            if edge_key in call_barrier_redirect_edges:
                logger.info(
                    "HandlerChainComposer: skipping region pred=%d"
                    " old_target=%d because call-barrier owns that edge",
                    pred_serial,
                    old_target,
                )
                continue
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

        # uee-b7ze Step 2: collect call-barrier ownership.  Each accepted
        # call-barrier candidate claims (a) the splice source, (b) the
        # handler block.  Both must be in the owned set so the engine
        # can route conflict checks through HCC.  CHAINED_CALL_ANCHOR
        # additionally claims the pre-anchor handler (referenced by the
        # InsertBlock body) and the InsertBlock's pred/succ.
        call_barrier_owned_blocks: set[int] = set()
        for mod in call_barrier_modifications:
            if isinstance(mod, RedirectGoto):
                call_barrier_owned_blocks.add(int(mod.from_serial))
                call_barrier_owned_blocks.add(int(mod.new_target))
            elif isinstance(mod, InsertBlock):
                call_barrier_owned_blocks.add(int(mod.pred_serial))
                call_barrier_owned_blocks.add(int(mod.succ_serial))

        # Combine SWR + region-collapse + call-barrier into a single fragment.
        if (
            swr_result is None
            and not region_modifications
            and not call_barrier_modifications
        ):
            return None

        # When SWR ran and produced mods (or has its full metadata
        # plumbing), use finalize_reconstruction_fragment so the SWR
        # conflict filters / DAG arbiter / metadata key all apply, then
        # extend with region-collapse mods + ownership.
        if swr_result is not None:
            # uee-b7ze: SWR (HCC's absorbed orchestration) ran AFTER
            # call-barrier and may have emitted a direct redirect from
            # the same source the call-barrier claimed (e.g. blk[90]
            # writing a state that BST routes to a chained
            # ``splice_source``).  Two redirects on the same 1-way
            # block produces CFG_50856_BAD_NSUCC at the engine's
            # projected_contract phase.  Call-barrier fired first and
            # is the authoritative claim; drop SWR redirects whose
            # source collides with a call-barrier accept.
            call_barrier_redirect_sources: set[int] = set()
            for cb_mod in call_barrier_modifications:
                if isinstance(cb_mod, RedirectGoto):
                    call_barrier_redirect_sources.add(int(cb_mod.from_serial))
                elif isinstance(cb_mod, RedirectBranch):
                    call_barrier_redirect_sources.add(int(cb_mod.from_serial))
                elif isinstance(cb_mod, InsertBlock):
                    # InsertBlock(pred=X, succ=Y) implicitly redirects
                    # X's outgoing edge into the new block.
                    call_barrier_redirect_sources.add(int(cb_mod.pred_serial))

            swr_mods = list(swr_result["modifications"])
            if call_barrier_redirect_sources:
                filtered_swr_mods: list = []
                dropped: list = []
                for sm in swr_mods:
                    src_serial: int | None = None
                    if isinstance(sm, RedirectGoto):
                        src_serial = int(sm.from_serial)
                    elif isinstance(sm, RedirectBranch):
                        src_serial = int(sm.from_serial)
                    elif isinstance(sm, InsertBlock):
                        src_serial = int(sm.pred_serial)
                    if (
                        src_serial is not None
                        and src_serial in call_barrier_redirect_sources
                    ):
                        dropped.append((type(sm).__name__, src_serial))
                        continue
                    filtered_swr_mods.append(sm)
                if dropped:
                    logger.info(
                        "HCC_SWR_MOD_FILTERED_BY_CALL_BARRIER:"
                        " dropped=%s call_barrier_sources=%s",
                        dropped,
                        sorted(call_barrier_redirect_sources),
                    )
                swr_mods = filtered_swr_mods

            # Append region-collapse mods into the SWR modifications list
            # before finalize so the DAG-arbiter / dup-conflict filters
            # can also reason about them as a single batch.  The filters
            # only target redirect-shaped mods; InsertBlock passes
            # through untouched.
            combined_modifications = list(swr_mods)
            combined_modifications.extend(region_modifications)
            combined_modifications.extend(call_barrier_modifications)
            combined_modifications = self._filter_payload_intermediate_redirects(
                combined_modifications,
                mba=snapshot.mba,
                dispatcher_serial=filter_dispatcher_serial,
                bst_node_blocks=filter_bst_node_blocks,
                state_var_stkoff=filter_state_var_stkoff,
            )
            # Corridor-shred guard for the SWR + region-collapse path.
            if (
                os.environ.get(
                    self._PRESERVE_TERMINAL_BYTE_CORRIDORS_ENV, ""
                ).strip()
                == "1"
            ):
                _swr_corridors = detect_side_effect_corridors(
                    getattr(snapshot, "flow_graph", None),
                    bst_block_set=frozenset(filter_bst_node_blocks),
                )
                if _swr_corridors:
                    for _c in _swr_corridors:
                        logger.info(
                            "CORRIDOR_GUARD: corridor detected (SWR+region "
                            "path): len=%d serials=%s",
                            len(_c),
                            list(_c[:8]),
                        )
                    combined_modifications = (
                        self._filter_corridor_shredding_mods(
                            combined_modifications,
                            _swr_corridors,
                        )
                    )
            combined_owned_blocks = set(swr_result["owned_blocks"])
            combined_owned_blocks.update(region_owned_blocks)
            combined_owned_blocks.update(call_barrier_owned_blocks)
            combined_owned_edges = set(swr_result["owned_edges"])

            # uee-b7ze Step 2 (Phase C): audit assertion -- m_call /
            # m_icall must NEVER appear in any InsertBlock body.  The
            # call-barrier path emits RedirectGoto pairs that wire flow
            # AROUND the original anchor; the call instruction stays
            # in place.  This invariant fires loudly on violation.
            self._assert_no_call_in_insert_blocks(combined_modifications)

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
            fragment.metadata["handler_chain_composer_call_barrier_count"] = (
                len(call_barrier_modifications)
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
        # Always run Phase C audit even on this path.
        if region_modifications or call_barrier_modifications:
            self._assert_no_call_in_insert_blocks(
                region_modifications + list(call_barrier_modifications)
            )
        if not region_modifications and not call_barrier_modifications:
            return None
        bst_result_for_filter = getattr(snapshot, "bst_result", None)
        # Optional: detect ordered byte-emission corridors and reject any
        # modification that would shred them.  Default off until validated.
        corridor_guard_enabled = (
            os.environ.get(
                self._PRESERVE_TERMINAL_BYTE_CORRIDORS_ENV, ""
            ).strip()
            == "1"
        )
        side_effect_corridors: tuple[tuple[int, ...], ...] = ()
        if corridor_guard_enabled:
            side_effect_corridors = detect_side_effect_corridors(
                getattr(snapshot, "flow_graph", None),
                bst_block_set=frozenset(
                    int(b) for b in (
                        getattr(bst_result_for_filter, "bst_node_blocks", set())
                        if bst_result_for_filter is not None
                        else set()
                    )
                ),
            )
            if side_effect_corridors:
                for corridor in side_effect_corridors:
                    logger.info(
                        "CORRIDOR_GUARD: corridor detected (region-collapse "
                        "path): len=%d serials=%s",
                        len(corridor),
                        list(corridor[:8]),
                    )
        filtered_modifications = self._filter_payload_intermediate_redirects(
            region_modifications + list(call_barrier_modifications),
            mba=snapshot.mba,
            dispatcher_serial=int(
                getattr(snapshot, "bst_dispatcher_serial", -1) or -1
            ),
            bst_node_blocks=frozenset(
                int(block)
                for block in (
                    getattr(bst_result_for_filter, "bst_node_blocks", set())
                    if bst_result_for_filter is not None
                    else set()
                )
            ),
            state_var_stkoff=_resolve_state_var_stkoff_loose(snapshot),
        )
        if corridor_guard_enabled and side_effect_corridors:
            filtered_modifications = self._filter_corridor_shredding_mods(
                filtered_modifications,
                side_effect_corridors,
            )
        owned_blocks_combined = set(region_owned_blocks)
        owned_blocks_combined.update(call_barrier_owned_blocks)
        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks_combined),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=len(owned_blocks_combined),
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=filtered_modifications,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.5,
            metadata={
                "handler_chain_composer_emitted": emitted,
                "handler_chain_composer_call_barrier_count": (
                    len(call_barrier_modifications)
                ),
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
        direct_use_def_veto_sources: set[int] = set()

        def _veto_use_def_severing_direct_redirect(mod, candidate):
            if not isinstance(mod, RedirectGoto):
                return None
            candidate_flow_graph = flow_graph
            if candidate_flow_graph is None:
                candidate_flow_graph = getattr(candidate, "flow_graph", None)
            if candidate_flow_graph is None:
                logger.debug(
                    "RECON DAG: use-def direct-veto skipped for"
                    " blk[%d]@?->blk[%d]@? because flow_graph is unavailable",
                    int(mod.from_serial),
                    int(mod.new_target),
                )
                return None
            edge = getattr(candidate, "edge", None)
            if edge is None and hasattr(candidate, "ordered_path"):
                edge = candidate
            ordered_path = tuple(
                int(serial)
                for serial in getattr(edge, "ordered_path", ()) or ()
            )
            if len(ordered_path) <= 1:
                return None
            candidate_site = getattr(candidate, "site", None)
            state_value_obj = getattr(candidate_site, "state_value", None)
            if state_value_obj is None:
                state_value_obj = getattr(candidate, "state_value", None)
            if state_value_obj is None:
                state_value_obj = getattr(getattr(edge, "target_key", None), "state_const", 0)
            state_value = int(state_value_obj or 0) & 0xFFFFFFFF
            target_entry_for_log = getattr(candidate, "target_entry", None)
            if target_entry_for_log is None:
                target_entry_for_log = getattr(edge, "target_entry_anchor", -1)
            if target_entry_for_log is None or int(target_entry_for_log) < 0:
                target_entry_for_log = int(mod.new_target)

            try:
                violations = check_redirect_severs_use_def(
                    mod,
                    mba,
                    candidate_flow_graph,
                )
            except Exception:
                logger.debug(
                    "RECON DAG: use-def direct-veto check raised for"
                    " %s %s",
                    flow_edge_label(
                        candidate_flow_graph,
                        int(mod.from_serial),
                        int(mod.new_target),
                    ),
                    flow_graph_context_label(candidate_flow_graph),
                    exc_info=True,
                )
                return None
            if not violations:
                return None
            real_violations = tuple(
                violation
                for violation in violations
                if state_var_stkoff is None
                or int(violation.var_stkoff) != int(state_var_stkoff)
            )
            if not real_violations:
                logger.info(
                    "RECON DAG: direct redirect use-def warning ignored"
                    " for %s because only state-variable"
                    " dispatcher uses would be severed",
                    flow_edge_label(
                        candidate_flow_graph,
                        int(mod.from_serial),
                        int(mod.new_target),
                    ),
                )
                return None
            violations = real_violations
            target_has_call = _block_contains_call_opcode(
                mba,
                int(target_entry_for_log),
            )
            # Keep the veto scoped away from plain one-block handoffs into
            # original call anchors.  Those are the good shapes for preserving
            # call blocks such as blk[48] -> blk[130] and blk[21] -> blk[75].
            # One-block redirects into non-call residual/terminal tails do not
            # have that preservation property; if they sever a def, they are
            # just as suspect as multi-block call-anchor shortcuts.
            if len(ordered_path) == 1 and target_has_call:
                return None
            logger.warning(
                "RECON DAG: direct redirect vetoed for use-def severance"
                " %s state=0x%08X target_entry=%s orphaned_uses=%d"
                " path=%s %s",
                flow_edge_label(
                    candidate_flow_graph,
                    int(mod.from_serial),
                    int(mod.new_target),
                ),
                state_value,
                flow_block_label(candidate_flow_graph, int(target_entry_for_log)),
                len(violations),
                ordered_path,
                flow_graph_context_label(candidate_flow_graph),
            )
            direct_use_def_veto_sources.add(int(mod.from_serial))
            return f"use_def_severance:{len(violations)}"

        def _veto_fixpoint_feeder_redirect(**kwargs):
            modification = kwargs.get("modification")
            if not isinstance(modification, RedirectGoto):
                return None
            target_block = kwargs.get("target_block")
            source_block = kwargs.get("source_block")
            try:
                source_serial = int(source_block)
            except Exception:
                source_serial = int(modification.from_serial)
            if source_serial in direct_use_def_veto_sources:
                return "direct_use_def_vetoed_source"
            try:
                target_serial = int(target_block)
            except Exception:
                target_serial = int(modification.new_target)
            target_npred = 0
            try:
                target_snapshot = flow_graph.get_block(target_serial)
                target_npred = int(getattr(target_snapshot, "npred", 0) or 0)
            except Exception:
                target_npred = 0
            if target_npred <= 1:
                return None
            try:
                violations = check_redirect_severs_use_def(
                    modification,
                    mba,
                    flow_graph,
                )
            except Exception:
                logger.debug(
                    "RECON FIXPOINT FEEDER: use-def veto check raised"
                    " for %s %s",
                    flow_edge_label(
                        flow_graph,
                        int(modification.from_serial),
                        int(modification.new_target),
                    ),
                    flow_graph_context_label(flow_graph),
                    exc_info=True,
                )
                return None
            real_violations = tuple(
                violation
                for violation in violations
                if state_var_stkoff is None
                or int(violation.var_stkoff) != int(state_var_stkoff)
            )
            if not real_violations:
                return None
            details = "; ".join(
                f"var_stk[{violation.var_stkoff:#x}]@blk[{violation.use_block}]"
                for violation in real_violations[:8]
            )
            if len(real_violations) > 8:
                details = f"{details}; ..."
            return f"use_def_severance:{len(real_violations)}:{details}"

        def _veto_payload_intermediate_conditional_redirect(**kwargs):
            modification = kwargs.get("modification")
            if not isinstance(modification, RedirectBranch):
                return None
            try:
                old_target = int(modification.old_target)
            except Exception:
                return None
            if old_target == int(dispatcher_serial) or old_target in bst_node_blocks:
                return None
            if not _block_has_non_state_payload(
                mba,
                old_target,
                state_var_stkoff=state_var_stkoff,
            ):
                return None
            return f"intermediate_payload:blk[{old_target}]"

        run = execute_primary_reconstruction_modifications(
            raw_candidates=list(raw_candidates),
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            dispatcher_serial=dispatcher_serial,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            force_clone_shared_blocks=force_clone_primary_shared_blocks,
            direct_redirect_veto=(
                _veto_use_def_severing_direct_redirect
                if self.HCC_USE_DEF_VETO_ENABLED
                else None
            ),
            conditional_redirect_veto=_veto_payload_intermediate_conditional_redirect,
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
                direct_redirect_veto=(
                    _veto_use_def_severing_direct_redirect
                    if self.HCC_USE_DEF_VETO_ENABLED
                    else None
                ),
                conditional_redirect_veto=_veto_payload_intermediate_conditional_redirect,
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
            fixpoint_redirect_veto=(
                _veto_fixpoint_feeder_redirect
                if self.HCC_USE_DEF_VETO_ENABLED
                else None
            ),
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
        def _shared_block_still_needs_late_clone(block_serial: int) -> bool:
            projected_block = (
                projected_flow_graph.get_block(int(block_serial))
                if projected_flow_graph is not None
                else None
            )
            if projected_block is None:
                return True
            succs = tuple(int(succ) for succ in getattr(projected_block, "succs", ()) or ())
            if len(succs) != 1:
                return True
            return int(succs[0]) in dispatcher_region

        fixpoint_resolved_shared_blocks = frozenset(
            int(entry.source_block)
            for entry in (
                postprocess.postprocess_plan.fixpoint_feeder_plan.log_entries
                if postprocess.postprocess_plan is not None
                else ()
            )
            if not _shared_block_still_needs_late_clone(int(entry.source_block))
        )
        if fixpoint_resolved_shared_blocks:
            logger.info(
                "RECON DAG: force-keeping fixpoint-resolved shared groups=%s",
                tuple(sorted(fixpoint_resolved_shared_blocks)),
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
                and _shared_block_still_needs_late_clone(int(result.shared_block))
            ),
            force_keep_per_pred_shared_blocks=frozenset(
                set(force_keep_per_pred_shared_blocks)
                | set(fixpoint_resolved_shared_blocks)
            ),
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
            "fixpoint_feeder_sources": frozenset(
                int(entry.source_block)
                for entry in (
                    postprocess.postprocess_plan.fixpoint_feeder_plan.log_entries
                    if postprocess.postprocess_plan is not None
                    else ()
                )
            ),
        }

    @staticmethod
    def _assert_no_call_in_insert_blocks(modifications: list) -> None:
        """uee-b7ze Step 2 (Phase C): audit ``InsertBlock`` bodies for calls.

        Step 2 must NEVER copy a call instruction into an InsertBlock
        body; the call-barrier path must rewire flow AROUND the anchor
        block via RedirectGoto pairs only.  Violations indicate a
        regression in either the call-barrier emission logic or the
        composer's forbidden-opcode classification.  Raises
        ``AssertionError`` after logging a structured error so the test
        harness fails loudly.
        """
        for mod in modifications:
            if not isinstance(mod, InsertBlock):
                continue
            for insn_snap in mod.instructions:
                try:
                    opcode = int(getattr(insn_snap, "opcode", -1))
                except Exception:
                    continue
                if opcode in (ida_hexrays.m_call, ida_hexrays.m_icall):
                    logger.error(
                        "HCC_CALL_BARRIER_INVARIANT_VIOLATION:"
                        " m_call/m_icall ea=0x%x in InsertBlock body"
                        " (block_serial=%d)",
                        int(getattr(insn_snap, "ea", 0)),
                        int(getattr(mod, "pred_serial", -1)),
                    )
                    raise AssertionError(
                        "m_call leaked into InsertBlock instructions"
                    )

    @staticmethod
    def _filter_swr_against_regions(
        swr_result: dict,
        *,
        region_anchor_blocks: set[int],
        region_pred_serials: set[int],
        preserve_redirect_sources: set[int] | None = None,
        mba: object | None = None,
        flow_graph: object | None = None,
        state_var_stkoff: int | None = None,
        veto_nonpreserved_use_def_severance: bool = False,
        use_def_veto_sources: set[int] | frozenset[int] | None = None,
    ) -> dict:
        """Drop SWR-style mods that overlap region-collapse anchors.

        The InsertBlock for a region replaces the dispatcher-routed
        progression through ``handler_serials``; any SWR-style redirect
        that targets one of those handlers (or whose source is the
        region's predecessor) is now redundant and would conflict with
        the InsertBlock's edge rewiring.
        """
        if (
            not region_anchor_blocks
            and not region_pred_serials
            and not veto_nonpreserved_use_def_severance
        ):
            return swr_result
        preserved_sources = {
            int(serial) for serial in (preserve_redirect_sources or set())
        }
        severance_veto_sources = {
            int(serial) for serial in (use_def_veto_sources or set())
        }
        kept_mods: list = []
        dropped = 0
        use_def_dropped: list[tuple[int, int, str]] = []
        for mod in swr_result["modifications"]:
            if (
                isinstance(mod, RedirectGoto)
                and int(mod.from_serial) in preserved_sources
            ):
                kept_mods.append(mod)
                continue
            if (
                veto_nonpreserved_use_def_severance
                and isinstance(mod, RedirectGoto)
                and mba is not None
                and flow_graph is not None
                and int(mod.from_serial) in severance_veto_sources
            ):
                try:
                    violations = check_redirect_severs_use_def(
                        mod,
                        mba,
                        flow_graph,
                    )
                except Exception:
                    logger.debug(
                        "HCC_SWR_USE_DEF_FILTER_CHECK_FAILED"
                        " source=blk[%d] target=blk[%d]",
                        int(mod.from_serial),
                        int(mod.new_target),
                        exc_info=True,
                    )
                    violations = ()
                real_violations = tuple(
                    violation
                    for violation in violations
                    if state_var_stkoff is None
                    or int(violation.var_stkoff) != int(state_var_stkoff)
                )
                if real_violations:
                    details = "; ".join(
                        "var_stk[%#x]@blk[%d]"
                        % (
                            int(violation.var_stkoff),
                            int(violation.use_block),
                        )
                        for violation in real_violations[:8]
                    )
                    if len(real_violations) > 8:
                        details = f"{details}; ..."
                    use_def_dropped.append(
                        (
                            int(mod.from_serial),
                            int(mod.new_target),
                            details,
                        )
                    )
                    continue
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
        if use_def_dropped:
            logger.info(
                "HCC_SWR_MOD_FILTERED_BY_USE_DEF dropped=%s"
                " preserved_sources=%s",
                use_def_dropped,
                sorted(preserved_sources),
            )
        return {**swr_result, "modifications": kept_mods}

    @staticmethod
    def _payload_intermediate_feeder_sources(
        modifications: list,
        *,
        mba: object,
        dispatcher_serial: int,
        bst_node_blocks: set[int] | frozenset[int],
        state_var_stkoff: int | None,
        region_anchor_blocks: set[int],
        region_pred_serials: set[int],
    ) -> set[int]:
        """Find feeder gotos paired with a payload-intermediate branch.

        For a bad branch rewrite ``P: old=B -> new=T`` where ``B`` has real
        payload, the sound repair is to keep ``P -> B`` and preserve the
        companion feeder ``B -> T``.  This helper identifies such ``B`` blocks
        before region-anchor overlap filtering can discard the feeder.
        """
        bst_nodes = {int(block) for block in bst_node_blocks}
        goto_pairs = {
            (int(mod.from_serial), int(mod.new_target))
            for mod in modifications
            if isinstance(mod, RedirectGoto)
        }
        preserve: set[int] = set()
        for mod in modifications:
            if not isinstance(mod, RedirectBranch):
                continue
            if HandlerChainComposerStrategy._mod_touches_region(
                mod,
                region_anchor_blocks=region_anchor_blocks,
                region_pred_serials=region_pred_serials,
            ):
                continue
            old_target = int(mod.old_target)
            if old_target == int(dispatcher_serial) or old_target in bst_nodes:
                continue
            if (old_target, int(mod.new_target)) not in goto_pairs:
                continue
            if not _block_has_non_state_payload(
                mba,
                old_target,
                state_var_stkoff=state_var_stkoff,
            ):
                continue
            preserve.add(old_target)
        if preserve:
            logger.info(
                "HCC_PAYLOAD_INTERMEDIATE_FEEDER_PRESERVED sources=%s",
                sorted(preserve),
            )
        return preserve

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

    # Env gate: when set, refuse to emit modifications that would shred a
    # detected ordered terminal byte-emission corridor (m_stx-bearing
    # linear cascade).  Off by default until validated; flip on with
    # ``D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS=1``.
    _PRESERVE_TERMINAL_BYTE_CORRIDORS_ENV = (
        "D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"
    )

    @staticmethod
    def _filter_corridor_shredding_mods(
        modifications: list,
        corridors: tuple[tuple[int, ...], ...],
    ) -> list:
        """Reject modifications that would mutate edges inside a side-effect
        corridor in a way that breaks the ordered byte-emission cascade.

        For each corridor ``(B_0, B_1, ..., B_k)``, we compute:
          * ``corridor_blocks``: the set of all ``B_i``
          * ``corridor_edges``: the set of ``(B_i, B_{i+1})`` ordered pairs
          * ``corridor_interiors``: ``{B_1, ..., B_k}`` (everything except
            the head — these are the blocks an external mod must NOT
            inject a new predecessor into)
          * ``corridor_tails``: ``{B_0, ..., B_{k-1}}`` (everything except
            the sink — these are the blocks whose tail must NOT be
            redirected away from the next corridor step)

        A modification is rejected if:
          * ``RedirectGoto(src, target, old_target)`` where
            ``(src, old_target)`` matches a corridor edge (rewriting a
            corridor block's tail to a non-corridor target).
          * ``RedirectGoto(src, target)`` where ``target`` is a
            corridor interior block (injecting a foreign predecessor
            into the corridor's middle).
          * ``RedirectBranch`` with the same shape.
          * ``InsertBlock(pred, succ)`` where ``(pred, succ)`` matches a
            corridor edge (splitting the corridor with an inserted block).
          * ``DuplicateAndRedirect(source_serial)`` where
            ``source_serial`` is in the corridor (cloning a corridor
            block destroys the ordered cascade).

        Diagnostic-rich logger: each rejection logs the rule that fired
        and the offending modification's serial fields.
        """
        if not corridors or not modifications:
            return modifications
        corridor_blocks: set[int] = set()
        corridor_edges: set[tuple[int, int]] = set()
        corridor_interiors: set[int] = set()
        for chain in corridors:
            corridor_blocks.update(int(b) for b in chain)
            corridor_interiors.update(int(b) for b in chain[1:])
            for i in range(len(chain) - 1):
                corridor_edges.add((int(chain[i]), int(chain[i + 1])))

        kept: list = []
        rejected_count = 0
        for mod in modifications:
            reject_reason: str | None = None
            if isinstance(mod, (RedirectGoto, RedirectBranch)):
                src = int(getattr(mod, "source_block", -1))
                old = getattr(mod, "old_target", None)
                tgt = int(getattr(mod, "new_target", -1))
                if old is not None and (src, int(old)) in corridor_edges:
                    reject_reason = (
                        f"would rewrite corridor edge {src}->{int(old)}"
                    )
                elif tgt in corridor_interiors:
                    reject_reason = (
                        f"would inject foreign pred into corridor block {tgt}"
                    )
            elif isinstance(mod, InsertBlock):
                pred = int(getattr(mod, "pred_serial", -1))
                succ = int(getattr(mod, "succ_serial", -1))
                if (pred, succ) in corridor_edges:
                    reject_reason = (
                        f"would split corridor edge {pred}->{succ} "
                        f"with an inserted block"
                    )
            elif isinstance(mod, DuplicateAndRedirect):
                src = int(getattr(mod, "source_serial", -1))
                if src in corridor_blocks:
                    reject_reason = (
                        f"would duplicate corridor block {src}"
                    )

            if reject_reason is None:
                kept.append(mod)
            else:
                rejected_count += 1
                logger.info(
                    "CORRIDOR_GUARD: rejected %s — %s",
                    type(mod).__name__,
                    reject_reason,
                )

        if rejected_count:
            logger.info(
                "CORRIDOR_GUARD: kept=%d rejected=%d corridors=%d "
                "(gate D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS=1)",
                len(kept),
                rejected_count,
                len(corridors),
            )
        return kept

    @staticmethod
    def _filter_payload_intermediate_redirects(
        modifications: list,
        *,
        mba: object,
        dispatcher_serial: int,
        bst_node_blocks: set[int] | frozenset[int],
        state_var_stkoff: int | None,
    ) -> list:
        """Drop branch redirects that bypass an old target with real payload.

        Redirecting ``pred -> payload_block`` to ``pred -> semantic_target`` is
        only sound when ``payload_block`` is dispatcher/BST/state-write glue.
        If the old target has non-state instructions, the planner must preserve
        the old edge and let a separate feeder/region rewrite handle the
        payload block itself.
        """
        kept: list = []
        dropped: list[tuple[int, int, int]] = []
        added_feeders: list[tuple[int, int, int]] = []
        bst_nodes = {int(block) for block in bst_node_blocks}
        goto_pairs = {
            (int(mod.from_serial), int(mod.new_target))
            for mod in modifications
            if isinstance(mod, RedirectGoto)
        }
        for mod in modifications:
            if not isinstance(mod, RedirectBranch):
                kept.append(mod)
                continue
            try:
                old_target = int(mod.old_target)
            except Exception:
                kept.append(mod)
                continue
            if old_target == int(dispatcher_serial) or old_target in bst_nodes:
                kept.append(mod)
                continue
            if not _block_has_non_state_payload(
                mba,
                old_target,
                state_var_stkoff=state_var_stkoff,
            ):
                kept.append(mod)
                continue
            dropped.append(
                (int(mod.from_serial), old_target, int(mod.new_target))
            )
            if (old_target, int(mod.new_target)) in goto_pairs:
                continue
            try:
                old_blk = mba.get_mblock(old_target)  # type: ignore[attr-defined]
                old_nsucc = int(old_blk.nsucc()) if old_blk is not None else 0
                old_succ = int(old_blk.succ(0)) if old_nsucc == 1 else -1
            except Exception:
                old_succ = -1
            if old_succ < 0:
                logger.info(
                    "HCC_PAYLOAD_INTERMEDIATE_FEEDER_SKIPPED"
                    " source=blk[%d] target=blk[%d] reason=old_target_not_1way",
                    old_target,
                    int(mod.new_target),
                )
                continue
            kept.append(
                RedirectGoto(
                    from_serial=old_target,
                    old_target=old_succ,
                    new_target=int(mod.new_target),
                )
            )
            goto_pairs.add((old_target, int(mod.new_target)))
            added_feeders.append((old_target, old_succ, int(mod.new_target)))
        if dropped:
            logger.info(
                "HCC_PAYLOAD_INTERMEDIATE_REDIRECT_FILTERED dropped=%s",
                dropped,
            )
        if added_feeders:
            logger.info(
                "HCC_PAYLOAD_INTERMEDIATE_FEEDER_ADDED added=%s",
                added_feeders,
            )
        return kept

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

        # Resolve the typed DAG-local facts bundle once.  Prefer the
        # snapshot's pre-built ``ReconRoundDiscoveryContext.local_facts``
        # (Phase 3 typed contract); fall back to building it on demand
        # when the snapshot did not publish one.
        local_facts = self._resolve_local_facts(snapshot, dag)

        # uee-b7ze A0/A1: pre-compose pass.  Emit ONE
        # ``REGION_LOWERING_CANDIDATE`` log line per detected region,
        # cross-referenced against the FULL raw region set (not just
        # previously-validated candidates).  This decouples observability
        # from ``_compose_region``'s success/failure path.
        raw_region_table = self._build_raw_region_table(
            mba=mba, dag=dag, regions=regions,
            state_var_stkoff=state_var_stkoff,
            local_facts=local_facts,
        )
        # uee-b7ze Step 2: stash for plan() to consume during call-barrier
        # segmentation.  Lifetime is one detect_chains() invocation.
        self._last_raw_region_table = raw_region_table
        self._last_dag_for_call_barrier = dag
        self._last_state_var_stkoff_for_call_barrier = state_var_stkoff
        self._last_local_facts_for_call_barrier = local_facts
        for info in raw_region_table:
            try:
                _log_region_lowering_candidate(
                    info=info,
                    raw_region_table=raw_region_table,
                    dag=dag,
                    local_facts=local_facts,
                    mba=mba,
                )
            except Exception as exc:  # pragma: no cover - diagnostic only
                logger.warning(
                    "HandlerChainComposer: REGION_LOWERING_CANDIDATE log"
                    " failed for region head=%d: %s",
                    info.head_anchor,
                    exc,
                )
        try:
            _log_region_lowering_summary(
                raw_region_table,
                dag=dag,
                local_facts=local_facts,
                mba=mba,
            )
        except Exception as exc:  # pragma: no cover - diagnostic only
            logger.warning(
                "HandlerChainComposer: REGION_LOWERING_SUMMARY log failed: %s",
                exc,
            )

        # FUSABLE_TAIL_EXTENSION (uee-tail-extension): collect any
        # tail-extension candidates BEFORE applying convergence or
        # linear fusion.  Priority order is FUSABLE_TAIL_EXTENSION >
        # FUSABLE_LOCAL_CONVERGENCE > FUSABLE_LINEAR.  When the gate
        # is on, these consume R1 + R2 (suppressing their default
        # singleton emission) and produce ONE ``HandlerChainCandidate``
        # per accepted candidate.  The candidate's ``pred_serial`` is
        # R2's ``splice_source_block`` (the convergence, preserved
        # in-place), ``handler_serials[0]`` is R2's
        # ``splice_old_target``, and ``succ_serial`` is R2's exit.
        # When the gate is off, ``tail_extension_candidates`` stays
        # empty and behavior is unaffected.
        tail_extension_candidates: list[HandlerChainCandidate] = []
        consumed_by_tail_extension: set[int] = set()
        if self.HCC_TAIL_EXTENSION_ENABLED:
            (
                tail_extension_candidates,
                consumed_by_tail_extension,
            ) = self._apply_fusable_tail_extension(
                dag=dag,
                local_facts=local_facts,
                mba=mba,
                raw_region_table=raw_region_table,
                state_var_stkoff=state_var_stkoff,
            )

        # FUSABLE_LOCAL_CONVERGENCE: DEMOTED to experimental.
        # Per-pred body cloning is SSA-hostile (see
        # ``HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION_ENABLED`` docstring).
        # Retained for experimental evidence only.  The classifier no
        # longer returns FUSABLE_LOCAL_CONVERGENCE in convergence shapes;
        # the loop below is effectively a no-op once
        # FUSABLE_TAIL_EXTENSION is enabled.
        convergence_candidates: list[HandlerChainCandidate] = []
        consumed_by_convergence: set[int] = set()
        if self.HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION_ENABLED:
            (
                convergence_candidates,
                consumed_by_convergence,
            ) = self._apply_fusable_local_convergence_fusion(
                dag=dag,
                local_facts=local_facts,
                mba=mba,
                raw_region_table=raw_region_table,
                state_var_stkoff=state_var_stkoff,
            )

        # Combine consumed-info tracking from both passes so the
        # downstream linear fusion / per-region pass skips them.
        all_consumed: set[int] = (
            set(consumed_by_tail_extension) | set(consumed_by_convergence)
        )

        # uee-b7ze Step 2: when the fusion gate is enabled, build a
        # FUSABLE_LINEAR fusion plan and try to compose each fused region.
        # On success, the fused region replaces the two originals; on
        # failure, the originals are preserved.  When the gate is off,
        # this is a no-op and behavior is byte-identical to the prior
        # logging-only step.
        composition_inputs: list[tuple[StateDagNode, ...]]
        if self.HCC_REGION_FUSION_ENABLED:
            composition_inputs = self._apply_fusable_linear_fusion(
                mba=mba,
                dag=dag,
                regions=regions,
                raw_region_table=raw_region_table,
                state_var_stkoff=state_var_stkoff,
                convergence_consumed_ids=all_consumed,
            )
        else:
            composition_inputs = [
                info.region_nodes
                for info in raw_region_table
                if id(info) not in all_consumed
            ] if all_consumed else list(regions)

        candidates: list[HandlerChainCandidate] = []
        for region_nodes in composition_inputs:
            candidate = self._compose_region(
                mba=mba,
                dag=dag,
                region_nodes=region_nodes,
                state_var_stkoff=state_var_stkoff,
            )
            if candidate is not None:
                candidates.append(candidate)

        # Append tail-extension candidates AFTER per-region candidates,
        # then convergence candidates.  Each is a fully validated
        # ``HandlerChainCandidate`` and flows through the same
        # InsertBlock emission loop in ``plan()``.
        candidates.extend(tail_extension_candidates)
        candidates.extend(convergence_candidates)

        return candidates

    def _apply_fusable_tail_extension(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        local_facts: DagLocalFacts,
        raw_region_table: tuple[_RawRegionInfo, ...],
        state_var_stkoff: int | None,
    ) -> tuple[list[HandlerChainCandidate], set[int]]:
        """Atomically lower FUSABLE_TAIL_EXTENSION candidates.

        For each ``info`` whose convergence-aware classification is
        ``FUSABLE_TAIL_EXTENSION``: emit ONE
        ``HandlerChainCandidate`` whose ``pred_serial`` is the
        convergence block (R2's ``splice_source_block``), whose
        ``handler_serials[0]`` is R2's ``splice_old_target``
        (the convergence's current outgoing dispatcher edge), and
        whose ``succ_serial`` is R2's exit target.  The body is R2's
        already-composed ``composed_candidate.composed_instructions``
        (R2's body only -- R1's convergence body is NOT cloned).

        Atomic: if R2 has no composed body, we cannot proceed; reject.
        Same-batch conflict: if the convergence block (which becomes
        the splice ``pred_serial``) is already claimed by another
        accepted tail-extension or fused emission in this batch,
        REJECT.

        Returns ``(per_candidate_list, consumed_info_ids)``:
        ``consumed_info_ids`` covers BOTH R1 (the cover region whose
        singleton emission is suppressed) and R2 (the candidate
        itself, whose plain emission is replaced by the tail-extension
        InsertBlock).
        """
        per_candidate: list[HandlerChainCandidate] = []
        consumed_ids: set[int] = set()
        accepted_count = 0
        rejected_count = 0
        consumed_r1_count = 0
        # Edges already claimed in this round, keyed by
        # (pred=convergence_block, old_target=splice_old_target).
        claimed_edges: set[tuple[int, int]] = set()
        # Track convergence (= splice_source_block) blocks already used
        # as a tail-extension splice pred so two candidates do not
        # race on the same physical edge.
        claimed_splice_sources: set[int] = set()

        for info in raw_region_table:
            label, plan = _classify_convergence_or_linear(
                self_info=info,
                raw_region_table=raw_region_table,
                dag=dag,
                local_facts=local_facts,
                mba=mba,
            )
            if label != "FUSABLE_TAIL_EXTENSION":
                continue
            if not isinstance(plan, _TailExtensionPlan):  # defensive
                continue

            covers = _find_cover_regions(
                self_info=info, raw_region_table=raw_region_table,
            )
            if len(covers) != 1:
                continue
            cover = covers[0]
            if id(cover) in consumed_ids or id(info) in consumed_ids:
                continue

            cov_state = int(cover.candidate.head_state) & 0xFFFFFFFF
            self_state = int(info.candidate.head_state) & 0xFFFFFFFF
            cov_handlers = tuple(int(n.entry_anchor) for n in cover.region_nodes)
            self_handlers = tuple(int(n.entry_anchor) for n in info.region_nodes)

            # Same-batch conflict: another accepted tail-extension
            # already claimed this convergence block as splice pred.
            if int(plan.convergence_block) in claimed_splice_sources:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] reason=splice_source_already_claimed",
                    cov_state, self_state, int(plan.convergence_block),
                )
                rejected_count += 1
                continue

            # Edge claim: (pred, old_target) on the convergence's
            # current outgoing dispatcher edge.
            edge_key = (
                int(plan.convergence_block),
                int(plan.splice_old_target),
            )
            if edge_key in claimed_edges:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " edge=(blk[%d]->blk[%d]) reason=edge_already_claimed",
                    cov_state, self_state, edge_key[0], edge_key[1],
                )
                rejected_count += 1
                continue

            # R2 must have a composed body: its instructions become
            # the InsertBlock body.  If R2 cannot compose under HCC
            # rules, we cannot proceed.
            if info.composed_candidate is None:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " reason=R2_compose_unavailable",
                    cov_state, self_state,
                )
                rejected_count += 1
                continue

            # Stale-target verification: re-fetch the splice source's
            # live mblock at emission time and confirm it still matches
            # the planned shape.  Plan-time data may be stale if an
            # earlier mod (in this round or a prior round) rewired the
            # convergence's outgoing edge.  Three sub-conditions:
            #   * splice_source_dead -- the convergence mblock is gone
            #     (None) entirely.
            #   * splice_source_no_longer_1way -- nsucc() != 1 (a 2-way
            #     conditional was bolted on, or it became 0-way).
            #   * stale_old_target -- nsucc()==1 but succ(0) != the
            #     planned splice_old_target.
            splice_source_block = int(plan.convergence_block)
            splice_old_target_planned = int(plan.splice_old_target)
            splice_blk = HandlerChainComposerStrategy._safe_get_mblock(
                mba, splice_source_block,
            )
            if splice_blk is None:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] reason=splice_source_dead",
                    cov_state, self_state, splice_source_block,
                )
                rejected_count += 1
                continue
            try:
                splice_nsucc = int(splice_blk.nsucc())  # type: ignore[attr-defined]
            except Exception:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] reason=splice_source_no_longer_1way",
                    cov_state, self_state, splice_source_block,
                )
                rejected_count += 1
                continue
            if splice_nsucc != 1:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] nsucc=%d"
                    " reason=splice_source_no_longer_1way",
                    cov_state, self_state, splice_source_block, splice_nsucc,
                )
                rejected_count += 1
                continue
            try:
                splice_succ_live = int(splice_blk.succ(0))  # type: ignore[attr-defined]
            except Exception:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] reason=stale_old_target",
                    cov_state, self_state, splice_source_block,
                )
                rejected_count += 1
                continue
            if splice_succ_live != splice_old_target_planned:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] live_succ=blk[%d]"
                    " planned_old_target=blk[%d] reason=stale_old_target",
                    cov_state, self_state, splice_source_block,
                    splice_succ_live, splice_old_target_planned,
                )
                rejected_count += 1
                continue

            # Surgical R1 suppression: identify the unique R1 (cover
            # region) whose composed_candidate.handler_serials contains
            # the splice source.  If 0 or 2+ regions match, refuse.
            r1_to_suppress = _find_r1_to_suppress(
                splice_source_block=splice_source_block,
                raw_region_table=raw_region_table,
                consumed_ids=consumed_ids,
            )
            if r1_to_suppress is None:
                logger.info(
                    "HCC_TAIL_EXTENSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " splice_source=blk[%d] reason=r1_not_uniquely_identified",
                    cov_state, self_state, splice_source_block,
                )
                rejected_count += 1
                continue

            # Build the tail-extension HandlerChainCandidate.  This
            # is structurally a plain UNCONDITIONAL_1WAY splice:
            # pred = convergence (preserved, preds intact),
            # old_target = current dispatcher edge,
            # succ = R2's exit,
            # body = R2's composed instructions (NOT R1's body).
            body = info.composed_candidate.composed_instructions
            states = info.composed_candidate.state_values
            tail_candidate = HandlerChainCandidate(
                # handler_serials[0] is consumed downstream as
                # ``old_target``; subsequent entries are advisory.
                # We carry the splice_old_target plus R2's anchors
                # so logging stays informative.
                handler_serials=(
                    int(plan.splice_old_target),
                ) + self_handlers,
                pred_serial=int(plan.convergence_block),
                succ_serial=int(plan.exit_target),
                composed_instructions=body,
                state_values=states,
            )

            per_candidate.append(tail_candidate)
            claimed_edges.add(edge_key)
            claimed_splice_sources.add(int(plan.convergence_block))
            # Suppress the surgically-identified R1 (the cover region
            # whose composed_candidate carries the splice source) AND
            # R2 (the candidate itself).  We keep ``cover`` in the
            # consumed set as well for backward-compat: the legacy
            # "find any cover" path still applies for downstream filters
            # that look at cover identity.
            consumed_ids.add(id(cover))
            consumed_ids.add(id(r1_to_suppress))
            consumed_ids.add(id(info))
            accepted_count += 1
            consumed_r1_count += 1
            logger.info(
                "HCC_TAIL_EXTENSION_ACCEPTED head_state=0x%08X"
                " covered_state=0x%08X\n"
                "  splice_source=blk[%d]  splice_old_target=blk[%d]"
                "  succ=blk[%d]\n"
                "  body_handlers=%s   covered_region_handlers=%s"
                "  preserved=YES",
                self_state,
                cov_state,
                int(plan.convergence_block),
                int(plan.splice_old_target),
                int(plan.exit_target),
                self_handlers,
                cov_handlers,
            )
            # CFG invariant marker (uee-tail-extension lock-down): a
            # future grep ``HCC_TAIL_EXTENSION_INVARIANT preserved_preds=True``
            # detects accidental drift of the no-clone semantics.
            logger.info(
                "HCC_TAIL_EXTENSION_INVARIANT preserved_preds=True"
                " splice_source=blk[%d] no_clone=True",
                int(plan.convergence_block),
            )

        logger.info(
            "HCC_TAIL_EXTENSION_SUMMARY accepted=%d rejected=%d"
            " consumed_R1_emissions=%d",
            accepted_count, rejected_count, consumed_r1_count,
        )
        return per_candidate, consumed_ids

    def _apply_call_barrier_segmentation(
        self,
        *,
        mba: object,
        flow_graph: object | None = None,
        dag: LinearizedStateDag,
        raw_region_table: tuple[_RawRegionInfo, ...],
        state_var_stkoff: int | None = None,
        local_facts: DagLocalFacts | None = None,
        prior_modifications: tuple = (),
        bst_node_blocks: frozenset[int] = frozenset(),
        dispatcher_serial: int = -1,
        bst_result: object | None = None,
    ) -> list:
        """Atomically lower opaque-call anchors.

        For each ``_RawRegionInfo`` whose ``opaque_call_anchor`` is set:

          * ``SIMPLE_1WAY_OUT``: emit TWO ``RedirectGoto`` mods
            atomically (inbound + outbound).  See
            :py:meth:`_emit_simple_1way_out_call_barrier` for details.

          * ``CHAINED_CALL_ANCHOR`` (Phase B chained): emit ONE
            ``InsertBlock`` (pre-anchor body composed inline before the
            call anchor) and OPTIONALLY ONE ``RedirectGoto`` outbound
            when the call anchor's existing edge is not already at
            ``block_outgoing_edge``.  See
            :py:meth:`_emit_chained_call_anchor` for details.

        Both succeed atomically per candidate; partial emission is
        forbidden.  Stale state aborts the bundle.

        The method NEVER copies the call instruction itself.  The
        call anchor block stays in place; CHAINED only adds a new
        InsertBlock that flows into it.

        Returns a list of ``RedirectGoto | InsertBlock`` mods.
        """
        accepted: list = []
        accepted_simple_count = 0
        accepted_chained_count = 0
        rejected_count = 0
        rejected_chained_count = 0
        # Track per-source claims so two candidates can't redirect the
        # same predecessor edge.
        claimed_inbound_sources: set[int] = set()
        # Track per-handler claims so we don't emit two outbound
        # redirects on the same handler.
        claimed_handlers: set[int] = set()
        # Track CHAINED claims so we don't emit two InsertBlocks for
        # the same call anchor or splice source.
        claimed_chained_anchors: set[int] = set()

        for info in raw_region_table:
            if info.opaque_call_anchor is None:
                continue
            if info.opaque_call_shape == "CHAINED_CALL_ANCHOR":
                emitted = self._emit_chained_call_anchor(
                    info=info,
                    mba=mba,
                    dag=dag,
                    state_var_stkoff=state_var_stkoff,
                    local_facts=local_facts,
                    claimed_inbound_sources=claimed_inbound_sources,
                    claimed_chained_anchors=claimed_chained_anchors,
                    prior_modifications=tuple(prior_modifications) + tuple(accepted),
                    bst_node_blocks=bst_node_blocks,
                    dispatcher_serial=dispatcher_serial,
                    bst_result=bst_result,
                )
                if emitted is None:
                    rejected_chained_count += 1
                    continue
                accepted.extend(emitted)
                accepted_chained_count += 1
                continue
            if info.opaque_call_shape != "SIMPLE_1WAY_OUT":
                continue
            anchor_serial, call_ea, _is_indirect = info.opaque_call_anchor
            anchor_serial = int(anchor_serial)
            call_ea = int(call_ea)
            candidate = info.candidate

            head_state = int(candidate.head_state) & 0xFFFFFFFF

            # Inbound prerequisites: candidate must carry a usable
            # splice_source_block and splice_old_target (Phase A's
            # SIMPLE_1WAY_OUT classifier already guarantees
            # UNCONDITIONAL_1WAY eligibility, but we re-check).
            splice_source = candidate.splice_source_block
            splice_old_target = candidate.splice_old_target
            if splice_source is None or splice_old_target is None:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=missing_splice_metadata",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue
            splice_source = int(splice_source)
            splice_old_target = int(splice_old_target)

            if splice_source in claimed_inbound_sources:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=splice_source_already_claimed"
                    " splice_source=blk[%d]",
                    anchor_serial, head_state, splice_source,
                )
                rejected_count += 1
                continue

            if anchor_serial in claimed_handlers:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=handler_already_claimed",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue

            # Outbound prerequisite: next_semantic_target.  Use the
            # candidate's ``proposed_exit`` (the resolved single
            # outgoing TRANSITION target).  SIMPLE_1WAY_OUT classifier
            # already enforced "exactly one outgoing TRANSITION,
            # zero conditionals", but we re-check defensively.
            next_semantic_target = info.proposed_exit
            if next_semantic_target is None:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=no_proposed_exit",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue
            next_semantic_target = int(next_semantic_target)

            # Atomic guard 1: splice source still 1-way and pointing
            # at the planned old target.
            splice_blk = self._safe_get_mblock(mba, splice_source)
            if splice_blk is None:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=splice_source_dead"
                    " splice_source=blk[%d]",
                    anchor_serial, head_state, splice_source,
                )
                rejected_count += 1
                continue
            try:
                splice_nsucc = int(splice_blk.nsucc())  # type: ignore[attr-defined]
            except Exception:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=splice_source_nsucc_unreadable",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue
            if splice_nsucc != 1:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=splice_source_not_1way"
                    " nsucc=%d",
                    anchor_serial, head_state, splice_nsucc,
                )
                rejected_count += 1
                continue
            try:
                splice_live_succ = int(splice_blk.succ(0))  # type: ignore[attr-defined]
            except Exception:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=splice_source_succ_unreadable",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue
            if splice_live_succ != splice_old_target:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=stale_splice_old_target"
                    " live_succ=blk[%d] planned=blk[%d]",
                    anchor_serial, head_state,
                    splice_live_succ, splice_old_target,
                )
                rejected_count += 1
                continue

            # Atomic guard 2: handler still 1-way and pointing at the
            # current dispatcher edge.
            handler_blk = self._safe_get_mblock(mba, anchor_serial)
            if handler_blk is None:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=handler_dead",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue
            try:
                handler_nsucc = int(handler_blk.nsucc())  # type: ignore[attr-defined]
            except Exception:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=handler_nsucc_unreadable",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue
            if handler_nsucc != 1:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=handler_not_1way"
                    " nsucc=%d",
                    anchor_serial, head_state, handler_nsucc,
                )
                rejected_count += 1
                continue
            try:
                current_succ = int(handler_blk.succ(0))  # type: ignore[attr-defined]
            except Exception:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=handler_succ_unreadable",
                    anchor_serial, head_state,
                )
                rejected_count += 1
                continue

            # Skip no-op outbound: when the handler already points at
            # the next semantic target, we don't need an outbound
            # redirect (and emitting one with old==new would be
            # rejected by the backend's stale_target check).
            emit_outbound = True
            if current_succ == next_semantic_target:
                logger.info(
                    "HCC_CALL_BARRIER_OUTBOUND_SKIPPED handler=%s"
                    " head_state=0x%08X reason=outbound_already_correct"
                    " current_succ=%s %s",
                    flow_block_label(flow_graph, anchor_serial),
                    head_state,
                    flow_block_label(flow_graph, current_succ),
                    flow_graph_context_label(flow_graph),
                )
                emit_outbound = False
            elif flow_graph is not None:
                outbound_probe = RedirectGoto(
                    from_serial=anchor_serial,
                    old_target=current_succ,
                    new_target=next_semantic_target,
                )
                try:
                    severed_uses = check_redirect_severs_use_def(
                        outbound_probe,
                        mba,
                        flow_graph,
                    )
                except Exception:
                    logger.debug(
                        "HCC_CALL_BARRIER_OUTBOUND_CHECK_RAISED"
                        " handler=%s current_succ=%s"
                        " next_semantic_target=%s %s",
                        flow_block_label(flow_graph, anchor_serial),
                        flow_block_label(flow_graph, current_succ),
                        flow_block_label(flow_graph, next_semantic_target),
                        flow_graph_context_label(flow_graph),
                        exc_info=True,
                    )
                    severed_uses = ()
                if severed_uses:
                    logger.info(
                        "HCC_CALL_BARRIER_OUTBOUND_SKIPPED handler=%s"
                        " head_state=0x%08X reason=use_def_severance"
                        " current_succ=%s next_semantic_target=%s"
                        " orphaned_uses=%d %s",
                        flow_block_label(flow_graph, anchor_serial),
                        head_state,
                        flow_block_label(flow_graph, current_succ),
                        flow_block_label(flow_graph, next_semantic_target),
                        len(severed_uses),
                        flow_graph_context_label(flow_graph),
                    )
                    emit_outbound = False

            # All guards passed.  Build BOTH redirects and commit
            # together.
            inbound = RedirectGoto(
                from_serial=splice_source,
                old_target=splice_old_target,
                new_target=anchor_serial,
            )
            accepted.append(inbound)
            if emit_outbound:
                outbound = RedirectGoto(
                    from_serial=anchor_serial,
                    old_target=current_succ,
                    new_target=next_semantic_target,
                )
                accepted.append(outbound)
            claimed_inbound_sources.add(splice_source)
            claimed_handlers.add(anchor_serial)
            accepted_simple_count += 1
            logger.info(
                "HCC_CALL_BARRIER_ACCEPTED handler=blk[%d] call_ea=0x%x\n"
                "  inbound: redirect blk[%d] from blk[%d] -> blk[%d]\n"
                "  outbound: %s blk[%d] from blk[%d] -> blk[%d]",
                anchor_serial, call_ea,
                splice_source, splice_old_target, anchor_serial,
                "redirect" if emit_outbound else "preserve",
                anchor_serial, current_succ, next_semantic_target,
            )

        logger.info(
            "HCC_CALL_BARRIER_SUMMARY accepted=%d rejected=%d"
            " call_barrier_chained_emit_distribution={ACCEPTED: %d,"
            " REJECTED: %d}",
            accepted_simple_count, rejected_count,
            accepted_chained_count, rejected_chained_count,
        )
        return accepted

    def _emit_chained_call_anchor(
        self,
        *,
        info: _RawRegionInfo,
        mba: object,
        dag: LinearizedStateDag | None = None,
        state_var_stkoff: int | None,
        local_facts: DagLocalFacts | None,
        claimed_inbound_sources: set[int],
        claimed_chained_anchors: set[int],
        prior_modifications: tuple = (),
        bst_node_blocks: frozenset[int] = frozenset(),
        dispatcher_serial: int = -1,
        bst_result: object | None = None,
    ) -> list | None:
        """Emit ``CHAINED_CALL_ANCHOR`` lowering bundle, atomically.

        For a 2-handler region ``(pre_anchor, call_anchor)`` whose
        ``opaque_call_shape == 'CHAINED_CALL_ANCHOR'``: compose the
        pre-anchor body inline as an ``InsertBlock`` between the
        semantic predecessor and the call anchor, and (when the call
        anchor's existing outgoing edge does not already match
        ``block_outgoing_edge``) optionally emit a ``RedirectGoto`` for
        the outbound edge.

        The call instruction stays in the call anchor's mblock; the
        pre-anchor body (which must be composable -- no calls, no
        forbidden opcodes) becomes the InsertBlock instructions.

        Returns:
          * ``None`` when any guard rejects the candidate.  The caller
            must NOT extend ``accepted`` in that case.
          * A list of mods (length 1 or 2) on success.  The first is
            always an ``InsertBlock``; the optional second is a
            ``RedirectGoto`` for the outbound edge when needed.
        """
        anchor_serial, call_ea, _is_indirect = info.opaque_call_anchor or (
            0, 0, False,
        )
        anchor_serial = int(anchor_serial)
        call_ea = int(call_ea)
        candidate = info.candidate
        head_state = int(candidate.head_state) & 0xFFFFFFFF

        # Guard 1: region_handlers arity must be exactly 2.  The
        # CHAINED_CALL_ANCHOR classifier guarantees the call anchor is
        # the LAST node and at least one composable predecessor exists;
        # here we only commit when the structure is the simple
        # 2-handler chain ``(pre_anchor, call_anchor)``.
        region_handlers = tuple(
            int(n.entry_anchor) for n in info.region_nodes
        )
        if len(region_handlers) != 2:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_unexpected_arity"
                " region_handlers=%s",
                anchor_serial, head_state, region_handlers,
            )
            return None
        pre_anchor_serial = int(region_handlers[0])
        call_anchor_serial = int(region_handlers[1])
        if call_anchor_serial != anchor_serial:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_anchor_mismatch"
                " region_handlers=%s",
                anchor_serial, head_state, region_handlers,
            )
            return None

        # Guard 2: semantic predecessor metadata must be UNCONDITIONAL_1WAY.
        if candidate.eligibility != EntryEligibility.UNCONDITIONAL_1WAY:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_pred_not_unconditional"
                " eligibility=%s",
                anchor_serial, head_state, candidate.eligibility.value,
            )
            return None
        splice_source = candidate.splice_source_block
        splice_old_target = candidate.splice_old_target
        if splice_source is None or splice_old_target is None:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_no_splice_source",
                anchor_serial, head_state,
            )
            return None
        splice_source = int(splice_source)
        splice_old_target = int(splice_old_target)

        # Same-batch conflict: same splice source / call anchor cannot
        # be claimed twice.
        if splice_source in claimed_inbound_sources:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_splice_source_already_claimed"
                " splice_source=blk[%d]",
                anchor_serial, head_state, splice_source,
            )
            return None
        if call_anchor_serial in claimed_chained_anchors:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_anchor_already_claimed",
                anchor_serial, head_state,
            )
            return None

        # Guard 3: stale-target verification on the splice source.
        # The semantic predecessor must still be 1-way and pointing at
        # ``splice_old_target``.  Mirrors tail-extension's stale guards.
        src_blk = self._safe_get_mblock(mba, splice_source)
        if src_blk is None:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_splice_source_dead"
                " splice_source=blk[%d]",
                anchor_serial, head_state, splice_source,
            )
            return None
        try:
            src_nsucc = int(src_blk.nsucc())  # type: ignore[attr-defined]
        except Exception:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_splice_source_nsucc_unreadable",
                anchor_serial, head_state,
            )
            return None
        if src_nsucc != 1:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_splice_source_not_1way"
                " nsucc=%d",
                anchor_serial, head_state, src_nsucc,
            )
            return None
        try:
            src_live_succ = int(src_blk.succ(0))  # type: ignore[attr-defined]
        except Exception:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_splice_source_succ_unreadable",
                anchor_serial, head_state,
            )
            return None
        if src_live_succ != splice_old_target:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_stale_splice_old_target"
                " live_succ=blk[%d] planned=blk[%d]",
                anchor_serial, head_state,
                src_live_succ, splice_old_target,
            )
            return None

        # Guard 4: stale-target verification on the call anchor's
        # outgoing edge.  Re-derive ``block_outgoing_edge`` from the
        # live mblock (the diagnostic field is captured at log time).
        ca_blk = self._safe_get_mblock(mba, call_anchor_serial)
        if ca_blk is None:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_call_anchor_dead",
                anchor_serial, head_state,
            )
            return None
        try:
            ca_nsucc = int(ca_blk.nsucc())  # type: ignore[attr-defined]
        except Exception:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_call_anchor_nsucc_unreadable",
                anchor_serial, head_state,
            )
            return None
        if ca_nsucc != 1:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_call_anchor_not_1way"
                " nsucc=%d",
                anchor_serial, head_state, ca_nsucc,
            )
            return None
        try:
            ca_live_succ = int(ca_blk.succ(0))  # type: ignore[attr-defined]
        except Exception:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_call_anchor_succ_unreadable",
                anchor_serial, head_state,
            )
            return None
        block_outgoing_edge = ca_live_succ

        # Guard 5: DAG-fact ownership lookup -- the call anchor must be
        # owned by exactly one known state per ``DagLocalFacts``.  This
        # is canonical truth (recon-time, persisted typed contract);
        # do NOT consult any live-rebuilt DAG.  When the lookup is
        # unavailable (no local_facts), accept anyway -- the diagnostic
        # log already filters via opaque_call_shape and the upstream
        # classifier already proved local_facts coherence.
        if local_facts is not None:
            owning_node = local_facts.node_by_any_local_block.get(
                call_anchor_serial,
            )
            if owning_node is None:
                logger.info(
                    "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                    " head_state=0x%08X reason=chained_no_canonical_owner",
                    anchor_serial, head_state,
                )
                return None

        # Guard 6: pre-anchor body must be fully composable.  The
        # CHAINED classifier already proved this once at classification
        # time, but we re-verify under the live mblock to guard against
        # post-classification drift.  Pre-anchor MUST NOT contain a
        # call (asserted again at the Phase C audit downstream).
        pre_blk = self._safe_get_mblock(mba, pre_anchor_serial)
        if pre_blk is None:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_pre_anchor_dead"
                " pre_anchor=blk[%d]",
                anchor_serial, head_state, pre_anchor_serial,
            )
            return None
        try:
            cap_result = self._capture_block_composable_instructions_v2(
                pre_blk, state_var_stkoff=state_var_stkoff,
            )
        except Exception:
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_pre_anchor_capture_raised"
                " pre_anchor=blk[%d]",
                anchor_serial, head_state, pre_anchor_serial,
            )
            return None
        if cap_result.kind != "composable":
            logger.info(
                "HCC_CALL_BARRIER_REJECTED handler=blk[%d]"
                " head_state=0x%08X reason=chained_pre_anchor_uncomposable"
                " pre_anchor=blk[%d] kind=%s",
                anchor_serial, head_state, pre_anchor_serial,
                cap_result.kind,
            )
            return None
        body = tuple(cap_result.snapshots or ())

        # Guard 7 (uee-b7ze): CoveredSourceResolution.  A structurally
        # correct chained InsertBlock is wasted if its splice_source is
        # orphaned by the same HCC batch (the dispatcher route gets
        # killed by region/tail-extension/SIMPLE redirects, leaving
        # ``splice_source`` with no live predecessor).  Reject when the
        # projected post-batch CFG would not preserve a path from entry
        # through ``splice_source`` to the InsertBlock.
        candidate_outbound_target_for_check = (
            int(info.proposed_exit) if info.proposed_exit is not None
            else block_outgoing_edge
        )
        resolution, resolution_info = self._classify_chained_splice_source(
            mba=mba,
            splice_source=splice_source,
            splice_old_target=splice_old_target,
            call_anchor_serial=call_anchor_serial,
            outbound_target=candidate_outbound_target_for_check,
            local_facts=local_facts,
            prior_modifications=tuple(prior_modifications),
            bst_node_blocks=bst_node_blocks,
            dispatcher_serial=dispatcher_serial,
        )
        # uee-b7ze: capture for downstream override.  When the
        # CoveredSourceResolution rejected a BST-only physical source,
        # the BST-only resolver below may produce a SEMANTIC source
        # exit that bypasses the BST entirely.  In that case we
        # override ``effective_splice_source`` and ``effective_old_target``
        # for the InsertBlock construction; the original ``splice_source``
        # remains in logs for traceability.
        effective_splice_source = splice_source
        effective_old_target = splice_old_target
        bst_only_override_applied = False

        if resolution != "LIVE_SOURCE":
            # Detect the "BST-only physical source" subcase: every live
            # pred is a BST/dispatcher routing block.  In that case a
            # straight reject leaves a real call un-preserved, even
            # though recon's DAG knows the genuine semantic predecessor.
            common = resolution_info if isinstance(resolution_info, dict) else {}
            live_preds_list = list(common.get("live_preds", ()) or ())
            bst_only = (
                live_preds_list
                and not common.get("surviving_preds")
                and not common.get("local_dag_preds")
                and not common.get("shared_suffix_preds")
                and not common.get("unmapped_preds")
                and (
                    set(common.get("bst_node_preds", ()) or ())
                    | set(common.get("dispatcher_preds", ()) or ())
                ) >= set(live_preds_list)
            )
            if bst_only and dag is not None:
                logger.info(
                    "HCC_CHAINED_BST_ONLY_SOURCE call_anchor=blk[%d]"
                    " head_state=0x%08X pre_anchor=blk[%d]"
                    " splice_source=blk[%d] live_preds=%s",
                    call_anchor_serial, head_state, pre_anchor_serial,
                    splice_source, live_preds_list,
                )
                # Build the set of blocks already claimed as the
                # ``splice_source_block`` of OTHER raw regions in this
                # plan().  HCC's region-collapse will redirect those
                # sources, so we must NOT pick the same block as our
                # chained semantic predecessor (would produce a 2-way
                # source from a 1-way block, triggering CFG_50856).
                region_claimed_sources: set[int] = set()
                try:
                    for other_info in (
                        self._last_raw_region_table or ()
                    ):
                        if other_info is info:
                            continue
                        oc = getattr(other_info, "candidate", None)
                        ssb = getattr(oc, "splice_source_block", None)
                        if ssb is not None:
                            region_claimed_sources.add(int(ssb))
                except Exception:
                    region_claimed_sources = set()

                semantic_pred, sem_info = (
                    self._resolve_semantic_predecessor_for_bst_only_source(
                        mba=mba,
                        dag=dag,
                        local_facts=local_facts,
                        splice_source=splice_source,
                        splice_old_target=splice_old_target,
                        call_anchor_serial=call_anchor_serial,
                        bst_node_blocks=bst_node_blocks,
                        dispatcher_serial=dispatcher_serial,
                        claimed_inbound_sources=claimed_inbound_sources,
                        bst_result=bst_result,
                        state_var_stkoff=state_var_stkoff,
                        region_claimed_sources=frozenset(
                            region_claimed_sources
                        ),
                    )
                )
                if semantic_pred is not None:
                    logger.info(
                        "HCC_CHAINED_SEMANTIC_PREDECESSOR_ACCEPTED"
                        " call_anchor=blk[%d] head_state=0x%08X"
                        " original_splice_source=blk[%d]"
                        " semantic_source_exit=blk[%d]"
                        " new_old_target=blk[%d]"
                        " detail=%s",
                        call_anchor_serial, head_state, splice_source,
                        semantic_pred,
                        int(sem_info.get("new_old_target", -1)),
                        sem_info,
                    )
                    effective_splice_source = int(semantic_pred)
                    effective_old_target = int(sem_info.get(
                        "new_old_target", splice_old_target,
                    ))
                    bst_only_override_applied = True
                else:
                    logger.info(
                        "HCC_CHAINED_SEMANTIC_PREDECESSOR_REJECTED"
                        " call_anchor=blk[%d] head_state=0x%08X"
                        " original_splice_source=blk[%d]"
                        " detail=%s",
                        call_anchor_serial, head_state, splice_source,
                        sem_info,
                    )

            if not bst_only_override_applied:
                logger.info(
                    "HCC_CHAINED_REJECTED call_anchor=blk[%d] head_state=0x%08X"
                    " pre_anchor=blk[%d] splice_source=blk[%d]"
                    " resolution=%s detail=%s",
                    call_anchor_serial, head_state, pre_anchor_serial,
                    splice_source, resolution, resolution_info,
                )
                # Pred-corridor diagnostic: classify each block on the
                # BFS backward frontier from splice_source.
                try:
                    corridor = self._dump_splice_source_corridor(
                        mba=mba,
                        splice_source=splice_source,
                        local_facts=local_facts,
                        bst_node_blocks=bst_node_blocks,
                        dispatcher_serial=dispatcher_serial,
                        max_depth=8,
                    )
                    logger.info(
                        "HCC_CHAINED_REJECT_DIAG call_anchor=blk[%d]"
                        " splice_source=blk[%d]\n  corridor=%s",
                        call_anchor_serial, splice_source, corridor,
                    )
                except Exception:
                    logger.debug(
                        "HCC_CHAINED_REJECT_DIAG: corridor dump raised",
                        exc_info=True,
                    )
                return None

        # uee-b7ze: when the BST-only resolver overrode the splice
        # source, the InsertBlock's pred is now the SEMANTIC predecessor
        # (e.g. blk[90] writing the routing state), but the original
        # splice_source (e.g. blk[152]) is BYPASSED.  Its composable
        # body provided the reaching defs that the pre_anchor's body
        # (and ultimately the call anchor) consumes -- skipping it
        # leaves the call's USEs without dominating defs and IDA's
        # GLBOPT1 reaching-defs proves the chain dead.  THIS IS THE
        # WHOLE POINT OF HCC's CHAINED EMIT: synthesize the reaching
        # defs into the InsertBlock so the call survives.  Prepend the
        # bypassed handler's composable body to ``body``.
        guarded_source_skip_redirect_info: tuple[int, int] | None = None
        if bst_only_override_applied:
            try:
                bypass_blk = self._safe_get_mblock(mba, splice_source)
                if bypass_blk is not None:
                    bypass_cap = self._capture_block_composable_instructions_v2(
                        bypass_blk, state_var_stkoff=state_var_stkoff,
                    )
                    if bypass_cap.kind == "composable":
                        bypass_body = tuple(bypass_cap.snapshots or ())
                        body = bypass_body + body
                        logger.info(
                            "HCC_CHAINED_BST_ONLY_BODY_EXTENDED"
                            " bypass_handler=blk[%d] bypass_ninsns=%d"
                            " new_total_ninsns=%d",
                            splice_source, len(bypass_body), len(body),
                        )
                    else:
                        logger.info(
                            "HCC_CHAINED_BST_ONLY_BODY_NOT_EXTENDED"
                            " bypass_handler=blk[%d] kind=%s -- defs may"
                            " be missing; call may still be DCE'd",
                            splice_source, bypass_cap.kind,
                        )
            except Exception:
                logger.debug(
                    "HCC_CHAINED_BST_ONLY_BODY_EXTENDED: capture raised",
                    exc_info=True,
                )
            # uee-b7ze: recursive body walk-back.  After prepending the
            # bypass handler, scan the body's top-level stkvar reads
            # and prepend more handlers until every read has a local
            # def (or no unique const-writer can be found).  This is
            # the WHOLE POINT of HCC's chained emit: synthesize all
            # the reaching defs the call's USEs depend on so IDA's
            # GLBOPT1 reaching-defs cannot fold the call away.
            try:
                walkback_result = self._walk_back_extend_body(
                    mba=mba,
                    body=body,
                    state_var_stkoff=state_var_stkoff,
                    splice_source=int(effective_splice_source),
                    max_depth=8,
                    return_result=True,
                )
                assert isinstance(walkback_result, _WalkBackResult)
                body = walkback_result.body
                if self.HCC_CHAINED_GUARDED_SOURCE_ENABLED:
                    retargeted = self._try_retarget_to_guarded_walkback_source(
                        mba=mba,
                        body=body,
                        walkback_result=walkback_result,
                        current_splice_source=int(effective_splice_source),
                        current_old_target=int(effective_old_target),
                        call_anchor_serial=call_anchor_serial,
                        head_state=head_state,
                        claimed_inbound_sources=claimed_inbound_sources,
                        bst_node_blocks=bst_node_blocks,
                        dispatcher_serial=dispatcher_serial,
                    )
                    if retargeted is not None:
                        (
                            effective_splice_source,
                            effective_old_target,
                            body,
                        ) = retargeted
                        try:
                            guarded_blk = self._safe_get_mblock(
                                mba, int(effective_splice_source)
                            )
                            guarded_npred = (
                                int(guarded_blk.npred())  # type: ignore[attr-defined]
                                if guarded_blk is not None else -1
                            )
                            if guarded_npred == 1:
                                guard_pred = int(
                                    guarded_blk.pred(0)  # type: ignore[attr-defined]
                                )
                                guard_blk = self._safe_get_mblock(mba, guard_pred)
                                guard_nsucc = (
                                    int(guard_blk.nsucc())  # type: ignore[attr-defined]
                                    if guard_blk is not None else -1
                                )
                                if guard_nsucc == 2:
                                    guard_succs = (
                                        int(guard_blk.succ(0)),  # type: ignore[attr-defined]
                                        int(guard_blk.succ(1)),  # type: ignore[attr-defined]
                                    )
                                    if int(effective_splice_source) in guard_succs:
                                        old_skip_target = (
                                            guard_succs[1]
                                            if guard_succs[0] == int(effective_splice_source)
                                            else guard_succs[0]
                                        )
                                        guarded_source_skip_redirect_info = (
                                            guard_pred,
                                            int(old_skip_target),
                                        )
                        except Exception:
                            logger.debug(
                                "HCC_CHAINED_GUARDED_SOURCE_SKIP_REDIRECT:"
                                " guard topology unreadable",
                                exc_info=True,
                            )
            except Exception:
                logger.debug(
                    "HCC_CHAINED_BST_ONLY_BODY_RECURSIVE: walk-back raised",
                    exc_info=True,
                )

        # Build the InsertBlock atomically.  pred = effective_splice_source
        # (overridden by BST-only resolver when applicable),
        # succ = call anchor (preserves the call-bearing block in
        # place), old_target = the existing physical edge being
        # replaced (the dispatcher route).
        insert_mod = InsertBlock(
            pred_serial=effective_splice_source,
            succ_serial=call_anchor_serial,
            instructions=body,
            old_target_serial=effective_old_target,
        )
        emitted: list = [insert_mod]

        # Outbound redirect.  The call anchor's existing succ may
        # already match ``block_outgoing_edge`` (the live succ derived
        # above); in that case skip the redirect (stale_target backend
        # check would reject old==new anyway).  When the diagnostic
        # ``info.proposed_exit`` differs and the live succ is the
        # dispatcher edge to be replaced, emit one RedirectGoto.
        outbound_target = block_outgoing_edge
        if ca_live_succ != outbound_target:
            outbound = RedirectGoto(
                from_serial=call_anchor_serial,
                old_target=ca_live_succ,
                new_target=outbound_target,
            )
            emitted.append(outbound)

        # Guarded-source passthrough.  When the recursive walk-back
        # retargets the splice to a guarded source block, the guard's
        # false arm must skip only the guarded call/reaching-def body,
        # then continue at the post-call anchor.  Without this redirect,
        # the false arm keeps flowing to the old fallback state and skips
        # the 0x62 continuation region.
        if guarded_source_skip_redirect_info is not None:
            guard_pred, old_skip_target = guarded_source_skip_redirect_info
            if old_skip_target != outbound_target:
                emitted.append(
                    RedirectBranch(
                        from_serial=guard_pred,
                        old_target=old_skip_target,
                        new_target=outbound_target,
                    )
                )
                logger.info(
                    "HCC_CHAINED_GUARDED_SOURCE_SKIP_REDIRECT"
                    " call_anchor=blk[%d] guard=blk[%d]"
                    " old_skip=blk[%d] new_skip=blk[%d]",
                    call_anchor_serial,
                    guard_pred,
                    old_skip_target,
                    outbound_target,
                )

        # Optional-call guard passthrough.  A 2-way guard whose one arm
        # enters the call anchor should skip only that call on the other
        # arm, then continue at the call anchor's post-call successor.
        # In sub_7FFD3338C040 this is the blk[129] exact-state arm:
        #   old: blk[129] -> blk[130] (0x11/0x4A) OR blk[131] (fallback)
        #   new: blk[129] -> blk[130] (0x11/0x4A) OR blk[143] (0x62)
        # This is deliberately emitted as a branch redirect on the guard,
        # not as another body copy, so the original call block remains an
        # anchor and the false arm preserves the surrounding CFG.
        guard_skip_redirect: RedirectBranch | None = None
        try:
            call_anchor_preds = tuple(int(pred) for pred in ca_blk.predset)
        except Exception:
            call_anchor_preds = ()
        guard_preds: list[tuple[int, int]] = []
        for pred_serial in call_anchor_preds:
            pred_blk = self._safe_get_mblock(mba, pred_serial)
            if pred_blk is None:
                continue
            try:
                if int(pred_blk.nsucc()) != 2:  # type: ignore[attr-defined]
                    continue
                pred_succs = (
                    int(pred_blk.succ(0)),  # type: ignore[attr-defined]
                    int(pred_blk.succ(1)),  # type: ignore[attr-defined]
                )
            except Exception:
                continue
            if call_anchor_serial not in pred_succs:
                continue
            old_skip_target = (
                pred_succs[1]
                if pred_succs[0] == call_anchor_serial
                else pred_succs[0]
            )
            if old_skip_target == outbound_target:
                continue
            guard_preds.append((pred_serial, old_skip_target))
        if len(guard_preds) == 1:
            guard_pred, old_skip_target = guard_preds[0]
            guard_skip_redirect = RedirectBranch(
                from_serial=guard_pred,
                old_target=old_skip_target,
                new_target=outbound_target,
            )
            emitted.append(guard_skip_redirect)
            logger.info(
                "HCC_CALL_BARRIER_CHAINED_SKIP_REDIRECT"
                " call_anchor=blk[%d] guard=blk[%d]"
                " old_skip=blk[%d] new_skip=blk[%d]",
                call_anchor_serial,
                guard_pred,
                old_skip_target,
                outbound_target,
            )
        elif len(guard_preds) > 1:
            logger.info(
                "HCC_CALL_BARRIER_CHAINED_SKIP_REDIRECT_SKIPPED"
                " call_anchor=blk[%d] reason=multiple_guard_preds guards=%s",
                call_anchor_serial,
                guard_preds,
            )

        # Claim the EFFECTIVE splice source (overridden by BST-only
        # resolver when applicable) so downstream HCC accepts can't
        # double-claim the same predecessor.
        claimed_inbound_sources.add(int(effective_splice_source))
        claimed_chained_anchors.add(call_anchor_serial)
        outbound_text = (
            (
                f"redirect blk[{call_anchor_serial}]"
                f" from blk[{ca_live_succ}] -> blk[{outbound_target}]"
            )
            if ca_live_succ != outbound_target
            else (
                f"no-op (current_succ=blk[{ca_live_succ}] already"
                f" matches block_outgoing_edge=blk[{outbound_target}])"
            )
        )
        # uee-b7ze: structured PLAN log so the post-apply invariant check
        # can correlate planner-claim vs CFG-state.  Use a dedicated
        # marker tag (HCC_CHAINED_PLAN) so diag queries can pull all
        # chained-emit plan records via a single grep.  When the BST-only
        # resolver overrode the splice source we log BOTH the original
        # and the effective values so downstream readers can audit the
        # rewrite without losing traceability.
        body_opcodes = tuple(int(s.opcode) for s in body)
        logger.info(
            "HCC_CHAINED_PLAN call_anchor=blk[%d] call_ea=0x%x"
            " pre_anchor=blk[%d] splice_source=blk[%d]"
            " effective_splice_source=blk[%d]"
            " splice_old_target=blk[%d]"
            " effective_old_target=blk[%d] block_outgoing_edge=blk[%d]"
            " body_source=blk[%d] body_ninsns=%d"
            " bst_only_override=%s body_opcodes=%s",
            call_anchor_serial, call_ea,
            pre_anchor_serial, splice_source,
            int(effective_splice_source),
            splice_old_target,
            int(effective_old_target), outbound_target,
            pre_anchor_serial, len(body),
            "yes" if bst_only_override_applied else "no",
            list(body_opcodes),
        )
        logger.info(
            "HCC_CALL_BARRIER_CHAINED_ACCEPTED handler=blk[%d]"
            " call_ea=0x%x\n"
            "  pre_anchor=blk[%d]  splice_source=blk[%d]"
            "  splice_old_target=blk[%d]\n"
            "  insert_block: pred=blk[%d] succ=blk[%d] body=copy(%d)"
            " ninsns=%d\n"
            "  outbound: %s",
            call_anchor_serial, call_ea,
            pre_anchor_serial, splice_source, splice_old_target,
            int(effective_splice_source), call_anchor_serial,
            pre_anchor_serial, len(body),
            outbound_text,
        )
        return emitted

    def _classify_chained_splice_source(
        self,
        *,
        mba: object,
        splice_source: int,
        splice_old_target: int,
        call_anchor_serial: int,
        outbound_target: int,
        local_facts: DagLocalFacts | None,
        prior_modifications: tuple,
        bst_node_blocks: frozenset[int] = frozenset(),
        dispatcher_serial: int = -1,
    ) -> tuple[str, dict]:
        """Classify ``splice_source`` liveness post HCC batch.

        Per uee-b7ze covered-source-aware emission: a chained
        ``InsertBlock`` is only worth emitting when ``splice_source``
        will still have a live, non-dispatcher predecessor AFTER the
        same HCC batch's region collapse + tail extension + call-barrier
        rewrites.  When the splice source's only inbound came from the
        dispatcher (or from a block that gets suppressed by another
        region), the InsertBlock lands on a dead branch and IDA's
        GLBOPT1 reaching-defs proves the chain dead -> the call we
        tried to preserve gets DCE'd anyway.

        Liveness model (first cut, ``DagLocalFacts``-driven):
          * a pred ``P`` is *surviving* iff ``P`` is itself a DAG
            region entry (``P in local_facts.owned_blocks_by_entry``)
            -- HCC's batch links into entries, never suppresses them.
          * a pred ``P`` is *suppressed* iff ``P`` is an inner owned
            block of exactly one region whose entry is not ``P``
            (the entry's emission collapses inner blocks into its
            own linearized body, breaking ``P``'s outbound).
          * any other pred (dispatcher, BST routing node, unmapped
            utility block) is NOT counted as surviving -- those go
            away under the dispatcher elimination this batch performs.

        Returns one of:
          * ``("LIVE_SOURCE", info)`` -- at least one pred is
            surviving.  Allow emission.
          * ``("COVERED_BY_REGION", info)`` -- no surviving preds, but
            ``splice_source`` is itself an inner block of exactly one
            DAG region (the unique covering entry is logged).  First
            cut: REJECT and report.
          * ``("COLLISION", info)`` -- multiple covering entries.
          * ``("ORPHANED_NO_COVER", info)`` -- no surviving preds and
            no unique cover for ``splice_source``.

        ``prior_modifications`` is accepted for forward compatibility;
        the live-pred + region-entry approximation is sufficient for
        the v1 reject decision and avoids the chicken-and-egg of
        projecting region/tail mods that have not yet been built when
        ``_apply_call_barrier_segmentation`` runs.
        """
        del prior_modifications, splice_old_target, call_anchor_serial, outbound_target

        if local_facts is None:
            return ("ORPHANED_NO_COVER", {"reason": "no_local_facts"})

        try:
            src_blk = self._safe_get_mblock(mba, splice_source)
        except Exception:
            src_blk = None
        if src_blk is None:
            return ("ORPHANED_NO_COVER", {
                "reason": "splice_source_dead_in_mba",
            })
        try:
            npred = int(src_blk.npred())  # type: ignore[attr-defined]
            live_preds = tuple(
                int(src_blk.pred(i))  # type: ignore[attr-defined]
                for i in range(npred)
            )
        except Exception:
            live_preds = ()

        if not live_preds:
            return ("ORPHANED_NO_COVER", {
                "reason": "splice_source_already_orphan",
            })

        owned_map = local_facts.owned_blocks_by_entry
        # Build a "is in any shared_suffix" lookup so we can distinguish
        # shared-suffix members from genuinely unmapped blocks.
        shared_suffix_blocks: frozenset[int] = frozenset(
            b for blocks in (
                local_facts.shared_suffix_by_entry.values()
            ) for b in blocks
        )
        node_by_block = local_facts.node_by_any_local_block

        surviving: list[int] = []
        suppressed_by: dict[int, int] = {}
        dispatcher_preds: list[int] = []
        bst_node_preds: list[int] = []
        shared_suffix_preds: list[int] = []
        local_dag_preds: list[int] = []  # in node_by_any_local_block but no specific role
        unmapped_preds: list[int] = []
        for p in live_preds:
            p_int = int(p)
            if dispatcher_serial >= 0 and p_int == int(dispatcher_serial):
                dispatcher_preds.append(p_int)
                continue
            if p_int in bst_node_blocks:
                bst_node_preds.append(p_int)
                continue
            if p_int in owned_map:
                # P is a DAG region entry -- HCC keeps it.
                surviving.append(p_int)
                continue
            covers_for_p = tuple(
                int(entry) for entry, owned in owned_map.items()
                if p_int in owned and int(entry) != p_int
            )
            if len(covers_for_p) == 1:
                suppressed_by[p_int] = covers_for_p[0]
                continue
            if len(covers_for_p) > 1:
                # Mark with sentinel -1 to distinguish ambiguous covers.
                suppressed_by[p_int] = -1
                continue
            if p_int in shared_suffix_blocks:
                shared_suffix_preds.append(p_int)
                continue
            if p_int in node_by_block:
                local_dag_preds.append(p_int)
                continue
            unmapped_preds.append(p_int)

        if surviving:
            return ("LIVE_SOURCE", {
                "surviving_preds": surviving,
                "suppressed_preds": suppressed_by,
                "dispatcher_preds": dispatcher_preds,
                "bst_node_preds": bst_node_preds,
                "shared_suffix_preds": shared_suffix_preds,
                "local_dag_preds": local_dag_preds,
                "unmapped_preds": unmapped_preds,
            })

        # No surviving pred.  Check coverage of splice_source itself.
        covers: tuple[int, ...] = tuple(
            int(entry) for entry, owned in owned_map.items()
            if int(splice_source) in owned and int(entry) != int(splice_source)
        )
        common_detail = {
            "live_preds": list(live_preds),
            "suppressed_preds": suppressed_by,
            "dispatcher_preds": dispatcher_preds,
            "bst_node_preds": bst_node_preds,
            "shared_suffix_preds": shared_suffix_preds,
            "local_dag_preds": local_dag_preds,
            "unmapped_preds": unmapped_preds,
        }
        if len(covers) == 0:
            return ("ORPHANED_NO_COVER", {
                "reason": "no_surviving_preds_no_cover",
                **common_detail,
            })
        if len(covers) > 1:
            return ("COLLISION", {
                "reason": "multiple_covers",
                "covers": list(covers),
                **common_detail,
            })
        return ("COVERED_BY_REGION", {
            "reason": "unique_cover_no_surviving_preds",
            "cover_entry": int(covers[0]),
            **common_detail,
        })

    def _find_unique_const_writer_for_stkoff(
        self,
        mba: object,
        target_stkoff: int,
        *,
        state_var_stkoff: int | None = None,
    ) -> int | None:
        """Scan all blocks for ``mov #const, %var[stkoff=target]``.

        Return the unique block serial whose body contains a constant
        m_mov targeting ``target_stkoff``, else ``None``.  Used by the
        recursive body-extension pass: when an InsertBlock body has
        an unresolved stkvar read, find the handler that constant-
        writes that stkvar and prepend its composable body.

        Skips matches on ``state_var_stkoff`` (the state variable
        itself is filtered by capture and shouldn't be chased).
        """
        if (
            state_var_stkoff is not None
            and int(target_stkoff) == int(state_var_stkoff)
        ):
            return None
        try:
            qty = int(getattr(mba, "qty", 0))
        except Exception:
            return None
        writers: list[int] = []
        for serial in range(qty):
            blk = self._safe_get_mblock(mba, serial)
            if blk is None:
                continue
            try:
                cur = blk.head
            except Exception:
                continue
            block_writes_const = False
            while cur is not None:
                try:
                    op = int(cur.opcode)
                    if op == ida_hexrays.m_mov:
                        d = cur.d
                        l = cur.l
                        if (
                            d is not None
                            and int(d.t) == ida_hexrays.mop_S
                            and int(d.s.off) == int(target_stkoff)
                            and l is not None
                            and int(l.t) == ida_hexrays.mop_n
                        ):
                            block_writes_const = True
                            break
                except Exception:
                    pass
                try:
                    cur = cur.next
                except Exception:
                    break
            if block_writes_const:
                writers.append(int(serial))
                if len(writers) > 1:
                    # Multiple distinct const-writers -> not unique;
                    # bail early without scanning the rest.
                    return None
        if len(writers) == 1:
            return writers[0]
        return None

    def _try_retarget_to_guarded_walkback_source(
        self,
        *,
        mba: object,
        body: tuple[InsnSnapshot, ...],
        walkback_result: _WalkBackResult,
        current_splice_source: int,
        current_old_target: int,
        call_anchor_serial: int,
        head_state: int,
        claimed_inbound_sources: set[int],
        bst_node_blocks: frozenset[int],
        dispatcher_serial: int,
    ) -> tuple[int, int, tuple[InsnSnapshot, ...]] | None:
        """Keep a single guard-success writer in CFG instead of copying it.

        The BST-only chained path may discover exactly one upstream writer
        block whose body was prepended to make reaching defs self-contained
        (for the motivating case, blk[109]).  Copying that writer's body into
        a later InsertBlock can make its definitions appear without executing
        the conditional edge that reaches the writer.  When the writer itself
        is a guarded 1-way block reached from a 2-way predecessor, prefer
        splicing from the original writer's outgoing edge and strip the copied
        writer body from the InsertBlock.  This preserves the guard in the
        real CFG and tests semantic equivalence rather than raw call survival.
        """
        chunks = tuple(walkback_result.prepended_chunks)
        if len(chunks) != 1:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " reason=walkback_chunk_count count=%d chunks=%s",
                call_anchor_serial, head_state, len(chunks), chunks,
            )
            return None

        chunk = chunks[0]
        writer_serial = int(chunk.writer_serial)
        if writer_serial == int(current_splice_source):
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_is_current_splice_source",
                call_anchor_serial, head_state, writer_serial,
            )
            return None
        if writer_serial in claimed_inbound_sources:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_already_claimed",
                call_anchor_serial, head_state, writer_serial,
            )
            return None
        if writer_serial in bst_node_blocks or (
            dispatcher_serial >= 0 and writer_serial == int(dispatcher_serial)
        ):
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_is_routing_infrastructure",
                call_anchor_serial, head_state, writer_serial,
            )
            return None

        writer_blk = self._safe_get_mblock(mba, writer_serial)
        if writer_blk is None:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_dead",
                call_anchor_serial, head_state, writer_serial,
            )
            return None

        try:
            writer_nsucc = int(writer_blk.nsucc())  # type: ignore[attr-defined]
            writer_succ = int(writer_blk.succ(0))  # type: ignore[attr-defined]
            writer_npred = int(writer_blk.npred())  # type: ignore[attr-defined]
            writer_preds = tuple(
                int(writer_blk.pred(i))  # type: ignore[attr-defined]
                for i in range(writer_npred)
            )
        except Exception:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_topology_unreadable",
                call_anchor_serial, head_state, writer_serial,
            )
            return None

        if writer_nsucc != 1:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_not_1way nsucc=%d",
                call_anchor_serial, head_state, writer_serial, writer_nsucc,
            )
            return None
        if writer_npred != 1:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=writer_pred_count npred=%d preds=%s",
                call_anchor_serial, head_state, writer_serial,
                writer_npred, writer_preds,
            )
            return None

        guard_pred = int(writer_preds[0])
        guard_blk = self._safe_get_mblock(mba, guard_pred)
        try:
            guard_nsucc = (
                int(guard_blk.nsucc())  # type: ignore[attr-defined]
                if guard_blk is not None else -1
            )
        except Exception:
            guard_nsucc = -1
        if guard_nsucc != 2:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] guard_pred=blk[%d]"
                " reason=guard_pred_not_2way nsucc=%d",
                call_anchor_serial, head_state, writer_serial,
                guard_pred, guard_nsucc,
            )
            return None

        strip_ninsns = int(chunk.ninsns)
        if strip_ninsns <= 0 or strip_ninsns > len(body):
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=strip_len_invalid"
                " strip_ninsns=%d body_ninsns=%d",
                call_anchor_serial, head_state, writer_serial,
                strip_ninsns, len(body),
            )
            return None
        stripped_body = tuple(body[strip_ninsns:])
        if not stripped_body:
            logger.info(
                "HCC_CHAINED_GUARDED_SOURCE_REJECTED"
                " call_anchor=blk[%d] head_state=0x%08X"
                " writer=blk[%d] reason=empty_body_after_strip",
                call_anchor_serial, head_state, writer_serial,
            )
            return None

        logger.info(
            "HCC_CHAINED_GUARDED_SOURCE_ACCEPTED"
            " call_anchor=blk[%d] head_state=0x%08X"
            " old_splice_source=blk[%d] old_target=blk[%d]"
            " guarded_source=blk[%d] guarded_old_target=blk[%d]"
            " guard_pred=blk[%d] stripped_ninsns=%d"
            " body_ninsns_before=%d body_ninsns_after=%d"
            " target_stkoff=0x%x",
            call_anchor_serial, head_state,
            int(current_splice_source), int(current_old_target),
            writer_serial, writer_succ, guard_pred, strip_ninsns,
            len(body), len(stripped_body), int(chunk.target_stkoff),
        )
        return (writer_serial, writer_succ, stripped_body)

    def _walk_back_extend_body(
        self,
        *,
        mba: object,
        body: tuple,
        state_var_stkoff: int | None,
        splice_source: int,
        max_depth: int = 8,
        return_result: bool = False,
    ) -> tuple | _WalkBackResult:
        """Recursively prepend handler bodies to ``body`` until every
        top-level stkvar read has a local def (or no unique writer
        exists).

        For each iteration:
          1. Compute the set of stkoffs READ at the top level of any
             instruction in ``body`` whose preceding instructions in
             ``body`` do not WRITE that stkoff.
          2. For each unresolved stkoff, locate the unique block whose
             composable body contains a constant m_mov to that stkoff
             via :py:meth:`_find_unique_const_writer_for_stkoff`.
          3. Capture each such writer's composable body and prepend.

        Stops at ``max_depth`` iterations or fixpoint.  Skips writers
        already prepended (preventing infinite walk-backs through
        cyclic state machines).

        Top-level scan only -- nested ``mop_d`` sub-instructions are
        not recursed because IDA's reaching-defs analysis traces
        nested operands through their parent's source registers, which
        the top-level pass already covers.
        """
        body = tuple(body)
        prepended_writers: set[int] = set()
        prepended_chunks: list[_WalkBackChunk] = []
        for iteration in range(max_depth):
            # Compute (written, needed) sets across body.
            written: set[int] = set()
            needed: set[int] = set()
            for snap in body:
                for slot in (
                    getattr(snap, "l", None),
                    getattr(snap, "r", None),
                ):
                    if slot is None:
                        continue
                    try:
                        slot_t = int(getattr(slot, "t", -1))
                    except Exception:
                        slot_t = -1
                    if slot_t != ida_hexrays.mop_S:
                        continue
                    stkoff = getattr(slot, "stkoff", None)
                    if stkoff is None:
                        continue
                    stkoff_int = int(stkoff)
                    if stkoff_int not in written:
                        needed.add(stkoff_int)
                d = getattr(snap, "d", None)
                if d is None:
                    continue
                try:
                    d_t = int(getattr(d, "t", -1))
                except Exception:
                    d_t = -1
                if d_t == ida_hexrays.mop_S:
                    d_off = getattr(d, "stkoff", None)
                    if d_off is not None:
                        written.add(int(d_off))
            if state_var_stkoff is not None:
                needed.discard(int(state_var_stkoff))
            unresolved = needed - written
            if not unresolved:
                break
            # Find unique writer for each unresolved stkoff and
            # prepend each writer's composable body.
            new_prepend: list = []
            iteration_resolved: set[int] = set()
            for target_stkoff in sorted(unresolved):
                writer_serial = self._find_unique_const_writer_for_stkoff(
                    mba, int(target_stkoff),
                    state_var_stkoff=state_var_stkoff,
                )
                if writer_serial is None:
                    continue
                if writer_serial == int(splice_source):
                    # The splice source itself dominates the InsertBlock
                    # naturally; no need to re-include its body.
                    continue
                if writer_serial in prepended_writers:
                    continue
                writer_blk = self._safe_get_mblock(mba, writer_serial)
                if writer_blk is None:
                    continue
                try:
                    cap = self._capture_block_composable_instructions_v2(
                        writer_blk, state_var_stkoff=state_var_stkoff,
                    )
                except Exception:
                    continue
                if cap.kind != "composable":
                    continue
                snaps = tuple(cap.snapshots or ())
                if not snaps:
                    continue
                prepended_writers.add(writer_serial)
                iteration_resolved.add(int(target_stkoff))
                new_prepend.extend(snaps)
                prepended_chunks.append(_WalkBackChunk(
                    writer_serial=int(writer_serial),
                    target_stkoff=int(target_stkoff),
                    ninsns=len(snaps),
                ))
                logger.info(
                    "HCC_CHAINED_BST_ONLY_BODY_RECURSIVE_PREPEND"
                    " writer=blk[%d] target_stkoff=0x%x ninsns=%d"
                    " iteration=%d",
                    writer_serial, target_stkoff, len(snaps), iteration,
                )
            if not new_prepend:
                # Nothing to add this iteration -> fixpoint.
                logger.info(
                    "HCC_CHAINED_BST_ONLY_BODY_RECURSIVE_FIXPOINT"
                    " unresolved=%s prepended_writers=%s iteration=%d",
                    sorted(unresolved), sorted(prepended_writers), iteration,
                )
                break
            body = tuple(new_prepend) + body
        if return_result:
            return _WalkBackResult(
                body=body,
                prepended_chunks=tuple(prepended_chunks),
            )
        return body

    def _classify_corridor_block(
        self,
        block_serial: int,
        *,
        local_facts: DagLocalFacts | None,
        bst_node_blocks: frozenset[int],
        dispatcher_serial: int,
    ) -> tuple[str, dict]:
        """Return ``(kind, info)`` for a single corridor block.

        ``kind`` is one of ``DISPATCHER`` / ``BST_NODE`` /
        ``REGION_ENTRY`` / ``REGION_INNER`` / ``SHARED_SUFFIX`` /
        ``LOCAL_DAG_NODE`` / ``UNMAPPED``.

        Info field carries role-specific metadata (e.g. owning entry
        for ``REGION_INNER``, state_const for ``LOCAL_DAG_NODE``).
        """
        b = int(block_serial)
        info: dict = {}
        if dispatcher_serial >= 0 and b == int(dispatcher_serial):
            return ("DISPATCHER", info)
        if b in bst_node_blocks:
            return ("BST_NODE", info)
        if local_facts is None:
            return ("UNMAPPED", info)
        owned_map = local_facts.owned_blocks_by_entry
        if b in owned_map:
            return ("REGION_ENTRY", {"entry": b})
        covers = tuple(
            int(entry) for entry, owned in owned_map.items()
            if b in owned and int(entry) != b
        )
        if len(covers) >= 1:
            return ("REGION_INNER", {"covers": list(covers)})
        for entry, suffix_blocks in (
            local_facts.shared_suffix_by_entry.items()
        ):
            if b in suffix_blocks:
                info = {"suffix_of_entry": int(entry)}
                return ("SHARED_SUFFIX", info)
        node = local_facts.node_by_any_local_block.get(b)
        if node is not None:
            state_const = getattr(node.key, "state_const", None)
            entry_anchor = int(getattr(node, "entry_anchor", -1))
            return ("LOCAL_DAG_NODE", {
                "state_const": (
                    int(state_const) & 0xFFFFFFFF
                    if state_const is not None else None
                ),
                "entry_anchor": entry_anchor,
            })
        return ("UNMAPPED", info)

    def _dump_splice_source_corridor(
        self,
        *,
        mba: object,
        splice_source: int,
        local_facts: DagLocalFacts | None,
        bst_node_blocks: frozenset[int],
        dispatcher_serial: int,
        max_depth: int = 8,
    ) -> dict:
        """BFS backward from ``splice_source`` up to ``max_depth`` and
        return a structured corridor dump.

        Distinguishes whether unmapped predecessors are real BST
        infrastructure (reject is correct) vs missed local blocks
        (recon coverage gap, fix is upstream not in HCC).
        """
        out: dict = {
            "splice_source": int(splice_source),
            "max_depth": int(max_depth),
            "blocks": [],
            "nearest_mapped_pred": None,
        }

        # Compute reachable set from entry once for the run.
        reachable_from_entry: set[int] = set()
        try:
            qty = int(getattr(mba, "qty", 0))
        except Exception:
            qty = 0
        worklist: list[int] = [0] if qty > 0 else []
        while worklist and len(reachable_from_entry) < qty + 4:
            cur = worklist.pop()
            if cur in reachable_from_entry:
                continue
            reachable_from_entry.add(cur)
            cur_blk = self._safe_get_mblock(mba, cur)
            if cur_blk is None:
                continue
            try:
                nsucc = int(cur_blk.nsucc())  # type: ignore[attr-defined]
                for i in range(nsucc):
                    worklist.append(int(cur_blk.succ(i)))  # type: ignore[attr-defined]
            except Exception:
                continue

        # BFS backward from splice_source.
        seen: set[int] = set()
        frontier: list[tuple[int, int]] = [(int(splice_source), 0)]
        nearest_mapped: int | None = None
        while frontier:
            block_serial, depth = frontier.pop(0)
            if block_serial in seen:
                continue
            seen.add(block_serial)
            blk = self._safe_get_mblock(mba, block_serial)
            if blk is None:
                out["blocks"].append({
                    "serial": block_serial,
                    "depth": depth,
                    "kind": "DEAD",
                })
                continue
            try:
                blk_type = int(blk.type)
                npred = int(blk.npred())
                nsucc = int(blk.nsucc())
                preds = tuple(int(blk.pred(i)) for i in range(npred))
                succs = tuple(int(blk.succ(i)) for i in range(nsucc))
                tail_op = int(blk.tail.opcode) if blk.tail is not None else -1
                tail_target = (
                    int(blk.tail.d.b)
                    if (blk.tail is not None
                        and getattr(blk.tail, "d", None) is not None
                        and getattr(blk.tail.d, "t", -1)
                        == ida_hexrays.mop_b)
                    else -1
                )
            except Exception:
                blk_type = -1
                preds = ()
                succs = ()
                tail_op = -1
                tail_target = -1

            kind, kind_info = self._classify_corridor_block(
                block_serial,
                local_facts=local_facts,
                bst_node_blocks=bst_node_blocks,
                dispatcher_serial=dispatcher_serial,
            )

            if (
                nearest_mapped is None
                and depth > 0
                and kind in (
                    "REGION_ENTRY",
                    "LOCAL_DAG_NODE",
                    "SHARED_SUFFIX",
                )
            ):
                nearest_mapped = block_serial

            entry_dist = (
                "REACHABLE" if block_serial in reachable_from_entry
                else "UNREACHABLE"
            )

            out["blocks"].append({
                "serial": block_serial,
                "depth": depth,
                "kind": kind,
                "kind_info": kind_info,
                "type": blk_type,
                "preds": list(preds),
                "succs": list(succs),
                "tail_op": tail_op,
                "tail_target": tail_target,
                "entry_reach": entry_dist,
            })

            if depth < max_depth:
                for p in preds:
                    if p not in seen:
                        frontier.append((p, depth + 1))

        out["nearest_mapped_pred"] = nearest_mapped
        return out

    def _resolve_semantic_predecessor_for_bst_only_source(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        local_facts: DagLocalFacts | None,
        splice_source: int,
        splice_old_target: int,
        call_anchor_serial: int,
        bst_node_blocks: frozenset[int],
        dispatcher_serial: int,
        claimed_inbound_sources: set[int],
        bst_result: object | None = None,
        state_var_stkoff: int | None = None,
        region_claimed_sources: frozenset[int] = frozenset(),
    ) -> tuple[int | None, dict]:
        """Resolve the SEMANTIC predecessor exit for a BST-only physical
        ``splice_source`` (uee-b7ze).

        When CoveredSourceResolution rejected ``splice_source`` because
        every live pred is BST/dispatcher routing, the chained emit
        cannot anchor to ``splice_source`` (its predecessors are killed
        by HCC's batch).  But recon's DAG still knows the *semantic*
        predecessor: whichever handler exit writes the state value
        whose dispatcher route lands at ``splice_source``.

        First-cut policy:
          * Look up the state node whose ``entry_anchor`` ==
            ``splice_source``.  If no such node exists in
            ``DagLocalFacts``, reject (``NO_TARGET_NODE``).
          * Find inbound TRANSITION edges into that node (skip
            CONDITIONAL_TRANSITION for v1 to keep the gate strict).
          * For each edge, candidate semantic source = either the
            deepest non-BST/non-dispatcher block on
            ``edge.ordered_path`` whose live ``succ(0)`` is the
            dispatcher (the "real" handler exit), else
            ``edge.source_anchor.block_serial``.
          * Validate per candidate:
              - exists in MBA
              - not BST node, not dispatcher
              - nsucc == 1
              - succ(0) is the dispatcher (matches the "stale
                dispatcher route" guard)
              - reachable from entry blk[0]
              - not already claimed by a prior HCC accept
          * Accept iff exactly ONE candidate validates; otherwise
            reject (zero -> ``NO_VALID_CANDIDATE``; multiple distinct
            -> ``MULTIPLE_VALID_CANDIDATES``).

        Returns ``(semantic_pred | None, info_dict)``.  When accepted,
        ``info_dict["new_old_target"]`` carries the dispatcher serial
        (the live ``succ(0)`` of the chosen pred), used as the
        ``old_target_serial`` field of the InsertBlock so the backend's
        stale-target guard succeeds.
        """
        del splice_old_target, call_anchor_serial  # unused in v1

        info: dict = {"phase": "init"}

        # --- 1. Resolve target state node(s) whose ``entry_anchor`` ==
        # ``splice_source``.  In OLLVM range-backed handler topology
        # multiple states can share an entry_anchor (one per state in
        # the range); collect every matching node and union their
        # inbound edges so we don't miss the real semantic predecessor.
        target_nodes: list = []
        target_states: list[int] = []
        try:
            for node in dag.nodes:
                if int(getattr(node, "entry_anchor", -1)) == int(splice_source):
                    target_nodes.append(node)
                    sc = getattr(node.key, "state_const", None)
                    if sc is not None:
                        target_states.append(int(sc) & 0xFFFFFFFF)
        except Exception:
            target_nodes = []
        if not target_nodes:
            return (None, {
                "reason": "NO_TARGET_NODE",
                "splice_source": int(splice_source),
            })
        info["target_state_count"] = len(target_nodes)
        info["target_state_consts"] = target_states
        target_keys = frozenset(node.key for node in target_nodes)
        target_entry_anchors = frozenset({int(splice_source)})
        target_state_set = frozenset(target_states) if target_states else frozenset()

        # --- 2. Find inbound edges into any matching target_node.
        # Edge identity in the recon DAG can use any of three handles
        # (target_key / target_entry_anchor / target_state); match on
        # the union to avoid missing edges when the DAG was built or
        # overridden via a different identity.  Include both TRANSITION
        # and CONDITIONAL_TRANSITION: in OLLVM topology genuine
        # state-writing edges are usually TRANSITION but conditional
        # arms can produce CONDITIONAL_TRANSITION.
        def _edge_targets_us(edge) -> bool:
            try:
                if edge.target_key in target_keys:
                    return True
                tea = getattr(edge, "target_entry_anchor", None)
                if tea is not None and int(tea) in target_entry_anchors:
                    return True
                ts = getattr(edge, "target_state", None)
                if (
                    ts is not None
                    and target_state_set
                    and (int(ts) & 0xFFFFFFFF) in target_state_set
                ):
                    return True
            except Exception:
                pass
            return False

        try:
            all_inbound_edges = tuple(
                edge for edge in dag.edges if _edge_targets_us(edge)
            )
        except Exception:
            all_inbound_edges = ()
        try:
            inbound_state_edges = tuple(
                edge for edge in all_inbound_edges
                if edge.kind in (
                    SemanticEdgeKind.TRANSITION,
                    SemanticEdgeKind.CONDITIONAL_TRANSITION,
                )
            )
        except Exception:
            inbound_state_edges = ()
        info["inbound_total_count"] = len(all_inbound_edges)
        info["inbound_state_edge_count"] = len(inbound_state_edges)
        info["inbound_kind_dist"] = {
            kind.name: sum(
                1 for e in all_inbound_edges if e.kind == kind
            )
            for kind in SemanticEdgeKind
        }
        # --- 2b. BST-table fallback.  Recon's range-backed handler
        # nodes do NOT receive a per-state-value TRANSITION edge for
        # every writer in the range -- the DAG abstracts the range
        # into a single node keyed at one state value.  When the DAG
        # path yields zero edges (or too-few) and we have a
        # ``bst_result``, scan the live MBA for state-var writes
        # whose constant routes to ``splice_source`` per
        # ``resolve_target_via_bst``.  Each such writer is a
        # candidate semantic predecessor.  The validation pass below
        # is identical to the DAG path.
        bst_table_candidates: list[dict] = []
        if (
            not inbound_state_edges
            and bst_result is not None
            and state_var_stkoff is not None
        ):
            try:
                from d810.recon.flow.bst_model import (
                    resolve_target_via_bst as _resolve_bst,
                )
            except Exception:
                _resolve_bst = None
            if _resolve_bst is not None:
                try:
                    qty = int(getattr(mba, "qty", 0))
                except Exception:
                    qty = 0
                state_stkoff = int(state_var_stkoff)
                scanned_writers = 0
                for serial in range(qty):
                    blk = self._safe_get_mblock(mba, serial)
                    if blk is None:
                        continue
                    try:
                        cur = blk.head
                    except Exception:
                        cur = None
                    while cur is not None:
                        try:
                            opcode = int(cur.opcode)
                            if opcode != ida_hexrays.m_mov:
                                cur = cur.next
                                continue
                            d = cur.d
                            l = cur.l
                            if (
                                d is None
                                or int(d.t) != ida_hexrays.mop_S
                                or l is None
                                or int(l.t) != ida_hexrays.mop_n
                            ):
                                cur = cur.next
                                continue
                            try:
                                d_off = int(d.s.off)
                            except Exception:
                                cur = cur.next
                                continue
                            if d_off != state_stkoff:
                                cur = cur.next
                                continue
                            try:
                                const_val = int(l.nnn.value) & 0xFFFFFFFF
                            except Exception:
                                cur = cur.next
                                continue
                            scanned_writers += 1
                            try:
                                routed_to = _resolve_bst(
                                    bst_result, const_val,
                                )
                            except Exception:
                                routed_to = None
                            if (
                                routed_to is not None
                                and int(routed_to) == int(splice_source)
                            ):
                                bst_table_candidates.append({
                                    "serial": int(serial),
                                    "via": "bst_table_scan",
                                    "edge_anchor_serial": -1,
                                    "ordered_path": [int(serial)],
                                    "written_state": int(const_val),
                                })
                        except Exception:
                            pass
                        try:
                            cur = cur.next
                        except Exception:
                            break
                info["bst_table_scanned_writers"] = scanned_writers
                info["bst_table_candidate_count"] = (
                    len(bst_table_candidates)
                )

        if not inbound_state_edges and not bst_table_candidates:
            return (None, {
                **info,
                "reason": (
                    "NO_INBOUND_TRANSITION"
                    if not all_inbound_edges
                    else "NO_INBOUND_STATE_EDGE"
                ),
            })

        # --- 3. Score candidates.  For each edge, derive a candidate
        # semantic source exit by walking ``ordered_path`` from deepest
        # block backward until a non-BST, non-dispatcher block is found
        # whose live ``succ(0)`` is the dispatcher.  Fall back to
        # ``edge.source_anchor.block_serial``.
        candidates: list[dict] = []
        seen_serials: set[int] = set()
        # Seed with BST-table candidates first so the audit log shows
        # the BST-derived predecessors before any DAG-edge ones.
        for c in bst_table_candidates:
            cs = int(c["serial"])
            if cs in seen_serials:
                continue
            seen_serials.add(cs)
            candidates.append(c)
        for edge in inbound_state_edges:
            anchor = getattr(edge, "source_anchor", None)
            anchor_serial = int(getattr(anchor, "block_serial", -1)) if anchor is not None else -1
            ordered_path = tuple(int(p) for p in (edge.ordered_path or ()))
            picked_serial: int | None = None
            picked_via: str | None = None
            # Walk ordered_path right-to-left; pick first block that is
            # not BST/dispatcher and whose live succ(0) is dispatcher.
            for blk_serial in reversed(ordered_path):
                if blk_serial == int(dispatcher_serial):
                    continue
                if blk_serial in bst_node_blocks:
                    continue
                blk = self._safe_get_mblock(mba, blk_serial)
                if blk is None:
                    continue
                try:
                    nsucc = int(blk.nsucc())
                    succ0 = int(blk.succ(0)) if nsucc >= 1 else -1
                except Exception:
                    nsucc = -1
                    succ0 = -1
                if nsucc != 1:
                    continue
                if succ0 != int(dispatcher_serial):
                    continue
                picked_serial = int(blk_serial)
                picked_via = "ordered_path_walk"
                break
            if picked_serial is None and anchor_serial >= 0:
                # Fallback: use edge.source_anchor.block_serial directly,
                # but still subject it to the validation pass below.
                picked_serial = anchor_serial
                picked_via = "source_anchor"
            if picked_serial is None:
                continue
            if picked_serial in seen_serials:
                continue
            seen_serials.add(picked_serial)
            candidates.append({
                "serial": int(picked_serial),
                "via": picked_via,
                "edge_anchor_serial": anchor_serial,
                "ordered_path": list(ordered_path),
            })

        if not candidates:
            return (None, {
                **info,
                "reason": "NO_CANDIDATE_FROM_EDGES",
                "edges": len(inbound_state_edges),
            })

        # Log every candidate before validating so a rejected case has
        # a full audit trail.
        for c in candidates:
            logger.info(
                "HCC_CHAINED_SEMANTIC_PREDECESSOR_CANDIDATE"
                " splice_source=blk[%d] candidate=blk[%d] via=%s"
                " edge_anchor=blk[%d] ordered_path=%s",
                int(splice_source), int(c["serial"]), c["via"],
                int(c["edge_anchor_serial"]), c["ordered_path"],
            )

        # --- 4. Validate per candidate.
        valid: list[dict] = []
        rejections: list[dict] = []
        for c in candidates:
            cs = int(c["serial"])
            blk = self._safe_get_mblock(mba, cs)
            if blk is None:
                rejections.append({**c, "rej": "block_dead"})
                continue
            if cs in bst_node_blocks:
                rejections.append({**c, "rej": "is_bst_node"})
                continue
            if cs == int(dispatcher_serial):
                rejections.append({**c, "rej": "is_dispatcher"})
                continue
            try:
                nsucc = int(blk.nsucc())
                succ0 = int(blk.succ(0)) if nsucc >= 1 else -1
            except Exception:
                rejections.append({**c, "rej": "succ_unreadable"})
                continue
            if nsucc != 1:
                rejections.append({**c, "rej": f"nsucc={nsucc}"})
                continue
            if succ0 != int(dispatcher_serial):
                rejections.append({
                    **c, "rej": f"succ0={succ0}_not_dispatcher",
                })
                continue
            if cs in claimed_inbound_sources:
                rejections.append({**c, "rej": "already_claimed"})
                continue
            # SEMANTIC_SOURCE_COVERED: candidate is already the
            # ``splice_source_block`` of another raw region in this
            # plan().  HCC's region-collapse will redirect it to that
            # region's target; emitting our chained InsertBlock from
            # the same source would produce a 2-way successor on a
            # 1-way block (CFG_50856 / CFG_50860).  Reject here per
            # the user's first-cut "covered, reject" policy.
            if cs in region_claimed_sources:
                rejections.append({**c, "rej": "SEMANTIC_SOURCE_COVERED"})
                continue

            # Reachability from entry blk[0].  Bounded BFS.
            try:
                qty = int(getattr(mba, "qty", 0))
            except Exception:
                qty = 0
            reach: set[int] = set()
            wl: list[int] = [0] if qty > 0 else []
            while wl and len(reach) < qty + 4:
                cur = wl.pop()
                if cur in reach:
                    continue
                reach.add(cur)
                if cur == cs:
                    break
                cur_blk = self._safe_get_mblock(mba, cur)
                if cur_blk is None:
                    continue
                try:
                    cn = int(cur_blk.nsucc())
                    for i in range(cn):
                        wl.append(int(cur_blk.succ(i)))
                except Exception:
                    pass
            if cs not in reach:
                rejections.append({**c, "rej": "unreachable_from_entry"})
                continue

            # Optional: cover-by-region check.  If splice_source is
            # owned (as inner) by a region that's also being lowered,
            # SEMANTIC_SOURCE_COVERED.  First cut: skip this; the
            # claimed_inbound_sources check above handles the immediate
            # tail-extension/SIMPLE collision.

            valid.append({
                **c,
                "live_succ0": int(succ0),
            })

        info["candidates"] = candidates
        info["rejections"] = rejections
        info["valid"] = valid
        if not valid:
            return (None, {**info, "reason": "NO_VALID_CANDIDATE"})
        if len(valid) > 1:
            return (None, {**info, "reason": "MULTIPLE_VALID_CANDIDATES"})

        chosen = valid[0]
        return (int(chosen["serial"]), {
            **info,
            "reason": "ACCEPTED",
            "chosen": chosen,
            # The InsertBlock's old_target must match the chosen pred's
            # current succ(0) so the backend's stale-target guard passes.
            "new_old_target": int(chosen["live_succ0"]),
        })

    def _apply_fusable_local_convergence_fusion(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        local_facts: DagLocalFacts,
        raw_region_table: tuple[_RawRegionInfo, ...],
        state_var_stkoff: int | None,
    ) -> tuple[list[HandlerChainCandidate], set[int]]:
        """**EXPERIMENTAL ONLY** -- atomically lower FUSABLE_LOCAL_CONVERGENCE.

        Per-pred body cloning of a multi-pred local convergence is
        **SSA-hostile** -- the cloned ``mov %var_X.{N}, ...`` references
        a value version that was joined at the original convergence and
        is no longer well-defined in either clone.  IDA's GLBOPT
        subsequently DCEs the resulting island.  This mode is retained
        for **experimental evidence only** and MUST NOT be treated as a
        viable fallback architecture.  The intended replacement for
        multi-pred local convergence shapes is ``FUSABLE_TAIL_EXTENSION``
        (preserve the join, redirect only the semantic exit).

        For each ``info`` whose convergence-aware classification is
        ``FUSABLE_LOCAL_CONVERGENCE``: compose the cover (R1) + info
        (R2) body once, then emit ONE ``HandlerChainCandidate`` per
        incoming edge in the convergence plan.  Atomic: if any per-pred
        emission would conflict with an already-claimed edge in this
        round, REJECT the entire candidate.

        Returns a pair ``(per_pred_candidates, consumed_info_ids)``:
        ``consumed_info_ids`` is the set of ``id(_RawRegionInfo)`` that
        the linear-fusion pass should skip and the default per-region
        pass should NOT compose individually.
        """
        per_pred: list[HandlerChainCandidate] = []
        consumed_ids: set[int] = set()
        # Edges already claimed in this round by previously-accepted
        # convergence candidates (keyed by (pred, old_target)).
        claimed: set[tuple[int, int]] = set()
        for info in raw_region_table:
            label, plan = _classify_convergence_or_linear(
                self_info=info,
                raw_region_table=raw_region_table,
                dag=dag,
                local_facts=local_facts,
                mba=mba,
            )
            if label != "FUSABLE_LOCAL_CONVERGENCE":
                continue
            if plan is None:  # defensive
                continue
            if not isinstance(plan, _ConvergencePlan):  # defensive
                continue
            covers = _find_cover_regions(
                self_info=info, raw_region_table=raw_region_table,
            )
            if len(covers) != 1:
                continue
            cover = covers[0]
            if id(cover) in consumed_ids or id(info) in consumed_ids:
                continue
            cov_state = int(cover.candidate.head_state) & 0xFFFFFFFF
            self_state = int(info.candidate.head_state) & 0xFFFFFFFF
            cov_handlers = tuple(int(n.entry_anchor) for n in cover.region_nodes)
            self_handlers = tuple(int(n.entry_anchor) for n in info.region_nodes)
            handlers_label = cov_handlers + self_handlers

            # Atomicity precheck: every (pred, old_target) edge must
            # be unclaimed.  If ANY conflicts, reject the whole set.
            edges_to_claim: list[tuple[int, int]] = []
            for incoming in plan.incoming_edges:
                key = (int(incoming.pred), int(incoming.old_target))
                if key in claimed:
                    edges_to_claim = []
                    break
                edges_to_claim.append(key)
            if not edges_to_claim:
                logger.info(
                    "HCC_CONVERGENCE_FUSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " handlers=%s reason=pred_edge_already_claimed",
                    cov_state, self_state, handlers_label,
                )
                continue

            # Compose the body once: R1 nodes + R2 nodes.  If
            # composition fails, reject atomically.
            fused_nodes = tuple(cover.region_nodes) + tuple(info.region_nodes)
            try:
                fused_candidate = self._compose_region(
                    mba=mba,
                    dag=dag,
                    region_nodes=fused_nodes,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception as exc:  # pragma: no cover - diagnostic only
                logger.warning(
                    "HCC_CONVERGENCE_FUSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " handlers=%s reason=compose-raised: %s",
                    cov_state, self_state, handlers_label, exc,
                )
                continue
            if fused_candidate is None:
                logger.info(
                    "HCC_CONVERGENCE_FUSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " handlers=%s reason=compose-returned-None",
                    cov_state, self_state, handlers_label,
                )
                continue

            # All checks passed.  Emit one HandlerChainCandidate per
            # incoming edge.  The `succ_serial` is taken from the
            # composed candidate (= R2's exit successor), which is
            # the post-convergence continuation block.
            succ_serial = int(fused_candidate.succ_serial)
            body = fused_candidate.composed_instructions
            states = fused_candidate.state_values
            for incoming in plan.incoming_edges:
                per_pred.append(
                    HandlerChainCandidate(
                        handler_serials=tuple(handlers_label),
                        pred_serial=int(incoming.pred),
                        succ_serial=succ_serial,
                        composed_instructions=body,
                        state_values=states,
                    )
                )
                claimed.add(
                    (int(incoming.pred), int(incoming.old_target))
                )
            consumed_ids.add(id(cover))
            consumed_ids.add(id(info))
            # Render the per-pred edge list for the log line.
            edge_strs = [
                f"pred=blk[{int(e.pred)}] kind={e.kind}"
                f" old_target={int(e.old_target)}"
                for e in plan.incoming_edges
            ]
            logger.info(
                "HCC_CONVERGENCE_FUSION_ACCEPTED head_states=(0x%08X, 0x%08X)"
                " handlers=%s succ=%d\n"
                "  convergence=blk[%d]\n"
                "  incoming=[%s]",
                cov_state, self_state, handlers_label, succ_serial,
                int(plan.convergence_block),
                ", ".join(edge_strs),
            )

        logger.info(
            "HCC_CONVERGENCE_FUSION_SUMMARY accepted_groups=%d"
            " emitted_candidates=%d consumed_infos=%d",
            len(consumed_ids) // 2,
            len(per_pred),
            len(consumed_ids),
        )
        return per_pred, consumed_ids

    def _apply_fusable_linear_fusion(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        regions: list[tuple[StateDagNode, ...]],
        raw_region_table: tuple[_RawRegionInfo, ...],
        state_var_stkoff: int | None,
        convergence_consumed_ids: set[int] | None = None,
    ) -> list[tuple[StateDagNode, ...]]:
        """Build the post-fusion composition input list.

        For each FUSABLE_LINEAR ``self_info``: locate its sole cover
        region ``cover``, build a fused ``region_nodes`` tuple
        ``cover.region_nodes + self_info.region_nodes``, attempt
        ``_compose_region`` on the fused tuple, and -- only if
        composition succeeds -- mark both originals consumed and append
        the fused tuple to the output.  On composition failure, the
        original ``cover`` and ``self_info`` regions stay in the output.

        ``convergence_consumed_ids`` (when non-None) carries the set of
        ``id(_RawRegionInfo)`` already claimed by FUSABLE_LOCAL_CONVERGENCE.
        Such infos are skipped here AND excluded from the output, since
        the convergence path will emit per-pred ``InsertBlock``s in
        their place.
        """
        # Map info -> position in raw_region_table for stable iteration.
        index_by_info: dict[int, int] = {
            id(info): idx for idx, info in enumerate(raw_region_table)
        }
        # Build classification for every YES_HANDLERS entry.
        sub_by_info: dict[int, str | None] = {}
        for info in raw_region_table:
            label, reasons = _classify_source_covered_by_other_region(
                self_info=info, raw_region_table=raw_region_table,
            )
            if "YES_HANDLERS" in reasons:
                try:
                    sub = _classify_yes_handlers_subclass(
                        self_info=info, raw_region_table=raw_region_table,
                    )
                except Exception:  # pragma: no cover - diagnostic only
                    sub = None
                sub_by_info[id(info)] = sub
            else:
                sub_by_info[id(info)] = None

        consumed: set[int] = set()
        if convergence_consumed_ids:
            consumed.update(convergence_consumed_ids)
        fused_pairs: list[tuple[_RawRegionInfo, _RawRegionInfo]] = []
        # Track physical pred edges already claimed by fused pairs in
        # this round.  If two FUSABLE_LINEAR candidates would emit
        # against the same (pred, old_target) edge, only the first
        # wins; the second is rejected as CONFLICT.
        claimed_pred_edges: set[tuple[int, int]] = set()
        # Process FUSABLE_LINEAR candidates in the original raw_region_table
        # order so log output is deterministic.
        for info in raw_region_table:
            if sub_by_info.get(id(info)) != "FUSABLE_LINEAR":
                continue
            if id(info) in consumed:
                continue
            covers = _find_cover_regions(
                self_info=info, raw_region_table=raw_region_table,
            )
            if len(covers) != 1:
                continue
            cover = covers[0]
            if id(cover) in consumed:
                continue
            # Defense-in-depth: revalidate cover composes today.  If
            # something invalidated it between classification and now,
            # skip the fusion attempt.
            if cover.composed_candidate is None:
                continue
            # Reject if this fused emission would collide with another
            # already-fused pair on the same physical pred edge.  The
            # cover's pre-composed candidate carries the authoritative
            # ``pred_serial`` and ``handler_serials[0]`` (= old_target);
            # those are the same values the fused candidate will use.
            cov_pred = int(cover.composed_candidate.pred_serial)
            cov_old_target = int(cover.composed_candidate.handler_serials[0])
            cov_state = int(cover.candidate.head_state) & 0xFFFFFFFF
            self_state = int(info.candidate.head_state) & 0xFFFFFFFF
            if (cov_pred, cov_old_target) in claimed_pred_edges:
                logger.info(
                    "HCC_FUSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " reason=pred_edge_already_claimed pred=%d"
                    " old_target=%d",
                    cov_state, self_state, cov_pred, cov_old_target,
                )
                continue
            # Compose the fused region BEFORE marking consumed.  On
            # composition success, mark both consumed; on failure, both
            # stay available for the regular per-region pass.
            fused_nodes: tuple[StateDagNode, ...] = tuple(
                cover.region_nodes
            ) + tuple(info.region_nodes)
            fused_handlers = tuple(int(n.entry_anchor) for n in fused_nodes)
            try:
                fused_candidate = self._compose_region(
                    mba=mba,
                    dag=dag,
                    region_nodes=fused_nodes,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception as exc:  # pragma: no cover - diagnostic only
                logger.warning(
                    "HCC_FUSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " handlers=%s reason=compose-raised: %s",
                    cov_state, self_state, fused_handlers, exc,
                )
                continue
            if fused_candidate is None:
                logger.info(
                    "HCC_FUSION_REJECTED head_states=(0x%08X, 0x%08X)"
                    " handlers=%s reason=compose-returned-None",
                    cov_state, self_state, fused_handlers,
                )
                continue
            # Composition succeeded.  Reserve the fused pair and mark
            # both originals consumed.
            consumed.add(id(cover))
            consumed.add(id(info))
            fused_pairs.append((cover, info))
            claimed_pred_edges.add((cov_pred, cov_old_target))
            logger.info(
                "HCC_FUSION_ACCEPTED head_states=(0x%08X, 0x%08X)"
                " handlers=%s pred=%d succ=%d",
                cov_state, self_state, fused_handlers,
                fused_candidate.pred_serial, fused_candidate.succ_serial,
            )

        # Compose the final input list in raw_region_table order: each
        # consumed cover is replaced by its fused tuple at the cover's
        # index; consumed self_info entries are skipped.  Infos already
        # consumed by FUSABLE_LOCAL_CONVERGENCE are also skipped -- the
        # convergence path will emit per-pred InsertBlocks for them.
        consumed_self_ids: set[int] = {id(info) for _, info in fused_pairs}
        consumed_cover_ids: set[int] = {id(cov) for cov, _ in fused_pairs}
        convergence_ids: set[int] = (
            set(convergence_consumed_ids)
            if convergence_consumed_ids
            else set()
        )
        fused_by_cover_id: dict[int, tuple[StateDagNode, ...]] = {
            id(cov): tuple(cov.region_nodes) + tuple(info.region_nodes)
            for cov, info in fused_pairs
        }

        output: list[tuple[StateDagNode, ...]] = []
        for info in raw_region_table:
            if id(info) in consumed_self_ids:
                continue
            if id(info) in convergence_ids:
                continue
            if id(info) in consumed_cover_ids:
                output.append(fused_by_cover_id[id(info)])
                continue
            output.append(info.region_nodes)
        # Preserve any regions that were not represented in the
        # raw_region_table (defensive: regions list and raw_region_table
        # are built from the same source, so this should be empty).
        if len(raw_region_table) != len(regions):  # pragma: no cover
            logger.warning(
                "HandlerChainComposer: raw_region_table count=%d differs"
                " from regions count=%d; falling back to raw regions",
                len(raw_region_table), len(regions),
            )
            return list(regions)
        logger.info(
            "HCC_FUSION_SUMMARY fused_pairs=%d fusable_linear_classified=%d"
            " consumed=%d output_regions=%d",
            len(fused_pairs),
            sum(
                1
                for v in sub_by_info.values()
                if v == "FUSABLE_LINEAR"
            ),
            len(consumed),
            len(output),
        )
        return output

    def _build_raw_region_table(
        self,
        *,
        mba: object,
        dag: LinearizedStateDag,
        regions: list[tuple[StateDagNode, ...]],
        state_var_stkoff: int | None = None,
        local_facts: DagLocalFacts | None = None,
    ) -> tuple[_RawRegionInfo, ...]:
        """Build per-region observation records for the pre-compose log pass.

        For each raw region, compute every field needed to emit a log line
        without depending on ``_compose_region``'s success.  ``_resolve_first_pred``
        and ``_resolve_region_exit`` are best-effort here -- failures
        produce ``None`` fields rather than aborting collection.

        Additionally, speculatively run ``_compose_region`` on every
        region and stash the result on ``_RawRegionInfo.composed_candidate``.
        ``_compose_region`` is purely observational at this stage (it
        only builds an immutable dataclass; it does not emit
        modifications), so calling it speculatively is safe regardless
        of whether the region is later kept, fused, or dropped.  The
        ``_classify_yes_handlers_subclass`` rule consults
        ``composed_candidate`` to decide whether a covering region is
        usable as the front half of a FUSABLE_LINEAR pair.
        """
        infos: list[_RawRegionInfo] = []
        for region_nodes in regions:
            if not region_nodes:
                continue
            head_node = region_nodes[0]
            tail_node = region_nodes[-1]
            head_anchor = int(head_node.entry_anchor)
            tail_anchor = int(tail_node.entry_anchor)
            region_anchors_set = {int(n.entry_anchor) for n in region_nodes}
            region_anchors = frozenset(region_anchors_set)

            # Best-effort physical-pred probe.
            old_physical_pred: int | None = None
            head_blk = self._safe_get_mblock(mba, head_anchor)
            if head_blk is not None:
                try:
                    old_physical_pred = self._resolve_first_pred(
                        mba=mba,
                        blk=head_blk,
                        region_anchors=region_anchors_set,
                        first_anchor=head_anchor,
                    )
                except Exception:
                    old_physical_pred = None

            # Best-effort exit probe.
            proposed_exit: int | None = None
            try:
                proposed_exit = self._resolve_region_exit(
                    mba=mba, dag=dag, last_node=tail_node,
                )
            except Exception:
                proposed_exit = None

            # Always-on candidate resolution.
            try:
                candidate = _resolve_semantic_entry_candidate(
                    dag=dag,
                    region_head_node=head_node,
                    region_anchors=region_anchors,
                    mba=mba,
                )
            except Exception as exc:  # pragma: no cover - diagnostic
                logger.warning(
                    "HandlerChainComposer: semantic entry resolution failed"
                    " for region head=%d: %s",
                    head_anchor,
                    exc,
                )
                head_state = int(getattr(head_node.key, "state_const", 0) or 0)
                candidate = SemanticEntryCandidate(
                    head_state=head_state,
                    head_entry=head_anchor,
                    splice_source_block=None,
                    splice_old_target=None,
                    transition_source_blocks=(),
                    nontransition_source_blocks=(),
                    eligibility=EntryEligibility.NO_TRANSITION_INCOMING,
                    reason=f"resolver raised: {exc}",
                )

            # Speculative compose: run the regular composer once per
            # region.  Returns ``None`` when the region is not
            # compose-viable (no usable pred, no exit, forbidden
            # opcodes, etc.).  The result is observational; the actual
            # emission happens later via the same routine.
            composed_candidate: HandlerChainCandidate | None
            try:
                composed_candidate = self._compose_region(
                    mba=mba,
                    dag=dag,
                    region_nodes=region_nodes,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception as exc:  # pragma: no cover - diagnostic
                logger.warning(
                    "HandlerChainComposer: speculative compose raised"
                    " for region head=%d: %s",
                    head_anchor,
                    exc,
                )
                composed_candidate = None

            # uee-b7ze Step 2: detect opaque-call anchors.  Walk every
            # region anchor block; if exactly one block returns
            # ``opaque_call_anchor``, record (block_serial, call_ea,
            # is_indirect) on the _RawRegionInfo.  Multi-anchor regions
            # with calls aren't supported in Phase B (Phase A only
            # records the first detected anchor for diagnostics).
            opaque_call_anchor: tuple[int, int, bool] | None = None
            opaque_call_pre_count: int | None = None
            opaque_call_post_count: int | None = None
            opaque_call_shape: str | None = None
            for node in region_nodes:
                anchor_serial = int(node.entry_anchor)
                anchor_blk = self._safe_get_mblock(mba, anchor_serial)
                if anchor_blk is None:
                    continue
                try:
                    cap_result = self._capture_block_composable_instructions_v2(
                        anchor_blk, state_var_stkoff=state_var_stkoff,
                    )
                except Exception:  # pragma: no cover - diagnostic
                    continue
                if cap_result.kind != "opaque_call_anchor":
                    continue
                if opaque_call_anchor is not None:
                    # Multi-anchor region with two opaque-call anchors:
                    # not supported in Phase B.  Discard this region's
                    # candidacy; Phase A logs both via per-block dump
                    # but the _RawRegionInfo records only the first.
                    opaque_call_shape = "OTHER"
                    break
                opaque_call_anchor = (
                    anchor_serial,
                    int(cap_result.call_ea or 0),
                    bool(cap_result.is_indirect),
                )
                opaque_call_pre_count = int(cap_result.pre_call_count or 0)
                opaque_call_post_count = int(cap_result.post_call_count or 0)

            # Compute opaque_call_shape if we found exactly one anchor
            # and shape was not already overridden to OTHER above.  We
            # FIRST run the legacy classifier (which preserves the
            # SIMPLE_1WAY_OUT lock-down semantics), then refine OTHER
            # via :func:`_refine_opaque_call_shape` into the Step 2.1
            # taxonomy (CHAINED_CALL_ANCHOR / SHARED_SUFFIX_CALL_ANCHOR
            # / ANCHOR_OUT_BRANCH / ANCHOR_MULTI_PRED).
            if opaque_call_anchor is not None and opaque_call_shape is None:
                base_shape = self._classify_opaque_call_shape(
                    mba=mba,
                    dag=dag,
                    handler_serial=opaque_call_anchor[0],
                    candidate=candidate,
                    region_nodes=region_nodes,
                )
                try:
                    opaque_call_shape = _refine_opaque_call_shape(
                        base_shape=base_shape,
                        region_nodes=region_nodes,
                        opaque_call_anchor=opaque_call_anchor,
                        dag=dag,
                        local_facts=local_facts,
                        mba=mba,
                        state_var_stkoff=state_var_stkoff,
                    )
                except Exception:  # pragma: no cover - diagnostic only
                    opaque_call_shape = base_shape

            infos.append(
                _RawRegionInfo(
                    region_nodes=region_nodes,
                    head_node=head_node,
                    tail_node=tail_node,
                    head_anchor=head_anchor,
                    tail_anchor=tail_anchor,
                    region_anchors=region_anchors,
                    old_physical_pred=old_physical_pred,
                    proposed_exit=proposed_exit,
                    candidate=candidate,
                    composed_candidate=composed_candidate,
                    opaque_call_anchor=opaque_call_anchor,
                    opaque_call_pre_count=opaque_call_pre_count,
                    opaque_call_post_count=opaque_call_post_count,
                    opaque_call_shape=opaque_call_shape,
                )
            )
        return tuple(infos)

    @staticmethod
    def _classify_opaque_call_shape(
        *,
        mba: object,
        dag: LinearizedStateDag,
        handler_serial: int,
        candidate: SemanticEntryCandidate,
        region_nodes: tuple[StateDagNode, ...],
    ) -> str:
        """Classify an opaque-call anchor as ``SIMPLE_1WAY_OUT`` or ``OTHER``.

        ``SIMPLE_1WAY_OUT`` requires:
          * the handler block is exactly 1-way (``nsucc()==1``),
          * its sole TRANSITION incoming edge is ``UNCONDITIONAL_1WAY``,
          * the region contains exactly one anchor (singleton region) so
            the call body is not entangled with neighbouring handlers,
          * the DAG has exactly ONE outgoing TRANSITION edge from the
            handler's state node.

        Anything else falls into ``OTHER``.
        """
        # 1) singleton region.
        if len(region_nodes) != 1:
            return "OTHER"
        # 2) handler is 1-way.
        handler_blk = HandlerChainComposerStrategy._safe_get_mblock(
            mba, handler_serial,
        )
        if handler_blk is None:
            return "OTHER"
        try:
            if int(handler_blk.nsucc()) != 1:  # type: ignore[attr-defined]
                return "OTHER"
        except Exception:
            return "OTHER"
        # 3) sole TRANSITION inbound is UNCONDITIONAL_1WAY.
        if candidate.eligibility is not EntryEligibility.UNCONDITIONAL_1WAY:
            return "OTHER"
        # 4) DAG has exactly one outgoing TRANSITION (no
        #    conditional/branching) from this handler's state.
        outgoing_transitions = 0
        outgoing_conditionals = 0
        head_node = region_nodes[0]
        for edge in dag.edges:
            if edge.source_key != head_node.key:
                continue
            if edge.kind is SemanticEdgeKind.TRANSITION:
                outgoing_transitions += 1
            else:
                outgoing_conditionals += 1
        if outgoing_transitions != 1 or outgoing_conditionals != 0:
            return "OTHER"
        return "SIMPLE_1WAY_OUT"

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
    def _resolve_local_facts(
        snapshot: "AnalysisSnapshot",
        dag: LinearizedStateDag,
    ) -> DagLocalFacts:
        """Return the typed DAG-local facts bundle for ``dag``.

        Prefers ``snapshot.discovery.local_facts`` (the canonical Phase-3
        bundle published by ``build_round_discovery_context``).  Falls
        back to building it on demand via :func:`_build_dag_local_facts`
        when the snapshot did not publish one (defensive: keeps HCC
        functional even when invoked outside the recon round publisher).
        """
        discovery = getattr(snapshot, "discovery", None)
        if discovery is not None:
            facts = getattr(discovery, "local_facts", None)
            if isinstance(facts, DagLocalFacts):
                return facts
        return _build_dag_local_facts(dag)

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

        region_anchors_set = {int(n.entry_anchor) for n in region_nodes}
        pred_serial = self._resolve_first_pred(
            mba=mba,
            blk=first_blk,
            region_anchors=region_anchors_set,
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

        # NOTE: REGION_LOWERING_CANDIDATE logging now happens in the
        # pre-compose pass driven from ``detect_chains`` (uee-b7ze A0).
        # Every raw region produces a log line there regardless of whether
        # this composition path succeeds.

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
        """Walk ``blk.head`` and capture composable instructions, or None.

        Legacy interface (preserves prior behavior): treats ANY opcode in
        ``_FORBIDDEN_COMPOSITION_OPCODES`` (including m_call/m_icall) as a
        composition refusal.  Phase A's call-barrier candidate
        classification uses :py:meth:`_capture_block_composable_instructions_v2`
        directly to distinguish closing-forbidden vs call-forbidden cases.
        """
        result = (
            HandlerChainComposerStrategy._capture_block_composable_instructions_v2(
                blk, state_var_stkoff=state_var_stkoff,
            )
        )
        if result.kind == "composable":
            return list(result.snapshots) if result.snapshots else []
        # Legacy callers: opaque-call anchors and closing aborts both
        # become None ("region not compose-viable").
        return None

    @staticmethod
    def _capture_block_composable_instructions_v2(
        blk: object,
        *,
        state_var_stkoff: int | None = None,
    ) -> _CaptureResult:
        """Walk ``blk.head`` and classify the block (uee-b7ze Step 2).

        Returns a :class:`_CaptureResult` distinguishing:
          * ``"composable"``: every instruction is whitelisted; the
            captured snapshots are returned in ``snapshots``.
          * ``"closing_abort"``: a closing-forbidden opcode (m_ret,
            m_jtbl, m_ijmp, m_ext) or jcond was hit, OR snapshot capture
            failed for an instruction.  ``abort_reason`` describes why.
          * ``"opaque_call_anchor"``: exactly ONE m_call/m_icall present;
            ``call_ea``, ``is_indirect``, ``pre_call_count``, and
            ``post_call_count`` populated.  If the call appears more
            than once, returns ``closing_abort`` (multi-call anchors
            aren't supported in Phase B).

        Side-effecting note: the v2 capture does NOT short-circuit on
        the first call.  It walks the entire block so that we can count
        pre- and post-call composable instructions, and so multi-call
        anchors degrade gracefully to ``closing_abort``.
        """
        try:
            insn = blk.head  # type: ignore[attr-defined]
        except Exception:
            return _CaptureResult(
                kind="closing_abort",
                abort_reason="blk_head_unreadable",
            )
        snapshots: list[InsnSnapshot] = []
        call_eas: list[tuple[int, bool]] = []  # (ea, is_indirect)
        pre_call_count = 0
        post_call_count = 0
        seen_call = False
        while insn is not None:
            try:
                opcode = int(insn.opcode)
            except Exception:
                return _CaptureResult(
                    kind="closing_abort",
                    abort_reason="opcode_unreadable",
                )
            if opcode in (ida_hexrays.m_goto, ida_hexrays.m_nop):
                insn = insn.next
                continue
            # Closing-forbidden opcodes: never become call anchors.
            if opcode in _CLOSING_FORBIDDEN:
                return _CaptureResult(
                    kind="closing_abort",
                    abort_reason=f"closing_forbidden_opcode={opcode}",
                )
            try:
                if ida_hexrays.is_mcode_jcond(opcode):
                    return _CaptureResult(
                        kind="closing_abort",
                        abort_reason=f"jcond_opcode={opcode}",
                    )
            except Exception:
                return _CaptureResult(
                    kind="closing_abort",
                    abort_reason="jcond_check_raised",
                )
            # Side-effecting calls: record the EA but do not capture a
            # snapshot for them (the call body stays in the original
            # block; Phase B never copies it elsewhere).
            if opcode in _CALL_FORBIDDEN:
                try:
                    call_ea = int(getattr(insn, "ea", 0))
                except Exception:
                    call_ea = 0
                is_indirect = opcode == ida_hexrays.m_icall
                call_eas.append((call_ea, is_indirect))
                seen_call = True
                insn = insn.next
                continue
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
                return _CaptureResult(
                    kind="closing_abort",
                    abort_reason="capture_snapshot_failed",
                )
            snapshots.append(snap)
            if seen_call:
                post_call_count += 1
            else:
                pre_call_count += 1
            insn = insn.next
        if not call_eas:
            return _CaptureResult(
                kind="composable",
                snapshots=tuple(snapshots),
            )
        if len(call_eas) > 1:
            return _CaptureResult(
                kind="closing_abort",
                abort_reason=f"multi_call_anchor_count={len(call_eas)}",
            )
        call_ea, is_indirect = call_eas[0]
        return _CaptureResult(
            kind="opaque_call_anchor",
            snapshots=None,
            call_ea=call_ea,
            is_indirect=is_indirect,
            pre_call_count=pre_call_count,
            post_call_count=post_call_count,
        )
