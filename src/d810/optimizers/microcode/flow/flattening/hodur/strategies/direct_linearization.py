"""DirectHandlerLinearizationStrategy — core BST-based linearization.

Faithful port of HodurUnflattener._linearize_handlers (first pass only) from
commit 4313af46.  Iterates all detected state machine handlers, runs DFS forward
evaluation to find handler exit paths and their final state values, then proposes
GOTO_REDIRECT / EDGE_REDIRECT / NOP_INSN edits that bypass the dispatcher entirely.
"""
from __future__ import annotations

import enum
from collections import deque
from dataclasses import dataclass

import ida_hexrays
from d810.core.typing import TYPE_CHECKING

from d810.core import logging
from d810.cfg.flow.graph_checks import prove_terminal_sink
from d810.recon.flow.bst_analysis import (
    find_bst_default_block_snapshot,
)
from d810.recon.flow.bst_model import resolve_target_via_bst
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    collect_state_machine_blocks,
    detect_conditional_transitions,
    evaluate_handler_paths,
    find_terminal_exit_target_snapshot,
    resolve_exit_via_bst_default_snapshot,
)
from d810.cfg.graph_modification import RedirectBranch
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    CarrierResolutionResult,
    HandlerPathResult,
    ResolutionMethod,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.transition_builder import (
    _get_state_var_stkoff,
)
from d810.cfg.flow.terminal_return import (
    TerminalCfgSuffixFrontier,
    TerminalSemanticLoweringFrontier,
    TerminalLoweringAction,
    classify_cfg_suffix_action,
    compute_terminal_cfg_suffix_frontier,
)

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.direct_linearization")

__all__ = [
    "CarrierBucket",
    "CarrierSourceKind",
    "CorridorRecommendation",
    "CorridorShape",
    "DirectHandlerLinearizationStrategy",
    "ForwardFrontierEntry",
    "SharedCorridorInfo",
    "SuffixGroupDecision",
    "_classify_carrier_bucket",
    "_classify_carrier_source",
    "_compute_suffix_group_decision",
    "_discover_shared_corridor",
]

# Minimum number of unique normalized anchors (handler body exits redirected
# to the shared epilogue entry) required before Phase 2 suffix privatization
# is emitted.  hodur_func has 3 anchors (benign convergence — IDA structures
# fine), sub_7FFD has 10 (severe fan-in that needs privatization).
_MIN_TERMINAL_ANCHORS_FOR_PRIVATIZATION = 4


class CarrierSourceKind(str, enum.Enum):
    """Classify what the forward-frontier candidate block carries."""

    STATE_CONST = "state_const"
    """Block writes a dispatcher state constant (dead after linearization)."""

    REAL_CONST = "real_const"
    """Block writes a concrete return value (e.g. literal integer)."""

    CURSOR_OR_PTR = "cursor_or_ptr"
    """Block writes a pointer/cursor value."""

    EXPR = "expr"
    """Block writes a computed expression."""

    UNKNOWN = "unknown"
    """Cannot classify the carried value."""


@dataclass(frozen=True)
class ForwardFrontierEntry:
    """Per-handler-entry forward ownership frontier diagnostic record.

    Attributes:
        handler_entry: Handler entry block serial.
        terminal_path: Ordered block serials from the DFS path.
        forward_candidate: Last non-infra block before hitting infrastructure
            (None if the path starts immediately in infra).
        candidate_succ: First infra block hit (None if no infra on path).
        shared_entry: Shared entry serial from the CFG frontier (None if
            no CFG frontier was computed).
        return_block: Return block serial from the CFG frontier.
        suffix_serials: Suffix block serials from the CFG frontier.
        semantic_action: Recommended lowering action from the semantic frontier.
        carrier_source_kind: Classification of the candidate's carried value.
        proof_status: ``"resolved"`` if candidate passes all validation gates,
            ``"unresolved"`` otherwise.
        notes: Free-form diagnostic notes.
    """

    handler_entry: int
    terminal_path: tuple[int, ...]
    forward_candidate: int | None
    candidate_succ: int | None
    shared_entry: int | None
    return_block: int | None
    suffix_serials: tuple[int, ...]
    semantic_action: TerminalLoweringAction
    carrier_source_kind: CarrierSourceKind
    proof_status: str
    notes: str = ""
    state_const_written: int | None = None
    requires_dtl: bool = False


class CorridorShape(str, enum.Enum):
    """Shape classification of shared terminal corridor."""

    LINEAR = "linear"
    """Each block: 1 succ, no fan-in from outside corridor."""

    FAN_IN = "fan_in"
    """1 succ but multi pred from handlers."""

    BRANCHING = "branching"
    """Multi succ within corridor."""

    COMPLEX = "complex"
    """Both fan-in and branching."""


class CorridorRecommendation(str, enum.Enum):
    """Recommended semantic action for a shared corridor group."""

    PRIVATE_RETURN_BLOCK = "private_return_block"
    PRIVATE_TERMINAL_SUFFIX = "private_terminal_suffix"
    PRIVATE_TERMINAL_CORRIDOR = "private_terminal_corridor"
    DIRECT_TERMINAL_LOWERING = "direct_terminal_lowering"
    UNRESOLVED = "unresolved"


class CarrierBucket(str, enum.Enum):
    """Semantic bucket for a suffix group's carrier profile."""

    BENIGN_SHARED_SUFFIX = "benign_shared_suffix"
    """All real_const — no PTS needed."""

    SUFFIX_AMBIGUOUS = "suffix_ambiguous"
    """Has unknown/expr/cursor_or_ptr (no state_const) — PTS candidate."""

    NEEDS_DIRECT_LOWERING = "needs_direct_lowering"
    """Has state_const — dispatcher semantic leak, not PTS."""


def _classify_carrier_bucket(carrier_kinds: tuple[str, ...]) -> CarrierBucket:
    """Classify carrier profile into a semantic bucket.

    Rules:
    - Any state_const → NEEDS_DIRECT_LOWERING (dispatcher leak)
    - Any unknown/expr/cursor_or_ptr (no state_const) → SUFFIX_AMBIGUOUS
    - All real_const → BENIGN_SHARED_SUFFIX
    """
    kinds_set = set(carrier_kinds)

    # state_const is the only carrier that definitively needs direct lowering
    if CarrierSourceKind.STATE_CONST.value in kinds_set:
        return CarrierBucket.NEEDS_DIRECT_LOWERING

    # Check for ambiguous carriers (unknown, expr, cursor_or_ptr)
    ambiguous_kinds = {
        CarrierSourceKind.UNKNOWN.value,
        CarrierSourceKind.EXPR.value,
        CarrierSourceKind.CURSOR_OR_PTR.value,
    }
    if kinds_set & ambiguous_kinds:
        return CarrierBucket.SUFFIX_AMBIGUOUS

    # All remaining (real_const only) → benign
    return CarrierBucket.BENIGN_SHARED_SUFFIX


@dataclass(frozen=True)
class SharedCorridorInfo:
    """Diagnostic info for a shared terminal corridor group."""

    shared_entry: int
    return_block: int
    suffix_serials: tuple[int, ...]
    corridor_blocks: tuple[int, ...]
    corridor_shape: CorridorShape
    corridor_length: int
    handler_entries: tuple[int, ...]
    handler_count: int
    entry_fan_in: int
    carrier_in_corridor: bool
    clonable: bool
    recommendation: CorridorRecommendation
    notes: str


@dataclass(frozen=True)
class SuffixGroupDecision:
    """Per-suffix-group PTS applicability decision."""

    shared_entry: int
    return_block: int
    suffix_serials: tuple[int, ...]
    handler_entries: tuple[int, ...]
    handler_count: int
    carrier_source_kinds: tuple[str, ...]  # distinct CarrierSourceKind values
    has_state_const_carrier: bool
    carrier_bucket: CarrierBucket
    proof_resolved_count: int
    proof_unresolved_count: int
    corridor_length: int
    clonable: bool
    should_emit: bool
    rejection_reasons: tuple[str, ...]  # why should_emit=False, empty if True
    dtl_anchor_serials: tuple[int, ...] = ()


def _compute_suffix_group_decision(
    forward_entries: list[ForwardFrontierEntry],
    corridor_info: SharedCorridorInfo,
    semantic_action: TerminalLoweringAction,
) -> SuffixGroupDecision:
    """Compute PTS applicability decision for a suffix group.

    Aggregates per-handler-entry forward frontier data and corridor info
    to produce a single decision record.  This is DIAGNOSTIC ONLY -- no
    mutations are performed.

    Args:
        forward_entries: Forward frontier entries from per-handler analysis.
        corridor_info: Shared corridor diagnostic info.
        semantic_action: The semantic lowering action for this group.

    Returns:
        A :class:`SuffixGroupDecision` with the aggregated decision.
    """
    # Collect handler entries.
    handler_entries = tuple(sorted({e.handler_entry for e in forward_entries}))
    handler_count = len(handler_entries)

    # Collect distinct carrier source kinds.
    carrier_kinds = tuple(sorted({e.carrier_source_kind.value for e in forward_entries}))
    has_state_const = any(
        e.carrier_source_kind == CarrierSourceKind.STATE_CONST
        for e in forward_entries
    )

    # Count proof statuses.
    proof_resolved = sum(1 for e in forward_entries if e.proof_status == "resolved")
    proof_unresolved = sum(1 for e in forward_entries if e.proof_status == "unresolved")

    # Classify carrier bucket.
    carrier_bucket = _classify_carrier_bucket(carrier_kinds)

    # Determine should_emit using carrier bucket predicate.
    rejection_reasons: list[str] = []

    if semantic_action != TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX:
        rejection_reasons.append(
            "semantic_action=%s (need PRIVATE_TERMINAL_SUFFIX)" % semantic_action.value
        )
    if not corridor_info.clonable:
        rejection_reasons.append("corridor not clonable")
    if handler_count < 2:
        rejection_reasons.append("handler_count=%d < 2" % handler_count)
    if proof_resolved > 0:
        rejection_reasons.append(
            "proof_resolved=%d > 0 (some already resolved)" % proof_resolved
        )
    if carrier_bucket == CarrierBucket.BENIGN_SHARED_SUFFIX:
        rejection_reasons.append("carrier_bucket=benign_shared_suffix (all real_const, structurally adequate)")
    if carrier_bucket == CarrierBucket.NEEDS_DIRECT_LOWERING:
        rejection_reasons.append("carrier_bucket=needs_direct_lowering (has state_const — dispatcher semantic leak)")

    should_emit = len(rejection_reasons) == 0

    # Collect per-anchor DTL candidates: anchors that leak known state constants.
    dtl_anchors = tuple(sorted(
        e.handler_entry for e in forward_entries if e.requires_dtl
    ))

    return SuffixGroupDecision(
        shared_entry=corridor_info.shared_entry,
        return_block=corridor_info.return_block,
        suffix_serials=corridor_info.suffix_serials,
        handler_entries=handler_entries,
        handler_count=handler_count,
        carrier_source_kinds=carrier_kinds,
        has_state_const_carrier=has_state_const,
        carrier_bucket=carrier_bucket,
        proof_resolved_count=proof_resolved,
        proof_unresolved_count=proof_unresolved,
        corridor_length=corridor_info.corridor_length,
        clonable=corridor_info.clonable,
        should_emit=should_emit,
        rejection_reasons=tuple(rejection_reasons),
        dtl_anchor_serials=dtl_anchors,
    )


def _discover_shared_corridor(
    fg: "FlowGraph",
    shared_entry_serial: int,
    suffix_serials: tuple[int, ...],
    full_infra: frozenset[int],
    forward_entries: list[ForwardFrontierEntry],
) -> SharedCorridorInfo:
    """Discover and classify the shared terminal corridor.

    Walks forward from ``shared_entry_serial`` through single-successor
    blocks that are NOT suffix blocks and NOT full infrastructure, collecting
    them as the corridor chain.  Then classifies the corridor shape, checks
    clonability, and recommends a semantic action.

    This is DIAGNOSTIC ONLY -- no mutations are performed.

    Args:
        fg: Flow graph snapshot.
        shared_entry_serial: First block of the shared region.
        suffix_serials: Suffix block serials from the CFG frontier.
        full_infra: Full infrastructure block set (BST + dispatcher + suffix +
            pre-header).
        forward_entries: Forward frontier entries from per-handler analysis.

    Returns:
        A :class:`SharedCorridorInfo` with corridor diagnostic data.
    """
    suffix_set = frozenset(suffix_serials)

    # Collect handler entries and return block from forward entries.
    handler_entries_list: list[int] = []
    return_block = 0
    for entry in forward_entries:
        handler_entries_list.append(entry.handler_entry)
        if entry.return_block is not None:
            return_block = entry.return_block
    handler_entries_tuple = tuple(sorted(set(handler_entries_list)))

    # Walk forward from shared_entry to discover corridor blocks.
    # Corridor = contiguous chain from shared_entry through blocks that are
    # NOT in suffix_serials and NOT the return_block, following single
    # successors.
    corridor: list[int] = []
    if shared_entry_serial not in suffix_set:
        current = shared_entry_serial
        visited: set[int] = set()
        while current not in suffix_set and current not in visited:
            visited.add(current)
            corridor.append(current)
            succs = fg.successors(current)
            if len(succs) != 1:
                break  # branching or terminal -- stop walk
            nxt = succs[0]
            if nxt in suffix_set or nxt == return_block:
                break  # reached suffix
            current = nxt
    # else: shared_entry IS a suffix serial -- corridor is empty (degenerate PTS)

    corridor_tuple = tuple(corridor)
    corridor_length = len(corridor_tuple)

    # Classify corridor shape.
    has_branching = False
    has_fan_in = False
    corridor_set = frozenset(corridor_tuple)

    for blk_serial in corridor_tuple:
        blk_snap = fg.get_block(blk_serial)
        if blk_snap is None:
            continue
        # Branching: >1 successor
        if blk_snap.nsucc > 1:
            has_branching = True
        # Fan-in: >1 predecessor from outside corridor
        outside_preds = [
            p for p in blk_snap.preds if p not in corridor_set
        ]
        if len(outside_preds) > 1:
            has_fan_in = True

    if has_branching and has_fan_in:
        corridor_shape = CorridorShape.COMPLEX
    elif has_branching:
        corridor_shape = CorridorShape.BRANCHING
    elif has_fan_in:
        corridor_shape = CorridorShape.FAN_IN
    else:
        corridor_shape = CorridorShape.LINEAR

    # Entry fan-in: count distinct predecessors of corridor entry from handlers.
    entry_fan_in = 0
    if corridor_tuple:
        entry_snap = fg.get_block(corridor_tuple[0])
        if entry_snap is not None:
            entry_fan_in = len([
                p for p in entry_snap.preds if p not in corridor_set
            ])

    # Carrier in corridor: check if any corridor block has non-trivial
    # instructions (beyond just control flow).
    _CONTROL_FLOW_OPCODES = frozenset({
        ida_hexrays.m_goto,
        ida_hexrays.m_jnz,
        ida_hexrays.m_ijmp,
        ida_hexrays.m_jtbl,
    })
    carrier_in_corridor = False
    for blk_serial in corridor_tuple:
        blk_snap = fg.get_block(blk_serial)
        if blk_snap is None:
            continue
        for insn in blk_snap.iter_insns():
            if insn.opcode not in _CONTROL_FLOW_OPCODES:
                carrier_in_corridor = True
                break
        if carrier_in_corridor:
            break

    # Clonability check.
    handler_count = len(handler_entries_tuple)
    clonable = (
        corridor_shape in (CorridorShape.LINEAR, CorridorShape.FAN_IN)
        and corridor_length <= 8
        and handler_count >= 2
    )

    # Recommendation.
    notes_parts: list[str] = []
    if handler_count < 2:
        recommendation = CorridorRecommendation.UNRESOLVED
        notes_parts.append("handler_count < 2")
    elif corridor_shape in (CorridorShape.BRANCHING, CorridorShape.COMPLEX):
        recommendation = CorridorRecommendation.UNRESOLVED
        notes_parts.append("corridor has branching/complex shape")
    elif corridor_length == 0:
        recommendation = CorridorRecommendation.PRIVATE_TERMINAL_SUFFIX
        notes_parts.append("degenerate corridor (length=0)")
    elif clonable:
        recommendation = CorridorRecommendation.PRIVATE_TERMINAL_CORRIDOR
        notes_parts.append(
            "corridor clonable (len=%d, shape=%s)"
            % (corridor_length, corridor_shape.value)
        )
    else:
        recommendation = CorridorRecommendation.UNRESOLVED
        notes_parts.append("corridor not clonable")

    return SharedCorridorInfo(
        shared_entry=shared_entry_serial,
        return_block=return_block,
        suffix_serials=suffix_serials,
        corridor_blocks=corridor_tuple,
        corridor_shape=corridor_shape,
        corridor_length=corridor_length,
        handler_entries=handler_entries_tuple,
        handler_count=handler_count,
        entry_fan_in=entry_fan_in,
        carrier_in_corridor=carrier_in_corridor,
        clonable=clonable,
        recommendation=recommendation,
        notes="; ".join(notes_parts) if notes_parts else "",
    )


def _extract_const_from_snapshot_mop(mop_snap: object) -> int | None:
    """Extract a numeric constant from a snapshot mop (CfgMopSnapshot or rich MopSnapshot).

    Handles both the lightweight CfgMopSnapshot (has .value directly) and the
    rich MopSnapshot from hexrays/ir/mop_snapshot.py (has .nnn.value proxy).

    Returns:
        The integer constant if the mop is mop_n and carries a value, else None.
    """
    if mop_snap is None:
        return None
    src_t = getattr(mop_snap, "t", None)
    if src_t != ida_hexrays.mop_n:
        return None
    # Rich MopSnapshot: .nnn.value proxy
    nnn = getattr(mop_snap, "nnn", None)
    if nnn is not None:
        val = getattr(nnn, "value", None)
        if val is not None:
            return int(val)
    # Lightweight CfgMopSnapshot: .value directly
    val = getattr(mop_snap, "value", None)
    if val is not None:
        return int(val)
    return None


def _resolve_indirect_state_write_via_mba(
    mba: object,
    candidate_serial: int,
    state_var_stkoff: int,
) -> CarrierResolutionResult | None:
    """Resolve indirect state variable writes using live MBA backward scan.

    For OLLVM patterns like ``v15 = 0x41FB8FBB; i = v15``, the snapshot sees
    ``m_mov state_var, v15`` (mop_r/mop_S source, not mop_n).  This function
    walks the live block backward to find the ``m_mov`` that writes to the
    state variable, then uses ``find_def_in_block`` to resolve the source
    operand to its defining instruction.

    Args:
        mba: Live ``ida_hexrays.mba_t`` object.
        candidate_serial: Block serial to inspect.
        state_var_stkoff: Stack offset of the state variable.

    Returns:
        A :class:`CarrierResolutionResult` with the resolved constant and
        def location, or ``None`` if resolution fails.
    """
    try:
        from d810.evaluator.hexrays_microcode.def_search import find_def_in_block
    except ImportError:
        return None

    try:
        live_blk = mba.get_mblock(candidate_serial)
    except Exception:
        return None
    if live_blk is None:
        return None

    # Walk backward through the live block to find the state variable write.
    cur_ins = live_blk.tail
    while cur_ins is not None:
        if cur_ins.opcode == ida_hexrays.m_mov and cur_ins.d is not None:
            # Check if destination is the state variable (mop_S with matching stkoff)
            if (
                cur_ins.d.t == ida_hexrays.mop_S
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == state_var_stkoff
            ):
                source_mop = cur_ins.l
                if source_mop is None:
                    break
                # If source is already a constant, return it directly.
                if source_mop.t == ida_hexrays.mop_n:
                    nnn = source_mop.nnn
                    if nnn is not None:
                        return CarrierResolutionResult(
                            kind=CarrierSourceKind.STATE_CONST.value,
                            const_value=int(nnn.value),
                            method=ResolutionMethod.MBA_DEF_SEARCH,
                            def_blk_serial=None,
                            def_insn_ea=None,
                            source_mop_type=int(source_mop.t),
                        )
                    break
                # Source is register or stack var — resolve backward.
                if source_mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
                    break
                def_ins = find_def_in_block(source_mop, live_blk, cur_ins)
                if def_ins is None:
                    # Fallback: cross-block predecessor walk for two-step pattern
                    # e.g. blk[194]: m_mov #0x41FB8FBB → %var_70
                    #      blk[195]: m_mov %var_70     → %var_7BC (state)
                    _pred_blk = live_blk
                    for _depth in range(3):
                        _npred = _pred_blk.npred()
                        if _npred != 1:
                            break
                        _pred_serial = _pred_blk.pred(0)
                        try:
                            _pred_blk = mba.get_mblock(_pred_serial)
                        except Exception:
                            break
                        if _pred_blk is None:
                            break
                        _scan = _pred_blk.tail
                        while _scan is not None:
                            if (
                                _scan.opcode == ida_hexrays.m_mov
                                and _scan.d is not None
                                and _scan.d.t == source_mop.t
                            ):
                                _dest_matches = False
                                if source_mop.t == ida_hexrays.mop_S:
                                    try:
                                        _dest_matches = _scan.d.s.off == source_mop.s.off
                                    except Exception:
                                        pass
                                elif source_mop.t == ida_hexrays.mop_r:
                                    try:
                                        _dest_matches = _scan.d.r == source_mop.r
                                    except Exception:
                                        pass
                                if _dest_matches and _scan.l is not None and _scan.l.t == ida_hexrays.mop_n:
                                    def_ins = _scan
                                    live_blk = _pred_blk
                                    break
                            _scan = _scan.prev
                        if def_ins is not None:
                            break
                if def_ins is None:
                    break
                # The defining instruction should be m_mov with mop_n source.
                if (
                    def_ins.opcode == ida_hexrays.m_mov
                    and def_ins.l is not None
                    and def_ins.l.t == ida_hexrays.mop_n
                ):
                    nnn = def_ins.l.nnn
                    if nnn is not None:
                        # Capture source operand identity for diagnostics.
                        src_stkoff: int | None = None
                        src_mreg: int | None = None
                        if source_mop.t == ida_hexrays.mop_S:
                            try:
                                src_stkoff = source_mop.s.off
                            except Exception:
                                pass
                        elif source_mop.t == ida_hexrays.mop_r:
                            try:
                                src_mreg = int(source_mop.r)
                            except Exception:
                                pass
                        return CarrierResolutionResult(
                            kind=CarrierSourceKind.STATE_CONST.value,
                            const_value=int(nnn.value),
                            method=ResolutionMethod.MBA_DEF_SEARCH,
                            def_blk_serial=live_blk.serial,
                            def_insn_ea=def_ins.ea,
                            source_mop_type=int(source_mop.t),
                            source_stkoff=src_stkoff,
                            source_mreg=src_mreg,
                        )
                break
        cur_ins = cur_ins.prev
    return None


def _resolve_state_const_via_valranges(
    mba: object,
    candidate_serial: int,
    state_var_stkoff: int,
) -> CarrierResolutionResult | None:
    """Resolve state variable constant via IDA value-range analysis.

    Uses ``collect_instruction_valrange_record_for_location`` to query the
    value range of the state variable at the ``m_mov`` instruction that writes
    to it.  Only returns a value when the range is a singleton (single value).

    Args:
        mba: Live ``ida_hexrays.mba_t`` object.
        candidate_serial: Block serial to inspect.
        state_var_stkoff: Stack offset of the state variable.

    Returns:
        A :class:`CarrierResolutionResult` with the resolved constant, or
        ``None`` if resolution fails or the range is not a singleton.
        Note: valranges does not track the def location, so
        ``def_blk_serial`` and ``def_insn_ea`` will be ``None``.
    """
    try:
        from d810.evaluator.hexrays_microcode.valranges import (
            ValrangeLocation,
            ValrangeLocationKind,
            collect_instruction_valrange_record_for_location,
        )
    except ImportError:
        return None

    try:
        live_blk = mba.get_mblock(candidate_serial)
    except Exception:
        return None
    if live_blk is None:
        return None

    # Find the state variable write instruction in the live block.
    cur_ins = live_blk.tail
    state_write_ins = None
    while cur_ins is not None:
        if cur_ins.opcode == ida_hexrays.m_mov and cur_ins.d is not None:
            if (
                cur_ins.d.t == ida_hexrays.mop_S
                and cur_ins.d.s is not None
                and cur_ins.d.s.off == state_var_stkoff
            ):
                state_write_ins = cur_ins
                break
        cur_ins = cur_ins.prev
    if state_write_ins is None:
        return None

    # Query valranges for the source operand at this instruction.
    source_mop = state_write_ins.l
    if source_mop is None:
        return None
    if source_mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
        return None

    if source_mop.t == ida_hexrays.mop_r:
        location = ValrangeLocation(
            kind=ValrangeLocationKind.REGISTER,
            identifier=int(source_mop.r),
            width=int(source_mop.size),
        )
    else:
        try:
            stkoff = source_mop.s.off
        except Exception:
            return None
        location = ValrangeLocation(
            kind=ValrangeLocationKind.STACK,
            identifier=int(stkoff),
            width=int(source_mop.size),
        )

    try:
        record = collect_instruction_valrange_record_for_location(
            live_blk, state_write_ins, location,
        )
    except Exception:
        return None
    if record is None:
        return None

    # Parse range_text for singleton values like "{0x41FB8FBB}" or "{1107294139}".
    rt = record.range_text.strip()
    if rt.startswith("{") and rt.endswith("}"):
        inner = rt[1:-1].strip()
        # Single value — no commas, no ranges
        if "," not in inner and ".." not in inner:
            try:
                val = int(inner, 0)
            except ValueError:
                return None
            return CarrierResolutionResult(
                kind=CarrierSourceKind.STATE_CONST.value,
                const_value=val,
                method=ResolutionMethod.VALRANGES,
                # valranges doesn't track def location
                def_blk_serial=None,
                def_insn_ea=None,
                source_mop_type=int(source_mop.t),
            )
    return None


def _classify_carrier_source(
    fg: FlowGraph,
    candidate_serial: int,
    state_var_stkoff: int,
    infra_blocks: frozenset[int],
    *,
    mba: object | None = None,
) -> tuple[CarrierSourceKind, int | None]:
    """Classify what value the candidate block carries into the shared suffix.

    Scans the candidate block's instructions for writes to the state variable
    (state_const) or to registers/other operands. Uses snapshot-based instruction
    iteration first, then falls back to live MBA backward resolution for indirect
    writes (e.g. OLLVM ``v15 = 0x41FB8FBB; i = v15`` patterns).

    Args:
        fg: Flow graph snapshot.
        candidate_serial: Block serial to classify.
        state_var_stkoff: Stack offset of the state variable.
        infra_blocks: Infrastructure block set (for context).
        mba: Optional live ``ida_hexrays.mba_t`` for resolving indirect state
            writes via backward def-search.  When ``None``, only snapshot-based
            classification is performed.

    Returns:
        A tuple of ``(kind, state_const_written)`` where *kind* is the
        inferred :class:`CarrierSourceKind` and *state_const_written* is the
        numeric constant written to the state variable (``mop_n`` value from
        the ``m_mov`` instruction), or ``None`` if no state write or the
        write is non-constant.
    """
    result = _classify_carrier_source_rich(
        fg, candidate_serial, state_var_stkoff, infra_blocks, mba=mba,
    )
    return CarrierSourceKind(result.kind), result.const_value


def _classify_carrier_source_rich(
    fg: FlowGraph,
    candidate_serial: int,
    state_var_stkoff: int,
    infra_blocks: frozenset[int],
    *,
    mba: object | None = None,
) -> CarrierResolutionResult:
    """Rich variant of :func:`_classify_carrier_source`.

    Returns the full :class:`CarrierResolutionResult` including def location
    for temp-def NOP support.

    Args:
        fg: Flow graph snapshot.
        candidate_serial: Block serial to classify.
        state_var_stkoff: Stack offset of the state variable.
        infra_blocks: Infrastructure block set (for context).
        mba: Optional live ``ida_hexrays.mba_t`` for resolving indirect state
            writes via backward def-search.

    Returns:
        A :class:`CarrierResolutionResult` with full resolution metadata.
    """
    blk_snap = fg.get_block(candidate_serial)
    if blk_snap is None:
        return CarrierResolutionResult(kind=CarrierSourceKind.UNKNOWN.value)

    has_state_write = False
    has_const_write = False
    has_ptr_write = False
    has_expr_write = False
    state_const_written: int | None = None
    # Track whether the state write source was non-constant on the snapshot
    # (eligible for live MBA resolution).
    state_write_source_indirect = False
    # Resolution result from MBA/valranges fallback (carries def location).
    mba_resolution: CarrierResolutionResult | None = None

    for insn in blk_snap.iter_insns():
        if insn.opcode == ida_hexrays.m_mov and insn.d is not None:
            if _mop_matches_stkoff_snapshot(insn.d, state_var_stkoff):
                has_state_write = True
                # Capture the constant value written to the state variable.
                # _extract_const_from_snapshot_mop handles both CfgMopSnapshot
                # (.value) and rich MopSnapshot (.nnn.value).
                const_val = _extract_const_from_snapshot_mop(insn.l)
                if const_val is not None:
                    state_const_written = const_val
                elif insn.l is not None:
                    # Source is non-constant (register/stack var) — mark for
                    # live MBA fallback resolution.
                    state_write_source_indirect = True
                continue
            # Check source operand type
            if insn.l is not None:
                src_t = getattr(insn.l, "t", None)
                if src_t == ida_hexrays.mop_n:
                    has_const_write = True
                elif src_t == ida_hexrays.mop_a:
                    has_ptr_write = True
                elif src_t is not None:
                    has_expr_write = True

    # Fallback: resolve indirect state writes via live MBA backward scan.
    if has_state_write and state_const_written is None and state_write_source_indirect and mba is not None:
        try:
            mba_resolution = _resolve_indirect_state_write_via_mba(
                mba, candidate_serial, state_var_stkoff,
            )
            if mba_resolution is not None:
                state_const_written = mba_resolution.const_value
                logger.info(
                    "[carrier] blk[%d] resolved indirect state write via def-search: %#x",
                    candidate_serial, state_const_written,
                )
        except Exception:
            pass

        # Secondary fallback: value-range analysis.
        if state_const_written is None:
            try:
                vr_resolution = _resolve_state_const_via_valranges(
                    mba, candidate_serial, state_var_stkoff,
                )
                if vr_resolution is not None:
                    state_const_written = vr_resolution.const_value
                    mba_resolution = vr_resolution
                    logger.info(
                        "[carrier] blk[%d] resolved indirect state write via valranges: %#x",
                        candidate_serial, state_const_written,
                    )
            except Exception:
                pass

    # Determine the carrier kind.
    if has_state_write and not (has_const_write or has_ptr_write or has_expr_write):
        kind = CarrierSourceKind.STATE_CONST
    elif has_const_write and not has_state_write:
        kind = CarrierSourceKind.REAL_CONST
    elif has_ptr_write:
        kind = CarrierSourceKind.CURSOR_OR_PTR
    elif has_expr_write:
        kind = CarrierSourceKind.EXPR
    else:
        kind = CarrierSourceKind.UNKNOWN

    # If we have a rich resolution result from MBA/valranges, propagate its
    # def location; otherwise build a snapshot-only result.
    if mba_resolution is not None:
        return CarrierResolutionResult(
            kind=kind.value,
            const_value=state_const_written,
            method=mba_resolution.method,
            def_blk_serial=mba_resolution.def_blk_serial,
            def_insn_ea=mba_resolution.def_insn_ea,
            source_mop_type=mba_resolution.source_mop_type,
            source_stkoff=mba_resolution.source_stkoff,
            source_mreg=mba_resolution.source_mreg,
        )
    return CarrierResolutionResult(
        kind=kind.value,
        const_value=state_const_written,
        method=ResolutionMethod.SNAPSHOT,
    )


def _compute_linear_suffix_chain(
    fg: FlowGraph,
    start_serial: int,
) -> list[int] | None:
    """Walk forward from start_serial following single successors until a 0-succ block.

    Returns the block serial chain [start, ..., return_block] or None if:
    - Any interior block has nsucc != 1
    - The final block has nsucc != 0
    - A cycle is detected
    - Chain length < 2 (degenerate / no shared corridor)
    """
    chain = [start_serial]
    visited = {start_serial}
    current = start_serial
    while True:
        succs = fg.successors(current)
        if len(succs) == 0:
            break  # terminal block found
        if len(succs) != 1:
            return None  # not linear, fail closed
        nxt = succs[0]
        if nxt in visited:
            return None  # cycle
        visited.add(nxt)
        chain.append(nxt)
        current = nxt
    if len(chain) < 2:
        return None  # degenerate, no shared corridor to privatize
    return chain


def _recover_handler_body_exit(
    ordered_path: list[int],
    infrastructure_blocks: frozenset[int],
) -> int | None:
    """Walk backward through DFS ordered_path, skip infrastructure blocks.

    Returns the serial of the last handler-owned block before the path
    enters dispatcher/BST/suffix infrastructure. Returns None if no
    valid body exit is found.
    """
    for serial in reversed(ordered_path):
        if serial not in infrastructure_blocks:
            return serial
    return None


def _mop_matches_stkoff_snapshot(mop_snap: object | None, stkoff: int) -> bool:
    """Snapshot-based equivalent of ``_mop_matches_stkoff`` for ``MopSnapshot``.

    Checks whether a :class:`~d810.cfg.flowgraph.MopSnapshot` represents a
    stack variable operand at the given stack offset.  This avoids touching
    live ``mop_t`` objects.
    """
    if mop_snap is None:
        return False
    return getattr(mop_snap, "stkoff", None) == stkoff


class DirectHandlerLinearizationStrategy:
    """Propose GOTO_REDIRECT / EDGE_REDIRECT / NOP_INSN edits for all resolved handler exits.

    This is a faithful port of HodurUnflattener._linearize_handlers (first pass only)
    from commit 4313af46.  It reads the BST analysis result from the snapshot and,
    for each handler entry, runs DFS forward evaluation, resolves exit states via BST
    lookup, and proposes redirects from handler exit blocks to target handler entries.

    No CFG mutations are performed until execution time; strategies emit
    backend-agnostic graph modifications inside a
    :class:`~d810.optimizers.microcode.flow.flattening.hodur.strategy.PlanFragment`.
    """

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "direct_handler_linearization"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a BST result with handlers.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if bst_result is populated with handler_state_map entries so
            that direct linearization can be attempted.
        """
        bst = snapshot.bst_result
        if bst is None:
            return False
        handler_state_map = getattr(bst, "handler_state_map", None) or {}
        return bool(handler_state_map)

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a PlanFragment with edits for all resolvable handler exits.

        Faithful port of HodurUnflattener._linearize_handlers (first pass, i.e.
        main handler loop + BST back-edge pass + pre-header redirect).  The
        second pass (hidden handler fixpoint closure) is handled by
        HiddenHandlerClosureStrategy.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A PlanFragment with at least one edit, or None when no work can
            be done.
        """
        if not self.is_applicable(snapshot):
            return None

        # K3: live mba_t still required for DEEP_IDA paths —
        # evaluate_handler_paths calls _forward_eval_insn on live minsn_t.
        # All topology and instruction-chain walks are migrated to flow_graph snapshots.
        mba = snapshot.mba
        bst_result = snapshot.bst_result
        dispatcher_serial: int = snapshot.bst_dispatcher_serial
        state_machine = snapshot.state_machine

        # ---- Resolve state_var_stkoff ----
        # Port of HodurUnflattener._get_effective_state_var_stkoff from 4313af46.
        # First try via detector (which wraps the same logic), then fall back to
        # reading mop_S.s.off directly from the state_machine's state_var mop_t.
        state_var_stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                state_var_stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if state_var_stkoff is None and state_machine is not None and state_machine.state_var is not None:
            sv = state_machine.state_var
            try:
                if sv.t == ida_hexrays.mop_S:
                    state_var_stkoff = sv.s.off
            except Exception:
                pass
        if state_var_stkoff is None:
            logger.info("Cannot linearize: state_var_stkoff is None")
            return None

        bst_node_blocks: set[int] = set(getattr(bst_result, "bst_node_blocks", set()) or set())
        bst_node_blocks.add(dispatcher_serial)
        sm_blocks = collect_state_machine_blocks(state_machine)

        # ---- Build all_handlers dict: handler_serial -> incoming_state ----
        all_handlers: dict[int, int] = {}
        handler_state_map: dict = getattr(bst_result, "handler_state_map", {}) or {}
        handler_range_map: dict = getattr(bst_result, "handler_range_map", {}) or {}
        for serial, state in handler_state_map.items():
            all_handlers[serial] = state
        for serial, (low, high) in handler_range_map.items():
            if serial not in all_handlers:
                mid = low if low is not None else (high if high is not None else 0)
                all_handlers[serial] = mid

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()

        resolved_count = 0
        claimed_exits: dict[int, int] = {}
        claimed_edges: dict[tuple[int, int], int] = {}
        bst_rootwalk_targets: set[int] = set()

        # Pass-0 redirect ledger (kept in metadata for G2 / diagnostics)
        pass0_ledger: list[dict] = []
        linearized_blocks: set[int] = set()

        # Accumulate all evaluated handler paths for return site extraction
        all_handler_paths: dict[int, list[HandlerPathResult]] = {}

        # Track terminal exit blocks for semantic gate cycle detection
        terminal_exit_blocks: set[int] = set()

        # Track anchors (exit blocks) that get redirected to the shared terminal target
        terminal_redirect_anchors: set[int] = set()

        # Collect terminal handler paths keyed by handler entry serial for
        # forward ownership frontier analysis.  Each entry maps to the list of
        # DFS paths that terminate (final_state=None, 0-succ exit block).
        terminal_handler_terminal_paths: dict[int, list[HandlerPathResult]] = {}
        _terminal_paths_total = 0  # diagnostic: total paths before dedup

        handler_entry_set: set[int] = set(all_handlers.keys())
        pre_header_serial: int | None = getattr(bst_result, "pre_header_serial", None)
        forbidden_blocks: set[int] = {dispatcher_serial} | handler_entry_set
        if pre_header_serial is not None:
            forbidden_blocks.add(pre_header_serial)
        # exit_blocks: blocks with 0 successors
        # _preflight_adj: adjacency for prove_terminal_sink validation
        # Use flow_graph snapshot when available to avoid live mba topology walk.
        exit_blocks: set[int] = set()
        _preflight_adj: dict[int, list[int]] = {}
        fg = snapshot.flow_graph
        if fg is not None:
            for serial, blk_snap in fg.blocks.items():
                if blk_snap.nsucc == 0:
                    exit_blocks.add(serial)
                _preflight_adj[serial] = list(blk_snap.succs)
        else:
            raise ValueError("K3: flow_graph is required but not available in snapshot")

        def _queue_redirect(
            path: object,
            target: int,
            reason: str,
        ) -> dict | None:
            """Queue a redirect for one handler exit path.

            Returns a dict with redirect metadata, or None on failure.
            This mirrors _queue_handler_redirect from the original, but instead
            of calling deferred.queue_*, it returns a descriptor that the outer
            function converts to graph modifications.
            """
            # Fast path: exit block not yet claimed by any handler.
            if path.exit_block not in claimed_exits:
                claimed_exits[path.exit_block] = target
                logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=None"
                    " decision=plain reason=%s via_pred_npred=None",
                    path.exit_block, target, reason,
                )
                return {
                    "kind": "plain",
                    "source_block": path.exit_block,
                    "via_pred": None,
                    "target": target,
                    "old_target": None,
                }

            # Already claimed for same target — no-op.
            if claimed_exits[path.exit_block] == target:
                return {
                    "kind": "already_claimed",
                    "source_block": path.exit_block,
                    "via_pred": None,
                    "target": target,
                    "old_target": None,
                }

            # Conflict: need edge-level redirect.
            if len(path.ordered_path) >= 2:
                via_pred = path.ordered_path[-2]
            else:
                logger.warning(
                    "EDGE_REDIRECT: no via_pred for exit blk[%d] -> target %d "
                    "(ordered_path too short: %s)",
                    path.exit_block, target, path.ordered_path,
                )
                return None

            old_target = 0
            # K3: TOPOLOGY_ONLY — use flow_graph for succ lookup
            _exit_snap = fg.get_block(path.exit_block)
            if _exit_snap is not None and _exit_snap.nsucc > 0:
                old_target = _exit_snap.succs[0]

            edge_key = (path.exit_block, via_pred)
            if edge_key in claimed_edges:
                if claimed_edges[edge_key] == target:
                    return {
                        "kind": "already_claimed_edge",
                        "source_block": path.exit_block,
                        "via_pred": via_pred,
                        "target": target,
                        "old_target": old_target,
                    }
                # Escalate: walk backward through ordered_path to find an unclaimed edge.
                logger.info(
                    "EDGE_ESCALATION: edge (%d, %d) claimed for %d, searching earlier segment for target %d",
                    path.exit_block, via_pred, claimed_edges[edge_key], target,
                )
                found_src: int | None = None
                found_pred: int | None = None
                for i in range(len(path.ordered_path) - 2, 0, -1):
                    seg_src = path.ordered_path[i]
                    seg_pred = path.ordered_path[i - 1]
                    seg_key = (seg_src, seg_pred)
                    if seg_key not in claimed_edges and seg_src not in bst_node_blocks:
                        # K3: TOPOLOGY_ONLY — use flow_graph for nsucc/succ checks
                        _seg_src_snap = fg.get_block(seg_src)
                        _seg_pred_snap = fg.get_block(seg_pred)
                        if _seg_src_snap is None or _seg_pred_snap is None:
                            continue
                        if _seg_src_snap.nsucc != 1:
                            continue
                        if _seg_pred_snap.nsucc != 1:
                            continue
                        if seg_src not in _seg_pred_snap.succs:
                            continue
                        found_src = seg_src
                        found_pred = seg_pred
                        break
                if found_src is None or found_pred is None:
                    logger.warning(
                        "EDGE_REDIRECT: all path segments claimed for exit blk[%d] -> target %d, "
                        "cannot queue redirect",
                        path.exit_block, target,
                    )
                    return None
                src_block = found_src
                use_pred = found_pred
                # K3: TOPOLOGY_ONLY — use flow_graph for succ lookup
                _src_snap = fg.get_block(src_block)
                old_target = _src_snap.succs[0] if _src_snap is not None and _src_snap.nsucc > 0 else 0
                logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                    " decision=escalated reason=prior_edge_claimed",
                    path.exit_block, target, use_pred,
                )
            else:
                src_block = path.exit_block
                use_pred = via_pred
                logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                    " decision=edge_split reason=exit_claimed",
                    path.exit_block, target, use_pred,
                )

            logger.info(
                "EDGE_REDIRECT: exit blk[%d] -> target %d conflicts with claimed=%d; "
                "using edge_redirect(src=%d, old=%d, new=%d, via_pred=%d)",
                path.exit_block, target, claimed_exits[path.exit_block],
                src_block, old_target, target, use_pred,
            )
            claimed_edges[(src_block, use_pred)] = target
            return {
                "kind": "edge",
                "source_block": src_block,
                "via_pred": use_pred,
                "target": target,
                "old_target": old_target,
            }

        def _append_nop(source_block: int, instruction_ea: int) -> None:
            modifications.append(
                builder.nop_instruction(
                    source_block=source_block,
                    instruction_ea=instruction_ea,
                )
            )

        # Track already-NOPed two-step temp defs to avoid duplicate NOPs.
        _two_step_nopped: set[tuple[int, int]] = set()

        def _nop_temp_def_if_resolved(
            write_blk: int,
            write_ea: int,
            handler_serial: int,
        ) -> bool:
            """NOP the temp-variable definition using live MBA backward resolution.

            Calls :func:`_resolve_indirect_state_write_via_mba` on the state
            write block to get a :class:`CarrierResolutionResult` with the temp
            def location, then queues a NOP if found.

            Args:
                write_blk: Block serial containing the state write.
                write_ea: Instruction EA of the state write.
                handler_serial: Handler entry serial (for diagnostics).

            Returns:
                True if a temp def NOP was queued.
            """
            if mba is None:
                return False
            result = _resolve_indirect_state_write_via_mba(
                mba, write_blk, state_var_stkoff,
            )
            if result is None:
                return False
            if result.def_blk_serial is None or result.def_insn_ea is None:
                return False
            key = (result.def_blk_serial, result.def_insn_ea)
            if key in _two_step_nopped:
                return False
            _two_step_nopped.add(key)
            _append_nop(source_block=result.def_blk_serial, instruction_ea=result.def_insn_ea)
            logger.info(
                "TWO_STEP_NOP: handler=blk[%d] temp_def=blk[%d]@0x%X const=0x%X method=%s",
                handler_serial, result.def_blk_serial, result.def_insn_ea,
                result.const_value if result.const_value is not None else 0,
                result.method.value,
            )
            return True

        def _emit_redirect(meta: dict, path: object, incoming_state: int, category: str, handler_serial: int) -> bool:
            """Convert redirect metadata into graph modifications."""
            kind = meta["kind"]
            target = meta["target"]
            src_block = meta["source_block"]

            if kind in ("already_claimed", "already_claimed_edge"):
                return True  # Already queued, no new edit needed.

            if kind == "plain":
                modifications.append(
                    builder.goto_redirect(
                        source_block=src_block,
                        target_block=target,
                    )
                )
                owned_blocks.add(src_block)
                owned_edges.add((src_block, target))
                pass0_ledger.append({
                    "category": category,
                    "handler_entry": handler_serial,
                    "incoming_state": incoming_state,
                    "exit_block": path.exit_block,
                    "final_state": path.final_state,
                    "source_block": src_block,
                    "via_pred": None,
                    "target_block": target,
                })
                return True

            if kind == "edge":
                via_pred = meta["via_pred"]
                old_target = meta["old_target"]
                modifications.append(
                    builder.edge_redirect(
                        source_block=src_block,
                        target_block=target,
                        old_target=old_target,
                        via_pred=via_pred,
                        rule_priority=550,
                    )
                )
                owned_blocks.add(src_block)
                owned_edges.add((src_block, target))
                pass0_ledger.append({
                    "category": category,
                    "handler_entry": handler_serial,
                    "incoming_state": incoming_state,
                    "exit_block": path.exit_block,
                    "final_state": path.final_state,
                    "source_block": src_block,
                    "via_pred": via_pred,
                    "target_block": target,
                })
                return True

            return False

        # ---- Main handler loop ----
        for handler_serial, incoming_state in all_handlers.items():
            if handler_serial in bst_node_blocks:
                continue

            # K3: DEEP_IDA — forward eval requires live minsn_t via mba
            paths = evaluate_handler_paths(
                mba=mba,
                entry_serial=handler_serial,
                incoming_state=incoming_state,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=state_var_stkoff,
            )

            if not paths:
                logger.debug(
                    "Handler blk[%d] (state 0x%x): no exit paths found, deferring to legacy",
                    handler_serial,
                    incoming_state,
                )
                continue

            all_handler_paths[handler_serial] = list(paths)
            linearized_blocks.add(handler_serial)

            # Phase 1 diagnostic: detect conditional intra-handler transitions
            _known_state_consts: set[int] = set(handler_state_map.values())
            if state_machine is not None:
                _known_state_consts |= state_machine.state_constants
            conditional_transitions = detect_conditional_transitions(
                handler_entry=handler_serial,
                paths=paths,
                state_constants=_known_state_consts,
                flow_graph=fg,
                incoming_state=incoming_state,
            )
            if conditional_transitions:
                for ct in conditional_transitions:
                    logger.info(
                        "CONDITIONAL_TRANSITION: handler=blk[%d] branch=blk[%d] "
                        "arm=%d target_state=0x%X write=blk[%d]@0x%X",
                        ct.handler_entry, ct.branch_block, ct.branch_arm,
                        ct.target_state, ct.state_write_block, ct.state_write_ea,
                    )

                # Phase 2: redirect conditional transition arms to resolved targets
                # Track redirected branch blocks: {branch_block: {arm: target}}
                redirected_branches: dict[int, dict[int, int]] = {}
                for ct in conditional_transitions:
                    # 1. Resolve target handler via BST
                    ct_target = resolve_target_via_bst(bst_result, ct.target_state)
                    if ct_target is None:
                        logger.info(
                            "CONDITIONAL_TRANSITION_SKIP: handler=blk[%d] "
                            "target_state=0x%X no BST resolution",
                            ct.handler_entry, ct.target_state,
                        )
                        continue
                    ct.target_handler = ct_target

                    # 2. Look up the current successor on the branch arm
                    branch_snap = fg.get_block(ct.branch_block)
                    if branch_snap is None or len(branch_snap.succs) != 2:
                        logger.info(
                            "CONDITIONAL_TRANSITION_SKIP: handler=blk[%d] "
                            "branch=blk[%d] not a 2-way block (succs=%s)",
                            ct.handler_entry, ct.branch_block,
                            branch_snap.succs if branch_snap else "None",
                        )
                        continue

                    old_target = branch_snap.succs[ct.branch_arm]

                    # Guard: skip if this specific edge is already claimed
                    edge_key = (ct.branch_block, old_target)
                    if edge_key in claimed_edges:
                        logger.info(
                            "CONDITIONAL_TRANSITION_SKIP: handler=blk[%d] "
                            "edge (%d->%d) already claimed by %d",
                            ct.handler_entry, ct.branch_block,
                            old_target, claimed_edges[edge_key],
                        )
                        continue

                    # Guard: skip if target is the same as old (no-op)
                    if old_target == ct_target:
                        logger.info(
                            "CONDITIONAL_TRANSITION_SKIP: handler=blk[%d] "
                            "branch=blk[%d] arm=%d already points to target blk[%d]",
                            ct.handler_entry, ct.branch_block,
                            ct.branch_arm, ct_target,
                        )
                        continue

                    # Guard: skip if both arms of the same branch block
                    # resolve to the same target (would create duplicate pred)
                    if ct.branch_block in redirected_branches:
                        prev = redirected_branches[ct.branch_block]
                        other_arm = next(iter(prev))
                        if prev[other_arm] == ct_target:
                            logger.info(
                                "CONDITIONAL_TRANSITION_SKIP_DUPLICATE: handler=blk[%d] "
                                "branch=blk[%d] both arms -> blk[%d], skipping arm=%d",
                                ct.handler_entry, ct.branch_block,
                                ct_target, ct.branch_arm,
                            )
                            continue

                    # 3. Emit redirect (arm-aware)
                    if ct.branch_arm == 1:
                        # Arm 1 = jcc taken target. RedirectBranch rewrites
                        # blk.tail.d.b — the only operand
                        # change_2way_block_conditional_successor touches.
                        modifications.append(
                            RedirectBranch(
                                from_serial=ct.branch_block,
                                old_target=old_target,
                                new_target=ct_target,
                            )
                        )
                        claimed_edges[edge_key] = ct_target
                        redirected_branches.setdefault(ct.branch_block, {})[ct.branch_arm] = ct_target
                        owned_blocks.add(ct.branch_block)
                        owned_edges.add((ct.branch_block, ct_target))
                    elif ct.branch_arm == 0:
                        # Arm 0 = fall-through successor.  Cannot be changed
                        # via jcc rewrite — change_2way_block_conditional_
                        # successor only modifies blk.tail.d.b (arm 1).  The
                        # downstream exit block already receives a RedirectGoto
                        # from the main linearization loop, so no additional
                        # redirect is needed here.  We still NOP the state
                        # write below.
                        logger.info(
                            "CONDITIONAL_TRANSITION_ARM0_SKIP: handler=blk[%d] "
                            "branch=blk[%d] arm=0 -> state 0x%x defers to "
                            "exit-block RedirectGoto",
                            ct.handler_entry, ct.branch_block, ct.target_state,
                        )

                    # 4. NOP the dead state write (skip multi-pred blocks)
                    # Fires for BOTH arms — the state variable write is dead
                    # regardless of which arm carried the transition.
                    _sw_snap = fg.get_block(ct.state_write_block)
                    if _sw_snap is None or _sw_snap.npred <= 1:
                        _append_nop(
                            source_block=ct.state_write_block,
                            instruction_ea=ct.state_write_ea,
                        )
                    # 4b. Always try to NOP the two-step temp def — it's in a
                    # different (predecessor) block, independent of the npred guard.
                    _nop_temp_def_if_resolved(
                        ct.state_write_block, ct.state_write_ea, ct.handler_entry,
                    )

                    # 5. Bookkeeping — only for arm=1 which emitted a redirect.
                    # Arm=0 transitions are resolved by the main loop's
                    # RedirectGoto on the downstream exit block; counting them
                    # here would double-count.
                    if ct.branch_arm != 0:
                        logger.info(
                            "CONDITIONAL_TRANSITION_REDIRECT: handler=blk[%d] "
                            "branch=blk[%d] arm=%d old_target=blk[%d] -> "
                            "new_target=blk[%d] (state=0x%X) write_nop=blk[%d]@0x%X",
                            ct.handler_entry, ct.branch_block, ct.branch_arm,
                            old_target, ct_target, ct.target_state,
                            ct.state_write_block, ct.state_write_ea,
                        )

                        resolved_count += 1
                        owned_transitions.add((incoming_state, ct.target_state))
                        pass0_ledger.append({
                            "category": "conditional_transition",
                            "handler_entry": handler_serial,
                            "incoming_state": incoming_state,
                            "exit_block": ct.branch_block,
                            "final_state": ct.target_state,
                            "source_block": ct.branch_block,
                            "via_pred": None,
                            "target_block": ct_target,
                        })

            for path in paths:
                if path.final_state is None:
                    # Terminal path — handler exits (e.g. m_ret or 0-succ block).
                    # The exit block may still goto the dispatcher; redirect it to
                    # the function's real exit corridor so it survives DCE.
                    terminal_exit_blocks.add(path.exit_block)
                    # K3: TOPOLOGY_ONLY — use flow_graph for 0-succ check
                    _exit_snap = fg.get_block(path.exit_block)
                    _exit_nsucc = _exit_snap.nsucc if _exit_snap is not None else None
                    if _exit_nsucc is not None and _exit_nsucc == 0:
                        # Block already has no successors (true terminal) — nothing to do.
                        logger.info(
                            "Handler blk[%d] (state=0x%x): true terminal exit via blk[%d] (0 succs)",
                            handler_serial,
                            incoming_state,
                            path.exit_block,
                        )
                        # Collect terminal path keyed by handler entry
                        _terminal_paths_total += 1
                        terminal_handler_terminal_paths.setdefault(
                            handler_serial, []
                        ).append(path)
                        resolved_count += 1
                        continue

                    # Exit block still has successors (likely goto dispatcher).
                    # Find the function's terminal exit target (K3.5: snapshot).
                    terminal_target = find_terminal_exit_target_snapshot(
                        fg, dispatcher_serial, sm_blocks
                    )
                    if terminal_target is not None and terminal_target != path.exit_block:
                        # Validate terminal sink before accepting redirect
                        sink_proof = prove_terminal_sink(
                            terminal_target, _preflight_adj, exit_blocks, forbidden_blocks
                        )
                        if not sink_proof.ok:
                            logger.warning(
                                "Handler blk[%d] (state=0x%x): terminal redirect "
                                "blk[%d] -> blk[%d] REJECTED: %s (witness: %s)",
                                handler_serial, incoming_state,
                                path.exit_block, terminal_target,
                                sink_proof.reason, sink_proof.witness_path,
                            )
                            continue

                        _reason = (
                            f"hodur-linear: blk[{handler_serial}] "
                            f"terminal exit blk[{path.exit_block}] -> exit blk[{terminal_target}]"
                        )
                        meta = _queue_redirect(path, terminal_target, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, incoming_state, "terminal_exit", handler_serial)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # Track redirect target so cycle detector walks from it too
                                terminal_exit_blocks.add(terminal_target)
                                # Track anchor for PrivateTerminalSuffix emission
                                terminal_redirect_anchors.add(path.exit_block)
                                # NOP dead state writes on the terminal path
                                for write_blk, write_ea in path.state_writes:
                                    _append_nop(

                                        source_block=write_blk,

                                        instruction_ea=write_ea,

                                    )
                                    _nop_temp_def_if_resolved(write_blk, write_ea, handler_serial)
                                logger.info(
                                    "Handler blk[%d] (state=0x%x): terminal exit blk[%d] -> exit blk[%d]",
                                    handler_serial,
                                    incoming_state,
                                    path.exit_block,
                                    terminal_target,
                                )
                        resolved_count += 1
                    else:
                        logger.info(
                            "Handler blk[%d] (state=0x%x): terminal exit via blk[%d] (no redirect target found)",
                            handler_serial,
                            incoming_state,
                            path.exit_block,
                        )
                        resolved_count += 1
                    continue

                target_serial = resolve_target_via_bst(bst_result, path.final_state)

                if target_serial is None:
                    # No handler matches this state value — it's an exit transition.
                    # K3: use flow_graph snapshot for topology-only BST default lookup
                    bst_default = find_bst_default_block_snapshot(
                        fg,
                        dispatcher_serial,
                        bst_result.bst_node_blocks,
                        set(handler_state_map.keys()),
                    )
                    exit_target: int | None = None
                    resolve_label: str = ""
                    if bst_default is not None and path.final_state is not None:
                        # K3: use flow_graph snapshot for BST walk
                        exit_target = resolve_exit_via_bst_default_snapshot(
                            fg, bst_default, path.final_state
                        )
                        if exit_target is not None:
                            resolve_label = f"BST default blk[{bst_default}]"
                    if exit_target is None and path.final_state is not None:
                        # K3: use flow_graph snapshot for BST root-walk
                        exit_target = resolve_exit_via_bst_default_snapshot(
                            fg, dispatcher_serial, path.final_state
                        )
                        if exit_target is not None:
                            resolve_label = "BST root-walk"
                            bst_rootwalk_targets.add(exit_target)
                        if exit_target is not None and exit_target in bst_node_blocks:
                            logger.info(
                                "hodur-linear: handler %d exit state 0x%x resolved to BST internal node blk[%d], skipping",
                                handler_serial,
                                path.final_state,
                                exit_target,
                            )
                            exit_target = None

                    if exit_target is not None:
                        _reason = (
                            f"hodur-linear: blk[{handler_serial}] "
                            f"exit 0x{path.final_state:x} -> {resolve_label} -> blk[{exit_target}]"
                        )
                        meta = _queue_redirect(path, exit_target, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, incoming_state, "exit_resolved", handler_serial)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # NOP dead state writes in exit path
                                for write_blk, write_ea in path.state_writes:
                                    _append_nop(

                                        source_block=write_blk,

                                        instruction_ea=write_ea,

                                    )
                                    _nop_temp_def_if_resolved(write_blk, write_ea, handler_serial)
                                # NOP dead state_var writes in the resolved exit target block.
                                # K3: INSN_CHAIN — migrated to snapshot iter_insns
                                _exit_tgt_snap = fg.get_block(exit_target)
                                if _exit_tgt_snap is not None and exit_target not in bst_node_blocks:
                                    for _scan_insn in _exit_tgt_snap.iter_insns():
                                        if (
                                            _scan_insn.opcode == ida_hexrays.m_mov
                                            and _scan_insn.d is not None
                                            and _mop_matches_stkoff_snapshot(
                                                _scan_insn.d,
                                                state_var_stkoff,
                                            )
                                        ):
                                            logger.info(
                                                "  NOP dead state_var write in exit target"
                                                " blk[%d] ea=%#x",
                                                exit_target,
                                                _scan_insn.ea,
                                            )
                                            _append_nop(

                                                source_block=exit_target,

                                                instruction_ea=_scan_insn.ea,

                                            )
                                resolved_count += 1
                                owned_transitions.add((incoming_state, path.final_state))
                        elif meta is not None and meta["kind"] in ("already_claimed", "already_claimed_edge"):
                            # Redirect already queued, but still NOP state writes
                            # (including two-step temp defs) to avoid constant leaks.
                            for write_blk, write_ea in path.state_writes:
                                _append_nop(
                                    source_block=write_blk,
                                    instruction_ea=write_ea,
                                )
                                _nop_temp_def_if_resolved(write_blk, write_ea, handler_serial)
                        else:
                            pass  # conflict, skip
                        continue

                    # Fallback: redirect to bst_default directly (or terminal exit)
                    if bst_default is None:
                        # K3: use flow_graph snapshot
                        bst_default = find_terminal_exit_target_snapshot(
                            fg, dispatcher_serial, sm_blocks
                        )
                    if bst_default is not None:
                        _reason = (
                            f"hodur-linear: blk[{handler_serial}] "
                            f"exit state 0x{path.final_state:x} -> bst_default blk[{bst_default}]"
                        )
                        meta = _queue_redirect(path, bst_default, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, incoming_state, "exit_bst_default", handler_serial)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # Keep state variable live for exit paths (no NOP).
                                resolved_count += 1
                                owned_transitions.add((incoming_state, path.final_state))
                    else:
                        logger.debug(
                            "Handler blk[%d]: exit state 0x%x -> no bst_default found, leaving intact",
                            handler_serial,
                            path.final_state,
                        )
                    continue

                # Normal state transition to another handler.
                # NOTE: is_self_loop uses BST-resolved target_serial == handler_serial,
                # which correctly handles MBA-computed states. The _helpers.py
                # conditional-transition filter uses exact state equality and
                # misses MBA self-loops — see ticket d81-b6yj.
                is_self_loop = target_serial == handler_serial
                _reason = (
                    f"hodur-linear: blk[{handler_serial}] "
                    f"0x{incoming_state:x}->0x{path.final_state:x} "
                    f"{'(loop)' if is_self_loop else ''}"
                )
                meta = _queue_redirect(path, target_serial, _reason)
                if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                    ok = _emit_redirect(meta, path, incoming_state, "state_transition", handler_serial)
                    if ok:
                        linearized_blocks.add(path.exit_block)
                        if is_self_loop:
                            # Self-loop: preserve state writes for loop back-edge.
                            # The redirect keeps the handler wired to itself; NOPing
                            # the state write would destroy the loop iteration.
                            logger.info(
                                "Self-loop detected: preserving state writes for "
                                "loop back-edge blk[%d] (state 0x%x)",
                                handler_serial,
                                incoming_state,
                            )
                        else:
                            # NOP dead state writes (skip multi-pred blocks)
                            for write_blk, write_ea in path.state_writes:
                                # K3: TOPOLOGY_ONLY — use flow_graph for npred check
                                _wb_snap = fg.get_block(write_blk)
                                if _wb_snap is not None and _wb_snap.npred > 1:
                                    continue
                                _append_nop(

                                    source_block=write_blk,

                                    instruction_ea=write_ea,

                                )
                                _nop_temp_def_if_resolved(write_blk, write_ea, handler_serial)
                        resolved_count += 1
                        owned_transitions.add((incoming_state, path.final_state))

        # ---- BST default back-edge pass ----
        # K3.4: use flow_graph snapshot for topology-only BST default lookup
        bst_default_for_backedge = find_bst_default_block_snapshot(
            fg,
            dispatcher_serial,
            bst_result.bst_node_blocks,
            set(handler_state_map.keys()),
        )
        if bst_default_for_backedge is not None:
            bst_default_region: set[int] = set()
            bde_queue: list[int] = [bst_default_for_backedge]
            handler_serials_set = set(handler_state_map.keys())
            while bde_queue:
                serial = bde_queue.pop()
                if (
                    serial in bst_default_region
                    or serial in bst_node_blocks
                    or serial == dispatcher_serial
                ):
                    continue
                if serial in handler_serials_set:
                    continue
                bst_default_region.add(serial)
                # K3: TOPOLOGY_ONLY — use flow_graph for successor expansion
                _bde_snap = fg.get_block(serial)
                if _bde_snap is not None:
                    for _s in _bde_snap.succs:
                        bde_queue.append(_s)

            for serial in bst_default_region:
                _bde_blk_snap = fg.get_block(serial)
                if _bde_blk_snap is None:
                    continue
                backedge_succs = [
                    s for s in _bde_blk_snap.succs
                    if s in bst_node_blocks
                ]
                if not backedge_succs:
                    continue

                # K3: INSN_CHAIN — migrated to snapshot iter_insns
                written_state = None
                state_write_ea = None
                for insn_snap in _bde_blk_snap.iter_insns():
                    if insn_snap.opcode == ida_hexrays.m_mov and insn_snap.d is not None:
                        if _mop_matches_stkoff_snapshot(insn_snap.d, state_var_stkoff):
                            if (
                                insn_snap.l is not None
                                and insn_snap.l.t == ida_hexrays.mop_n
                                and insn_snap.l.value is not None
                            ):
                                written_state = int(insn_snap.l.value)
                                state_write_ea = insn_snap.ea
                if written_state is None:
                    continue

                # K3.4: use flow_graph snapshot for BST walk
                target = resolve_exit_via_bst_default_snapshot(
                    fg, bst_default_for_backedge, written_state
                )
                if target is None:
                    continue

                logger.info(
                    "  BST default back-edge: blk[%d] state %#x -> resolved blk[%d]",
                    serial,
                    written_state,
                    target,
                )

                _synthetic_path = HandlerPathResult(
                    exit_block=serial,
                    final_state=written_state,
                    state_writes=[],
                    ordered_path=[serial],
                )
                _reason = (
                    f"hodur-linear: BST default blk[{serial}] {written_state:#x}->blk[{target}]"
                )
                meta = _queue_redirect(_synthetic_path, target, _reason)
                if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                    ok = _emit_redirect(meta, _synthetic_path, written_state, "bst_default_backedge", serial)
                    if ok:
                        if state_write_ea is not None:
                            _append_nop(

                                source_block=serial,

                                instruction_ea=state_write_ea,

                            )
                            _nop_temp_def_if_resolved(serial, state_write_ea, serial)
                        # K3: INSN_CHAIN — migrated to snapshot iter_insns
                        _tgt_snap = fg.get_block(target)
                        if _tgt_snap is not None and target not in bst_node_blocks:
                            for _scan_insn in _tgt_snap.iter_insns():
                                if (
                                    _scan_insn.opcode == ida_hexrays.m_mov
                                    and _scan_insn.d is not None
                                    and _mop_matches_stkoff_snapshot(
                                        _scan_insn.d, state_var_stkoff
                                    )
                                ):
                                    _append_nop(

                                        source_block=target,

                                        instruction_ea=_scan_insn.ea,

                                    )
                        resolved_count += 1

        # ---- PASS 2: Hidden handler fixpoint closure ----
        # Iterate bst_rootwalk_targets collected during pass 1.
        # For each hidden handler entry, run DFS forward eval, resolve exits,
        # and emit redirects.  Continue until no new hidden handlers are found
        # (fixpoint convergence).
        hidden_worklist: deque[int] = deque(bst_rootwalk_targets)
        hidden_seen: set[int] = set(bst_rootwalk_targets)
        hidden_processed: set[int] = set()
        hidden_redirects_seen: set[tuple[int, int, int, int]] = set()

        while hidden_worklist:
            rootwalk_blk = hidden_worklist.popleft()
            if rootwalk_blk in hidden_processed:
                continue
            hidden_processed.add(rootwalk_blk)
            if rootwalk_blk in bst_node_blocks:
                continue  # Skip actual BST comparison nodes
            try:
                # K3: DEEP_IDA — forward eval requires live minsn_t via mba
                hidden_paths = evaluate_handler_paths(
                    mba=mba,
                    entry_serial=rootwalk_blk,
                    incoming_state=0,
                    bst_node_blocks=bst_node_blocks,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception:
                continue

            for path in hidden_paths:
                if path.final_state is None:
                    # Terminal path — redirect to function exit if the block
                    # still has successors (goto dispatcher).
                    terminal_exit_blocks.add(path.exit_block)
                    # K3: TOPOLOGY_ONLY — use flow_graph for 0-succ check
                    _h_exit_snap = fg.get_block(path.exit_block)
                    _h_exit_nsucc = _h_exit_snap.nsucc if _h_exit_snap is not None else None
                    if _h_exit_nsucc is not None and _h_exit_nsucc == 0:
                        # Collect terminal path keyed by hidden handler entry
                        _terminal_paths_total += 1
                        terminal_handler_terminal_paths.setdefault(
                            rootwalk_blk, []
                        ).append(path)
                        resolved_count += 1
                        continue  # True terminal, nothing to do.
                    # K3.5: use flow_graph snapshot
                    terminal_target = find_terminal_exit_target_snapshot(
                        fg, dispatcher_serial, sm_blocks
                    )
                    if terminal_target is not None and terminal_target != path.exit_block:
                        # Validate terminal sink before accepting redirect
                        sink_proof = prove_terminal_sink(
                            terminal_target, _preflight_adj, exit_blocks, forbidden_blocks
                        )
                        if not sink_proof.ok:
                            logger.warning(
                                "Hidden blk[%d]: terminal redirect "
                                "blk[%d] -> blk[%d] REJECTED: %s (witness: %s)",
                                rootwalk_blk,
                                path.exit_block, terminal_target,
                                sink_proof.reason, sink_proof.witness_path,
                            )
                            resolved_count += 1
                            continue

                        _reason = (
                            f"hodur-linear: hidden blk[{rootwalk_blk}] "
                            f"terminal exit blk[{path.exit_block}] -> exit blk[{terminal_target}]"
                        )
                        meta = _queue_redirect(path, terminal_target, _reason)
                        if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                            ok = _emit_redirect(meta, path, 0, "hidden_terminal_exit", rootwalk_blk)
                            if ok:
                                linearized_blocks.add(path.exit_block)
                                # Track redirect target so cycle detector walks from it too
                                terminal_exit_blocks.add(terminal_target)
                                # Track anchor for PrivateTerminalSuffix emission
                                terminal_redirect_anchors.add(path.exit_block)
                                for write_blk, write_ea in path.state_writes:
                                    _append_nop(

                                        source_block=write_blk,

                                        instruction_ea=write_ea,

                                    )
                                    _nop_temp_def_if_resolved(write_blk, write_ea, rootwalk_blk)
                                logger.info(
                                    "hodur-linear: hidden blk[%d] terminal exit blk[%d] -> exit blk[%d]",
                                    rootwalk_blk,
                                    path.exit_block,
                                    terminal_target,
                                )
                        resolved_count += 1
                    else:
                        resolved_count += 1
                    continue

                # Try exact BST resolution first
                target = resolve_target_via_bst(bst_result, path.final_state)
                if target is None:
                    # Try BST root-walk (K3: use flow_graph snapshot)
                    target = resolve_exit_via_bst_default_snapshot(
                        fg, dispatcher_serial, path.final_state
                    )
                    # Chain detection diagnostic
                    if (
                        target is not None
                        and target not in bst_node_blocks
                        and target not in all_handlers
                    ):
                        logger.info(
                            "Chain candidate: hidden blk[%d] exit -> blk[%d] "
                            "(not a known handler, potential chained hidden handler)",
                            rootwalk_blk,
                            target,
                        )
                if target is None:
                    continue
                if target in bst_node_blocks:
                    continue  # Don't redirect to BST internal nodes
                if target == path.exit_block:
                    logger.info(
                        "hodur-linear: hidden-handler blk[%d] exit_blk=%d resolved to itself, skipping",
                        rootwalk_blk,
                        path.exit_block,
                    )
                    continue

                if target not in all_handlers and target not in hidden_seen:
                    hidden_seen.add(target)
                    hidden_worklist.append(target)
                    logger.info(
                        "Queued chained hidden handler: blk[%d] from hidden blk[%d] state=0x%x",
                        target,
                        rootwalk_blk,
                        path.final_state,
                    )

                hidden_key = (rootwalk_blk, path.exit_block, path.final_state, target)
                if hidden_key in hidden_redirects_seen:
                    logger.info(
                        "hodur-linear: hidden-handler duplicate redirect skipped "
                        "blk[%d] exit_blk=%d state=0x%x target=%d",
                        rootwalk_blk,
                        path.exit_block,
                        path.final_state,
                        target,
                    )
                    continue
                hidden_redirects_seen.add(hidden_key)

                _reason = (
                    f"hodur-linear: hidden-handler blk[{rootwalk_blk}]"
                    f" exit 0x{path.final_state:x} -> blk[{target}]"
                )
                meta = _queue_redirect(path, target, _reason)
                if meta is not None and meta["kind"] not in ("already_claimed", "already_claimed_edge"):
                    ok = _emit_redirect(meta, path, 0, "hidden_handler", rootwalk_blk)
                    if ok:
                        linearized_blocks.add(path.exit_block)
                        logger.info(
                            "hodur-linear: hidden-handler blk[%d] exit_blk=%d -> target blk[%d] (state 0x%x)",
                            rootwalk_blk,
                            path.exit_block,
                            target,
                            path.final_state,
                        )
                        for write_blk, write_ea in path.state_writes:
                            # K3: TOPOLOGY_ONLY — use flow_graph for npred check
                            _hwb_snap = fg.get_block(write_blk)
                            if _hwb_snap is not None and _hwb_snap.npred > 1:
                                continue  # Skip NOP on shared multi-pred blocks
                            _append_nop(

                                source_block=write_blk,

                                instruction_ea=write_ea,

                            )
                            _nop_temp_def_if_resolved(write_blk, write_ea, rootwalk_blk)
                        resolved_count += 1

        # ---- Pre-header redirect ----
        initial_state = getattr(bst_result, "initial_state", None)
        pre_header_serial = getattr(bst_result, "pre_header_serial", None)
        if initial_state is not None and pre_header_serial is not None:
            initial_handler = resolve_target_via_bst(bst_result, initial_state)
            if initial_handler is not None:
                _reason = "hodur-linear: pre-header -> initial handler"
                modifications.append(
                    builder.goto_redirect(
                        source_block=pre_header_serial,
                        target_block=initial_handler,
                    )
                )
                owned_blocks.add(pre_header_serial)
                owned_edges.add((pre_header_serial, initial_handler))
                pass0_ledger.append({
                    "category": "preheader",
                    "handler_entry": pre_header_serial,
                    "incoming_state": initial_state,
                    "exit_block": pre_header_serial,
                    "final_state": initial_state,
                    "source_block": pre_header_serial,
                    "via_pred": None,
                    "target_block": initial_handler,
                })
                resolved_count += 1

        logger.info(
            "Hodur direct linearization: %d transitions resolved for %d handlers",
            resolved_count,
            len(all_handlers),
        )

        # --- Forward ownership-frontier analysis (DIAGNOSTIC ONLY) ---
        # Replaces the backward-walk _recover_handler_body_exit approach which
        # collapsed distinct terminal paths to shared blocks.  For each terminal
        # handler entry, walks ordered_path forward and stops at the first block
        # in full_infra; the previous block is the handler-owned exit candidate.
        private_suffix_count = 0
        cfg_frontier: TerminalCfgSuffixFrontier | None = None
        forward_frontier_entries: list[ForwardFrontierEntry] = []
        corridor_infos: list[SharedCorridorInfo] = []
        suffix_group_decisions: list[SuffixGroupDecision] = []

        if terminal_handler_terminal_paths:
            terminal_target_for_suffix = find_terminal_exit_target_snapshot(
                fg, dispatcher_serial, sm_blocks
            )
            if terminal_target_for_suffix is not None:
                cfg_frontier = compute_terminal_cfg_suffix_frontier(
                    return_block_serial=terminal_target_for_suffix,
                    predecessors_of=fg.predecessors,
                )
                shared_entry = cfg_frontier.shared_entry_serial
                return_block = cfg_frontier.return_block_serial
                suffix_serials_tuple = cfg_frontier.suffix_serials

                # Compute full infrastructure set
                full_infra = frozenset(
                    bst_node_blocks
                    | {dispatcher_serial}
                    | set(suffix_serials_tuple)
                    | ({pre_header_serial} if pre_header_serial is not None else set())
                )

                semantic_frontier = classify_cfg_suffix_action(cfg_frontier)

                # Track candidate frequency across all handler entries for
                # shared-path rejection.
                candidate_frequency: dict[int, int] = {}

                # Phase 1: Forward walk per handler entry
                for handler_entry, paths in terminal_handler_terminal_paths.items():
                    # Use the first path for the forward walk (all paths from the
                    # same handler entry share the same prefix through handler body).
                    path = paths[0]
                    ordered = path.ordered_path

                    # Forward walk: find first infra block; previous = candidate
                    fw_candidate: int | None = None
                    fw_candidate_succ: int | None = None
                    prev_block: int | None = None
                    for blk_serial in ordered:
                        if blk_serial in full_infra:
                            fw_candidate = prev_block
                            fw_candidate_succ = blk_serial
                            break
                        prev_block = blk_serial

                    if fw_candidate is not None:
                        candidate_frequency[fw_candidate] = (
                            candidate_frequency.get(fw_candidate, 0) + 1
                        )

                    # Classify carrier source kind
                    carrier_kind = CarrierSourceKind.UNKNOWN
                    carrier_const: int | None = None
                    if fw_candidate is not None:
                        carrier_kind, carrier_const = _classify_carrier_source(
                            fg, fw_candidate, state_var_stkoff, full_infra,
                            mba=mba,
                        )

                    # Validate candidate
                    proof_status = "unresolved"
                    notes_parts: list[str] = []
                    if fw_candidate is None:
                        notes_parts.append("no non-infra block before first infra hit")
                    else:
                        cand_snap = fg.get_block(fw_candidate)
                        if cand_snap is None:
                            notes_parts.append("candidate block snapshot unavailable")
                        elif cand_snap.nsucc != 1:
                            notes_parts.append(
                                "candidate nsucc=%d (expected 1)" % cand_snap.nsucc
                            )
                        elif not cand_snap.succs or cand_snap.succs[0] not in full_infra:
                            notes_parts.append(
                                "candidate succ not in infrastructure"
                            )
                        else:
                            # Passes structural validation; frequency check deferred
                            proof_status = "resolved"

                    entry = ForwardFrontierEntry(
                        handler_entry=handler_entry,
                        terminal_path=tuple(ordered),
                        forward_candidate=fw_candidate,
                        candidate_succ=fw_candidate_succ,
                        shared_entry=shared_entry,
                        return_block=return_block,
                        suffix_serials=suffix_serials_tuple,
                        semantic_action=semantic_frontier.action,
                        carrier_source_kind=carrier_kind,
                        proof_status=proof_status,
                        notes="; ".join(notes_parts) if notes_parts else "",
                        state_const_written=carrier_const,
                    )
                    forward_frontier_entries.append(entry)

                # Phase 2: Reject shared candidates (frequency > 1)
                for entry in forward_frontier_entries:
                    if (
                        entry.proof_status == "resolved"
                        and entry.forward_candidate is not None
                        and candidate_frequency.get(entry.forward_candidate, 0) > 1
                    ):
                        # Mutate via replacement (frozen dataclass)
                        idx = forward_frontier_entries.index(entry)
                        forward_frontier_entries[idx] = ForwardFrontierEntry(
                            handler_entry=entry.handler_entry,
                            terminal_path=entry.terminal_path,
                            forward_candidate=entry.forward_candidate,
                            candidate_succ=entry.candidate_succ,
                            shared_entry=entry.shared_entry,
                            return_block=entry.return_block,
                            suffix_serials=entry.suffix_serials,
                            semantic_action=entry.semantic_action,
                            carrier_source_kind=entry.carrier_source_kind,
                            proof_status="unresolved",
                            notes="shared candidate (freq=%d)" % candidate_frequency[
                                entry.forward_candidate
                            ],
                            state_const_written=entry.state_const_written,
                        )

                # --- Structured per-handler diagnostic ---
                resolved_entries = [
                    e for e in forward_frontier_entries if e.proof_status == "resolved"
                ]
                unresolved_entries = [
                    e for e in forward_frontier_entries if e.proof_status != "resolved"
                ]

                logger.info(
                    "PTS forward-frontier: %d handler entries, %d resolved, %d unresolved, "
                    "suffix=blk[%d]->blk[%d] (%d blocks), semantic=%s",
                    len(forward_frontier_entries),
                    len(resolved_entries),
                    len(unresolved_entries),
                    shared_entry,
                    return_block,
                    len(suffix_serials_tuple),
                    semantic_frontier.action.value,
                )

                for entry in forward_frontier_entries:
                    logger.info(
                        "PTS forward-frontier entry: handler=blk[%d] candidate=blk[%s] "
                        "succ=blk[%s] carrier=%s proof=%s semantic=%s notes=%s",
                        entry.handler_entry,
                        entry.forward_candidate,
                        entry.candidate_succ,
                        entry.carrier_source_kind.value,
                        entry.proof_status,
                        entry.semantic_action.value,
                        entry.notes or "<none>",
                    )

                # --- Group candidates by (shared_entry, return_block, suffix) ---
                group_key = (
                    shared_entry,
                    return_block,
                    frozenset(suffix_serials_tuple),
                )
                group_resolved = [
                    e for e in forward_frontier_entries if e.proof_status == "resolved"
                ]
                logger.info(
                    "PTS forward-frontier group (%d, %d, %d-block suffix): "
                    "%d resolved candidates, %d total entries, "
                    "min_anchors=%d, would_emit=%s",
                    group_key[0],
                    group_key[1],
                    len(suffix_serials_tuple),
                    len(group_resolved),
                    len(forward_frontier_entries),
                    _MIN_TERMINAL_ANCHORS_FOR_PRIVATIZATION,
                    (
                        len(group_resolved) >= _MIN_TERMINAL_ANCHORS_FOR_PRIVATIZATION
                        and semantic_frontier.action
                        == TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX
                    ),
                )

                # --- Shared corridor diagnostic ---
                corridor_infos: list[SharedCorridorInfo] = []
                suffix_group_decisions: list[SuffixGroupDecision] = []
                if cfg_frontier is not None and forward_frontier_entries:
                    corridor_info = _discover_shared_corridor(
                        fg=fg,
                        shared_entry_serial=shared_entry,
                        suffix_serials=suffix_serials_tuple,
                        full_infra=full_infra,
                        forward_entries=forward_frontier_entries,
                    )
                    corridor_infos.append(corridor_info)

                    if logger.debug_on:
                        logger.debug(
                            "[corridor-diag] shape=%s len=%d handlers=%d fan_in=%d "
                            "carrier_in_corridor=%s clonable=%s rec=%s "
                            "corridor_blocks=%s notes=%s",
                            corridor_info.corridor_shape.value,
                            corridor_info.corridor_length,
                            corridor_info.handler_count,
                            corridor_info.entry_fan_in,
                            corridor_info.carrier_in_corridor,
                            corridor_info.clonable,
                            corridor_info.recommendation.value,
                            corridor_info.corridor_blocks,
                            corridor_info.notes,
                        )

                    # INFO-level summary
                    logger.info(
                        "[corridor-diag] shared_entry=blk[%d] corridor=%s shape=%s "
                        "len=%d handlers=%d clonable=%s rec=%s",
                        corridor_info.shared_entry,
                        [("blk[%d]" % s) for s in corridor_info.corridor_blocks],
                        corridor_info.corridor_shape.value,
                        corridor_info.corridor_length,
                        corridor_info.handler_count,
                        corridor_info.clonable,
                        corridor_info.recommendation.value,
                    )

                    # --- Suffix group decision table ---
                    decision = _compute_suffix_group_decision(
                        forward_entries=forward_frontier_entries,
                        corridor_info=corridor_info,
                        semantic_action=semantic_frontier.action
                        if semantic_frontier
                        else TerminalLoweringAction.NO_ACTION,
                    )
                    suffix_group_decisions.append(decision)

                    logger.info(
                        "[decision-table] shared_entry=blk[%d] handlers=%d "
                        "bucket=%s carriers=%s state_const=%s "
                        "resolved=%d unresolved=%d "
                        "clonable=%s should_emit=%s reasons=%s",
                        decision.shared_entry,
                        decision.handler_count,
                        decision.carrier_bucket.value,
                        decision.carrier_source_kinds,
                        decision.has_state_const_carrier,
                        decision.proof_resolved_count,
                        decision.proof_unresolved_count,
                        decision.clonable,
                        decision.should_emit,
                        decision.rejection_reasons,
                    )

                # EMISSION DISABLED — PTS modifications poison PlanFragment contract checker.

        if not modifications:
            return None

        # Claim BST node blocks as influenced.
        owned_blocks.update(bst_node_blocks)

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=len(all_handlers),
            transitions_resolved=resolved_count,
            blocks_freed=len(bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=[],
            expected_benefit=benefit,
            risk_score=0.1,
            # Store ledger and bookkeeping for diagnostics.
            # hidden_processed: set of hidden handler serials processed in Pass 2.
            metadata={
                "pass0_redirect_ledger": pass0_ledger,
                "linearized_blocks": linearized_blocks,
                "bst_rootwalk_targets": bst_rootwalk_targets,
                "hidden_processed": hidden_processed,
                "resolved_transitions": set(owned_transitions),
                "handler_paths": all_handler_paths,
                "handler_entry_serials": set(all_handlers.keys()),
                "terminal_exit_blocks": terminal_exit_blocks,
                "dispatcher_serial": dispatcher_serial,
                "forbidden_blocks": forbidden_blocks,
                "exit_blocks": exit_blocks,
                "pre_header_serial": pre_header_serial,
                "private_terminal_suffix_count": private_suffix_count,
                "forward_frontier_entries": forward_frontier_entries,
                "corridor_infos": corridor_infos,
                "suffix_group_decisions": suffix_group_decisions,
            },
        )
