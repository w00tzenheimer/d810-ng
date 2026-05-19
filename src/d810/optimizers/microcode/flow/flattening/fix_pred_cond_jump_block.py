"""FixPredecessorOfConditionalJumpBlock - optimized with caching.

Detect if a predecessor of a conditional block always takes the same path
and patch it. Works for O-LLVM style control flow flattening.

Performance optimizations (merged from v2):
1. Cache predecessor analysis results - avoids re-tracing same paths
2. Lazy logging - avoid formatting strings when logging disabled
3. State var repr caching - avoid repeated string formatting

Architecture:
Uses deferred CFG modification pattern to avoid race conditions.
All analysis happens first, then modifications are applied atomically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from d810.core.typing import Optional

import ida_hexrays

from d810.core import getLogger
from d810.core.bits import unsigned_to_signed
from d810.cfg.fix_predecessor_classification import (
    FixPredecessorBucket,
    FixPredecessorClassification,
    classify_predecessor_modification,
)
from d810.cfg.fix_predecessor_planning import (
    FixPredecessorCloneAsGotoDecision,
    FixPredecessorCloneAsGotoFromBranchArmDecision,
    FixPredecessorOutcome,
    plan_fix_predecessor_clone_as_goto,
    plan_fix_predecessor_clone_from_branch_arm,
)
from d810.cfg.flowgraph import FlowGraph
from d810.hexrays.mutation.cfg_mutations import (
    make_2way_block_goto)
from d810.hexrays.mutation.cfg_verify import (
    safe_verify)
from d810.hexrays.mutation.cfg_mutations import (
    update_blk_successor)
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.hexrays.utils.hexrays_formatters import (
    dump_microcode_for_debug,
    format_minsn_t,
    maturity_to_string,
)
from d810.evaluator.hexrays_microcode.tracker import MopTracker
from d810.recon.flow.dispatcher_detection import (
    DispatcherCache,
    DispatcherType,
)
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.flow.handler import FlowRulePriority
from d810.evaluator.hexrays_microcode.tracker import get_all_possibles_values

unflat_logger = getLogger("D810.unflat")

JMP_OPCODE_HANDLED = [
    ida_hexrays.m_jnz, ida_hexrays.m_jz,
    ida_hexrays.m_jae, ida_hexrays.m_jb,
    ida_hexrays.m_ja, ida_hexrays.m_jbe,
    ida_hexrays.m_jge, ida_hexrays.m_jg,
    ida_hexrays.m_jl, ida_hexrays.m_jle
]


class PredecessorAnalysisCache:
    """Cache for predecessor analysis results.

    Key insight from profiling: The same predecessor paths are traced
    repeatedly across passes. Caching the results provides significant speedup.

    Cache key: (entry_ea, blk_serial, pred_serial, state_var_repr, maturity)
    Cache value: list of possible state values for this predecessor
    """

    def __init__(self, max_size: int = 10000):
        self._cache: dict[tuple, list[int]] = {}
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def _make_key(
        self,
        mba: ida_hexrays.mba_t,
        blk_serial: int,
        pred_serial: int,
        state_var_repr: str,
        maturity: int
    ) -> tuple:
        """Create cache key using mba.entry_ea as stable function identifier."""
        return (mba.entry_ea, blk_serial, pred_serial, state_var_repr, maturity)

    def get(
        self,
        mba: ida_hexrays.mba_t,
        blk_serial: int,
        pred_serial: int,
        state_var_repr: str,
        maturity: int
    ) -> Optional[list]:
        """Get cached predecessor values, or None if not cached."""
        key = self._make_key(mba, blk_serial, pred_serial, state_var_repr, maturity)
        result = self._cache.get(key)
        if result is not None:
            self._hits += 1
        else:
            self._misses += 1
        return result

    def put(
        self,
        mba: ida_hexrays.mba_t,
        blk_serial: int,
        pred_serial: int,
        state_var_repr: str,
        maturity: int,
        values: list
    ) -> None:
        """Cache predecessor values."""
        if len(self._cache) >= self._max_size:
            # Simple eviction: clear half the cache
            keys_to_remove = list(self._cache.keys())[:self._max_size // 2]
            for k in keys_to_remove:
                del self._cache[k]

        key = self._make_key(mba, blk_serial, pred_serial, state_var_repr, maturity)
        self._cache[key] = values

    def invalidate_for_mba(self, mba: ida_hexrays.mba_t) -> None:
        """Invalidate all cache entries for a given mba (after CFG modification)."""
        entry_ea = mba.entry_ea
        keys_to_remove = [k for k in self._cache if k[0] == entry_ea]
        for k in keys_to_remove:
            del self._cache[k]

    def stats(self) -> dict:
        """Return cache statistics."""
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total > 0 else 0,
            "size": len(self._cache),
        }


# Global cache instance (shared across transform for performance)
_pred_analysis_cache = PredecessorAnalysisCache()


def get_cache_stats() -> dict:
    """Get statistics from the global predecessor analysis cache."""
    return _pred_analysis_cache.stats()


def clear_cache() -> None:
    """Clear the global predecessor analysis cache."""
    global _pred_analysis_cache
    _pred_analysis_cache = PredecessorAnalysisCache()


class PredecessorModificationType(Enum):
    """Type of modification to apply to a predecessor."""
    ALWAYS_TAKEN = auto()  # Jump is always taken -> redirect to jump target
    NEVER_TAKEN = auto()   # Jump is never taken -> redirect to fallthrough


@dataclass
class PredecessorModification:
    """Represents a queued modification for a predecessor of a conditional block."""
    mod_type: PredecessorModificationType
    pred_serial: int          # Predecessor block to modify
    cond_block_serial: int    # The conditional block being analyzed
    target_serial: int        # Target serial to redirect to
    description: str = ""


class _BranchOperandRef:
    """Tiny adapter exposing a ``block_num`` attribute for a branch target.

    Used only inside the classification-snapshot path so
    :func:`d810.cfg.fix_predecessor_planning.infer_conditional_target`
    can resolve the explicit jump arm from the live tail.
    """

    __slots__ = ("block_num",)

    def __init__(self, block_num: int) -> None:
        self.block_num = int(block_num)


def _snapshot_cfg_for_classification(
    mba: ida_hexrays.mba_t,
) -> tuple[FlowGraph, set[int]]:
    """Build a CFG snapshot tuned for FixPredecessor classification.

    Mirrors :func:`d810.optimizers.microcode.flow.context._flowgraph_from_live_mba`
    but additionally captures the tail ``d`` operand for 2-way conditional
    blocks via ``operand_slots``.  Without that, planner-side
    :func:`infer_conditional_target` always returns ``None`` and every
    classification falls into ``unsupported_shape``.
    """
    from d810.cfg.flowgraph import (
        BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot,
    )

    blocks: dict[int, BlockSnapshot] = {}
    side_effect_blocks: set[int] = set()

    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        succs = list(blk.succset)
        preds = list(blk.predset)

        insn = blk.head
        while insn is not None:
            if insn.has_side_effects():
                side_effect_blocks.add(i)
                break
            insn = insn.next

        insns: tuple[InsnSnapshot, ...] = ()
        tail = blk.tail
        if tail is not None:
            l_snap = r_snap = None
            if tail.l and tail.l.t != 0:
                stkoff = None
                if tail.l.t == 3 and hasattr(tail.l, "s") and tail.l.s:  # mop_S
                    stkoff = tail.l.s.off
                l_snap = MopSnapshot(t=tail.l.t, size=tail.l.size, stkoff=stkoff)
            if tail.r and tail.r.t != 0:
                val = None
                if tail.r.t == 2:  # mop_n
                    val = (
                        tail.r.nnn.value
                        if hasattr(tail.r, "nnn") and tail.r.nnn
                        else None
                    )
                r_snap = MopSnapshot(t=tail.r.t, size=tail.r.size, value=val)
            operand_slots: tuple = ()
            if (
                tail.d is not None
                and tail.d.t == ida_hexrays.mop_b
            ):
                operand_slots = (("d", _BranchOperandRef(tail.d.b)),)
            insns = (
                InsnSnapshot(
                    opcode=tail.opcode,
                    ea=tail.ea,
                    operands=(),
                    l=l_snap,
                    r=r_snap,
                    operand_slots=operand_slots,
                ),
            )

        blocks[i] = BlockSnapshot(
            serial=i,
            block_type=blk.type,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=blk.flags,
            start_ea=blk.start,
            insn_snapshots=insns,
        )

    return (
        FlowGraph(blocks=blocks, entry_serial=0, func_ea=mba.entry_ea),
        side_effect_blocks,
    )


def _modification_outcome(
    modification: PredecessorModification,
) -> FixPredecessorOutcome:
    return (
        FixPredecessorOutcome.ALWAYS_TAKEN
        if modification.mod_type == PredecessorModificationType.ALWAYS_TAKEN
        else FixPredecessorOutcome.NEVER_TAKEN
    )


def plan_predecessor_modification_clone_as_goto(
    cfg: FlowGraph,
    modification: PredecessorModification,
) -> FixPredecessorCloneAsGotoDecision:
    """Project a live FixPredecessor modification into CFG planning intent.

    This adapter is intentionally read-only.  It lets tests and diagnostics
    compare the legacy queued modification against the backend-neutral
    one-way clone-as-goto shape before any shared-engine executor path is
    selected.  Use :func:`plan_predecessor_modification_clone_from_branch_arm`
    for the 2-way predecessor branch-arm sibling shape.
    """
    return plan_fix_predecessor_clone_as_goto(
        cfg,
        pred_serial=modification.pred_serial,
        conditional_serial=modification.cond_block_serial,
        selected_target_serial=modification.target_serial,
        outcome=_modification_outcome(modification),
        description=modification.description,
    )


def plan_predecessor_modification_clone_from_branch_arm(
    cfg: FlowGraph,
    modification: PredecessorModification,
    *,
    side_effect_blocks: frozenset[int] = frozenset(),
) -> FixPredecessorCloneAsGotoFromBranchArmDecision:
    """Project a live FixPredecessor modification into the 2-way arm shape.

    Read-only sibling of
    :func:`plan_predecessor_modification_clone_as_goto`.  Returns the
    branch-arm planner's decision for parity comparisons against the legacy
    live rule's ``change_2way_block_conditional_successor`` path.
    """
    return plan_fix_predecessor_clone_from_branch_arm(
        cfg,
        pred_serial=modification.pred_serial,
        conditional_serial=modification.cond_block_serial,
        selected_target_serial=modification.target_serial,
        outcome=_modification_outcome(modification),
        side_effect_blocks=side_effect_blocks,
        description=modification.description,
    )


class FixPredecessorOfConditionalJumpBlock(GenericUnflatteningRule):
    """Detect if a predecessor of a conditional block always takes the same path and patch it.

    Works for O-LLVM style control flow flattening.

    Gate operation mode: ``GATE_ONLY``
    -----------------------------------
    Uses :meth:`FlowMaturityContext.evaluate_fix_predecessor_gate` in
    :meth:`check_if_rule_should_be_used`.  Gate is always enforced (rule
    skipped when ``allowed=False``), with no planner/strategy influence.

    See :class:`~d810.core.gate_modes.GateOperationMode`.

    Architecture:
    Uses deferred modification pattern:
    1. analyze_blk() queues all needed modifications (stores only serials)
    2. _apply_queued_modifications() applies them after analysis completes
    3. No live pointers stored across CFG modifications

    Gate policy — AUDIT_ONLY (targeted rule, no bulk safeguard):
    This is a per-block targeted rule, NOT a bulk CFG reconstruction pass.
    The ``should_apply_bulk_cfg_modifications`` bulk safeguard is intentionally
    absent — it is designed for batch dispatcher rewrites and would be too
    aggressive for small, targeted predecessor patches. This rule uses its
    own structural gate via ``flow_context.evaluate_fix_predecessor_gate()``.
    """

    DESCRIPTION = "Detect if a predecessor of a conditional block always takes the same path and patch it (works for O-LLVM style control flow flattening)"
    PRIORITY = FlowRulePriority.PREDICATE_PREDECESSOR_FIX
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2
    ]
    DEFAULT_MAX_PASSES = 100

    def __init__(self):
        super().__init__()
        self._state_var_repr_cache: dict[int, str] = {}  # blk_serial -> repr
        self._pending_modifications: list[PredecessorModification] = []
        self._modifier: Optional[DeferredGraphModifier] = None
        # Diagnostic-only classification records.  Populated per optimize()
        # pass *before* modifications are applied so the topology reflects
        # the pre-modification CFG.  Read by the apply path to opt admitted
        # branch-arm shapes into the engine path.
        self._classifications: list[FixPredecessorClassification] = []
        # Per-modification classification lookup, keyed by ``id(mod)``.
        # Reset on every optimize() call alongside _pending_modifications so
        # stale entries from earlier passes are never read.
        self._classifications_by_mod_id: dict[int, FixPredecessorClassification] = {}
        # Diagnostic counters for the engine-path migration: number of
        # ``CloneConditionalAsGotoFromBranchArm`` emissions admitted by the
        # planner and the subset that the engine path successfully applied.
        # Reset on maturity change.
        self._branch_arm_engine_admissions: int = 0
        self._branch_arm_engine_applied: int = 0
        self._branch_arm_engine_failures: int = 0
        # Set when safe_verify fails -- prevents further processing on a
        # corrupted MBA that would cause IDA hangs.
        self._verify_failed: bool = False
        # Set when we hit a hard apply failure (e.g. duplicate->goto conversion
        # failure). Used to disable this rule for the current maturity to avoid
        # retry loops that keep growing the CFG with dead duplicates.
        self._critical_apply_failure: bool = False

    def _get_state_var_repr(self, blk: ida_hexrays.mblock_t) -> str:
        """Get cached string representation of the state variable being compared."""
        if blk.serial in self._state_var_repr_cache:
            return self._state_var_repr_cache[blk.serial]

        from d810.hexrays.utils.hexrays_formatters import format_mop_t
        rep = format_mop_t(blk.tail.l)
        self._state_var_repr_cache[blk.serial] = rep
        return rep

    def _get_dispatcher_analysis(self, blk: ida_hexrays.mblock_t):
        if self.flow_context is not None:
            analysis = self.flow_context.ensure_dispatcher_analysis()
            if analysis is not None:
                return analysis
        cache = DispatcherCache.get_or_create(blk.mba)
        return cache.analyze()

    def is_jump_taken(
        self,
        jmp_blk: ida_hexrays.mblock_t,
        pred_comparison_values: list[int]
    ) -> tuple[bool, bool]:
        """Determine if jump is always/never taken based on predecessor values.

        Returns: (is_always_taken, is_never_taken)
        """
        if len(pred_comparison_values) == 0:
            return False, False

        jmp_ins = jmp_blk.tail
        compared_value = jmp_ins.r.nnn.value
        compared_value_size = jmp_ins.r.size
        opcode = jmp_ins.opcode

        # Fast path for common opcodes (no signed conversion needed)
        if opcode == ida_hexrays.m_jnz:
            is_always = all(v != compared_value for v in pred_comparison_values)
            is_never = all(v == compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jz:
            is_always = all(v == compared_value for v in pred_comparison_values)
            is_never = all(v != compared_value for v in pred_comparison_values)
            return is_always, is_never

        # Unsigned comparisons
        if opcode == ida_hexrays.m_jae:
            is_always = all(v >= compared_value for v in pred_comparison_values)
            is_never = all(v < compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jb:
            is_always = all(v < compared_value for v in pred_comparison_values)
            is_never = all(v >= compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_ja:
            is_always = all(v > compared_value for v in pred_comparison_values)
            is_never = all(v <= compared_value for v in pred_comparison_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jbe:
            is_always = all(v <= compared_value for v in pred_comparison_values)
            is_never = all(v > compared_value for v in pred_comparison_values)
            return is_always, is_never

        # Signed comparisons - convert values once
        def to_signed(v):
            return unsigned_to_signed(v, compared_value_size)

        signed_compared = to_signed(compared_value)
        signed_values = [to_signed(v) for v in pred_comparison_values]

        if opcode == ida_hexrays.m_jg:
            is_always = all(sv > signed_compared for sv in signed_values)
            is_never = all(sv <= signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jge:
            is_always = all(sv >= signed_compared for sv in signed_values)
            is_never = all(sv < signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jl:
            is_always = all(sv < signed_compared for sv in signed_values)
            is_never = all(sv >= signed_compared for sv in signed_values)
            return is_always, is_never

        if opcode == ida_hexrays.m_jle:
            is_always = all(sv <= signed_compared for sv in signed_values)
            is_never = all(sv > signed_compared for sv in signed_values)
            return is_always, is_never

        return False, False

    def _analyze_predecessor(
        self,
        blk: ida_hexrays.mblock_t,
        pred_serial: int,
        op_compared: ida_hexrays.mop_t,
        state_var_repr: str,
        dispatcher_info
    ) -> tuple[list, bool]:
        """Analyze a single predecessor to find possible state values.

        Returns: (values_list, has_unknown)
        """
        # Check cache first
        cached = _pred_analysis_cache.get(
            self.mba, blk.serial, pred_serial, state_var_repr, self.mba.maturity
        )
        if cached is not None:
            has_unknown = None in cached
            values = [v for v in cached if v is not None]
            return values, has_unknown

        # Not cached - do the analysis
        cmp_variable_tracker = MopTracker(
            [op_compared], max_nb_block=100, max_path=1000,
            dispatcher_info=dispatcher_info
        )
        cmp_variable_tracker.reset()

        pred_blk = self.mba.get_mblock(pred_serial)
        pred_histories = cmp_variable_tracker.search_backward(
            pred_blk, pred_blk.tail
        )

        # P0: Resolve opaque table globals (mop_v operands in writable
        # segments with no write xrefs).  try_resolve_memory_mops() reads
        # concrete values from the IDB so that is_resolved() returns True.
        # The emulator's eval() handles mop_v natively via
        # is_never_written_var() + fetch_idb_value(), so no manual
        # add_mop_initial_value propagation is needed (and would crash
        # with EmulationException since define() rejects mop_v).
        cmp_variable_tracker.try_resolve_memory_mops()

        pred_values = get_all_possibles_values(pred_histories, [op_compared])
        values = [x[0] for x in pred_values]

        # Cache the result
        _pred_analysis_cache.put(
            self.mba, blk.serial, pred_serial, state_var_repr,
            self.mba.maturity, values
        )

        # Lazy logging - only format if enabled
        if unflat_logger.info_on:
            unflat_logger.info(
                "Pred %d has %d possible paths (%d different cst): %s",
                pred_serial, len(values), len(set(values)), values
            )

        has_unknown = None in values
        return [v for v in values if v is not None], has_unknown

    def sort_predecessors(self, blk: ida_hexrays.mblock_t):
        """Sort predecessors into always-taken, never-taken, and unknown lists."""
        pred_jmp_always_taken = []
        pred_jmp_never_taken = []
        pred_jmp_unk = []

        op_compared = ida_hexrays.mop_t(blk.tail.l)
        state_var_repr = self._get_state_var_repr(blk)
        blk_preset_list = list(blk.predset)

        # Determine dispatcher_info based on dispatcher type.
        # For CONDITIONAL_CHAIN (nested jnz/jz comparisons like Hodur, C2 frameworks):
        #   - DO NOT use dispatcher_info (set to None)
        #   - When MopTracker loops back through the dispatcher, it returns None/"unknown"
        #   - This prevents cascading unreachability where all predecessors get
        #     redirected based on a single initial state value
        #
        # For SWITCH_TABLE (O-LLVM, Tigress switch mode):
        #   - Could potentially use dispatcher_info to resume tracking
        #   - But None also works fine (just skips the resume optimization)
        analysis = self._get_dispatcher_analysis(blk)

        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "CONDITIONAL_CHAIN dispatcher detected - using dispatcher_info=None "
                    "to prevent cascading unreachability"
                )
        dispatcher_info = None

        for pred_serial in blk_preset_list:
            pred_values, has_unknown = self._analyze_predecessor(
                blk, pred_serial, op_compared, state_var_repr, dispatcher_info
            )

            pred_blk = self.mba.get_mblock(pred_serial)

            if has_unknown:
                pred_jmp_unk.append(pred_blk)
                continue

            is_jmp_always_taken, is_jmp_never_taken = self.is_jump_taken(
                blk, pred_values
            )

            if is_jmp_always_taken and is_jmp_never_taken:
                # Should never happen
                if unflat_logger.error_on:
                    unflat_logger.error(
                        "Logic error: '%s' is always taken and never taken from %d: %s",
                        format_minsn_t(blk.tail), pred_serial, pred_values
                    )
                pred_jmp_unk.append(pred_blk)
                continue

            if is_jmp_always_taken:
                if unflat_logger.info_on:
                    unflat_logger.info(
                        "Jump '%s' always taken from pred %d: %s",
                        format_minsn_t(blk.tail), pred_serial, pred_values
                    )
                pred_jmp_always_taken.append(pred_blk)

            if is_jmp_never_taken:
                if unflat_logger.info_on:
                    unflat_logger.info(
                        "Jump '%s' never taken from pred %d: %s",
                        format_minsn_t(blk.tail), pred_serial, pred_values
                    )
                pred_jmp_never_taken.append(pred_blk)

        return pred_jmp_always_taken, pred_jmp_never_taken, pred_jmp_unk

    def analyze_blk(self, blk: ida_hexrays.mblock_t) -> int:
        """Analyze a block and queue modifications for predecessors with known jump outcomes.

        Returns the number of modifications queued.
        """
        if blk.tail is None or blk.tail.opcode not in JMP_OPCODE_HANDLED:
            return 0
        if blk.tail.r.t != ida_hexrays.mop_n:
            return 0
        if blk.npred() < 2:
            # Single-predecessor conditional blocks are usually structured
            # control flow (loop/ladder checks), not flattened dispatchers.
            return 0
        for succ_serial in list(blk.succset):
            succ_blk = self.mba.get_mblock(int(succ_serial))
            if succ_blk is not None and succ_blk.nsucc() == 0:
                if unflat_logger.info_on:
                    unflat_logger.info(
                        "Skipping blk[%d]: conditional has terminal successor blk[%d]",
                        blk.serial,
                        int(succ_serial),
                    )
                return 0

        analysis = self._get_dispatcher_analysis(blk)
        # This rule is meant for predicate chains. On switch-table dispatchers
        # (jtbl) it tends to misclassify normal structured conditionals and can
        # create invalid CFG rewrites.
        if analysis.dispatcher_type == DispatcherType.SWITCH_TABLE:
            return 0
        if blk.serial not in analysis.dispatchers:
            return 0
        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            state_constants = tuple(
                int(value) for value in getattr(analysis, "state_constants", ()) or ()
            )
            compared_value = getattr(getattr(getattr(blk.tail, "r", None), "nnn", None), "value", None)
            if (
                compared_value is not None
                and state_constants
                and int(compared_value) == max(state_constants)
            ):
                if unflat_logger.info_on:
                    unflat_logger.info(
                        "Skipping blk[%d]: conditional-chain max-state terminal boundary 0x%X",
                        blk.serial,
                        int(compared_value),
                    )
                return 0

        # --- Terminal boundary guard ---
        # Skip blocks that sit on the BST-to-cleanup boundary.  Resolving
        # their predecessors causes terminal state writes to become redundant,
        # which IDA's DCE then removes, destroying loop-termination
        # information needed at later maturities (LVARS) to produce returns.
        if blk.serial in self.flow_context.get_terminal_cone_blocks():
            if unflat_logger.info_on:
                unflat_logger.info(
                    "Skipping blk[%d]: terminal boundary block", blk.serial,
                )
            return 0

        # NOTE: For CONDITIONAL_CHAIN dispatchers (nested jnz/jz comparisons),
        # this rule uses dispatcher_info=None to avoid cascading unreachability.
        # See sort_predecessors() for details on why this is necessary.
        if unflat_logger.info_on:
            unflat_logger.info(
                "Checking if block %d can be simplified: %s",
                blk.serial, format_minsn_t(blk.tail)
            )

        pred_jmp_always_taken, pred_jmp_never_taken, pred_jmp_unk = (
            self.sort_predecessors(blk)
        )

        if unflat_logger.info_on:
            unflat_logger.info(
                "Block %d has %d preds: %d always jmp, %d never jmp, %d unk",
                blk.serial, blk.npred(),
                len(pred_jmp_always_taken),
                len(pred_jmp_never_taken),
                len(pred_jmp_unk)
            )

        nb_queued = 0

        # Queue modifications for always-taken predecessors
        # Target: conditional jump target (blk.tail.d.b)
        for pred_blk in pred_jmp_always_taken:
            self._pending_modifications.append(PredecessorModification(
                mod_type=PredecessorModificationType.ALWAYS_TAKEN,
                pred_serial=pred_blk.serial,
                cond_block_serial=blk.serial,
                target_serial=blk.tail.d.b,  # Jump target
                description=f"pred {pred_blk.serial} always takes jump in block {blk.serial}"
            ))
            nb_queued += 1

            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Queued ALWAYS_TAKEN: pred %d -> cond block %d -> target %d",
                    pred_blk.serial, blk.serial, blk.tail.d.b
                )

        # Queue modifications for never-taken predecessors
        # Target: fallthrough (blk.nextb.serial)
        for pred_blk in pred_jmp_never_taken:
            self._pending_modifications.append(PredecessorModification(
                mod_type=PredecessorModificationType.NEVER_TAKEN,
                pred_serial=pred_blk.serial,
                cond_block_serial=blk.serial,
                target_serial=blk.nextb.serial,  # Fallthrough
                description=f"pred {pred_blk.serial} never takes jump in block {blk.serial}"
            ))
            nb_queued += 1

            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Queued NEVER_TAKEN: pred %d -> cond block %d -> fallthrough %d",
                    pred_blk.serial, blk.serial, blk.nextb.serial
                )

        return nb_queued

    def _apply_queued_modifications(self) -> int:
        """Apply all queued predecessor modifications.

        Returns the number of modifications successfully applied.
        """
        if not self._pending_modifications:
            return 0

        self._critical_apply_failure = False

        if unflat_logger.info_on:
            unflat_logger.info(
                "Applying %d queued predecessor modifications",
                len(self._pending_modifications)
            )

        applied_count = 0

        # Group modifications by conditional block for better debugging
        mods_by_cond_block: dict[int, list[PredecessorModification]] = {}
        for mod in self._pending_modifications:
            if mod.cond_block_serial not in mods_by_cond_block:
                mods_by_cond_block[mod.cond_block_serial] = []
            mods_by_cond_block[mod.cond_block_serial].append(mod)

        # Process each conditional block's modifications
        for cond_block_serial, mods in mods_by_cond_block.items():
            # Re-fetch the conditional block (fresh pointer)
            cond_blk = self.mba.get_mblock(cond_block_serial)
            if cond_blk is None:
                unflat_logger.warning(
                    "Conditional block %d not found, skipping %d modifications",
                    cond_block_serial, len(mods)
                )
                continue

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba, self.log_dir,
                    f"{self.cur_maturity_pass}_{cond_block_serial}_before_pred_fix"
                )

            # Apply modifications for this conditional block
            for mod in mods:
                try:
                    if self._apply_single_modification(mod, cond_blk):
                        applied_count += 1
                except Exception as e:
                    unflat_logger.error(
                        "Exception applying modification %s: %s",
                        mod.description, e
                    )
                    import traceback
                    unflat_logger.error("Traceback: %s", traceback.format_exc())

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba, self.log_dir,
                    f"{self.cur_maturity_pass}_{cond_block_serial}_after_pred_fix"
                )

        # Clear pending modifications after applying.  The per-mod
        # classification lookup is keyed by ``id(mod)``; since the pending
        # mods are about to be discarded, the id keys would become dangling
        # so the lookup table must be cleared in the same step.
        self._pending_modifications.clear()
        self._classifications_by_mod_id.clear()

        if unflat_logger.info_on:
            unflat_logger.info(
                "Applied %d predecessor modifications successfully",
                applied_count
            )

        if self._critical_apply_failure and applied_count == 0:
            self._verify_failed = True
            unflat_logger.warning(
                "Disabling FixPredecessorOfConditionalJumpBlock for this maturity: "
                "critical predecessor redirection failures with zero successful "
                "patches (prevents retry loops and CFG growth)"
            )

        return applied_count

    def _orphan_block(self, block: ida_hexrays.mblock_t | None, reason: str = "") -> None:
        """Best-effort cleanup for a partially-created or now-unreachable block."""
        if block is None:
            return
        try:
            mba = self.mba
            # Remove this block from all successors' predsets.
            for succ_serial in list(block.succset):
                succ_blk = mba.get_mblock(succ_serial)
                if succ_blk is not None:
                    succ_blk.predset._del(block.serial)
                    if succ_blk.serial != mba.qty - 1:
                        succ_blk.mark_lists_dirty()
                block.succset._del(succ_serial)

            # Remove incoming edges from predecessors.
            for pred_serial in list(block.predset):
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is not None:
                    pred_blk.succset._del(block.serial)
                    if pred_blk.serial != mba.qty - 1:
                        pred_blk.mark_lists_dirty()
                block.predset._del(pred_serial)

            block.type = ida_hexrays.BLT_0WAY
            if block.tail is not None:
                block.make_nop(block.tail)
            block.flags &= ~ida_hexrays.MBL_GOTO
            block.mark_lists_dirty()
            mba.mark_chains_dirty()
        except Exception as e:
            unflat_logger.debug(
                "Best-effort orphan cleanup failed for block %s (%s): %s",
                getattr(block, "serial", "?"),
                reason,
                e,
            )

    def _clone_conditional_block(self, cond_blk: ida_hexrays.mblock_t) -> ida_hexrays.mblock_t | None:
        """Clone a 2-way conditional block for predecessor redirection.

        We intentionally avoid cfg_utils.duplicate_block() here because its
        conditional path creates an extra default child via insert_nop_blk(),
        and that extra structural edit can invalidate block serial/pointer
        assumptions in this rule's hot path.
        """
        if cond_blk.nsucc() != 2:
            unflat_logger.warning(
                "Cannot clone non-2way conditional block %d (type=%d, nsucc=%d, succset=%s)",
                cond_blk.serial,
                cond_blk.type,
                cond_blk.nsucc(),
                [x for x in cond_blk.succset],
            )
            return None

        cloned = self.mba.copy_block(cond_blk, self.mba.qty - 1)
        # MBL_KEEP (0x10000) so optimize_global's structural sweep doesn't
        # cull this clone -- mba.copy_block does not inherit it.  See memory
        # ``ida_optimize_global_cfg_kill``.
        if cloned is not None:
            try:
                cloned.flags |= 0x10000
            except Exception:
                pass
        cloned = self.mba.get_mblock(cloned.serial)
        if cloned is None:
            return None

        # copy_block clones predecessor links from cond_blk. Those links do not
        # exist in predecessor succsets, so they must be cleared for consistency.
        for pred_serial in list(cloned.predset):
            cloned.predset._del(pred_serial)

        cloned.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        return cloned

    def _try_apply_branch_arm_engine_path(
        self,
        mod: PredecessorModification,
        cond_blk: ida_hexrays.mblock_t,
    ) -> bool:
        """Apply a modification through the engine path if admitted.

        Returns ``True`` on success (caller should NOT run the legacy path),
        ``False`` if the engine path is not eligible OR if it failed and the
        caller should fall back to the legacy clone + ``update_blk_successor``
        sequence.  Increments diagnostic counters either way.
        """
        if self._modifier is None:
            return False
        classification = self._classifications_by_mod_id.get(id(mod))
        if classification is None:
            return False
        if not classification.matches_clone_conditional_as_goto_from_branch_arm:
            return False

        try:
            engine_ok = (
                self._modifier._apply_clone_conditional_as_goto_from_branch_arm(
                    source_blk=cond_blk,
                    pred_serial=mod.pred_serial,
                    goto_target_serial=mod.target_serial,
                )
            )
        except Exception as exc:
            self._branch_arm_engine_failures += 1
            unflat_logger.warning(
                "fix_pred engine path raised for pred=%d cond=%d target=%d: %s; "
                "falling back to legacy",
                mod.pred_serial,
                mod.cond_block_serial,
                mod.target_serial,
                exc,
            )
            return False

        if not engine_ok:
            self._branch_arm_engine_failures += 1
            unflat_logger.warning(
                "fix_pred engine path declined pred=%d cond=%d target=%d at "
                "apply-time; falling back to legacy",
                mod.pred_serial,
                mod.cond_block_serial,
                mod.target_serial,
            )
            return False

        self._branch_arm_engine_applied += 1
        if unflat_logger.debug_on:
            unflat_logger.debug(
                "fix_pred engine path applied: "
                "clone_conditional_as_goto_from_branch_arm pred=%d cond=%d target=%d",
                mod.pred_serial,
                mod.cond_block_serial,
                mod.target_serial,
            )
        return True

    def _apply_single_modification(
        self,
        mod: PredecessorModification,
        cond_blk: ida_hexrays.mblock_t
    ) -> bool:
        """Apply a single predecessor modification.

        Args:
            mod: The modification to apply
            cond_blk: Fresh pointer to the conditional block

        Returns:
            True if successful, False otherwise
        """
        # Re-fetch predecessor block (fresh pointer)
        pred_blk = self.mba.get_mblock(mod.pred_serial)
        if pred_blk is None:
            unflat_logger.warning(
                "Predecessor block %d not found for modification %s",
                mod.pred_serial, mod.description
            )
            return False

        # Re-fetch conditional block too. Prior modifications can stale pointers.
        cond_blk = self.mba.get_mblock(mod.cond_block_serial)
        if cond_blk is None:
            unflat_logger.warning(
                "Conditional block %d not found for modification %s",
                mod.cond_block_serial, mod.description
            )
            return False

        if unflat_logger.debug_on:
            unflat_logger.debug(
                "Applying modification: %s (pred %d -> cond %d -> target %d)",
                mod.mod_type.name, mod.pred_serial,
                mod.cond_block_serial, mod.target_serial
            )

        # Engine path: when the branch-arm planner admits this shape, emit
        # CloneConditionalAsGotoFromBranchArm via the deferred modifier so
        # the migration is observable through the typed primitive instead of
        # untyped clone + update_blk_successor.  For ``pred_arm == 1`` the
        # net mutation is identical to the legacy path
        # (``change_2way_block_conditional_successor`` is the shared low-level
        # helper).  Falls back to legacy on engine-path failure as defense in
        # depth; ``arm == 0`` cases are not admitted by the planner so they
        # never enter this branch.
        if self._try_apply_branch_arm_engine_path(mod, cond_blk):
            return True

        try:
            new_jmp_block = None
            new_jmp_block = self._clone_conditional_block(cond_blk)
            if new_jmp_block is None:
                unflat_logger.warning(
                    "Failed to clone conditional block %d for modification %s",
                    mod.cond_block_serial,
                    mod.description
                )
                self._critical_apply_failure = True
                return False

            # Convert 2-way block to 1-way goto pointing to target.
            if not make_2way_block_goto(new_jmp_block, mod.target_serial, verify=False):
                unflat_logger.warning(
                    "Failed to convert block %d to goto %d "
                    "(type=%d, nsucc=%d, succset=%s, nextb=%s)",
                    new_jmp_block.serial,
                    mod.target_serial,
                    new_jmp_block.type,
                    new_jmp_block.nsucc(),
                    [x for x in new_jmp_block.succset],
                    new_jmp_block.nextb.serial if new_jmp_block.nextb is not None else None,
                )
                self._critical_apply_failure = True
                # Conversion failed after duplication; aggressively clean up the
                # newly created blocks to avoid CFG growth across retries.
                self._orphan_block(new_jmp_block, "make_2way_block_goto failure (new_jmp_block)")
                return False

            # Update predecessor to point to new block instead of original conditional block
            if not update_blk_successor(pred_blk, mod.cond_block_serial, new_jmp_block.serial, verify=False):
                unflat_logger.warning(
                    "Failed to update predecessor %d: %d -> %d",
                    mod.pred_serial, mod.cond_block_serial, new_jmp_block.serial
                )
                self._critical_apply_failure = True
                # No predecessor points to new_jmp_block yet; remove it to avoid
                # leaving dead duplicate blocks around.
                self._orphan_block(new_jmp_block, "update_blk_successor failure")
                return False

            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Successfully applied: created block %d, redirected pred %d",
                    new_jmp_block.serial, mod.pred_serial
                )

            return True

        except Exception as e:
            unflat_logger.error(
                "Exception in _apply_single_modification for %s: %s",
                mod.description, e
            )
            self._critical_apply_failure = True
            return False

    def _classify_pending_modifications(self) -> None:
        """Snapshot the live CFG once and classify every queued modification.

        Diagnostic-only.  Runs *before* any modification is applied so the
        bucket assignments reflect pre-rewrite topology.  The classifications
        list is appended to across blocks in a single ``optimize()`` pass and
        is reset at the next call to ``optimize()``.
        """
        if not self._pending_modifications:
            return

        try:
            cfg, side_effect_blocks = _snapshot_cfg_for_classification(self.mba)
        except Exception as exc:  # pragma: no cover - diagnostic only
            unflat_logger.debug(
                "Skipping FixPredecessor classification: snapshot failed: %s",
                exc,
            )
            return

        side_effect_frozen = frozenset(side_effect_blocks)
        for mod in self._pending_modifications:
            outcome = (
                FixPredecessorOutcome.ALWAYS_TAKEN
                if mod.mod_type == PredecessorModificationType.ALWAYS_TAKEN
                else FixPredecessorOutcome.NEVER_TAKEN
            )
            try:
                classification = classify_predecessor_modification(
                    cfg,
                    pred_serial=mod.pred_serial,
                    conditional_serial=mod.cond_block_serial,
                    selected_target_serial=mod.target_serial,
                    outcome=outcome,
                    side_effect_blocks=side_effect_frozen,
                    description=mod.description,
                )
            except Exception as exc:  # pragma: no cover - diagnostic only
                unflat_logger.debug(
                    "Skipping classification for %s: %s",
                    mod.description, exc,
                )
                continue

            self._classifications.append(classification)
            self._classifications_by_mod_id[id(mod)] = classification
            if classification.matches_clone_conditional_as_goto_from_branch_arm:
                self._branch_arm_engine_admissions += 1
            if unflat_logger.debug_on:
                rejection = (
                    classification.planner_rejection.value
                    if classification.planner_rejection is not None
                    else "accepted"
                )
                unflat_logger.debug(
                    "fix_pred bucket: %s pred=%d cond=%d target=%d "
                    "outcome=%s pred_topology=%s arm=%s "
                    "cond_succs=%d cond_preds=%d target_preds=%d "
                    "side_effects=%s matches_one_way=%s matches_arm=%s "
                    "planner=%s",
                    classification.bucket.value,
                    classification.selected_predecessor,
                    classification.target_conditional_block,
                    classification.selected_target,
                    classification.outcome.value,
                    classification.predecessor_topology.value,
                    classification.predecessor_arm,
                    classification.conditional_target_successor_count,
                    classification.conditional_target_predecessor_count,
                    classification.selected_target_predecessor_count,
                    classification.conditional_has_body_side_effects,
                    classification.matches_clone_conditional_as_goto,
                    classification.matches_clone_conditional_as_goto_from_branch_arm,
                    rejection,
                )

    @property
    def classifications(self) -> tuple[FixPredecessorClassification, ...]:
        """Diagnostic classification records for the current maturity pass.

        Accumulates across blocks within a maturity pass and is reset on
        maturity change.  Read-only — apply path never references this.
        """
        return tuple(self._classifications)

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Main optimization entry point.

        Architecture:
        1. Clear pending modifications from previous pass
        2. Check if rule should be used
        3. Analyze block and queue modifications
        4. Apply all queued modifications atomically
        5. Clean up and verify
        """
        self.mba = blk.mba

        # Initialize modifier if needed
        if self._modifier is None:
            self._modifier = DeferredGraphModifier(self.mba)

        # Clear pending modifications from previous pass.  Classifications
        # are intentionally retained across optimize() calls within the same
        # maturity pass and cleared on maturity change (see
        # check_if_rule_should_be_used) so corpus diagnostics can aggregate.
        self._pending_modifications.clear()

        if not self.check_if_rule_should_be_used(blk):
            return 0

        # Phase 1: Analysis - queue all modifications
        nb_queued = self.analyze_blk(blk)

        if nb_queued == 0:
            return 0

        # Phase 1.5: Diagnostic classification (read-only).
        # Captures topology before any modification is applied.
        self._classify_pending_modifications()

        # NOTE: No bulk-CFG safeguard here. FixPredecessor makes targeted
        # per-block edge redirects (not bulk CFG rewrites like Hodur).
        # It already has two safety gates:
        #   1. flow_context.evaluate_fix_predecessor_gate() in check_if_rule_should_be_used
        #   2. Per-block structural checks (tail opcode, maturity, max passes)
        # should_apply_bulk_cfg_modifications is too aggressive for small dispatchers
        # like abc_xor_dispatch where resolving 1-2 predecessors IS the solution.
        # G2: audit trail via structured logging only.
        unflat_logger.info(
            "fix_pred gate: applying %d modifications for block %d",
            nb_queued, blk.serial,
        )

        # Phase 2: Apply - execute all modifications
        self.last_pass_nb_patch_done = self._apply_queued_modifications()

        if self.last_pass_nb_patch_done > 0:
            # Invalidate cache after CFG modification
            _pred_analysis_cache.invalidate_for_mba(self.mba)

            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
            try:
                safe_verify(
                    self.mba,
                    "optimizing FixPredecessorOfConditionalJumpBlock",
                    logger_func=unflat_logger.error
                )
            except RuntimeError:
                self._verify_failed = True
                unflat_logger.warning(
                    "MBA verify failed in FixPredecessorOfConditionalJumpBlock "
                    "-- disabling rule to prevent further corruption"
                )
                # Return patch count so caller knows MBA was modified
                return self.last_pass_nb_patch_done

        return self.last_pass_nb_patch_done

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        """Check if this rule should be applied to the given block."""
        if self._verify_failed:
            unflat_logger.debug(
                "Skipping rule -- MBA verify previously failed"
            )
            return False

        if self.cur_maturity != self.mba.maturity:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
            self._state_var_repr_cache.clear()  # Clear cache on maturity change
            self._verify_failed = False  # Reset on maturity change
            self._classifications.clear()  # Reset diagnostic records
            self._classifications_by_mod_id.clear()
            self._branch_arm_engine_admissions = 0
            self._branch_arm_engine_applied = 0
            self._branch_arm_engine_failures = 0

        if self.cur_maturity not in self.maturities:
            # Gate: maturity filter — normal operation, not a bypass.
            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Gate skipped [maturity_filter]: %s at maturity %s not in %s",
                    self.__class__.__name__,
                    maturity_to_string(self.cur_maturity),
                    self.maturities,
                )
            return False

        if self.flow_context is not None:
            gate = self.flow_context.evaluate_fix_predecessor_gate()
            # Record flow gate outcome
            if hasattr(self.flow_context, 'report_outcome'):
                self.flow_context.report_outcome(gate, "fixpred_gate")
            if not gate.allowed:
                unflat_logger.debug(
                    "Skipping %s via flow context gate: %s",
                    self.__class__.__name__,
                    gate.reason,
                )
                return False

        if self.DEFAULT_MAX_PASSES is not None and self.cur_maturity_pass >= self.DEFAULT_MAX_PASSES:
            # Gate: max passes reached.
            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Gate skipped [max_passes]: %s pass %d >= %d",
                    self.__class__.__name__,
                    self.cur_maturity_pass,
                    self.DEFAULT_MAX_PASSES,
                )
            return False

        if blk.tail is None or blk.tail.opcode not in JMP_OPCODE_HANDLED:
            return False

        if blk.tail.r.t != ida_hexrays.mop_n:
            return False

        self.cur_maturity_pass += 1
        return True
