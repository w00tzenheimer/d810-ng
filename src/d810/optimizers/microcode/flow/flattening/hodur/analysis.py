"""Hodur state machine detector and analysis snapshot types.

``HodurStateMachineDetector`` performs the heavy microcode analysis to
identify Hodur-style while-loop CFF patterns.

``AnalysisSnapshot`` is an immutable value object that captures the results
of one analysis pass and is passed to every strategy's ``plan()`` method.
``ReachabilityInfo`` is a helper frozen dataclass used within snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import ida_hexrays

from d810.cfg.dominator import compute_dom_tree
from d810.cfg.mop_identity import mop_snapshot_key
from d810.core import logging
from d810.core.bits import unsigned_to_signed
from d810.evaluator.evaluators import evaluate_concrete
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.chains import (
    DefSite,
    _scan_block_for_reg_defs,
    _scan_block_for_stkvar_defs,
    collect_pred_defs_for_block,
    ensure_graph_and_lists_ready,
    find_reaching_defs_for_reg,
    find_reaching_defs_for_stkvar,
)
from d810.evaluator.hexrays_microcode.tracker import (
    MopTracker,
    get_all_possibles_values,
)
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.evaluator.hexrays_microcode.def_search import resolve_mop_via_predecessors
from d810.hexrays.utils.hexrays_formatters import format_mop_t
from d810.hexrays.utils.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
    extract_num_mop,
    get_mop_index,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
)
from d810.recon.flow.bst_model import BSTAnalysisResult
from d810.optimizers.microcode.flow.dispatcher.dispatcher_history import (
    DispatcherAnalysis,
    analyze_dispatcher_live,
)
from d810.recon.flow.transition_builder import (
    StateHandler,
    StateTransition,
    StateUpdateSite,
)

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)

# ---------------------------------------------------------------------------
# Module-level constants used by the detector
# ---------------------------------------------------------------------------

# State values must exceed this threshold to be considered dispatcher constants.
MIN_STATE_CONSTANT = 0x01000000
# Minimum number of unique state constants to consider it a state machine
MIN_STATE_CONSTANTS = 3
# Maximum number of state constants - if more, it's likely OLLVM FLA not Hodur
MAX_STATE_CONSTANTS_HODUR = 30

HODUR_STATE_CHECK_OPCODES = [
    ida_hexrays.m_jnz,
    ida_hexrays.m_jz,
    ida_hexrays.m_jae,
    ida_hexrays.m_jb,
    ida_hexrays.m_ja,
    ida_hexrays.m_jbe,
    ida_hexrays.m_jg,
    ida_hexrays.m_jge,
    ida_hexrays.m_jl,
    ida_hexrays.m_jle,
]

HODUR_STATE_UPDATE_OPCODES = {
    ida_hexrays.m_mov,
    ida_hexrays.m_add,
    ida_hexrays.m_sub,
    ida_hexrays.m_xor,
    ida_hexrays.m_or,
    ida_hexrays.m_and,
    ida_hexrays.m_xdu,
    ida_hexrays.m_xds,
}

from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)

__all__ = [
    "MIN_STATE_CONSTANT",
    "MIN_STATE_CONSTANTS",
    "MAX_STATE_CONSTANTS_HODUR",
    "HODUR_STATE_CHECK_OPCODES",
    "HODUR_STATE_UPDATE_OPCODES",
    "HodurStateMachineDetector",
    "ReachabilityInfo",
    "AnalysisSnapshot",
]


# ---------------------------------------------------------------------------
# HodurStateMachineDetector
# ---------------------------------------------------------------------------


def _live_mop_matches_snapshot_key(
    mop: "ida_hexrays.mop_t", key: str | None
) -> bool:
    """Return ``True`` if ``mop`` produces the given snapshot key.

    Mirrors ``d810.cfg.mop_identity.mop_snapshot_key`` on the live
    side so the dispatcher-cache's portable state-variable identity
    (held as a ``MopSnapshot``) can be matched against the live
    operands in hodur's local ``state_check_blocks`` without holding
    a live ``mop_t`` reference inside ``StateVariableCandidate``.

    Inlined rather than imported from a shared helper because the
    only equivalent on the live side lives in
    ``recon/flow/dispatcher_detection._build_state_var_snapshot``
    (private) and the matching logic itself is one ``if``/``elif``
    cascade -- not worth a cross-module dependency.
    """
    if key is None or mop is None:
        return False
    t = mop.t
    if t == ida_hexrays.mop_r:
        return key == f"r{mop.r}"
    if t == ida_hexrays.mop_S:
        return key == f"S{mop.s.off}"
    if t == ida_hexrays.mop_v:
        return key == f"v{mop.g}"
    if t == ida_hexrays.mop_l:
        return key == f"l{mop.l.off}"
    return False


class HodurStateMachineDetector:
    """Detects Hodur-style while-loop state machines in microcode."""

    def __init__(
        self,
        mba: ida_hexrays.mba_t,
        use_cache: bool = True,
        min_state_constant: int = MIN_STATE_CONSTANT,
        min_state_constants: int = MIN_STATE_CONSTANTS,
        max_state_constants: int = MAX_STATE_CONSTANTS_HODUR,
    ):
        self.mba = mba
        self.state_machine: DispatcherStateMachine | None = None
        self.use_cache = use_cache
        self._dispatcher_analysis: DispatcherAnalysis | None = None
        self.bst_result: BSTAnalysisResult | None = None
        self.min_state_constant = min_state_constant
        self.min_state_constants = min_state_constants
        self.max_state_constants = max_state_constants

    def detect(self) -> DispatcherStateMachine | None:
        """
        Detect if the function contains a Hodur state machine.

        Returns the state machine structure if found, None otherwise.

        Uses cached dispatcher analysis when available for performance.
        """
        # Use cached dispatcher detection if available
        if self.use_cache:
            self._dispatcher_analysis = analyze_dispatcher_live(self.mba)
            analysis = self._dispatcher_analysis

            # Quick check: is this Hodur-style?
            if not analysis.is_conditional_chain:
                unflat_logger.debug(
                    "Dispatcher cache says not Hodur-style (constants=%d, nested=%d)",
                    len(analysis.state_constants),
                    analysis.nested_loop_depth,
                )
                return None
            else:
                unflat_logger.debug(
                    "Dispatcher cache confirms Hodur-style: %d state constants, initial=%s",
                    len(analysis.state_constants),
                    (
                        hex(analysis.initial_state)
                        if analysis.initial_state
                        else "unknown"
                    ),
                )

        # Step 1: Find all state comparison blocks (jnz with large constants)
        state_check_blocks = self._find_state_check_blocks()
        if len(state_check_blocks) < self.min_state_constants:
            unflat_logger.debug(
                "Not enough state check blocks found: %d < %d",
                len(state_check_blocks),
                self.min_state_constants,
            )
            return None

        # Step 1.5: Check if this looks more like OLLVM FLA than Hodur
        if len(state_check_blocks) > self.max_state_constants:
            unflat_logger.info(
                "Too many state check blocks (%d > %d) - likely OLLVM FLA, not Hodur",
                len(state_check_blocks),
                self.max_state_constants,
            )
            return None

        # Step 2: Find the state variable (the operand being compared).
        #
        # E3-schema (dispatcher_facts): ``analysis.state_variable.mop``
        # is now a portable ``MopSnapshot``, not a live
        # ``ida_hexrays.mop_t``.  We can't
        # just pull ``.mop`` out and pass it to live-mop operations
        # (``format_mop_t``, downstream walking).
        #
        # BUT: dispatcher analysis' selection logic ("operand with the most
        # state comparisons across the whole function") IS more
        # discriminating than ``_identify_state_variable``'s
        # "non-constant operand of the first check block".  For
        # functions with mixed/decoy early comparisons these can
        # diverge, so we MUST preserve the cache-driven selection.
        #
        # We bridge dispatcher analysis' portable identity to a live operand
        # by matching the snapshot key against the live operands in
        # our own ``state_check_blocks``: find the check whose
        # non-constant operand has the same ``mop_snapshot_key`` as
        # the cache's candidate, and use that block's live mop.
        # This preserves the cache's "most comparisons" wisdom while
        # keeping ``StateVariableCandidate.mop`` schema-pure.
        #
        # SCOPE INVARIANT: we iterate ``state_check_blocks`` --
        # hodur's already-filtered candidate set -- NOT
        # ``cached.comparison_blocks`` (the dispatcher cache's
        # full set across the whole function).  If we iterated the
        # cache's list, we might select a live operand from a block
        # that hodur already rejected as a non-state-check, which
        # would violate hodur's filtering invariant.  The cache's
        # role here is purely to PICK the right operand among
        # hodur's set, not to expand the set.
        state_var = None
        if self._dispatcher_analysis is not None:
            cached = self._dispatcher_analysis.state_variable
            if cached is not None:
                cached_key = mop_snapshot_key(cached.mop)
                if cached_key is not None:
                    for blk_serial, _, _ in state_check_blocks:
                        blk = self.mba.get_mblock(blk_serial)
                        if blk.tail is None:
                            continue
                        _, candidate = extract_num_mop(blk.tail)
                        if candidate is None:
                            continue
                        if _live_mop_matches_snapshot_key(
                            candidate, cached_key
                        ):
                            state_var = ida_hexrays.mop_t(candidate)
                            if unflat_logger.debug_on:
                                unflat_logger.debug(
                                    "Using dispatcher-cache state-variable "
                                    "(kind=%s, comparisons=%d) located in "
                                    "block %d",
                                    cached.mop.kind.name,
                                    cached.comparison_count,
                                    blk_serial,
                                )
                            break

        if state_var is None:
            state_var = self._identify_state_variable(state_check_blocks)

        if state_var is None:
            unflat_logger.debug("Could not identify state variable")
            return None

        # Step 3: Find all state constants
        state_constants = set()
        if self._dispatcher_analysis:
            analysis = self._dispatcher_analysis
            if analysis.state_constants:
                state_constants = set(analysis.state_constants)
                unflat_logger.debug(
                    "Using %d cached state constants",
                    len(state_constants),
                )

        if not state_constants:
            for blk_serial, opcode, const in state_check_blocks:
                state_constants.add(const)

        # Step 4: Find state assignments and build transition graph
        state_assignments = self._find_state_assignments(state_var)

        # Step 5: Find initial state
        initial_state = None
        if self._dispatcher_analysis and self._dispatcher_analysis.initial_state:
            initial_state = self._dispatcher_analysis.initial_state
        else:
            initial_state = self._find_initial_state(state_constants)

        # Build the state machine structure
        self.state_machine = DispatcherStateMachine(
            mba=self.mba,
            state_var=state_var,
            initial_state=initial_state,
            state_constants=state_constants,
        )

        # Build handlers for each state
        for blk_serial, opcode, const in state_check_blocks:
            handler = StateHandler(
                state_value=const,
                check_block=blk_serial,
            )
            self.state_machine.add_handler(handler)

        # Build transitions
        self._build_transitions(state_assignments, state_check_blocks)

        unflat_logger.info(
            "Detected Hodur state machine: %d states, %d transitions, initial=%s",
            len(state_constants),
            len(self.state_machine.transitions),
            hex(initial_state) if initial_state else "unknown",
        )

        return self.state_machine

    def _find_state_check_blocks(self) -> list[tuple[int, int, int]]:
        """Find blocks with conditional comparisons against large constants."""
        state_blocks = []
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.tail and blk.tail.opcode in HODUR_STATE_CHECK_OPCODES:
                num_mop, _ = extract_num_mop(blk.tail)
                if num_mop is None or num_mop.nnn is None:
                    continue
                const_val = num_mop.nnn.value
                if const_val > self.min_state_constant:
                    state_blocks.append((blk.serial, blk.tail.opcode, const_val))
        return state_blocks

    def _identify_state_variable(
        self, state_check_blocks: list[tuple[int, int, int]]
    ) -> ida_hexrays.mop_t | None:
        """Identify the state variable from comparison blocks."""
        if not state_check_blocks:
            return None

        first_blk_serial = state_check_blocks[0][0]
        first_blk = self.mba.get_mblock(first_blk_serial)
        if first_blk.tail:
            _, state_mop = extract_num_mop(first_blk.tail)
            if state_mop is not None:
                return ida_hexrays.mop_t(state_mop)
        return None

    @staticmethod
    def _is_jump_taken_for_state(
        opcode: int,
        left_value: int,
        right_value: int,
        right_value_size: int,
    ) -> bool | None:
        """Evaluate whether a conditional jump is taken for a known state value."""
        cmp_mask = (1 << (right_value_size * 8)) - 1
        left_cmp = left_value & cmp_mask
        right_cmp = right_value & cmp_mask
        if opcode == ida_hexrays.m_jnz:
            return left_cmp != right_cmp
        if opcode == ida_hexrays.m_jz:
            return left_cmp == right_cmp
        if opcode == ida_hexrays.m_jae:
            return left_cmp >= right_cmp
        if opcode == ida_hexrays.m_jb:
            return left_cmp < right_cmp
        if opcode == ida_hexrays.m_ja:
            return left_cmp > right_cmp
        if opcode == ida_hexrays.m_jbe:
            return left_cmp <= right_cmp
        if opcode == ida_hexrays.m_jg:
            return unsigned_to_signed(left_cmp, right_value_size) > unsigned_to_signed(
                right_cmp, right_value_size
            )
        if opcode == ida_hexrays.m_jge:
            return unsigned_to_signed(left_cmp, right_value_size) >= unsigned_to_signed(
                right_cmp, right_value_size
            )
        if opcode == ida_hexrays.m_jl:
            return unsigned_to_signed(left_cmp, right_value_size) < unsigned_to_signed(
                right_cmp, right_value_size
            )
        if opcode == ida_hexrays.m_jle:
            return unsigned_to_signed(left_cmp, right_value_size) <= unsigned_to_signed(
                right_cmp, right_value_size
            )
        return None

    @staticmethod
    def _swap_jump_opcode_for_reversed_operands(opcode: int) -> int:
        """Return the equivalent jump opcode when comparison operands are swapped."""
        swapped = {
            ida_hexrays.m_jae: ida_hexrays.m_jbe,
            ida_hexrays.m_jb: ida_hexrays.m_ja,
            ida_hexrays.m_ja: ida_hexrays.m_jb,
            ida_hexrays.m_jbe: ida_hexrays.m_jae,
            ida_hexrays.m_jg: ida_hexrays.m_jl,
            ida_hexrays.m_jge: ida_hexrays.m_jle,
            ida_hexrays.m_jl: ida_hexrays.m_jg,
            ida_hexrays.m_jle: ida_hexrays.m_jge,
        }
        return swapped.get(opcode, opcode)

    @staticmethod
    def _extract_check_constant_and_opcode(
        insn: ida_hexrays.minsn_t,
    ) -> tuple[int, int, int] | None:
        """Extract comparison constant and normalized opcode from a check instruction."""
        num_mop, _ = extract_num_mop(insn)
        if num_mop is None or num_mop.nnn is None:
            return None

        normalized_opcode = insn.opcode
        if insn.l.t == ida_hexrays.mop_n:
            normalized_opcode = (
                HodurStateMachineDetector._swap_jump_opcode_for_reversed_operands(
                    insn.opcode
                )
            )

        return (normalized_opcode, int(num_mop.nnn.value), num_mop.size)

    @staticmethod
    def _get_jump_and_fallthrough_targets(
        blk: ida_hexrays.mblock_t,
    ) -> tuple[int | None, int | None]:
        """Return jump-target and fall-through successor for a conditional block."""
        if blk.tail is None or blk.tail.d.t != ida_hexrays.mop_b:
            return None, None

        jump_target = blk.tail.d.b
        fallthrough = None
        for succ in blk.succset:
            if succ != jump_target:
                fallthrough = succ
                break

        if fallthrough is None and blk.serial + 1 < blk.mba.qty:
            fallthrough = blk.serial + 1

        return jump_target, fallthrough

    def _mops_match_state_var(
        self,
        candidate: ida_hexrays.mop_t | None,
        state_var: ida_hexrays.mop_t,
    ) -> bool:
        """Compare state mops with structural and semantic fallback.

        At MMAT_GLBOPT1 IDA assigns SSA version tags (valnum) to operands.
        ``equal_mops(EQ_IGNSIZE)`` may fail when the candidate and state_var
        carry different SSA versions.  A structural fallback compares only
        the underlying location (register number for mop_r, stack offset +
        size for mop_S) to tolerate version differences.
        """
        if candidate is None:
            return False

        try:
            if candidate.equal_mops(state_var, ida_hexrays.EQ_IGNSIZE):
                return True
        except Exception:
            pass

        if candidate.t == state_var.t:
            try:
                if candidate.t == ida_hexrays.mop_r and candidate.r == state_var.r:
                    return True
                if (
                    candidate.t == ida_hexrays.mop_S
                    and candidate.s.off == state_var.s.off
                    and candidate.size == state_var.size
                ):
                    return True
            except Exception:
                pass

        try:
            from d810.backends.ast.z3 import Z3MopProver

            return bool(Z3MopProver().are_equal(candidate, state_var))
        except Exception:
            return False

    def _find_state_assignments(
        self, state_var: ida_hexrays.mop_t
    ) -> list[StateUpdateSite]:
        """
        Find semantic state-update instructions (not only mov constants).
        """
        assignments: list[StateUpdateSite] = []
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            insn = blk.head
            while insn:
                if (
                    insn.opcode in HODUR_STATE_UPDATE_OPCODES
                    and insn.d is not None
                    and insn.d.t != ida_hexrays.mop_z
                    and self._mops_match_state_var(insn.d, state_var)
                ):
                    assignments.append(StateUpdateSite(blk.serial, insn))
                insn = insn.next
        return assignments

    def _resolve_single_mop_constant(
        self,
        blk: ida_hexrays.mblock_t,
        insn: ida_hexrays.minsn_t,
        mop: ida_hexrays.mop_t | None,
    ) -> int | None:
        """Resolve *mop* to a single constant before *insn* executes."""
        if mop is None:
            return None
        if hasattr(mop, "to_mop"):
            try:
                mop = mop.to_mop()  # type: ignore[assignment]
            except Exception:
                return None
        if mop.t == ida_hexrays.mop_n:
            return int(mop.nnn.value)

        tracker = MopTracker([mop], max_nb_block=100, max_path=100)
        tracker.reset()
        histories = tracker.search_backward(
            blk,
            insn,
            stop_at_first_duplication=True,
        )
        if not histories:
            return None

        values = get_all_possibles_values(histories, [mop])
        resolved_values = set()
        for value_list in values:
            if not value_list or value_list[0] is None:
                return None
            resolved_values.add(int(value_list[0]))

        if len(resolved_values) != 1:
            return None
        return next(iter(resolved_values))

    def _evaluate_state_update_with_emulator(
        self,
        blk: ida_hexrays.mblock_t,
        insn: ida_hexrays.minsn_t,
        state_var: ida_hexrays.mop_t,
        from_state: int,
    ) -> int | None:
        """Evaluate one state update by running the existing microcode emulator."""
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        try:
            env.define(state_var, int(from_state))
        except Exception:
            return None

        cur = blk.head
        count = 0
        while cur is not None:
            ok = interpreter.eval_instruction(
                blk,
                cur,
                environment=env,
                raise_exception=False,
            )
            if cur.ea == insn.ea and cur.opcode == insn.opcode:
                if not ok:
                    return None
                value = env.lookup(state_var, raise_exception=False)
                if value is not None:
                    return int(value)
                value = interpreter.eval_mop(
                    insn.d, environment=env, raise_exception=False
                )
                return int(value) if value is not None else None
            count += 1
            cur = cur.next

        return None

    def _evaluate_state_update_with_ast(
        self,
        blk: ida_hexrays.mblock_t,
        insn: ida_hexrays.minsn_t,
        state_var: ida_hexrays.mop_t,
        from_state: int,
    ) -> int | None:
        """AST fallback for state updates when concrete emulation cannot resolve."""
        ast = minsn_to_ast(insn)
        if ast is None:
            return None
        if ast.dest_size is None and insn.d is not None:
            ast.dest_size = insn.d.size

        leaf_values: dict[int, int] = {}
        for leaf in ast.get_leaf_list():
            if leaf.ast_index is None or leaf.mop is None:
                continue
            if leaf.is_constant():
                continue
            if self._mops_match_state_var(leaf.mop, state_var):
                leaf_values[leaf.ast_index] = int(from_state)
                continue

            resolved = self._resolve_single_mop_constant(blk, insn, leaf.mop)
            if resolved is None:
                return None
            leaf_values[leaf.ast_index] = int(resolved)

        try:
            result = evaluate_concrete(ast, leaf_values)
            return int(result) if result is not None else None
        except Exception:
            return None

    def _resolve_next_state_value(
        self,
        blk: ida_hexrays.mblock_t,
        insn: ida_hexrays.minsn_t,
        state_var: ida_hexrays.mop_t,
        from_state: int,
    ) -> int | None:
        """
        Resolve the concrete next-state from an update instruction.

        Uses interpreter first, then AST fallback for resilience.
        """
        next_state = self._evaluate_state_update_with_emulator(
            blk, insn, state_var, from_state
        )
        if next_state is None:
            next_state = self._evaluate_state_update_with_ast(
                blk, insn, state_var, from_state
            )
        if next_state is None:
            return None

        size = state_var.size if getattr(state_var, "size", 0) in (1, 2, 4, 8) else 4
        mask = (1 << (size * 8)) - 1
        return int(next_state) & mask

    def _extract_assigned_state_from_block(
        self,
        block_serial: int,
        assignment_map: dict[int, list],
        state_var: ida_hexrays.mop_t,
    ) -> int | None:
        """Extract the state constant assigned in a block, using assignment_map.

        Tries direct constant extraction first (for m_mov), then emulator
        fallback with each handler state as from_state (for xor/add/sub).
        """
        if block_serial not in assignment_map:
            return None

        blk = self.mba.get_mblock(block_serial)
        for insn in assignment_map[block_serial]:
            # Direct constant extraction for m_mov
            if insn.opcode == ida_hexrays.m_mov and insn.l.t == ida_hexrays.mop_n:
                val = int(insn.l.nnn.value)
                # Mask to state_var size
                size = (
                    state_var.size
                    if getattr(state_var, "size", 0) in (1, 2, 4, 8)
                    else 4
                )
                val &= (1 << (size * 8)) - 1
                if (
                    self.state_machine is not None
                    and val in self.state_machine.state_constants
                ):
                    return val

            # Emulator fallback for xor/add/sub
            if self.state_machine is not None:
                for from_state in self.state_machine.handlers.keys():
                    result = self._resolve_next_state_value(
                        blk, insn, state_var, int(from_state)
                    )
                    if (
                        result is not None
                        and result in self.state_machine.state_constants
                    ):
                        return result

        return None

    def _find_initial_state(self, state_constants: set[int]) -> int | None:
        """Find the initial state value (set before entering the state machine)."""
        entry_blk = self.mba.get_mblock(0)

        insn = entry_blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_mov:
                if insn.l.t == ida_hexrays.mop_n:
                    const_val = insn.l.nnn.value
                    if const_val in state_constants:
                        return const_val
            insn = insn.next

        for i in range(1, min(5, self.mba.qty)):
            blk = self.mba.get_mblock(i)
            insn = blk.head
            while insn:
                if insn.opcode == ida_hexrays.m_mov:
                    if insn.l.t == ida_hexrays.mop_n:
                        const_val = insn.l.nnn.value
                        if const_val in state_constants:
                            return const_val
                insn = insn.next

        return None

    def _eval_binop(self, opcode: int, lval: int, rval: int) -> "int | None":
        """Evaluate a binary microcode operation on two integer constants."""
        MASK32 = 0xFFFFFFFF
        ops = {
            ida_hexrays.m_add: lambda a, b: (a + b) & MASK32,
            ida_hexrays.m_sub: lambda a, b: (a - b) & MASK32,
            ida_hexrays.m_xor: lambda a, b: (a ^ b) & MASK32,
            ida_hexrays.m_and: lambda a, b: (a & b) & MASK32,
            ida_hexrays.m_or: lambda a, b: (a | b) & MASK32,
        }
        fn = ops.get(opcode)
        return fn(lval, rval) if fn else None

    def _fold_block_local(
        self,
        blk: "ida_hexrays.mblock_t",
        mop: "ida_hexrays.mop_t",
        stop_serial: int,
        _depth: int = 0,
    ) -> "int | None":
        """Fold mop to a 32-bit constant using only same-block defs before stop_serial.

        Performs a pure backward scan within *blk* restricted to instructions
        whose ``ea`` is strictly less than *stop_serial*.  Handles:

        * ``mop_n`` — direct numeric literal.
        * ``mop_r`` — register/temp assigned a constant or constant-foldable
          binary op in this block before the state-variable assignment.
        * ``mop_S`` — stack variable assigned a constant or constant-foldable
          binary op in this block before stop_serial.  Enables folding of MBA
          patterns like ``i = (v22 ^ v23) - v21`` where intermediaries live on
          the stack.
        * Binary ops (add/sub/xor/and/or) whose both operands are foldable.

        Returns the folded 32-bit integer or ``None`` if not resolvable.
        """
        _MAX_DEPTH = 16
        if mop is None or _depth > _MAX_DEPTH:
            return None
        if mop.t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFF
        if mop.t == ida_hexrays.mop_r:
            ins = blk.tail
            while ins is not None and ins.ea >= stop_serial:
                ins = ins.prev
            while ins is not None:
                if (
                    ins.d is not None
                    and ins.d.t == ida_hexrays.mop_r
                    and ins.d.r == mop.r
                ):
                    if ins.opcode == ida_hexrays.m_mov:
                        return self._fold_block_local(blk, ins.l, ins.ea, _depth + 1)
                    lv = self._fold_block_local(blk, ins.l, ins.ea, _depth + 1)
                    rv = self._fold_block_local(blk, ins.r, ins.ea, _depth + 1)
                    if lv is not None and rv is not None:
                        return self._eval_binop(ins.opcode, lv, rv)
                    return None
                ins = ins.prev
        if mop.t == ida_hexrays.mop_d:
            sub = mop.d
            if sub is not None and sub.l is not None and sub.r is not None:
                lv = self._fold_block_local(blk, sub.l, stop_serial, _depth + 1)
                rv = self._fold_block_local(blk, sub.r, stop_serial, _depth + 1)
                if lv is not None and rv is not None:
                    return self._eval_binop(sub.opcode, lv, rv)
        if mop.t == ida_hexrays.mop_S:
            stk_off = mop.s.off
            stk_sz = mop.size
            ins = blk.tail
            while ins is not None and ins.ea >= stop_serial:
                ins = ins.prev
            while ins is not None:
                d = ins.d
                if (
                    d is not None
                    and d.t == ida_hexrays.mop_S
                    and d.s.off == stk_off
                    and d.size == stk_sz
                ):
                    if ins.opcode == ida_hexrays.m_mov:
                        return self._fold_block_local(blk, ins.l, ins.ea, _depth + 1)
                    lv = self._fold_block_local(blk, ins.l, ins.ea, _depth + 1)
                    rv = self._fold_block_local(blk, ins.r, ins.ea, _depth + 1)
                    if lv is not None and rv is not None:
                        return self._eval_binop(ins.opcode, lv, rv)
                    return None
                ins = ins.prev
        return None

    def _fold_mop_inter_block(
        self,
        blk: "ida_hexrays.mblock_t",
        mop: "ida_hexrays.mop_t",
        stop_serial: int,
        max_pred_depth: int = 6,
    ) -> "int | None":
        """Fold mop to a constant, crossing block boundaries if needed.

        First tries block-local folding (fast path).  If that fails and the mop
        is a register or stack variable, walks predecessor blocks up to
        *max_pred_depth* levels and attempts block-local folding in each.

        The predecessor join rule is strict: a constant is only returned when
        **all** predecessor paths agree on the same value.  This is safe for
        Hodur CFF where handler sequences are typically linear chains with a
        single predecessor at each step.

        Args:
            blk: The block containing the state-variable assignment.
            mop: The operand to fold.
            stop_serial: Instruction EA upper bound (same semantics as
                _fold_block_local).
            max_pred_depth: Maximum number of predecessor hops to follow.
                Defaults to 6 (Hodur handler chains are typically 3-6 hops).  Set to 0 to disable cross-block search.

        Returns:
            Folded 32-bit integer constant, or None if not resolvable.
        """
        result = self._fold_block_local(blk, mop, stop_serial)
        if result is not None:
            return result

        if mop is None or mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
            return None
        if max_pred_depth <= 0:
            return None

        current_level: list["ida_hexrays.mblock_t"] = []
        try:
            current_level = list(blk.preds())
        except Exception:
            return None

        visited: set[int] = {blk.serial}
        for _hop in range(max_pred_depth):
            if not current_level:
                break

            values: list[int] = []
            all_resolved = True
            next_level: list["ida_hexrays.mblock_t"] = []

            for pred_blk in current_level:
                if pred_blk.serial in visited:
                    all_resolved = False
                    break
                visited.add(pred_blk.serial)

                pred_val = self._fold_block_local(pred_blk, mop, 0xFFFFFFFFFFFFFFFF)
                if pred_val is None:
                    all_resolved = False
                    try:
                        next_level.extend(pred_blk.preds())
                    except Exception:
                        pass
                else:
                    values.append(pred_val)

            if all_resolved and values:
                if len(set(values)) == 1:
                    return values[0]
                return None

            if values and not all_resolved:
                if len(set(values)) > 1:
                    return None

            current_level = next_level

        return None

    def _find_owning_state(
        self,
        blk: "ida_hexrays.mblock_t",
        check_map: "dict[int, int]",
    ) -> "int | None":
        """Find which state constant owns this block by walking backwards to nearest check block.

        check_map maps block_serial -> state_constant.
        """
        visited: set[int] = set()
        queue = [p.serial for p in blk.preds()]
        while queue:
            pred_serial = queue.pop(0)
            if pred_serial in visited:
                continue
            visited.add(pred_serial)
            if pred_serial in check_map:
                return check_map[pred_serial]
            if len(visited) < 20 and 0 <= pred_serial < self.mba.qty:
                pred_blk = self.mba.get_mblock(pred_serial)
                if pred_blk is not None:
                    queue.extend([p.serial for p in pred_blk.preds()])
        return None

    def _build_transitions_by_scan(
        self, mba: "ida_hexrays.mba_t"
    ) -> "list[StateTransition]":
        """Build state transitions by scanning all blocks for state variable assignments.

        Uses block-local constant folding via IDA's def-search instead of BFS+MopTracker.
        Handles MBA state assignments like: v21=C1; v22=C2; i=(v21^v22)-C3
        """
        if self.state_machine is None or self.state_machine.state_var is None:
            return []

        transitions: list[StateTransition] = []
        state_var = self.state_machine.state_var
        state_constants = self.state_machine.state_constants

        check_map: dict[int, int] = {
            handler.check_block: state_val
            for state_val, handler in self.state_machine.handlers.items()
        }
        dispatcher_serials = set(check_map.keys())

        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            if blk_idx in dispatcher_serials:
                continue

            insn = blk.head
            while insn is not None:
                if (
                    insn.opcode in HODUR_STATE_UPDATE_OPCODES
                    and insn.d is not None
                    and insn.d.t != ida_hexrays.mop_z
                    and self._mops_match_state_var(insn.d, state_var)
                ):
                    if insn.opcode == ida_hexrays.m_mov:
                        folded = self._fold_mop_inter_block(blk, insn.l, insn.ea)
                    else:
                        lv = self._fold_mop_inter_block(blk, insn.l, insn.ea)
                        rv = self._fold_mop_inter_block(blk, insn.r, insn.ea)
                        folded = (
                            self._eval_binop(insn.opcode, lv, rv)
                            if lv is not None and rv is not None
                            else None
                        )
                    if folded is None or folded not in state_constants:
                        insn = insn.next
                        continue
                    current_state = self._find_owning_state(blk, check_map)
                    if current_state is None:
                        insn = insn.next
                        continue
                    if current_state == folded:
                        insn = insn.next
                        continue
                    transitions.append(
                        StateTransition(
                            from_state=current_state,
                            to_state=folded,
                            from_block=blk_idx,
                        )
                    )
                insn = insn.next

        unflat_logger.info(
            "SCAN: found %d transitions across %d blocks", len(transitions), mba.qty
        )
        return transitions

    def _forward_eval_instruction(
        self,
        insn: "ida_hexrays.minsn_t",
        stk_map: "dict[int, int]",
        reg_map: "dict[int, int]",
        state_var: "ida_hexrays.mop_t",
    ) -> "int | None":
        """Evaluate one instruction forward, updating stk_map/reg_map.

        Returns the constant value written to state_var if the instruction
        targets state_var and both operands are resolvable, else None.

        Side-effects: updates stk_map and reg_map in place.
        """
        if insn is None:
            return None

        def _resolve_mop(mop: "ida_hexrays.mop_t") -> "int | None":
            """Resolve a single operand to a constant using current maps."""
            if mop is None:
                return None
            if mop.t == ida_hexrays.mop_n:
                return int(mop.nnn.value) & 0xFFFFFFFF
            if mop.t == ida_hexrays.mop_S:
                return stk_map.get(mop.s.off)
            if mop.t == ida_hexrays.mop_r:
                return reg_map.get(mop.r)
            if mop.t == ida_hexrays.mop_d:
                sub = mop.d
                if sub is None or sub.l is None or sub.r is None:
                    return None
                lv = _resolve_mop(sub.l)
                rv = _resolve_mop(sub.r)
                if lv is not None and rv is not None:
                    return self._eval_binop(sub.opcode, lv, rv)
                return None
            return None

        def _update_dst(dst: "ida_hexrays.mop_t", val: int) -> None:
            """Write resolved constant into the appropriate map slot."""
            if dst is None:
                return
            if dst.t == ida_hexrays.mop_S:
                stk_map[dst.s.off] = val
            elif dst.t == ida_hexrays.mop_r:
                reg_map[dst.r] = val

        opcode = insn.opcode

        if opcode == ida_hexrays.m_call:
            reg_map.clear()
            return None

        dst = insn.d
        if dst is None or dst.t == ida_hexrays.mop_z:
            return None

        result: "int | None" = None

        if opcode == ida_hexrays.m_mov:
            src_val = _resolve_mop(insn.l)
            if src_val is not None:
                _update_dst(dst, src_val)
                result = src_val
        elif opcode in (
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_xor,
            ida_hexrays.m_and,
            ida_hexrays.m_or,
        ):
            lv = _resolve_mop(insn.l)
            rv = _resolve_mop(insn.r)
            if lv is not None and rv is not None:
                computed = self._eval_binop(opcode, lv, rv)
                if computed is not None:
                    _update_dst(dst, computed)
                    result = computed
            elif unflat_logger.debug_on:
                # Diagnostic: log when a binop operand fails to resolve
                l_type = insn.l.t if insn.l else -1
                r_type = insn.r.t if insn.r else -1
                unflat_logger.debug(
                    "BINOP_RESOLVE_FAIL: ea=0x%x opcode=%d "
                    "l_type=%d l_val=%s r_type=%d r_val=%s "
                    "stk_map={%s} reg_map={%s}",
                    insn.ea, opcode,
                    l_type, "None" if lv is None else hex(lv),
                    r_type, "None" if rv is None else hex(rv),
                    ", ".join(
                        "%s: %s" % (hex(k), hex(v))
                        for k, v in stk_map.items()
                    ),
                    ", ".join(
                        "%s: %s" % (hex(k), hex(v))
                        for k, v in reg_map.items()
                    ),
                )

        if result is not None and self._mops_match_state_var(dst, state_var):
            return result
        return None

    def _resolve_transitions_forward_prop(
        self,
        state_machine: "DispatcherStateMachine",
        mba: "ida_hexrays.mba_t",
    ) -> "list[StateTransition]":
        """Resolve unresolved handler states via forward constant propagation.

        For each state K that has a known handler but no outgoing transition,
        seeds the state variable value at handler entry with K and walks forward
        through handler blocks, tracking constant assignments in stk_map/reg_map.
        When an instruction writing to state_var is found and the result is a
        known state constant, a new StateTransition is created.

        Returns a list of newly discovered StateTransition objects.
        """
        if state_machine.state_var is None:
            return []

        state_var = state_machine.state_var
        state_constants = state_machine.state_constants

        resolved_from_states = {t.from_state for t in state_machine.transitions}
        unresolved_states = state_constants - resolved_from_states

        if not unresolved_states:
            return []

        unflat_logger.debug(
            "Forward prop: %d unresolved states to probe",
            len(unresolved_states),
        )

        new_transitions: list[StateTransition] = []

        for K in unresolved_states:
            handler = state_machine.handlers.get(K)
            if handler is None:
                continue

            stk_map: dict[int, int] = {}
            reg_map: dict[int, int] = {}

            if state_var.t == ida_hexrays.mop_S:
                stk_map[state_var.s.off] = K
            elif state_var.t == ida_hexrays.mop_r:
                reg_map[state_var.r] = K

            to_state: "int | None" = None
            found_block: "int | None" = None
            provenance: "list[tuple[int, int]]" = []

            for blk_serial in handler.handler_blocks:
                if mba is None:
                    break
                blk = mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                insn = blk.head
                while insn is not None:
                    val = self._forward_eval_instruction(
                        insn, stk_map, reg_map, state_var
                    )
                    if val is not None and val != K:
                        provenance.append((blk_serial, val))
                        if val in state_constants or val >= self.min_state_constant:
                            to_state = val
                            found_block = blk_serial
                            break
                    insn = insn.next
                if to_state is not None:
                    break

            # --- Tail chase: walk into shared successor blocks ---
            if to_state is None and mba is not None:
                handler_block_set = set(handler.handler_blocks)

                # Start from the last walked block, or check_block if
                # handler_blocks is empty
                last_serial = (
                    handler.handler_blocks[-1]
                    if handler.handler_blocks
                    else handler.check_block
                )

                # BFS chase up to depth 5
                chase_frontier: list[tuple[int, int]] = [
                    (last_serial, 0)
                ]  # (serial, depth)
                chased_visited: set[int] = set(handler_block_set)
                chased_visited.add(last_serial)
                chased_blocks: list[int] = []
                _MAX_TAIL_CHASE_DEPTH = 5

                while chase_frontier and to_state is None:
                    cur_serial, cur_depth = chase_frontier.pop(0)
                    cur_blk = mba.get_mblock(cur_serial)
                    if cur_blk is None:
                        continue

                    for succ_serial_raw in cur_blk.succset:
                        succ_serial = int(succ_serial_raw)
                        if succ_serial in chased_visited:
                            continue
                        if succ_serial in handler_block_set:
                            continue
                        chased_visited.add(succ_serial)
                        chased_blocks.append(succ_serial)

                        succ_blk = mba.get_mblock(succ_serial)
                        if succ_blk is None:
                            continue

                        insn = succ_blk.head
                        while insn is not None:
                            val = self._forward_eval_instruction(
                                insn, stk_map, reg_map, state_var
                            )
                            if val is not None and val != K:
                                provenance.append((succ_serial, val))
                                if (
                                    val in state_constants
                                    or val >= self.min_state_constant
                                ):
                                    to_state = val
                                    found_block = succ_serial
                                    break
                            insn = insn.next
                        if to_state is not None:
                            unflat_logger.info(
                                "TAIL_CHASE: state=0x%X resolved via "
                                "successor blk[%d] -> 0x%X",
                                K,
                                succ_serial,
                                to_state,
                            )
                            break

                        # Enqueue deeper successors if within depth limit
                        if cur_depth + 1 < _MAX_TAIL_CHASE_DEPTH:
                            chase_frontier.append(
                                (succ_serial, cur_depth + 1)
                            )

                if to_state is None and chased_blocks:
                    handler_entry = (
                        handler.handler_blocks[0]
                        if handler.handler_blocks
                        else -1
                    )
                    unflat_logger.info(
                        "TAIL_CHASE_FAILED: state=0x%X entry_blk=%d "
                        "chased_blocks=%s",
                        K,
                        handler_entry,
                        chased_blocks,
                    )

            if to_state is not None and found_block is not None:
                unflat_logger.debug(
                    "Forward prop: state %s -> %s (block %d)",
                    K,
                    to_state,
                    found_block,
                )
                new_transitions.append(
                    StateTransition(
                        from_state=K,
                        to_state=to_state,
                        from_block=found_block,
                        provenance_chain=list(provenance),
                    )
                )
                # Emit additional transitions for intermediate values
                # that match known handler states but differ from the
                # final resolved state.
                for prov_blk, prov_val in provenance:
                    if prov_val in state_constants and prov_val != to_state:
                        unflat_logger.info(
                            "PROVENANCE_INTERMEDIATE: state=0x%X "
                            "intermediate_state=0x%X at blk[%d] "
                            "(final=0x%X)",
                            K,
                            prov_val,
                            prov_blk,
                            to_state,
                        )
                        new_transitions.append(
                            StateTransition(
                                from_state=K,
                                to_state=prov_val,
                                from_block=prov_blk,
                            )
                        )
            else:
                # Diagnostic: why did forward prop fail for this handler?
                sv_stkoff = (
                    hex(state_var.s.off)
                    if state_var.t == ida_hexrays.mop_S
                    else "reg=%d" % state_var.r
                    if state_var.t == ida_hexrays.mop_r
                    else "type=%d" % state_var.t
                )
                handler_entry = (
                    handler.handler_blocks[0]
                    if handler.handler_blocks
                    else -1
                )
                unflat_logger.info(
                    "UNRESOLVED_DIAG: state=0x%X entry_blk=%d "
                    "handler_blocks=%s state_var_loc=%s\n"
                    "  stk_map={%s}\n"
                    "  reg_map={%s}",
                    K,
                    handler_entry,
                    [s for s in handler.handler_blocks],
                    sv_stkoff,
                    ", ".join(
                        "0x%X: 0x%X" % (k, v) for k, v in stk_map.items()
                    ),
                    ", ".join(
                        "%d: 0x%X" % (k, v) for k, v in reg_map.items()
                    ),
                )

        # --- Supplemental provenance pass for already-resolved handlers ---
        # These handlers were resolved by BFS but may have intermediate state
        # values hidden in temp variables that BFS couldn't capture.  We run
        # the same handler-block walk (without tail chase) and record ALL
        # intermediate values that match known state constants.
        handlers = state_machine.handlers
        supplemental_count = 0

        for K in resolved_from_states:
            if K not in handlers:
                continue
            handler = handlers[K]
            handler_blks = handler.handler_blocks
            if not handler_blks:
                continue

            stk_map: dict[int, int] = {}
            reg_map: dict[int, int] = {}

            if state_var.t == ida_hexrays.mop_S:
                stk_map[state_var.s.off] = K
            elif state_var.t == ida_hexrays.mop_r:
                reg_map[state_var.r] = K

            # Find the BFS-resolved to_state for this handler
            bfs_to_state: "int | None" = None
            for t in state_machine.transitions:
                if t.from_state == K:
                    bfs_to_state = t.to_state
                    break

            provenance: "list[tuple[int, int]]" = []

            for blk_serial in handler_blks:
                if mba is None:
                    break
                blk = mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                insn = blk.head
                while insn is not None:
                    val = self._forward_eval_instruction(
                        insn, stk_map, reg_map, state_var
                    )
                    if val is not None and val != K:
                        provenance.append((blk_serial, val))
                    insn = insn.next

            # --- Supplemental tail chase: walk into successor blocks ---
            # Unlike the main loop tail chase which breaks on first match,
            # we continue exploring to find ALL intermediate state_var values.
            if mba is not None:
                handler_block_set = set(handler_blks)
                last_serial = (
                    handler_blks[-1]
                    if handler_blks
                    else handler.check_block
                )

                sup_chase_frontier: list[tuple[int, int]] = [
                    (last_serial, 0)
                ]
                sup_chased_visited: set[int] = set(handler_block_set)
                sup_chased_visited.add(last_serial)
                _MAX_SUP_TAIL_CHASE_DEPTH = 5

                while sup_chase_frontier:
                    cur_serial, cur_depth = sup_chase_frontier.pop(0)
                    cur_blk = mba.get_mblock(cur_serial)
                    if cur_blk is None:
                        continue

                    for succ_serial_raw in cur_blk.succset:
                        succ_serial = int(succ_serial_raw)
                        if succ_serial in sup_chased_visited:
                            continue
                        if succ_serial in handler_block_set:
                            continue
                        sup_chased_visited.add(succ_serial)

                        succ_blk = mba.get_mblock(succ_serial)
                        if succ_blk is None:
                            continue

                        insn = succ_blk.head
                        while insn is not None:
                            val = self._forward_eval_instruction(
                                insn, stk_map, reg_map, state_var
                            )
                            if val is not None and val != K:
                                provenance.append((succ_serial, val))
                            insn = insn.next

                        # Enqueue deeper successors if within depth
                        if cur_depth + 1 < _MAX_SUP_TAIL_CHASE_DEPTH:
                            sup_chase_frontier.append(
                                (succ_serial, cur_depth + 1)
                            )

            # Emit supplemental transitions for intermediate values that
            # match a known handler state but differ from the BFS result.
            for prov_blk, prov_val in provenance:
                if (
                    prov_val in state_constants
                    and prov_val != bfs_to_state
                    and prov_val != K
                ):
                    new_transitions.append(
                        StateTransition(
                            from_state=K,
                            to_state=prov_val,
                            from_block=prov_blk,
                            provenance_chain=list(provenance),
                        )
                    )
                    supplemental_count += 1
                    unflat_logger.info(
                        "PROVENANCE_SUPPLEMENTAL: handler 0x%X "
                        "intermediate 0x%X at blk[%d] "
                        "(BFS resolved to 0x%X)",
                        K,
                        prov_val,
                        prov_blk,
                        bfs_to_state,
                    )

        unflat_logger.info(
            "Forward prop: resolved %d new transitions from %d unresolved "
            "states, %d supplemental from %d resolved states "
            "(total returning: %d)",
            len(new_transitions) - supplemental_count,
            len(unresolved_states),
            supplemental_count,
            len(resolved_from_states),
            len(new_transitions),
        )
        return new_transitions

    def _discover_transitions_via_ud_chains(
        self,
        mba: "ida_hexrays.mba_t",
        bst_result: BSTAnalysisResult | None = None,
    ) -> "list[StateTransition]":
        """Discover uncovered handler transitions via UD chain analysis.

        Uses IDA's use-def chains to find ALL blocks that define the state
        variable, then checks uncovered def sites for literal constants that
        map to known handler states.  For non-literal sources, performs one
        level of backward UD chain lookup to resolve through temp variables.

        When *bst_result* is provided and the BFS predecessor walk fails to
        resolve ``from_state``, a BST provenance fallback is attempted via
        :meth:`BSTNodeMap.resolve_state_for_block`.

        Returns a list of newly discovered :class:`StateTransition` objects.
        """
        if self.state_machine is None or self.state_machine.state_var is None:
            return []

        state_var = self.state_machine.state_var
        state_constants = self.state_machine.state_constants

        # --- Extract state variable location ---
        if state_var.t == ida_hexrays.mop_S:
            stkoff = state_var.s.off
            width = state_var.size
        else:
            unflat_logger.debug(
                "UD_CHAIN: state_var is not mop_S (type=%d), skipping",
                state_var.t,
            )
            return []

        # --- Build block-to-handler reverse map ---
        block_to_handler: dict[int, int] = {}
        for state_val, handler in self.state_machine.handlers.items():
            for blk_serial in handler.handler_blocks:
                block_to_handler[blk_serial] = state_val

        # --- Build existing (from_state, to_state) pairs for dedup ---
        existing_pairs: set[tuple[int | None, int]] = {
            (t.from_state, t.to_state) for t in self.state_machine.transitions
        }

        # --- Prepare graph and lists for chain queries ---
        try:
            ensure_graph_and_lists_ready(mba)
        except Exception:
            unflat_logger.debug(
                "UD_CHAIN: ensure_graph_and_lists_ready failed, skipping"
            )
            return []

        # --- Find all blocks that define the state variable ---
        # Query UD chains at the dispatcher entry (block 0 or first BST node)
        # to find all reaching defs.  But we actually want ALL defs globally,
        # so we scan every block for state var defs via the scan helper.
        all_def_sites: list[DefSite] = []
        for blk_idx in range(mba.qty):
            defs = _scan_block_for_stkvar_defs(mba, blk_idx, stkoff, width)
            all_def_sites.extend(defs)

        if not all_def_sites:
            unflat_logger.debug(
                "UD_CHAIN: no def sites found for stkoff=0x%X width=%d",
                stkoff,
                width,
            )
            return []

        unflat_logger.info(
            "UD_CHAIN: %d total def sites for stkoff=0x%X",
            len(all_def_sites),
            stkoff,
        )

        new_transitions: list[StateTransition] = []

        for def_site in all_def_sites:
            blk = mba.get_mblock(def_site.block_serial)
            if blk is None:
                continue

            # --- Find the instruction at this def site ---
            insn = blk.head
            target_insn = None
            while insn is not None:
                if insn.ea == def_site.ins_ea:
                    target_insn = insn
                    break
                insn = insn.next

            if target_insn is None:
                continue

            # --- Try to extract the constant being written ---
            const_val: int | None = None

            # Case 1: Direct literal constant (m_mov #imm, state_var)
            if (
                target_insn.l is not None
                and target_insn.l.t == ida_hexrays.mop_n
            ):
                const_val = int(target_insn.l.nnn.value) & 0xFFFFFFFF

            # Case 2: Binary op with two resolvable operands
            elif target_insn.opcode in (
                ida_hexrays.m_add,
                ida_hexrays.m_sub,
                ida_hexrays.m_xor,
                ida_hexrays.m_and,
                ida_hexrays.m_or,
            ):
                lv = self._try_resolve_operand_constant(
                    mba, def_site.block_serial, target_insn.l
                )
                rv = self._try_resolve_operand_constant(
                    mba, def_site.block_serial, target_insn.r
                )
                if lv is not None and rv is not None:
                    const_val = self._eval_binop(target_insn.opcode, lv, rv)

            # Case 3: Non-literal source — one level backward UD chain lookup
            elif target_insn.opcode == ida_hexrays.m_mov:
                const_val = self._try_resolve_operand_constant(
                    mba, def_site.block_serial, target_insn.l
                )

            if const_val is None:
                # --- Per-predecessor resolution for shared merge blocks ---
                # When a merge block reads a temp defined differently by each
                # predecessor, create one transition per predecessor.
                if (
                    target_insn.opcode == ida_hexrays.m_mov
                    and target_insn.l is not None
                    and target_insn.l.t != ida_hexrays.mop_n
                ):
                    per_pred = self._resolve_operand_constants_per_pred(
                        mba, def_site.block_serial, target_insn.l
                    )
                    for pred_serial, pred_const in per_pred.items():
                        if pred_const not in state_constants:
                            continue

                        # Determine from_state from the predecessor block
                        pred_from: int | None = None
                        if pred_serial in block_to_handler:
                            pred_from = block_to_handler[pred_serial]
                        else:
                            # BFS walk backward up to depth 4
                            try:
                                visited_pp = {pred_serial}
                                frontier_pp = [pred_serial]
                                for _depth in range(4):
                                    next_frontier_pp: list[int] = []
                                    for cur_pp in frontier_pp:
                                        cur_pp_blk = mba.get_mblock(cur_pp)
                                        if cur_pp_blk is None:
                                            continue
                                        for pp_raw in cur_pp_blk.predset:
                                            pp = int(pp_raw)
                                            if pp in visited_pp:
                                                continue
                                            visited_pp.add(pp)
                                            if pp in block_to_handler:
                                                pred_from = block_to_handler[pp]
                                                break
                                            next_frontier_pp.append(pp)
                                        if pred_from is not None:
                                            break
                                    if pred_from is not None:
                                        break
                                    frontier_pp = next_frontier_pp
                            except (AttributeError, RuntimeError):
                                pass

                        if pred_from is None and bst_result is not None:
                            # BFS backward walk through BST provenance (depth 4)
                            pp_bst_node_map = bst_result.bst_node_blocks
                            pp_bst_hsm = bst_result.handler_state_map
                            pp_bst_frontier: set[int] = {pred_serial}
                            pp_visited_bst: set[int] = set()
                            pp_bst_resolved = False
                            _pp_bst_depth = 0
                            for _pp_bst_depth in range(4):
                                pp_next_bst_frontier: set[int] = set()
                                for pp_blk_serial in pp_bst_frontier:
                                    if pp_blk_serial in pp_visited_bst:
                                        continue
                                    pp_visited_bst.add(pp_blk_serial)
                                    pp_resolved = pp_bst_node_map.resolve_state(
                                        pp_blk_serial, pp_bst_hsm,
                                    )
                                    if pp_resolved is not None:
                                        pred_from = pp_resolved
                                        pp_bst_resolved = True
                                        break
                                    # Expand predecessors
                                    try:
                                        pp_blk_obj = mba.get_mblock(pp_blk_serial)
                                        if pp_blk_obj is not None:
                                            for pp_p_raw in pp_blk_obj.predset:
                                                pp_p_int = int(pp_p_raw)
                                                if pp_p_int not in pp_visited_bst:
                                                    pp_next_bst_frontier.add(pp_p_int)
                                    except (AttributeError, RuntimeError):
                                        pass
                                if pp_bst_resolved:
                                    break
                                pp_bst_frontier = pp_next_bst_frontier
                            if pred_from is not None and unflat_logger.debug_on:
                                unflat_logger.debug(
                                    "UD_CHAIN_DIAG: BST provenance resolved "
                                    "pred_from=0x%X for pred blk[%d] (depth %d)",
                                    pred_from,
                                    pred_serial,
                                    _pp_bst_depth,
                                )

                        if pred_from is None:
                            # Emit with from_state=None rather than discarding
                            transition = StateTransition(
                                from_state=None,
                                to_state=pred_const,
                                from_block=def_site.block_serial,
                                provenance_chain=[(-1, 0)],
                            )
                            new_transitions.append(transition)
                            if unflat_logger.debug_on:
                                unflat_logger.debug(
                                    "UD_CHAIN_PER_PRED: emitting transition "
                                    "from_state=None -> 0x%X at blk[%d] via "
                                    "pred blk[%d]",
                                    pred_const,
                                    def_site.block_serial,
                                    pred_serial,
                                )
                            continue
                        if pred_from == pred_const:
                            continue
                        pair = (pred_from, pred_const)
                        if pair in existing_pairs:
                            continue

                        transition = StateTransition(
                            from_state=pred_from,
                            to_state=pred_const,
                            from_block=def_site.block_serial,
                            provenance_chain=[
                                (pred_serial, pred_const),
                                (def_site.block_serial, pred_const),
                            ],
                        )
                        new_transitions.append(transition)
                        existing_pairs.add(pair)

                        unflat_logger.info(
                            "UD_CHAIN_PER_PRED: discovered transition "
                            "0x%X -> 0x%X at blk[%d] via pred blk[%d]",
                            pred_from,
                            pred_const,
                            def_site.block_serial,
                            pred_serial,
                        )

                elif unflat_logger.debug_on:
                    unflat_logger.debug(
                        "UD_CHAIN: blk[%d] ea=0x%X opcode=%d — "
                        "could not resolve constant",
                        def_site.block_serial,
                        def_site.ins_ea,
                        def_site.ins_opcode,
                    )
                continue

            # --- Check if resolved constant is a valid state ---
            if const_val not in state_constants:
                if unflat_logger.debug_on:
                    unflat_logger.debug(
                        "UD_CHAIN: blk[%d] writes 0x%X — not a state constant",
                        def_site.block_serial,
                        const_val,
                    )
                continue

            # --- Determine from_state ---
            from_state: int | None = None

            # Check if def block is in a handler's blocks
            if def_site.block_serial in block_to_handler:
                from_state = block_to_handler[def_site.block_serial]
            else:
                # BFS walk backward up to depth 4 to find owning handler
                try:
                    visited = {def_site.block_serial}
                    frontier = [def_site.block_serial]
                    for _depth in range(4):
                        next_frontier: list[int] = []
                        for cur in frontier:
                            cur_blk = mba.get_mblock(cur)
                            if cur_blk is None:
                                continue
                            for pred_raw in cur_blk.predset:
                                pred = int(pred_raw)
                                if pred in visited:
                                    continue
                                visited.add(pred)
                                if pred in block_to_handler:
                                    from_state = block_to_handler[pred]
                                    break
                                next_frontier.append(pred)
                            if from_state is not None:
                                break
                        if from_state is not None:
                            break
                        frontier = next_frontier
                except (AttributeError, RuntimeError):
                    pass

            if from_state is None and bst_result is not None:
                # BFS backward walk through BST provenance (depth 4)
                bst_node_map = bst_result.bst_node_blocks
                bst_hsm = bst_result.handler_state_map
                bst_frontier: set[int] = {def_site.block_serial}
                visited_bst: set[int] = set()
                bst_resolved = False
                _bst_depth = 0
                for _bst_depth in range(4):
                    next_bst_frontier: set[int] = set()
                    for blk_serial in bst_frontier:
                        if blk_serial in visited_bst:
                            continue
                        visited_bst.add(blk_serial)
                        resolved = bst_node_map.resolve_state(
                            blk_serial, bst_hsm,
                        )
                        if resolved is not None:
                            from_state = resolved
                            bst_resolved = True
                            break
                        # Expand predecessors
                        try:
                            blk_obj = mba.get_mblock(blk_serial)
                            if blk_obj is not None:
                                for p_raw in blk_obj.predset:
                                    p_int = int(p_raw)
                                    if p_int not in visited_bst:
                                        next_bst_frontier.add(p_int)
                        except (AttributeError, RuntimeError):
                            pass
                    if bst_resolved:
                        break
                    bst_frontier = next_bst_frontier
                if from_state is not None and unflat_logger.debug_on:
                    unflat_logger.debug(
                        "UD_CHAIN_DIAG: BST provenance resolved "
                        "from_state=0x%X for block %d (depth %d)",
                        from_state,
                        def_site.block_serial,
                        _bst_depth,
                    )

            if from_state is None:
                # Emit transition with from_state=None rather than discarding
                transition = StateTransition(
                    from_state=None,
                    to_state=const_val,
                    from_block=def_site.block_serial,
                    provenance_chain=[(-1, 0)],
                )
                new_transitions.append(transition)
                if unflat_logger.debug_on:
                    unflat_logger.debug(
                        "UD_CHAIN: blk[%d] writes 0x%X — "
                        "emitting with from_state=None",
                        def_site.block_serial,
                        const_val,
                    )
                continue

            # Skip self-transitions
            if from_state == const_val:
                continue

            # Skip duplicates
            pair = (from_state, const_val)
            if pair in existing_pairs:
                continue

            # --- Create the transition ---
            transition = StateTransition(
                from_state=from_state,
                to_state=const_val,
                from_block=def_site.block_serial,
                provenance_chain=[(def_site.block_serial, const_val)],
            )
            new_transitions.append(transition)
            existing_pairs.add(pair)

            unflat_logger.info(
                "UD_CHAIN: discovered transition 0x%X -> 0x%X at blk[%d]",
                from_state,
                const_val,
                def_site.block_serial,
            )

        # --- Diagnostic: why are uncovered handler targets still uncovered? ---
        covered_targets: set[int] = {
            t.to_state for t in self.state_machine.transitions
        }
        for t in new_transitions:
            covered_targets.add(t.to_state)

        uncovered_targets = state_constants - covered_targets
        if uncovered_targets:
            unflat_logger.info(
                "UD_CHAIN_DIAG: %d uncovered target states: %s",
                len(uncovered_targets),
                [hex(s) for s in sorted(uncovered_targets)],
            )

            for target_state in sorted(uncovered_targets):
                found = False
                # Pass 1: check direct literal defs
                for ds in all_def_sites:
                    ds_blk = mba.get_mblock(ds.block_serial)
                    if ds_blk is None:
                        continue
                    ds_insn = ds_blk.head
                    while ds_insn is not None:
                        if ds_insn.ea == ds.ins_ea:
                            if (
                                ds_insn.l is not None
                                and ds_insn.l.t == ida_hexrays.mop_n
                            ):
                                val = int(ds_insn.l.nnn.value) & 0xFFFFFFFF
                                if val == target_state:
                                    fs: int | None = block_to_handler.get(
                                        ds.block_serial
                                    )
                                    if fs is None:
                                        visited_d = {ds.block_serial}
                                        frontier_d = [ds.block_serial]
                                        for _dd in range(4):
                                            next_fd: list[int] = []
                                            for cd in frontier_d:
                                                cd_blk = mba.get_mblock(cd)
                                                if cd_blk is None:
                                                    continue
                                                for p_raw in cd_blk.predset:
                                                    p = int(p_raw)
                                                    if p in visited_d:
                                                        continue
                                                    visited_d.add(p)
                                                    if p in block_to_handler:
                                                        fs = block_to_handler[p]
                                                        break
                                                    next_fd.append(p)
                                                if fs is not None:
                                                    break
                                            if fs is not None:
                                                break
                                            frontier_d = next_fd
                                    if fs is None:
                                        reason = "from_state=None"
                                    elif fs == target_state:
                                        reason = "self_transition"
                                    elif (fs, target_state) in existing_pairs:
                                        reason = "already_existing"
                                    else:
                                        reason = "SUCCESS"
                                    unflat_logger.info(
                                        "UD_CHAIN_DIAG: state 0x%X written at "
                                        "blk[%d] opcode=%d from_state=%s "
                                        "reason=%s",
                                        target_state,
                                        ds.block_serial,
                                        ds.ins_opcode,
                                        hex(fs) if fs is not None else "None",
                                        reason,
                                    )
                                    found = True
                            break
                        ds_insn = ds_insn.next

                if not found:
                    # Pass 2: check per-pred resolution potential
                    for ds in all_def_sites:
                        ds_blk2 = mba.get_mblock(ds.block_serial)
                        if ds_blk2 is None:
                            continue
                        ds_insn2 = ds_blk2.head
                        while ds_insn2 is not None:
                            if ds_insn2.ea == ds.ins_ea:
                                if (
                                    ds_insn2.opcode == ida_hexrays.m_mov
                                    and ds_insn2.l is not None
                                    and ds_insn2.l.t != ida_hexrays.mop_n
                                ):
                                    per_pred = (
                                        self._resolve_operand_constants_per_pred(
                                            mba,
                                            ds.block_serial,
                                            ds_insn2.l,
                                        )
                                    )
                                    for ps, pc in per_pred.items():
                                        if pc == target_state:
                                            fs2: int | None = (
                                                block_to_handler.get(ps)
                                            )
                                            if fs2 is None:
                                                try:
                                                    visited_d2 = {ps}
                                                    frontier_d2 = [ps]
                                                    for _dd2 in range(4):
                                                        next_fd2: list[int] = []
                                                        for cd2 in frontier_d2:
                                                            cd2_blk = (
                                                                mba.get_mblock(cd2)
                                                            )
                                                            if cd2_blk is None:
                                                                continue
                                                            for pp_raw in (
                                                                cd2_blk.predset
                                                            ):
                                                                pp = int(pp_raw)
                                                                if (
                                                                    pp in visited_d2
                                                                ):
                                                                    continue
                                                                visited_d2.add(pp)
                                                                if (
                                                                    pp
                                                                    in block_to_handler
                                                                ):
                                                                    fs2 = (
                                                                        block_to_handler[
                                                                            pp
                                                                        ]
                                                                    )
                                                                    break
                                                                next_fd2.append(pp)
                                                            if fs2 is not None:
                                                                break
                                                        if fs2 is not None:
                                                            break
                                                        frontier_d2 = next_fd2
                                                except (
                                                    AttributeError,
                                                    RuntimeError,
                                                ):
                                                    pass
                                            if fs2 is None:
                                                reason2 = "from_state=None"
                                            elif fs2 == target_state:
                                                reason2 = "self_transition"
                                            elif (
                                                fs2,
                                                target_state,
                                            ) in existing_pairs:
                                                reason2 = "already_existing"
                                            else:
                                                reason2 = "SUCCESS"
                                            unflat_logger.info(
                                                "UD_CHAIN_DIAG: state 0x%X "
                                                "via per-pred blk[%d]->blk[%d]"
                                                " from_state=%s reason=%s",
                                                target_state,
                                                ps,
                                                ds.block_serial,
                                                hex(fs2)
                                                if fs2 is not None
                                                else "None",
                                                reason2,
                                            )
                                            found = True
                                break
                            ds_insn2 = ds_insn2.next

                    if not found:
                        unflat_logger.info(
                            "UD_CHAIN_DIAG: state 0x%X — no def site found "
                            "(direct or per-pred)",
                            target_state,
                        )

        return new_transitions

    def _try_resolve_operand_constant(
        self,
        mba: "ida_hexrays.mba_t",
        blk_serial: int,
        mop: "ida_hexrays.mop_t | None",
    ) -> "int | None":
        """Try to resolve a micro-operand to a constant.

        First checks if the operand is a literal constant.  If not, performs
        one level of backward UD chain lookup to find a reaching definition
        with a literal constant source.

        Args:
            mba: The MBA instance.
            blk_serial: Block serial where the operand is used.
            mop: The micro-operand to resolve.

        Returns:
            The resolved constant value (masked to 32 bits), or ``None`` if
            resolution fails or is ambiguous.
        """
        if mop is None:
            return None

        # Direct literal
        if mop.t == ida_hexrays.mop_n:
            return int(mop.nnn.value) & 0xFFFFFFFF

        # One-level backward UD chain lookup
        try:
            reaching_defs: list[DefSite] = []
            if mop.t == ida_hexrays.mop_r:
                reaching_defs = find_reaching_defs_for_reg(
                    mba, blk_serial, mop.r, mop.size
                )
            elif mop.t == ida_hexrays.mop_S:
                reaching_defs = find_reaching_defs_for_stkvar(
                    mba, blk_serial, mop.s.off, mop.size
                )
            else:
                return None

            if not reaching_defs:
                return None

            # Check if all reaching defs agree on the same constant
            resolved_constants: set[int] = set()
            for rd in reaching_defs:
                rd_blk = mba.get_mblock(rd.block_serial)
                if rd_blk is None:
                    continue
                rd_insn = rd_blk.head
                while rd_insn is not None:
                    if rd_insn.ea == rd.ins_ea:
                        if (
                            rd_insn.l is not None
                            and rd_insn.l.t == ida_hexrays.mop_n
                        ):
                            val = int(rd_insn.l.nnn.value) & 0xFFFFFFFF
                            resolved_constants.add(val)
                        break
                    rd_insn = rd_insn.next

            # Ambiguous — multiple different constants
            if len(resolved_constants) != 1:
                return None

            return next(iter(resolved_constants))

        except Exception:
            unflat_logger.debug(
                "UD_CHAIN: backward resolve failed for blk[%d] mop_type=%d",
                blk_serial,
                mop.t if mop else -1,
            )
            return None

    def _resolve_operand_constants_per_pred(
        self,
        mba: "ida_hexrays.mba_t",
        blk_serial: int,
        mop: "ida_hexrays.mop_t | None",
    ) -> "dict[int, int]":
        """Resolve a temp operand to per-predecessor constants.

        When a merge block reads a temp variable that different predecessors
        define with different constants, this method returns one constant per
        predecessor instead of giving up.

        Scans each predecessor of *blk_serial* for definitions of the temp
        variable described by *mop*.  For each predecessor where the last
        definition has a literal source, records ``{pred_serial: constant}``.

        Args:
            mba: The MBA instance.
            blk_serial: Serial of the merge block where *mop* is read.
            mop: The micro-operand (must be ``mop_r`` or ``mop_S``).

        Returns:
            ``{pred_serial: constant_value}`` for each predecessor that
            writes a resolvable literal.  Empty dict on failure.
        """
        if mop is None:
            return {}

        try:
            blk = mba.get_mblock(blk_serial)
            if blk is None:
                return {}
            pred_serials: list[int] = [int(p) for p in blk.predset]
        except (AttributeError, RuntimeError):
            return {}

        if len(pred_serials) < 2:
            return {}

        result: dict[int, int] = {}

        for pred_serial in pred_serials:
            # Scan predecessor for defs of the temp variable
            defs: list[DefSite] = []
            if mop.t == ida_hexrays.mop_r:
                defs = _scan_block_for_reg_defs(
                    mba, pred_serial, mop.r, mop.size
                )
            elif mop.t == ida_hexrays.mop_S:
                defs = _scan_block_for_stkvar_defs(
                    mba, pred_serial, mop.s.off, mop.size
                )
            else:
                continue

            if not defs:
                # No def in this predecessor — try one level deeper
                # (single-pred chain walk)
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None:
                    continue
                inner_preds = [int(p) for p in pred_blk.predset]
                if len(inner_preds) != 1:
                    continue
                inner_pred = inner_preds[0]
                if mop.t == ida_hexrays.mop_r:
                    defs = _scan_block_for_reg_defs(
                        mba, inner_pred, mop.r, mop.size
                    )
                elif mop.t == ida_hexrays.mop_S:
                    defs = _scan_block_for_stkvar_defs(
                        mba, inner_pred, mop.s.off, mop.size
                    )

            if not defs:
                continue

            # Use the LAST def in the block (final write wins)
            last_def = defs[-1]
            rd_blk = mba.get_mblock(last_def.block_serial)
            if rd_blk is None:
                continue

            # Find the instruction and extract the literal source
            rd_insn = rd_blk.head
            while rd_insn is not None:
                if rd_insn.ea == last_def.ins_ea:
                    if (
                        rd_insn.l is not None
                        and rd_insn.l.t == ida_hexrays.mop_n
                    ):
                        val = int(rd_insn.l.nnn.value) & 0xFFFFFFFF
                        result[pred_serial] = val
                    break
                rd_insn = rd_insn.next

        if result and unflat_logger.debug_on:
            unflat_logger.debug(
                "UD_CHAIN_PER_PRED: blk[%d] preds=%s resolved=%s",
                blk_serial,
                pred_serials,
                {p: hex(v) for p, v in result.items()},
            )

        return result

    def _build_transitions(
        self,
        state_assignments: list[StateUpdateSite],
        state_check_blocks: list[tuple[int, int, int]],
    ) -> None:
        """Build state transitions based on assignments and checks."""
        if self.state_machine is None or self.state_machine.state_var is None:
            return

        state_var = self.state_machine.state_var

        assignment_map: dict[int, list[ida_hexrays.minsn_t]] = {}
        for update_site in state_assignments:
            assignment_map.setdefault(update_site.block_serial, []).append(
                update_site.instruction
            )

        if self.state_machine is not None:
            self.state_machine.assignment_map = assignment_map

        check_map = {const: blk_serial for blk_serial, _, const in state_check_blocks}
        check_serials = set(check_map.values())

        try:
            successors = {
                blk_serial: [int(succ) for succ in self.mba.get_mblock(blk_serial).succset]
                for blk_serial in range(self.mba.qty)
            }
            dom_tree = compute_dom_tree(successors, entry=0)
        except Exception:
            unflat_logger.warning("Dominator computation failed, using unbounded BFS")
            dom_tree = None

        for state_val, handler in self.state_machine.handlers.items():
            check_blk = self.mba.get_mblock(handler.check_block)

            visited = set()
            to_visit = []
            # Collect all (block_serial, resolved_value) pairs for provenance
            provenance_steps: list[tuple[int, int]] = []

            handler_entry_serial: int | None = None
            for succ_serial in check_blk.succset:
                if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                    if succ_serial == check_blk.tail.d.b:
                        continue
                to_visit.append(succ_serial)
                if handler_entry_serial is None:
                    handler_entry_serial = succ_serial

            while to_visit:
                curr_serial = to_visit.pop(0)
                if curr_serial in visited:
                    continue
                visited.add(curr_serial)

                # Skip check blocks for other states -- they are BST
                # comparison nodes the BFS entered via fall-through.
                # Don't add them to handler_blocks but still expand
                # through them to reach the real handler body.
                if curr_serial not in check_serials:
                    handler.handler_blocks.append(curr_serial)

                if curr_serial in assignment_map:
                    curr_blk = self.mba.get_mblock(curr_serial)
                    for assignment_insn in assignment_map[curr_serial]:
                        next_state = self._resolve_next_state_value(
                            curr_blk,
                            assignment_insn,
                            state_var,
                            int(state_val),
                        )
                        if next_state is None:
                            continue
                        if next_state == state_val:
                            continue
                        # Record every resolved value for provenance, even
                        # values that are not valid state constants.
                        provenance_steps.append((curr_serial, next_state))
                        if next_state not in self.state_machine.state_constants:
                            unflat_logger.debug(
                                "BFS: skipping invalid transition %s -> %s (not a state constant)",
                                state_val,
                                next_state,
                            )
                            continue
                        transition = StateTransition(
                            from_state=state_val,
                            to_state=next_state,
                            from_block=curr_serial,
                            provenance_chain=list(provenance_steps),
                        )
                        self.state_machine.add_transition(transition)

                curr_blk = self.mba.get_mblock(curr_serial)
                for succ_serial in curr_blk.succset:
                    if succ_serial in visited:
                        continue
                    if succ_serial in check_map.values():
                        continue
                    if (
                        dom_tree is not None
                        and handler_entry_serial is not None
                        and not dom_tree.dominates(handler_entry_serial, succ_serial)
                    ):
                        continue
                    to_visit.append(succ_serial)

            # Log provenance summary when multiple state writes were seen
            if len(provenance_steps) > 1:
                emitted_targets = {
                    v for _, v in provenance_steps
                    if v in self.state_machine.state_constants and v != state_val
                }
                unflat_logger.debug(
                    "BFS provenance for handler 0x%X: %d steps, %d emitted targets %s",
                    state_val,
                    len(provenance_steps),
                    len(emitted_targets),
                    [
                        "(blk[%d]=0x%X)" % (bs, val)
                        for bs, val in provenance_steps
                    ],
                )

        unflat_logger.info(
            "BFS found %d transitions; running scan to fill gaps",
            len(self.state_machine.transitions),
        )
        scan_transitions = self._build_transitions_by_scan(self.mba)
        bfs_covered_from_states = {t.from_state for t in self.state_machine.transitions}
        scan_added = 0
        for t in scan_transitions:
            if t.from_state is None:
                continue
            if t.from_state not in self.state_machine.state_constants:
                continue
            if t.to_state not in self.state_machine.state_constants:
                continue
            if t.from_state not in bfs_covered_from_states:
                self.state_machine.add_transition(t)
                bfs_covered_from_states.add(t.from_state)
                scan_added += 1
        unflat_logger.info(
            "Scan supplemented %d additional transitions (total %d)",
            scan_added,
            len(self.state_machine.transitions),
        )

        forward_transitions = self._resolve_transitions_forward_prop(
            self.state_machine, self.mba
        )
        if forward_transitions:
            unflat_logger.info(
                "Forward propagation resolved %d additional transitions",
                len(forward_transitions),
            )
            # Track existing (from_state, to_state) pairs to avoid exact
            # duplicates while still allowing supplemental transitions that
            # share a from_state but have a different to_state (conditional
            # forks).
            existing_pairs_fwd: set[tuple[int | None, int]] = {
                (t.from_state, t.to_state) for t in self.state_machine.transitions
            }
            added_count = 0
            for ft in forward_transitions:
                if ft.to_state not in self.state_machine.state_constants:
                    self.state_machine.state_constants.add(ft.to_state)
                pair = (ft.from_state, ft.to_state)
                if pair not in existing_pairs_fwd:
                    self.state_machine.add_transition(ft)
                    existing_pairs_fwd.add(pair)
                    added_count += 1
            unflat_logger.info(
                "Forward prop: %d/%d transitions added to state machine "
                "(duplicates filtered: %d)",
                added_count,
                len(forward_transitions),
                len(forward_transitions) - added_count,
            )

        # Phase 3.5: Compute BST analysis for UD chain provenance fallback
        if self.bst_result is None and self.state_machine.handlers:
            entry_serial = list(self.state_machine.handlers.values())[0].check_block
            stkoff_for_bst: int | None = None
            if self.state_machine.state_var is not None:
                sv = self.state_machine.state_var
                if sv.t == ida_hexrays.mop_S:
                    stkoff_for_bst = sv.s.off
            try:
                from d810.recon.flow.bst_analysis import analyze_bst_dispatcher

                raw_bst = analyze_bst_dispatcher(
                    self.mba,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=stkoff_for_bst,
                )
                if raw_bst is not None and len(raw_bst.handler_state_map) > 0:
                    self.bst_result = raw_bst
                    unflat_logger.debug(
                        "BST analysis computed for UD chain fallback: "
                        "%d handler mappings",
                        len(raw_bst.handler_state_map),
                    )
            except Exception:
                unflat_logger.debug(
                    "BST analysis for UD chain fallback failed"
                )

        # Phase 4: UD chain discovery with fixpoint iteration
        _UD_CHAIN_MAX_ITERATIONS = 5
        for iteration in range(_UD_CHAIN_MAX_ITERATIONS):
            try:
                ud_transitions = self._discover_transitions_via_ud_chains(
                    self.mba, bst_result=self.bst_result,
                )
            except Exception:
                unflat_logger.debug(
                    "UD chain discovery failed at iteration %d", iteration
                )
                break
            if not ud_transitions:
                break
            for ut in ud_transitions:
                self.state_machine.add_transition(ut)
            unflat_logger.info(
                "UD chain discovery iteration %d: found %d new transitions "
                "(total %d)",
                iteration,
                len(ud_transitions),
                len(self.state_machine.transitions),
            )

        from_block_groups: dict[int, list[StateTransition]] = {}
        for t in self.state_machine.transitions:
            from_block_groups.setdefault(t.from_block, []).append(t)

        for from_blk_serial, group in from_block_groups.items():
            unique_to_states = {t.to_state for t in group}
            if len(unique_to_states) == 2:
                for t in group:
                    t.is_conditional = True
                    t.condition_block = from_blk_serial
                if unflat_logger.debug_on:
                    unflat_logger.debug(
                        "Conditional fork at block %d: states %s",
                        from_blk_serial,
                        unique_to_states,
                    )
