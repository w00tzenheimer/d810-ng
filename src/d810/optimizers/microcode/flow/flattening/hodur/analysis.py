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
from d810.core import logging
from d810.core.bits import unsigned_to_signed
from d810.evaluator.evaluators import evaluate_concrete
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.tracker import (
    MopTracker,
    get_all_possibles_values,
)
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.recon.flow.def_search import resolve_mop_via_predecessors
from d810.hexrays.utils.hexrays_formatters import format_mop_t
from d810.hexrays.utils.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
    extract_num_mop,
    get_mop_index,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import HodurStateMachine
from d810.recon.flow.dispatcher_detection import DispatcherCache
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
}

from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
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
        self.state_machine: HodurStateMachine | None = None
        self.use_cache = use_cache
        self._cache: DispatcherCache | None = None
        self.min_state_constant = min_state_constant
        self.min_state_constants = min_state_constants
        self.max_state_constants = max_state_constants

    def detect(self) -> HodurStateMachine | None:
        """
        Detect if the function contains a Hodur state machine.

        Returns the state machine structure if found, None otherwise.

        Uses cached dispatcher analysis when available for performance.
        """
        # Use cached dispatcher detection if available
        if self.use_cache:
            self._cache = DispatcherCache.get_or_create(self.mba)
            analysis = self._cache.analyze()

            # Quick check: is this Hodur-style?
            if not analysis.is_conditional_chain:
                unflat_logger.debug(
                    "Dispatcher cache says not Hodur-style (constants=%d, nested=%d)",
                    len(analysis.state_constants),
                    analysis.nested_loop_depth,
                )
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

        # Step 2: Find the state variable (the operand being compared)
        state_var = None
        if self._cache:
            analysis = self._cache.analyze()
            if analysis.state_variable is not None:
                state_var = analysis.state_variable.mop
                unflat_logger.debug(
                    "Using cached state variable: %s (type=%d, comparisons=%d)",
                    format_mop_t(state_var),
                    analysis.state_variable.mop_type,
                    analysis.state_variable.comparison_count,
                )

        if state_var is None:
            state_var = self._identify_state_variable(state_check_blocks)

        if state_var is None:
            unflat_logger.debug("Could not identify state variable")
            return None

        # Step 3: Find all state constants
        state_constants = set()
        if self._cache:
            analysis = self._cache.analyze()
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
        if self._cache and self._cache.analyze().initial_state:
            initial_state = self._cache.analyze().initial_state
        else:
            initial_state = self._find_initial_state(state_constants)

        # Build the state machine structure
        self.state_machine = HodurStateMachine(
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

        if result is not None and self._mops_match_state_var(dst, state_var):
            return result
        return None

    def _resolve_transitions_forward_prop(
        self,
        state_machine: "HodurStateMachine",
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
                        if val in state_constants or val >= self.min_state_constant:
                            to_state = val
                            found_block = blk_serial
                            break
                    insn = insn.next
                if to_state is not None:
                    break

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
                    )
                )

        unflat_logger.info(
            "Forward prop: resolved %d new transitions from %d unresolved states",
            len(new_transitions),
            len(unresolved_states),
        )
        return new_transitions

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
            covered_from_states = {t.from_state for t in self.state_machine.transitions}
            for ft in forward_transitions:
                if ft.to_state not in self.state_machine.state_constants:
                    self.state_machine.state_constants.add(ft.to_state)
                if ft.from_state not in covered_from_states:
                    self.state_machine.add_transition(ft)
                    covered_from_states.add(ft.from_state)

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
