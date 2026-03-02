"""
Hodur While-Loop State Machine Unflattener

This module handles deobfuscation of Hodur-style control flow flattening which uses
nested while(1) loops with a state variable instead of switch statements.

Pattern:
    state = INITIAL_STATE;  // e.g., 0xB2FD8FB6
    while(1) {
        // ... handler code for state N ...
        if (state != STATE_N) break;
        // ... more code ...
        state = NEXT_STATE;  // transition
    }
    while(1) { ... }  // next state handler

Key differences from O-LLVM:
- No switch/jtbl dispatcher
- Uses nested while(1) loops with break
- State comparisons use jnz (jump if not zero/not equal)
- Each while loop handles one state value
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import ida_hexrays
import ida_pro

from d810.cfg.dominators import compute_dominators, dominates
from d810.core import logging
from d810.core.bits import unsigned_to_signed
from d810.expr.ast import minsn_to_ast
from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.expr.z3_utils import _resolve_mop_via_predecessors
from d810.hexrays.bst_analysis import (
    BSTAnalysisResult,
    _forward_eval_insn,
    _mop_matches_stkoff,
    analyze_bst_dispatcher,
    find_bst_default_block,
    resolve_target_via_bst,
)
from d810.hexrays.cfg_mutations import convert_jtbl_to_goto
from d810.hexrays.cfg_utils import (
    change_1way_block_successor,
    duplicate_block,
    make_2way_block_goto,
    safe_verify,
    update_blk_successor,
)
from d810.hexrays.deferred_modifier import DeferredGraphModifier
from d810.hexrays.hexrays_formatters import format_mop_t
from d810.hexrays.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
    extract_num_mop,
    get_mop_index,
)
from d810.hexrays.tracker import (
    InstructionDefUseCollector,
    MopHistory,
    MopTracker,
    remove_segment_registers,
)
from d810.optimizers.microcode.flow.flattening.dispatcher_detection import (
    DispatcherCache,
    DispatcherStrategy,
)
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_cfg_modifications,
)
from d810.optimizers.microcode.flow.flattening.transition_builder import (
    StateHandler,
    StateTransition,
    StateUpdateSite,
    TransitionBuilder,
    TransitionResult,
    _get_state_var_stkoff,
)
from d810.optimizers.microcode.flow.flattening.utils import get_all_possibles_values
from d810.optimizers.microcode.handler import ConfigParam

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)

# State values must exceed this threshold to be considered dispatcher constants.
# Real obfuscators use values from 0x1000+ (hardened OLLVM) to 0xDEAD0000+ (Hodur).
# Lowered from 0x10000000 to 0x01000000 to capture states like 0x0B8148F6 which are
# 28-bit values just below the original 0x10000000 cutoff.
MIN_STATE_CONSTANT = 0x01000000
# Minimum number of unique state constants to consider it a state machine
MIN_STATE_CONSTANTS = 3
# Maximum number of state constants - if more, it's likely OLLVM FLA not Hodur
# Hodur typically has ~10-20 states, OLLVM FLA can have 50+
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


@dataclass
class HodurStateMachine:
    """Represents the complete Hodur state machine structure."""

    mba: ida_hexrays.mba_t
    state_var: ida_hexrays.mop_t | None = None
    initial_state: int | None = None
    state_constants: set[int] = field(default_factory=set)
    handlers: dict[int, StateHandler] = field(
        default_factory=dict
    )  # state_value -> handler
    transitions: list[StateTransition] = field(default_factory=list)
    assignment_map: dict[int, list] = field(default_factory=dict)

    def add_state_constant(self, const: int) -> None:
        self.state_constants.add(const)

    def add_handler(self, handler: StateHandler) -> None:
        self.handlers[handler.state_value] = handler

    def add_transition(self, transition: StateTransition) -> None:
        self.transitions.append(transition)
        if transition.from_state in self.handlers:
            self.handlers[transition.from_state].transitions.append(transition)


@dataclass
class HandlerPathResult:
    """Result of evaluating one exit path from a handler."""

    exit_block: int  # block serial where handler exits to dispatcher
    final_state: Optional[int]  # concrete state value at exit; None for terminal (m_ret) paths
    state_writes: list  # [(block_serial, insn_ea), ...] of state var writes
    ordered_path: list = field(default_factory=list)  # ordered sequence of block serials visited during DFS


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
        # OLLVM FLA typically has many more state constants (50+)
        # Hodur typically has ~10-20 states
        if len(state_check_blocks) > self.max_state_constants:
            unflat_logger.info(
                "Too many state check blocks (%d > %d) - likely OLLVM FLA, not Hodur",
                len(state_check_blocks),
                self.max_state_constants,
            )
            return None

        # Step 2: Find the state variable (the operand being compared)
        # Prefer cached state variable from DispatcherCache (more sophisticated detection)
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

        # Fall back to simple detection if cache doesn't have it
        if state_var is None:
            state_var = self._identify_state_variable(state_check_blocks)

        if state_var is None:
            unflat_logger.debug("Could not identify state variable")
            return None

        # Step 3: Find all state constants
        # Prefer cached state constants (includes constants from both comparisons and assignments)
        state_constants = set()
        if self._cache:
            analysis = self._cache.analyze()
            if analysis.state_constants:
                state_constants = set(analysis.state_constants)
                unflat_logger.debug(
                    "Using %d cached state constants",
                    len(state_constants),
                )

        # Fall back to extracting from state check blocks
        if not state_constants:
            for blk_serial, opcode, const in state_check_blocks:
                state_constants.add(const)

        # Step 4: Find state assignments and build transition graph
        state_assignments = self._find_state_assignments(state_var)

        # Step 5: Find initial state (assignment in entry block or its immediate successors)
        # Use cached value if available
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

        # Get the left operand from the first comparison (should be the state var)
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
            # Defensive fallback for malformed succset bookkeeping.
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

        # SSA-tolerant structural fallback: compare underlying location only,
        # ignoring valnum / SSA version tags that differ across blocks.
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

        # Use semantic equality as fallback to tolerate wrapper differences.
        try:
            from d810.expr.z3_utils import z3_check_mop_equality

            return bool(z3_check_mop_equality(candidate, state_var))
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
            return int(ast.evaluate(leaf_values))
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
        # Look in the entry block and its immediate successors
        entry_blk = self.mba.get_mblock(0)

        # Check entry block
        insn = entry_blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_mov:
                if insn.l.t == ida_hexrays.mop_n:
                    const_val = insn.l.nnn.value
                    if const_val in state_constants:
                        return const_val
            insn = insn.next

        # Check first few blocks (state might be set after some setup code)
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
            # Scan backward in this block for the most recent assignment to mop.r
            # that occurs before stop_serial.
            ins = blk.tail
            # Skip past stop_serial first (tail may equal the assignment itself).
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
            # Inline sub-instruction — fold both sides at the same stop boundary.
            sub = mop.d
            if sub is not None and sub.l is not None and sub.r is not None:
                lv = self._fold_block_local(blk, sub.l, stop_serial, _depth + 1)
                rv = self._fold_block_local(blk, sub.r, stop_serial, _depth + 1)
                if lv is not None and rv is not None:
                    return self._eval_binop(sub.opcode, lv, rv)
        if mop.t == ida_hexrays.mop_S:
            # Stack variable intermediary: scan backward for a definition that
            # writes to the same stack slot (matched by offset and size) before
            # stop_serial.  Handles MBA patterns such as:
            #   i = (v22 ^ v23) - v21
            # where v22/v23/v21 are mop_S stack slots.
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
        # Fast path: try within the current block first.
        result = self._fold_block_local(blk, mop, stop_serial)
        if result is not None:
            return result

        # Only cross-block for register and stack operands; numerics and
        # sub-instructions are already handled by _fold_block_local.
        if mop is None or mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
            return None
        if max_pred_depth <= 0:
            return None

        # Walk the predecessor BFS up to max_pred_depth levels.
        # Each level: collect the set of predecessor blocks at that depth.
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

                # Fold from the *tail* of the predecessor (no stop_serial bound —
                # use a sentinel that is larger than any EA so the whole block is
                # searched).
                pred_val = self._fold_block_local(pred_blk, mop, 0xFFFFFFFFFFFFFFFF)
                if pred_val is None:
                    all_resolved = False
                    # Still collect preds for the next hop.
                    try:
                        next_level.extend(pred_blk.preds())
                    except Exception:
                        pass
                else:
                    values.append(pred_val)

            if all_resolved and values:
                # All preds at this level resolved to constants; check agreement.
                if len(set(values)) == 1:
                    return values[0]
                # Disagreement — different predecessor paths disagree; give up.
                return None

            if values and not all_resolved:
                # Some preds resolved, some did not — try next hop only for the
                # unresolved ones (already accumulated in next_level).
                # If all resolved values agree so far, keep looking; otherwise bail.
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
            # Go further back but limit depth to avoid full traversal
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

        # Build check_map: block_serial -> state_constant (for dispatcher blocks)
        check_map: dict[int, int] = {
            handler.check_block: state_val
            for state_val, handler in self.state_machine.handlers.items()
        }
        dispatcher_serials = set(check_map.keys())

        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            if blk_idx in dispatcher_serials:
                continue  # skip dispatcher check blocks

            insn = blk.head
            while insn is not None:
                # Look for: state_var := EXPR  (mov OR binary op writing to state var)
                # Handles both plain m_mov and MBA patterns like (v^w)-c with state var as dest.
                if (
                    insn.opcode in HODUR_STATE_UPDATE_OPCODES
                    and insn.d is not None
                    and insn.d.t != ida_hexrays.mop_z
                    and self._mops_match_state_var(insn.d, state_var)
                ):
                    if insn.opcode == ida_hexrays.m_mov:
                        folded = self._fold_mop_inter_block(blk, insn.l, insn.ea)
                    else:
                        # Binary op writing directly to state var: fold both operands.
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
                        # Self-loop: state var assigned its own current value — skip.
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

        # m_call: invalidate all register bindings (stack vars survive).
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

        # Check whether dst is the state variable
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

            # Initialise variable maps and seed with the known state value.
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
                        # Accept if val is a known state constant OR looks like one
                        # (state_constants may be incomplete if IDA optimized away checks)
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

        # Create a map: block_serial -> update instructions
        assignment_map: dict[int, list[ida_hexrays.minsn_t]] = {}
        for update_site in state_assignments:
            assignment_map.setdefault(update_site.block_serial, []).append(
                update_site.instruction
            )

        # Persist assignment_map on state machine for later use by resolvers
        if self.state_machine is not None:
            self.state_machine.assignment_map = assignment_map

        # Create a map: state_constant -> check_block serial
        check_map = {const: blk_serial for blk_serial, _, const in state_check_blocks}

        # Compute dominator tree for BFS bounding
        try:
            dom = compute_dominators(self.mba)
        except Exception:
            unflat_logger.warning("Dominator computation failed, using unbounded BFS")
            dom = None

        # For each state handler, find what state it transitions to
        for state_val, handler in self.state_machine.handlers.items():
            check_blk = self.mba.get_mblock(handler.check_block)

            # The "match" path is the fall-through (when state == STATE_N)
            # For jnz: if state != STATE_N, jump; else fall through
            # So fall-through is the handler code for this state

            # Find state assignments reachable from the handler
            visited = set()
            to_visit = []

            # Start from the fall-through successor
            handler_entry_serial: int | None = None
            for succ_serial in check_blk.succset:
                # Skip the jump target (that's the "break" path)
                if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                    if succ_serial == check_blk.tail.d.b:
                        continue
                to_visit.append(succ_serial)
                if handler_entry_serial is None:
                    handler_entry_serial = succ_serial

            # BFS to find state assignments
            while to_visit:
                curr_serial = to_visit.pop(0)
                if curr_serial in visited:
                    continue
                visited.add(curr_serial)
                handler.handler_blocks.append(curr_serial)

                # Check if this block has a state assignment
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
                        # Skip self-loops (re-assignment of current state at handler start)
                        if next_state == state_val:
                            continue
                        # Skip transitions to unknown states (BFS noise from shared blocks)
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

                # Continue BFS but stop at state check blocks
                curr_blk = self.mba.get_mblock(curr_serial)
                for succ_serial in curr_blk.succset:
                    if succ_serial in visited:
                        continue
                    if succ_serial in check_map.values():
                        continue
                    # Only enqueue successor if dominated by handler entry
                    if (
                        dom is not None
                        and handler_entry_serial is not None
                        and not dominates(dom, handler_entry_serial, succ_serial)
                    ):
                        continue
                    to_visit.append(succ_serial)

        # Always run global scan as a supplement: fills gaps where BFS cannot cross
        # call boundaries or shared merge-point blocks produce spurious results.
        unflat_logger.info(
            "BFS found %d transitions; running scan to fill gaps",
            len(self.state_machine.transitions),
        )
        scan_transitions = self._build_transitions_by_scan(self.mba)
        # Merge: BFS transitions already recorded; scan fills from_state slots not covered.
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

        # Phase 3: Forward propagation for unresolved handlers
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
                # Backfill any to_state that was found but not yet in state_constants
                # (IDA may have optimized away the corresponding check block)
                if ft.to_state not in self.state_machine.state_constants:
                    self.state_machine.state_constants.add(ft.to_state)
                # Only add if not already covered
                if ft.from_state not in covered_from_states:
                    self.state_machine.add_transition(ft)
                    covered_from_states.add(ft.from_state)

        # Post-process: detect conditional forks (2 transitions from same from_block)
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


class HodurUnflattener(GenericUnflatteningRule):
    """
    Unflattener for Hodur-style while-loop state machines.

    This rule detects and removes control flow flattening that uses nested while(1)
    loops with a state variable, as seen in Hodur malware.
    """

    DESCRIPTION = "Remove Hodur-style while-loop control flow flattening"
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]
    DEFAULT_MAX_PASSES = 3
    HARD_MAX_PASSES = 10
    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100

    CONFIG_SCHEMA = GenericUnflatteningRule.CONFIG_SCHEMA + (
        ConfigParam(
            "min_state_constant",
            int,
            MIN_STATE_CONSTANT,
            "Minimum value to qualify as a state constant",
        ),
        ConfigParam(
            "min_state_constants",
            int,
            MIN_STATE_CONSTANTS,
            "Minimum unique state constants for state machine detection",
        ),
        ConfigParam(
            "max_state_constants",
            int,
            MAX_STATE_CONSTANTS_HODUR,
            "Maximum state constants before classifying as OLLVM-style",
        ),
        ConfigParam(
            "max_passes",
            int,
            DEFAULT_MAX_PASSES,
            "Maximum unflattening passes",
        ),
    )

    def __init__(self):
        super().__init__()
        self.state_machine: HodurStateMachine | None = None
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.min_state_constant = MIN_STATE_CONSTANT
        self.min_state_constants = MIN_STATE_CONSTANTS
        self.max_state_constants = MAX_STATE_CONSTANTS_HODUR
        self.deferred: DeferredGraphModifier | None = None
        self._actual_pass_count: int = 0
        self._current_tracked_maturity: int = ida_hexrays.MMAT_ZERO
        self._resolved_transitions: set[tuple[int, int]] = set()
        self._initial_transitions: list | None = None
        self._detector: HodurStateMachineDetector | None = None
        self._jtbl_converted: bool = False
        self._jtbl_dispatcher_serial: int = -1
        self._jtbl_state_to_handler: dict[int, int] = {}
        self._jtbl_handler_state_map: dict[int, int] = {}
        self._linearized_blocks: set[int] = set()

    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_state_constant" in self.config:
            self.min_state_constant = int(self.config["min_state_constant"])
        if "min_state_constants" in self.config:
            self.min_state_constants = int(self.config["min_state_constants"])
        if "max_state_constants" in self.config:
            self.max_state_constants = int(self.config["max_state_constants"])
        if "max_passes" in self.config:
            self.max_passes = int(self.config["max_passes"])

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        """Check if this rule should be applied."""
        if not super().check_if_rule_should_be_used(blk):
            return False

        # Reset pass count on maturity change
        if self.mba.maturity != self._current_tracked_maturity:
            self._current_tracked_maturity = self.mba.maturity
            self._actual_pass_count = 0
            self.max_passes = self.DEFAULT_MAX_PASSES
            self._resolved_transitions = set()
            self._initial_transitions = None
            self._linearized_blocks = set()

        # Gate on actual Hodur runs, not block callback count
        if self._actual_pass_count >= self.max_passes:
            return False

        return True

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Main optimization entry point."""
        self.mba = blk.mba

        if not self.check_if_rule_should_be_used(blk):
            return 0

        unflat_logger.debug(
            "HodurUnflattener: Starting pass %d/%d at maturity %d",
            self._actual_pass_count,
            self.max_passes,
            self.cur_maturity,
        )

        # Detect state machine
        detector = HodurStateMachineDetector(
            self.mba,
            min_state_constant=self.min_state_constant,
            min_state_constants=self.min_state_constants,
            max_state_constants=self.max_state_constants,
        )
        self.state_machine = detector.detect()
        self._detector = detector

        if self.state_machine is None:
            # Fallback to robust cache analysis
            cache = DispatcherCache.get_or_create(self.mba)
            analysis = cache.analyze()
            if analysis.is_conditional_chain:
                self.state_machine = self._build_state_machine_from_cache(analysis)

        if self.state_machine is None:
            unflat_logger.info("No Hodur state machine detected")
            return 0

        # Save full transition list from first detection for carry-forward
        if self._actual_pass_count == 0:
            self._initial_transitions = list(self.state_machine.transitions)

        # Log the detected structure
        self._log_state_machine()

        # Try BST analysis to find additional transitions not found by BFS
        if self.state_machine is not None:
            builder = TransitionBuilder()
            bst_result = builder.build(self.mba, detector)
            if bst_result is not None and bst_result.resolved_count > len(
                self.state_machine.transitions
            ):
                self._merge_bst_transitions(bst_result)
                unflat_logger.info(
                    "BST walker found %d transitions (vs BFS %d), merged",
                    bst_result.resolved_count,
                    len(self.state_machine.transitions) - bst_result.resolved_count,
                )

        # On subsequent passes, supplement re-detected transitions with
        # unresolved transitions carried forward from the initial detection.
        if self._actual_pass_count > 0 and self._initial_transitions is not None:
            detected_keys = {
                (t.from_state, t.to_state) for t in self.state_machine.transitions
            }
            supplemented = 0
            for t in self._initial_transitions:
                key = (t.from_state, t.to_state)
                if key not in self._resolved_transitions and key not in detected_keys:
                    self.state_machine.transitions.append(t)
                    supplemented += 1
            unflat_logger.debug(
                "HodurUnflattener: supplemented %d transitions from initial detection "
                "(resolved: %d, re-detected: %d)",
                supplemented,
                len(self._resolved_transitions),
                len(detected_keys),
            )

        # Direct linearization: store BST result for use after deferred init.
        self._jtbl_converted = False
        self._jtbl_dispatcher_serial = -1
        self._jtbl_state_to_handler = {}
        self._jtbl_handler_state_map = {}
        self._bst_result: BSTAnalysisResult | None = None
        self._bst_dispatcher_serial: int = -1
        if self.state_machine is not None:
            bst_stkoff = (
                _get_state_var_stkoff(self._detector)
                if self._detector is not None
                else None
            )
            entry_serial = (
                list(self.state_machine.handlers.values())[0].check_block
                if self.state_machine.handlers
                else 0
            )
            try:
                raw_bst = analyze_bst_dispatcher(
                    self.mba,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=bst_stkoff,
                )
            except Exception:
                raw_bst = None

            if raw_bst is not None and len(raw_bst.handler_state_map) > 0:
                self._bst_result = raw_bst
                self._bst_dispatcher_serial = entry_serial

        # Initialize deferred modifier - queue all changes first, apply later
        self.deferred = DeferredGraphModifier(self.mba)

        # Direct linearization: queue goto redirects from BST analysis
        if self._bst_result is not None:
            linearized = self._linearize_handlers(
                self._bst_result,
                dispatcher_serial=self._bst_dispatcher_serial,
            )
            if linearized > 0:
                unflat_logger.info(
                    "Direct linearization: %d redirects queued", linearized
                )

        # Ensure DispatcherCache has run (for emulation path in conditional forks)
        _ = DispatcherCache.get_or_create(self.mba).analyze()

        # Queue direct transition patches (more effective for Hodur-style)
        direct_transition_patches = self._queue_transitions_direct()

        # Queue conditional fork resolutions via predecessor walking
        self._resolve_conditional_forks_via_predecessors()

        # Queue predecessor-based patches for any remaining cases
        self._queue_predecessor_patches()

        # Also queue removal of state assignment instructions
        self._queue_state_assignment_removals()

        # Apply all queued modifications at once
        nb_changes = 0

        # Pre-apply BLT_NWAY consistency fix: blocks with BLT_NWAY type but
        # incompatible tail/successor topology cause INTERR 50860 at mba.verify().
        # Fix before apply() to prevent pre_apply_verify failures.
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk is None or blk.type != ida_hexrays.BLT_NWAY:
                continue
            # Case 2: BLT_NWAY + m_goto tail + nsucc==1 → downgrade to BLT_1WAY
            if (
                blk.tail is not None
                and blk.nsucc() == 1
                and blk.tail.opcode == ida_hexrays.m_goto
            ):
                blk.type = ida_hexrays.BLT_1WAY
                self.mba.mark_chains_dirty()
                unflat_logger.info(
                    "blk[%d] BLT_NWAY+goto downgraded to BLT_1WAY (pre-apply)",
                    blk.serial,
                )
            # Case 1: BLT_NWAY + null tail + nsucc==2 → find dispatcher trampoline and fix
            elif blk.tail is None and blk.nsucc() == 2:
                # Check if one successor is a 1-way trampoline leading to a known Hodur
                # state-check block (single succ in its succset is also a state checker)
                succs = list(blk.succset)
                fixed = False
                for succ_serial in succs:
                    succ_blk = self.mba.get_mblock(succ_serial)
                    if succ_blk is None:
                        continue
                    if succ_blk.nsucc() == 1:
                        # This might be a trampoline — remove it and keep the other
                        keep_serial = next(s for s in succs if s != succ_serial)
                        keep_blk = self.mba.get_mblock(keep_serial)
                        if keep_blk is None:
                            continue
                        # Insert goto to keep_serial
                        goto_insn = ida_hexrays.minsn_t(blk.start)
                        goto_insn.opcode = ida_hexrays.m_goto
                        goto_insn.l.make_blkref(keep_serial)
                        blk.insert_into_block(goto_insn, blk.tail)
                        # Fix succset
                        blk.succset.erase(succ_serial)
                        succ_blk.predset.erase(blk.serial)
                        blk.type = ida_hexrays.BLT_1WAY
                        self.mba.mark_chains_dirty()
                        unflat_logger.info(
                            "blk[%d] BLT_NWAY null-tail fixed via trampoline %d → keep %d (hodur pre-apply)",
                            blk.serial,
                            succ_serial,
                            keep_serial,
                        )
                        fixed = True
                        break

        if self.deferred.has_modifications():
            num_redirected = len(self.deferred.modifications)
            total_handlers = len(self.state_machine.handlers)
            if not should_apply_cfg_modifications(
                num_redirected, total_handlers, "hodur"
            ):
                self.deferred.reset()
            else:
                unflat_logger.info(
                    "Applying %d queued modifications", len(self.deferred.modifications)
                )
                nb_changes += self.deferred.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )

                self._log_post_apply_reachability()

                # _prune_resolved_jtbl_cases skipped: direct linearization does not
                # create an m_jtbl switch, so pruning is not needed.

        unflat_logger.debug(
            "HodurUnflattener: pass %d direct transition patches = %d",
            self.cur_maturity_pass,
            direct_transition_patches,
        )

        # Phase 2: resolve remaining back-edges using assignment map
        remaining_resolved = self._resolve_remaining_via_assignment_map()
        if remaining_resolved > 0:
            nb_changes += remaining_resolved
            unflat_logger.info(
                "Resolved %d remaining back-edges via assignment map",
                remaining_resolved,
            )

        # Use MopTracker resolution whenever unresolved transitions remain.
        if self._state_machine_still_present():
            unflat_logger.info(
                "Unresolved transitions remain; running path-based Hodur patching"
            )
            nb_changes += self._resolve_and_patch()

        # Final cleanup for residual infinite-loop artifacts.
        # Keep it limited to extended comparison dispatchers; legacy jnz/jz
        # Hodur shapes are handled by direct back-edge rewrites.
        if self._uses_extended_dispatch_ops():
            nb_changes += self._fix_degenerate_terminal_loops()

        self.last_pass_nb_patch_done = nb_changes

        # Adaptive convergence: extend max_passes when making progress
        if nb_changes > 0 and self.max_passes < self.HARD_MAX_PASSES:
            self.max_passes += 1
            unflat_logger.debug(
                "HodurUnflattener: progress detected, extending max_passes to %d",
                self.max_passes,
            )

        unflat_logger.info(
            "HodurUnflattener: Pass %d made %d changes",
            self._actual_pass_count,
            nb_changes,
        )

        if nb_changes == 0:
            unflat_logger.info(
                "HodurUnflattener: convergence reached at pass %d, maturity %d",
                self._actual_pass_count,
                self.cur_maturity,
            )

        self._actual_pass_count += 1

        return nb_changes

    def _evaluate_handler_paths(
        self,
        entry_serial: int,
        incoming_state: int,
        bst_node_blocks: set[int],
        state_var_stkoff: int,
    ) -> list[HandlerPathResult]:
        """DFS forward eval of a handler, forking state at conditional branches.

        Walks all blocks from entry_serial, forward-evaluating each instruction.
        When an exit to the dispatcher (successor in bst_node_blocks) is found,
        records the exit block and the current state variable value.
        Uses per-path visited set to handle diamonds and prevent infinite loops.
        """
        results: list[HandlerPathResult] = []

        queue: list[tuple[int, dict, dict, frozenset, list, list]] = [
            (entry_serial, {}, {state_var_stkoff: incoming_state}, frozenset(), [], [entry_serial]),
        ]

        while queue:
            curr_serial, reg_map, stk_map, path_visited, state_writes, ordered_path = queue.pop()

            if curr_serial in path_visited:
                continue
            path_visited = path_visited | {curr_serial}

            blk = self.mba.get_mblock(curr_serial)

            cur_writes = list(state_writes)
            insn = blk.head
            while insn is not None:
                old_val = stk_map.get(state_var_stkoff)
                _forward_eval_insn(
                    insn,
                    stk_map,
                    reg_map,
                    state_var_stkoff,
                    mba=self.mba,
                )
                new_val = stk_map.get(state_var_stkoff)
                if new_val != old_val:
                    cur_writes.append((curr_serial, insn.ea))
                insn = insn.next

            succs = [blk.succ(i) for i in range(blk.nsucc())]

            if not succs:
                # Terminal block (e.g., m_ret) — handler exits the function naturally.
                # Record as a terminal path with final_state=None.
                results.append(HandlerPathResult(
                    exit_block=curr_serial,
                    final_state=None,
                    state_writes=list(cur_writes),
                    ordered_path=list(ordered_path),
                ))
                continue

            for succ_serial in succs:
                if succ_serial in bst_node_blocks:
                    final_val = stk_map.get(state_var_stkoff)
                    if final_val is not None:
                        results.append(
                            HandlerPathResult(
                                exit_block=curr_serial,
                                final_state=final_val & 0xFFFFFFFF,
                                state_writes=cur_writes,
                                ordered_path=list(ordered_path),
                            )
                        )
                else:
                    new_ordered = ordered_path + [succ_serial]
                    queue.append(
                        (
                            succ_serial,
                            dict(reg_map),
                            dict(stk_map),
                            path_visited,
                            list(cur_writes),
                            new_ordered,
                        )
                    )

        return results

    # Comparison opcodes supported by the BST walk.
    _BST_CMP_OPCODES: frozenset[int] = frozenset()  # populated in _init_bst_cmp_opcodes

    @staticmethod
    def _init_bst_cmp_opcodes() -> frozenset[int]:
        """Build the set of comparison opcodes for BST walking."""
        return frozenset({
            ida_hexrays.m_jnz,   # !=
            ida_hexrays.m_jz,    # ==
            ida_hexrays.m_jbe,   # unsigned <=
            ida_hexrays.m_ja,    # unsigned >
            ida_hexrays.m_jb,    # unsigned <
            ida_hexrays.m_jae,   # unsigned >=
        })

    @staticmethod
    def _eval_bst_condition(opcode: int, state: int, cmp_val: int) -> bool:
        """Evaluate a BST comparison: does the condition cause a jump?"""
        if opcode == ida_hexrays.m_jnz:
            return state != cmp_val
        if opcode == ida_hexrays.m_jz:
            return state == cmp_val
        if opcode == ida_hexrays.m_jbe:
            return state <= cmp_val
        if opcode == ida_hexrays.m_ja:
            return state > cmp_val
        if opcode == ida_hexrays.m_jb:
            return state < cmp_val
        if opcode == ida_hexrays.m_jae:
            return state >= cmp_val
        return False

    def _resolve_exit_via_bst_default(
        self, bst_default_serial: int, exit_state: int
    ) -> int | None:
        """Resolve an exit state by walking BST comparison blocks.

        Walks a chain/tree of 2WAY comparison blocks (jnz/jz/jbe/ja/jb/jae)
        starting from *bst_default_serial*, following the branch dictated by
        *exit_state* at each node.  Stops at the first block that is NOT a
        state-variable comparison and returns its serial.

        Can be called with the BST default leaf (original use) or the BST root
        (dispatcher entry) to resolve states through the full tree.

        Args:
            bst_default_serial: Block serial to start the walk from.
            exit_state: The final state value for this exit path.

        Returns:
            The successor serial to redirect to, or None if unresolvable.
        """
        current_serial = bst_default_serial
        visited: set[int] = set()
        state_var_ref: tuple[int, int] | None = None
        state_var_stkoff: int | None = None

        while current_serial not in visited:
            visited.add(current_serial)

            blk = self.mba.get_mblock(current_serial)
            if blk is None or blk.nsucc() != 2:
                # Not a 2WAY comparison — this is the actual target block.
                return current_serial if current_serial != bst_default_serial else None

            tail = blk.tail
            if not self._BST_CMP_OPCODES:
                # Lazy init — ida_hexrays constants need IDA runtime.
                HodurUnflattener._BST_CMP_OPCODES = self._init_bst_cmp_opcodes()
            if tail is None or tail.opcode not in self._BST_CMP_OPCODES:
                return current_serial if current_serial != bst_default_serial else None

            # Extract the comparison constant from the right operand.
            if tail.r is None or tail.r.t != ida_hexrays.mop_n:
                return current_serial if current_serial != bst_default_serial else None

            # Verify the left operand is the state variable.
            if state_var_ref is None:
                # First iteration: capture state variable identity from left operand.
                state_var_ref = (tail.l.t, tail.l.size)
                if tail.l.t == 3:  # mop_S (stack var)
                    state_var_stkoff = tail.l.s.off
            else:
                # Subsequent iterations: verify left operand is still the state variable.
                if (tail.l.t, tail.l.size) != state_var_ref:
                    unflat_logger.info(
                        "  exit %#x: blk[%d] compares non-state-var (mop_t=%d), stopping",
                        exit_state,
                        current_serial,
                        tail.l.t,
                    )
                    return current_serial
                if tail.l.t == 3 and tail.l.s.off != state_var_stkoff:
                    unflat_logger.info(
                        "  exit %#x: blk[%d] compares non-state-var (mop_t=%d), stopping",
                        exit_state,
                        current_serial,
                        tail.l.t,
                    )
                    return current_serial

            comparison_value = int(tail.r.nnn.value)

            # succ(0) = fall-through (condition false), succ(1) = jump (condition true)
            condition_true = self._eval_bst_condition(
                tail.opcode, exit_state, comparison_value
            )

            next_serial = blk.succ(1) if condition_true else blk.succ(0)

            unflat_logger.info(
                "  exit %#x: resolved through blk[%d] -> blk[%d]",
                exit_state,
                current_serial,
                next_serial,
            )

            current_serial = next_serial

        # Loop detected — return last resolved serial.
        return current_serial

    def _log_post_apply_reachability(self) -> None:
        """BFS from pre-header to check which handler entries are reachable post-apply.

        Logs reachable count vs total and lists unreachable handler serials.
        Only runs when debug logging is active.
        """
        if not unflat_logger.debug_on:
            return

        if self._bst_result is None:
            return

        # Determine BFS start: pre-header if available, else block 0
        start_serial: int = 0
        if hasattr(self._bst_result, "pre_header_serial") and self._bst_result.pre_header_serial is not None:
            start_serial = self._bst_result.pre_header_serial

        # BFS over the post-apply CFG
        reachable: set[int] = set()
        bfs_queue: list[int] = [start_serial]
        while bfs_queue:
            serial = bfs_queue.pop(0)
            if serial in reachable:
                continue
            reachable.add(serial)
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                succ = blk.succ(i)
                if succ not in reachable:
                    bfs_queue.append(succ)

        # Check handler entries
        handler_serials = set(self._bst_result.handler_state_map.keys())
        range_serials = set(self._bst_result.handler_range_map.keys())
        all_handler_entries = handler_serials | range_serials

        reachable_handlers = all_handler_entries & reachable
        unreachable_handlers = all_handler_entries - reachable

        unflat_logger.debug(
            "Post-apply reachability: %d/%d handler entries reachable from blk[%d]",
            len(reachable_handlers),
            len(all_handler_entries),
            start_serial,
        )
        if unreachable_handlers:
            unflat_logger.debug(
                "Post-apply unreachable handler entries: %s",
                sorted(unreachable_handlers),
            )

    def _log_dispatcher_predecessor_census(
        self,
        bst_node_blocks: set[int],
        handler_entries: set[int],
        processed_rootwalk: set[int],
    ) -> None:
        """Log which blocks still have successors pointing to BST nodes."""
        bst_preds: dict[str, list[int]] = {
            "handler_exit": [],
            "hidden_handler": [],
            "bst_internal": [],
            "unknown": [],
        }
        for serial in range(self.mba.qty):
            blk = self.mba.get_mblock(serial)
            for i in range(blk.nsucc()):
                succ = blk.succ(i)
                if succ in bst_node_blocks:
                    if serial in bst_node_blocks:
                        bst_preds["bst_internal"].append(serial)
                    elif serial in handler_entries:
                        bst_preds["handler_exit"].append(serial)
                    elif serial in processed_rootwalk:
                        bst_preds["hidden_handler"].append(serial)
                    else:
                        bst_preds["unknown"].append(serial)
                    break
        unflat_logger.info(
            "Dispatcher pred census: handler_exit=%d, hidden=%d, bst_internal=%d, unknown=%d",
            len(bst_preds["handler_exit"]),
            len(bst_preds["hidden_handler"]),
            len(bst_preds["bst_internal"]),
            len(bst_preds["unknown"]),
        )
        if bst_preds["unknown"]:
            unflat_logger.info("Unknown BST preds: %s", bst_preds["unknown"])
        if bst_preds["handler_exit"]:
            unflat_logger.info("Handler exits still pointing to BST: %s", bst_preds["handler_exit"])

    def _queue_handler_redirect(
        self,
        path: "HandlerPathResult",
        target: int,
        reason: str,
        claimed_exits: dict[int, int],
        claimed_edges: dict[tuple[int, int], int],
        bst_node_blocks: set[int],
    ) -> bool:
        """Queue a goto redirect for one handler exit path, using edge-level split on conflict.

        Fast path: if path.exit_block not yet claimed, queue a plain goto_change.
        Conflict path: if exit_block already claimed for a different target, attempt
        an edge-level redirect (EDGE_REDIRECT_VIA_PRED_SPLIT) using the predecessor
        from path.ordered_path.  Falls back to walking earlier path segments if the
        immediate predecessor edge is already claimed.

        Args:
            path: DFS path result (exit_block, ordered_path, etc.)
            target: Block serial of the desired redirect target.
            reason: Human-readable description string for logging/queuing.
            claimed_exits: Tracks block_serial -> target for already-claimed exits.
            claimed_edges: Tracks (src_block, via_pred) -> target for edge-level claims.
            bst_node_blocks: BST comparison node serials (should not be cloned).

        Returns:
            True if a redirect was successfully queued or already resolved, False on failure.
        """
        exit_blk = self.mba.get_mblock(path.exit_block)

        # Fast path: exit block not yet claimed by any handler.
        if path.exit_block not in claimed_exits:
            self.deferred.queue_goto_change(
                block_serial=path.exit_block,
                new_target=target,
                rule_priority=550,
                description=reason,
            )
            claimed_exits[path.exit_block] = target
            return True

        # Already claimed for the same target — no-op.
        if claimed_exits[path.exit_block] == target:
            return True

        # Conflict: exit_block claimed for a different target. Use edge-level redirect.
        if len(path.ordered_path) >= 2:
            via_pred = path.ordered_path[-2]
        else:
            unflat_logger.warning(
                "EDGE_REDIRECT: no via_pred for exit blk[%d] -> target %d "
                "(ordered_path too short: %s)",
                path.exit_block, target, path.ordered_path,
            )
            return False

        # Determine old_target (current successor of exit_block leading to dispatcher).
        old_target = 0
        if exit_blk is not None and exit_blk.nsucc() > 0:
            old_target = exit_blk.succ(0)

        # Check if this specific edge is already claimed.
        edge_key = (path.exit_block, via_pred)
        if edge_key in claimed_edges:
            if claimed_edges[edge_key] == target:
                return True  # Already claimed for same target.
            # Escalate: walk backward through ordered_path to find an unclaimed edge.
            unflat_logger.info(
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
                    found_src = seg_src
                    found_pred = seg_pred
                    break
            if found_src is None or found_pred is None:
                unflat_logger.warning(
                    "EDGE_REDIRECT: all path segments claimed for exit blk[%d] -> target %d, "
                    "cannot queue redirect",
                    path.exit_block, target,
                )
                return False
            src_block = found_src
            use_pred = found_pred
            src_blk = self.mba.get_mblock(src_block)
            old_target = src_blk.succ(0) if src_blk is not None and src_blk.nsucc() > 0 else 0
        else:
            src_block = path.exit_block
            use_pred = via_pred

        unflat_logger.info(
            "EDGE_REDIRECT: exit blk[%d] -> target %d conflicts with claimed=%d; "
            "using edge_redirect(src=%d, old=%d, new=%d, via_pred=%d)",
            path.exit_block, target, claimed_exits[path.exit_block],
            src_block, old_target, target, use_pred,
        )
        self.deferred.queue_edge_redirect(
            src_block=src_block,
            old_target=old_target,
            new_target=target,
            via_pred=use_pred,
            rule_priority=550,
            description=reason,
        )
        claimed_edges[(src_block, use_pred)] = target
        return True

    def _linearize_handlers(
        self,
        bst_result: BSTAnalysisResult,
        dispatcher_serial: int,
    ) -> int:
        """Linearize all handlers by redirecting exits directly to target handlers.

        For each handler:
        1. Run DFS forward eval to find exit paths and their final state values.
        2. Resolve each final state to a target handler via BST lookup.
        3. Queue goto redirect: handler exit -> target handler entry.
        4. Queue NOP for state variable writes (dead after redirect).

        Args:
            bst_result: Parsed BST analysis with handler maps and node blocks.
            dispatcher_serial: Block serial of the dispatcher entry.

        Returns:
            Number of transitions successfully resolved.
        """
        state_var_stkoff = _get_state_var_stkoff(self._detector)
        if state_var_stkoff is None:
            unflat_logger.info("Cannot linearize: state_var_stkoff is None")
            return 0

        bst_node_blocks = bst_result.bst_node_blocks | {dispatcher_serial}
        sm_blocks = self._collect_state_machine_blocks()
        resolved_count = 0
        claimed_exits: dict[int, int] = {}
        claimed_edges: dict[tuple[int, int], int] = {}
        deferred_conflict_count = 0
        bst_rootwalk_targets: set[int] = set()

        # All handlers: exact + range
        all_handlers: dict[int, int] = {}  # handler_serial -> incoming_state
        for serial, state in bst_result.handler_state_map.items():
            all_handlers[serial] = state
        # Range handlers: seed forward eval with range low (or high) as incoming state.
        # The entry block writes a concrete constant regardless of which exact value
        # dispatched here; the seed only matters if no state write is found at entry.
        for serial, (low, high) in bst_result.handler_range_map.items():
            if serial not in all_handlers:
                mid = low if low is not None else (high if high is not None else 0)
                all_handlers[serial] = mid

        for handler_serial, incoming_state in all_handlers.items():
            # Skip handlers that are BST comparison nodes themselves
            if handler_serial in bst_node_blocks:
                continue

            paths = self._evaluate_handler_paths(
                entry_serial=handler_serial,
                incoming_state=incoming_state,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=state_var_stkoff,
            )

            if not paths:
                unflat_logger.debug(
                    "Handler blk[%d] (state 0x%x): no exit paths found, deferring to legacy",
                    handler_serial,
                    incoming_state,
                )
                continue

            # Only claim handler as linearized after successful path evaluation
            self._linearized_blocks.add(handler_serial)

            for path in paths:
                if path.final_state is None:
                    # Terminal path — handler already exits naturally (e.g., function return).
                    # No redirect needed. Count as resolved.
                    unflat_logger.info(
                        "Handler blk[%d] (state=0x%x): terminal exit via blk[%d]",
                        handler_serial,
                        incoming_state,
                        path.exit_block,
                    )
                    resolved_count += 1
                    continue

                target_serial = resolve_target_via_bst(bst_result, path.final_state)
                if target_serial is None:
                    # No handler matches this state value — it's an exit transition.
                    # Try to resolve THROUGH the BST default block's comparison so we
                    # redirect to the actual exit target rather than blk[bst_default].
                    bst_default = find_bst_default_block(
                        self.mba,
                        dispatcher_serial,
                        bst_result.bst_node_blocks,
                        set(bst_result.handler_state_map.keys()),
                    )
                    exit_target: int | None = None
                    resolve_label: str = ""
                    if bst_default is not None and path.final_state is not None:
                        exit_target = self._resolve_exit_via_bst_default(
                            bst_default, path.final_state
                        )
                        if exit_target is not None:
                            resolve_label = f"BST default blk[{bst_default}]"
                    if exit_target is None and path.final_state is not None:
                        # Exact/range map missed this state, but it may still
                        # be a comparison constant in the BST.  Walk from root.
                        exit_target = self._resolve_exit_via_bst_default(
                            dispatcher_serial, path.final_state
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
                        _redirect_ok = self._queue_handler_redirect(
                            path=path,
                            target=exit_target,
                            reason=(
                                f"hodur-linear: blk[{handler_serial}] "
                                f"exit 0x{path.final_state:x} -> {resolve_label} -> blk[{exit_target}]"
                            ),
                            claimed_exits=claimed_exits,
                            claimed_edges=claimed_edges,
                            bst_node_blocks=bst_node_blocks,
                        )
                        if _redirect_ok:
                            self._linearized_blocks.add(path.exit_block)
                        else:
                            deferred_conflict_count += 1
                        for write_blk, write_ea in path.state_writes:
                            self.deferred.queue_insn_nop(
                                block_serial=write_blk,
                                insn_ea=write_ea,
                                description=f"hodur-linear: dead state write (exit) in blk[{write_blk}]",
                            )
                        # NOP dead state_var writes in the resolved exit target block.
                        # OLLVM often places a dead default-state write at the top of
                        # the first post-dispatcher block (e.g. "mov %var_110, #0xD62B0F79").
                        # If that write is left alive the state variable stays live and
                        # IDA cannot eliminate the dispatcher, leaving while(1) loops.
                        # Guard: skip if exit_target is a BST/shared node — NOP'ing
                        # state writes there would destroy writes needed by other handlers.
                        exit_blk = self.mba.get_mblock(exit_target)
                        if exit_blk is not None and exit_target not in bst_node_blocks:
                            scan_insn = exit_blk.head
                            while scan_insn is not None:
                                if (
                                    scan_insn.opcode == ida_hexrays.m_mov
                                    and scan_insn.d is not None
                                    and _mop_matches_stkoff(
                                        scan_insn.d,
                                        state_var_stkoff,
                                        mba=self.mba,
                                    )
                                ):
                                    unflat_logger.info(
                                        "  NOP dead state_var write in exit target"
                                        " blk[%d] ea=%#x",
                                        exit_target,
                                        scan_insn.ea,
                                    )
                                    self.deferred.queue_insn_nop(
                                        block_serial=exit_target,
                                        insn_ea=scan_insn.ea,
                                        description=(
                                            f"hodur-linear: dead state write"
                                            f" (exit target) in blk[{exit_target}]"
                                        ),
                                    )
                                scan_insn = scan_insn.next
                        resolved_count += 1
                        self._resolved_transitions.add(
                            (incoming_state, path.final_state)
                        )
                        unflat_logger.info(
                            "Handler blk[%d]: exit state 0x%x -> %s -> blk[%d]",
                            handler_serial,
                            path.final_state,
                            resolve_label,
                            exit_target,
                        )
                        continue

                    # Fallback: redirect to bst_default directly (or terminal exit)
                    if bst_default is None:
                        bst_default = self._find_terminal_exit_target(
                            dispatcher_serial, sm_blocks
                        )
                    if bst_default is not None:
                        _redirect_ok = self._queue_handler_redirect(
                            path=path,
                            target=bst_default,
                            reason=(
                                f"hodur-linear: blk[{handler_serial}] "
                                f"exit state 0x{path.final_state:x} -> bst_default blk[{bst_default}]"
                            ),
                            claimed_exits=claimed_exits,
                            claimed_edges=claimed_edges,
                            bst_node_blocks=bst_node_blocks,
                        )
                        if _redirect_ok:
                            self._linearized_blocks.add(path.exit_block)
                        else:
                            deferred_conflict_count += 1
                        # Keep state variable live for exit paths (no NOP).
                        resolved_count += 1
                        self._resolved_transitions.add(
                            (incoming_state, path.final_state)
                        )
                        unflat_logger.info(
                            "Handler blk[%d]: exit state 0x%x -> bst_default blk[%d]",
                            handler_serial,
                            path.final_state,
                            bst_default,
                        )
                    else:
                        unflat_logger.debug(
                            "Handler blk[%d]: exit state 0x%x -> no bst_default found, leaving intact",
                            handler_serial,
                            path.final_state,
                        )
                    continue

                is_self_loop = target_serial == handler_serial

                _redirect_ok = self._queue_handler_redirect(
                    path=path,
                    target=target_serial,
                    reason=(
                        f"hodur-linear: blk[{handler_serial}] "
                        f"0x{incoming_state:x}->0x{path.final_state:x} "
                        f"{'(loop)' if is_self_loop else ''}"
                    ),
                    claimed_exits=claimed_exits,
                    claimed_edges=claimed_edges,
                    bst_node_blocks=bst_node_blocks,
                )
                if _redirect_ok:
                    self._linearized_blocks.add(path.exit_block)
                else:
                    deferred_conflict_count += 1

                for write_blk, write_ea in path.state_writes:
                    write_blk_obj = self.mba.get_mblock(write_blk)
                    if write_blk_obj is not None and write_blk_obj.npred() > 1:
                        continue  # Skip NOP on shared multi-pred blocks
                    self.deferred.queue_insn_nop(
                        block_serial=write_blk,
                        insn_ea=write_ea,
                        description=f"hodur-linear: dead state write in blk[{write_blk}]",
                    )

                resolved_count += 1
                self._resolved_transitions.add((incoming_state, path.final_state))

        # --- Second pass: linearize BST root-walk hidden handler exits ---
        # Some handler exits resolve to "hidden handler" blocks in the BST
        # default region via BST root-walk. These hidden handlers' own exits
        # back to the dispatcher are never linearized because they're not in
        # the handler transition table. Process them now.
        for rootwalk_blk in bst_rootwalk_targets:
            if rootwalk_blk in bst_node_blocks:
                continue  # Skip actual BST comparison nodes
            try:
                hidden_paths = self._evaluate_handler_paths(
                    entry_serial=rootwalk_blk,
                    incoming_state=0,
                    bst_node_blocks=bst_node_blocks,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception:
                continue

            for path in hidden_paths:
                if path.final_state is None:
                    continue  # Terminal path, no redirect needed

                # Try exact BST resolution first
                target = resolve_target_via_bst(bst_result, path.final_state)
                if target is None:
                    # Try BST root-walk
                    target = self._resolve_exit_via_bst_default(
                        dispatcher_serial, path.final_state
                    )
                    # Chain detection diagnostic
                    if (target is not None
                            and target not in bst_node_blocks
                            and target not in all_handlers):
                        unflat_logger.info(
                            "Chain candidate: hidden blk[%d] exit -> blk[%d] "
                            "(not a known handler, potential chained hidden handler)",
                            rootwalk_blk, target,
                        )
                if target is None:
                    continue
                if target in bst_node_blocks:
                    continue  # Don't redirect to BST internal nodes

                _redirect_ok = self._queue_handler_redirect(
                    path=path,
                    target=target,
                    reason=(
                        f"hodur-linear: hidden-handler blk[{rootwalk_blk}]"
                        f" exit 0x{path.final_state:x} -> blk[{target}]"
                    ),
                    claimed_exits=claimed_exits,
                    claimed_edges=claimed_edges,
                    bst_node_blocks=bst_node_blocks,
                )
                if _redirect_ok:
                    self._linearized_blocks.add(path.exit_block)
                else:
                    deferred_conflict_count += 1
                unflat_logger.info(
                    "hodur-linear: hidden-handler blk[%d] exit_blk=%d -> target blk[%d] (state 0x%x)",
                    rootwalk_blk,
                    path.exit_block,
                    target,
                    path.final_state,
                )

                for write_blk, write_ea in path.state_writes:
                    write_blk_obj = self.mba.get_mblock(write_blk)
                    if write_blk_obj is not None and write_blk_obj.npred() > 1:
                        continue  # Skip NOP on shared multi-pred blocks
                    self.deferred.queue_insn_nop(
                        block_serial=write_blk,
                        insn_ea=write_ea,
                        description=(
                            f"hodur-linear: dead state write"
                            f" (hidden-handler blk[{rootwalk_blk}]) in blk[{write_blk}]"
                        ),
                    )

                resolved_count += 1

        # Predecessor census (diagnostic only)
        handler_entries = set(all_handlers.keys())
        rootwalk_processed = set(bst_rootwalk_targets)  # all were processed in second pass
        self._log_dispatcher_predecessor_census(
            bst_node_blocks=bst_node_blocks,
            handler_entries=handler_entries,
            processed_rootwalk=rootwalk_processed,
        )

        # --- Linearize BST default region back-edges ---
        # The BST default region may contain hidden handlers that loop back
        # to the dispatcher. Find blocks in the default region that have
        # back-edges to the dispatcher and resolve their state through the
        # BST default chain.
        bst_default = find_bst_default_block(
            self.mba,
            dispatcher_serial,
            bst_result.bst_node_blocks,
            set(bst_result.handler_state_map.keys()),
        )
        if bst_default is not None:
            # Walk blocks reachable from bst_default that aren't BST nodes or handlers
            bst_default_region: set[int] = set()
            queue: list[int] = [bst_default]
            handler_serials = set(bst_result.handler_state_map.keys())
            while queue:
                serial = queue.pop()
                if (
                    serial in bst_default_region
                    or serial in bst_node_blocks
                    or serial == dispatcher_serial
                ):
                    continue
                if serial in handler_serials:
                    continue
                bst_default_region.add(serial)
                blk = self.mba.get_mblock(serial)
                if blk is None:
                    continue
                for i in range(blk.nsucc()):
                    queue.append(blk.succ(i))

            # Find blocks in the default region that jump back to the dispatcher
            # (any BST node counts as a valid back-edge target, not just the entry)
            for serial in bst_default_region:
                blk = self.mba.get_mblock(serial)
                if blk is None:
                    continue
                # Find any successor that is a BST node (back-edge to dispatcher tree)
                backedge_succs = [
                    blk.succ(i) for i in range(blk.nsucc())
                    if blk.succ(i) in bst_node_blocks
                ]
                if not backedge_succs:
                    continue
                # This block has a back-edge to the dispatcher
                # Read the state value it writes
                insn = blk.head
                written_state = None
                state_write_ea = None
                while insn is not None:
                    if insn.opcode == ida_hexrays.m_mov and insn.d is not None:
                        if _mop_matches_stkoff(insn.d, state_var_stkoff, mba=self.mba):
                            if insn.l is not None and insn.l.t == ida_hexrays.mop_n:
                                written_state = int(insn.l.nnn.value)
                                state_write_ea = insn.ea
                    insn = insn.next

                if written_state is None:
                    continue

                # Resolve through BST default
                target = self._resolve_exit_via_bst_default(bst_default, written_state)
                if target is None:
                    continue

                unflat_logger.info(
                    "  BST default back-edge: blk[%d] state %#x -> resolved blk[%d]",
                    serial,
                    written_state,
                    target,
                )

                # Redirect the back-edge
                _synthetic_path = HandlerPathResult(
                    exit_block=serial,
                    final_state=written_state,
                    state_writes=[],
                    ordered_path=[serial],
                )
                _redirect_ok = self._queue_handler_redirect(
                    path=_synthetic_path,
                    target=target,
                    reason=f"hodur-linear: BST default blk[{serial}] {written_state:#x}->blk[{target}]",
                    claimed_exits=claimed_exits,
                    claimed_edges=claimed_edges,
                    bst_node_blocks=bst_node_blocks,
                )
                if not _redirect_ok:
                    deferred_conflict_count += 1

                # NOP the state write (runs unconditionally)
                if state_write_ea is not None:
                    self.deferred.queue_insn_nop(
                        block_serial=serial,
                        insn_ea=state_write_ea,
                        description=f"hodur-linear: dead state write (BST default) in blk[{serial}]",
                    )

                # Also NOP state writes in the target block, but only if the
                # target is not a BST/shared node (NOP'ing there would destroy
                # writes needed by other handlers using the same block).
                target_blk = self.mba.get_mblock(target)
                if target_blk is not None and target not in bst_node_blocks:
                    scan_insn = target_blk.head
                    while scan_insn is not None:
                        if (
                            scan_insn.opcode == ida_hexrays.m_mov
                            and scan_insn.d is not None
                            and _mop_matches_stkoff(
                                scan_insn.d, state_var_stkoff, mba=self.mba
                            )
                        ):
                            self.deferred.queue_insn_nop(
                                block_serial=target,
                                insn_ea=scan_insn.ea,
                                description=f"hodur-linear: dead state write (BST default target) in blk[{target}]",
                            )
                        scan_insn = scan_insn.next

                resolved_count += 1

        # Redirect pre-header to initial handler
        if (
            bst_result.initial_state is not None
            and bst_result.pre_header_serial is not None
        ):
            initial_handler = resolve_target_via_bst(
                bst_result, bst_result.initial_state
            )
            if initial_handler is not None:
                self.deferred.queue_goto_change(
                    block_serial=bst_result.pre_header_serial,
                    new_target=initial_handler,
                    description="hodur-linear: pre-header -> initial handler",
                    rule_priority=550,
                )
                resolved_count += 1

        if deferred_conflict_count > 0:
            unflat_logger.info(
                "EXIT_CONFLICT_SUMMARY: %d exit conflicts deferred (first claimant wins); "
                "claimed_exits has %d unique redirected blocks",
                deferred_conflict_count,
                len(claimed_exits),
            )
        unflat_logger.info(
            "Hodur linearization: %d transitions resolved for %d handlers",
            resolved_count,
            len(all_handlers),
        )
        return resolved_count

    def _convert_bst_to_jtbl(
        self,
        bst_result: BSTAnalysisResult,
        dispatcher_serial: int,
    ) -> bool:
        """Replace BST comparison tree with m_jtbl switch instruction.

        All handler code blocks become switch case targets, keeping them
        reachable regardless of how many transitions are resolved.
        Returns True if conversion succeeded.
        """
        if self.state_machine is None or self.state_machine.state_var is None:
            return False
        if not bst_result.handler_state_map:
            return False

        # Step 1: Group transitions by target — prevents INTERR 50753 where each
        # target serial must appear exactly once in mcases_t.targets.
        groups: dict[int, list[int]] = defaultdict(list)
        for handler_blk, state_val in bst_result.handler_state_map.items():
            groups[handler_blk].append(state_val)

        # Step 2: Build mcases_t.
        mc = ida_hexrays.mcases_t()
        for tgt in sorted(groups):
            mc.targets.push_back(tgt)
            uv = ida_pro.svalvec_t()
            for val in groups[tgt]:
                uv.push_back(val)
            mc.values.push_back(uv)

        # Step 3: Collect old successor set from dispatcher block.
        dispatcher_blk = self.mba.get_mblock(dispatcher_serial)
        if dispatcher_blk is None:
            return False
        blk_serial = int(dispatcher_blk.serial)
        old_succs = set(int(s) for s in dispatcher_blk.succset)

        # Step 4: Clear dispatcher block instructions (make_nop before remove
        # to prevent Error 52123).
        insns = []
        cur = dispatcher_blk.head
        while cur is not None:
            insns.append(cur)
            cur = cur.next
        for insn in insns:
            dispatcher_blk.make_nop(insn)
            dispatcher_blk.remove_from_block(insn)

        # Step 5: Create and insert m_jtbl instruction.
        # Use mba.entry_ea for safe EA — prevents INTERR 50863.
        safe_ea = self.mba.entry_ea
        jtbl_ins = ida_hexrays.minsn_t(safe_ea)
        jtbl_ins.ea = safe_ea
        jtbl_ins.opcode = ida_hexrays.m_jtbl
        # l operand: state variable (deep copy via assign)
        jtbl_ins.l = ida_hexrays.mop_t()
        jtbl_ins.l.assign(self.state_machine.state_var)
        # r operand: mcases_t
        jtbl_ins.r = ida_hexrays.mop_t()
        jtbl_ins.r.t = ida_hexrays.mop_c
        jtbl_ins.r.c = mc
        # d operand: erase
        jtbl_ins.d = ida_hexrays.mop_t()
        jtbl_ins.d.erase()
        # Insert into now-empty block
        dispatcher_blk.insert_into_block(jtbl_ins, dispatcher_blk.head)

        # Step 6: Set block type to NWAY.
        dispatcher_blk.type = ida_hexrays.BLT_NWAY

        # Step 7: Rebuild succset/predset — mark_chains_dirty alone is insufficient.
        dispatcher_blk.succset.clear()
        new_succs = set()
        for i in range(mc.targets.size()):
            tgt = int(mc.targets[i])
            dispatcher_blk.succset.add_unique(tgt)
            new_succs.add(tgt)

        for removed in old_succs - new_succs:
            r_blk = self.mba.get_mblock(removed)
            if r_blk is not None:
                r_blk.predset._del(blk_serial)
                r_blk.mark_lists_dirty()

        for added in new_succs - old_succs:
            a_blk = self.mba.get_mblock(added)
            if a_blk is not None:
                a_blk.predset.push_back(blk_serial)
                a_blk.mark_lists_dirty()

        dispatcher_blk.mark_lists_dirty()

        # Step 8: NOP dead BST blocks (comparison nodes), excluding the dispatcher
        # itself (which we just converted, not dead).
        dead_serials = bst_result.bst_node_blocks - {dispatcher_serial}
        for dead_serial in sorted(dead_serials):
            dead_blk = self.mba.get_mblock(dead_serial)
            if dead_blk is None:
                continue
            # Remove all instructions
            d_insns = []
            cur = dead_blk.head
            while cur is not None:
                d_insns.append(cur)
                cur = cur.next
            for insn in d_insns:
                dead_blk.make_nop(insn)
                dead_blk.remove_from_block(insn)
            # Disconnect successors
            d_old_succs = [int(s) for s in dead_blk.succset]
            for ss in d_old_succs:
                dead_blk.succset._del(ss)
                s_blk = self.mba.get_mblock(ss)
                if s_blk is not None:
                    s_blk.predset._del(dead_serial)
                    s_blk.mark_lists_dirty()
            # Disconnect predecessors (also clean up their succsets)
            d_old_preds = [int(p) for p in dead_blk.predset]
            for pp in d_old_preds:
                dead_blk.predset._del(pp)
                p_blk = self.mba.get_mblock(pp)
                if p_blk is not None:
                    p_blk.succset._del(dead_serial)
                    p_blk.mark_lists_dirty()
            dead_blk.type = ida_hexrays.BLT_0WAY
            dead_blk.mark_lists_dirty()

        # Step 9: Finalize.
        self.mba.mark_chains_dirty()
        self._jtbl_converted = True
        self._jtbl_dispatcher_serial = dispatcher_serial
        self._jtbl_handler_state_map = dict(bst_result.handler_state_map)
        self._jtbl_state_to_handler = {
            state: blk for blk, state in bst_result.handler_state_map.items()
        }

        unflat_logger.info(
            "BST->m_jtbl: converted %d states on blk[%d], NOPed %d BST blocks",
            len(bst_result.handler_state_map),
            dispatcher_serial,
            len(dead_serials),
        )
        return True

    def _find_state_write_in_block(
        self,
        blk: "ida_hexrays.mblock_t",
        state_var: "ida_hexrays.mop_t",
    ) -> "tuple[str, tuple] | None":
        """Scan block backward for last state variable write.

        Returns:
            ("literal", (const_value, insn_ea)) for mov state_var, CONST
            ("computed", (insn, blk)) for xor/sub/add/mul/and/or state_var, ...
            None if no state write found.
        """
        _COMPUTE_OPCODES = {
            ida_hexrays.m_xor,
            ida_hexrays.m_sub,
            ida_hexrays.m_add,
            ida_hexrays.m_mul,
            ida_hexrays.m_and,
            ida_hexrays.m_or,
        }
        insn = blk.tail
        while insn is not None:
            if insn.opcode == ida_hexrays.m_goto:
                insn = insn.prev
                continue
            if insn.d and insn.d.equal_mops(state_var, ida_hexrays.EQ_IGNSIZE):
                if insn.opcode == ida_hexrays.m_mov and insn.l.t == ida_hexrays.mop_n:
                    return ("literal", (insn.l.nnn.value, insn.ea))
                if insn.opcode in _COMPUTE_OPCODES:
                    return ("computed", (insn, blk))
            insn = insn.prev
        return None

    def _trace_case_body(
        self,
        case_entry: int,
        switch_head: int,
        max_depth: int = 64,
        _visited: "set[int] | None" = None,
    ) -> "tuple[int, str, tuple] | None":
        """Follow successor chain from case entry to back-edge or exit.

        Returns:
            (tail_serial, "terminal", None) — case exits function
            (tail_serial, "literal", (const_value, insn_ea)) — literal state write
            (tail_serial, "computed", (insn, blk)) — computed state write
            (current_serial, "conditional", [(tail, type, info), ...]) — 2-way split
            None — tracing failed
        """
        if _visited is None:
            _visited = set()
        visited: list[int] = []
        current = case_entry
        for _ in range(max_depth):
            if current in _visited:
                return None
            _visited.add(current)
            visited.append(current)
            blk = self.mba.get_mblock(current)
            nsucc = blk.nsucc()
            if nsucc == 0:
                return (current, "terminal", None)
            if nsucc == 1:
                succ = next(iter(blk.succset))
                if succ == switch_head:
                    # Scan backward through visited chain for state write
                    for scan_serial in reversed(visited):
                        scan_blk = self.mba.get_mblock(scan_serial)
                        result = self._find_state_write_in_block(
                            scan_blk, self.state_machine.state_var
                        )
                        if result is not None:
                            kind, info = result
                            if kind == "literal":
                                const_val, insn_ea = info
                                return (
                                    current,
                                    kind,
                                    (const_val, insn_ea, scan_serial),
                                )
                            return (current, kind, info)
                    return None
                current = succ
                continue
            if nsucc == 2:
                succs = list(blk.succset)
                branches = []
                for succ in succs:
                    if succ == switch_head:
                        result = self._find_state_write_in_block(
                            blk, self.state_machine.state_var
                        )
                        if result is not None:
                            kind, info = result
                            if kind == "literal":
                                const_val, insn_ea = info
                                branches.append(
                                    (current, kind, (const_val, insn_ea, current))
                                )
                            else:
                                branches.append((current, kind, info))
                    else:
                        sub = self._trace_case_body(
                            succ, switch_head, max_depth=16, _visited=_visited
                        )
                        if sub is not None:
                            branches.append(sub)
                if branches:
                    return (current, "conditional", branches)
                return None
            # nsucc > 2: unexpected topology
            return None
        return None

    def _resolve_jtbl_switch(self) -> int:
        """Resolve m_jtbl switch cases by redirecting back-edges to target handlers.

        For each switch case body:
        - Literal v10=CONST: redirect to target case block via mcases_t lookup
        - Computed v10=expr: attempt forward eval or MopTracker resolution
        - Terminal (return): no action
        - Conditional: resolve each branch independently
        """
        if (
            not self._jtbl_converted
            or self.deferred is None
            or self.state_machine is None
        ):
            return 0
        switch_blk = self.mba.get_mblock(self._jtbl_dispatcher_serial)
        unflat_logger.info(
            "Post-m_jtbl _resolve: switch blk[%d] nsucc=%d, state_var=%s",
            self._jtbl_dispatcher_serial,
            switch_blk.nsucc(),
            (
                self.state_machine.state_var.dstr()
                if self.state_machine.state_var
                else "None"
            ),
        )
        resolved = 0

        def _handle_result(result, entry_serial: int) -> int:
            nonlocal resolved
            if result is None:
                return 0
            tail_serial, kind, info = result
            if kind == "terminal":
                return 0
            if kind == "literal":
                const_value, insn_ea, write_blk = (
                    info if len(info) == 3 else (*info, tail_serial)
                )
                target = self._jtbl_state_to_handler.get(const_value)
                if target is not None:
                    self.deferred.queue_goto_change(
                        tail_serial,
                        target,
                        description=f"jtbl-resolve: blk[{entry_serial}] state 0x{const_value:x} -> blk[{target}]",
                    )
                    self.deferred.queue_insn_nop(
                        write_blk,
                        insn_ea,
                        description=f"jtbl-resolve: nop state write at ea=0x{insn_ea:x}",
                    )
                    from_state = self._jtbl_handler_state_map.get(entry_serial, 0)
                    self._resolved_transitions.add((from_state, const_value))
                    resolved += 1
                    return 1
                return 0
            if kind == "computed":
                return self._resolve_jtbl_computed_case(entry_serial, tail_serial, info)
            if kind == "conditional":
                count = 0
                for branch in info:
                    count += _handle_result(branch, entry_serial)
                return count
            return 0

        for case_entry in list(switch_blk.succset):
            result = self._trace_case_body(case_entry, self._jtbl_dispatcher_serial)
            _handle_result(result, case_entry)

        return resolved

    def _prune_resolved_jtbl_cases(self) -> int:
        """Remove resolved cases from the m_jtbl instruction after deferred.apply().

        After _resolve_jtbl_switch() redirects handler back-edges, the switch
        structure remains because mcases_t still has all cases.  This method
        prunes case entries whose state constants have all been resolved, keeping
        the m_jtbl lean so that IDA can further simplify the CFG.

        Returns:
            Number of case entries removed (or total cases if fully converted).
        """
        if not self._jtbl_converted or not self._resolved_transitions:
            return 0

        switch_blk = self.mba.get_mblock(self._jtbl_dispatcher_serial)
        if switch_blk is None:
            return 0
        tail = switch_blk.tail
        if tail is None or tail.opcode != ida_hexrays.m_jtbl:
            return 0
        if tail.r is None or tail.r.t != ida_hexrays.mop_c:
            return 0

        cases = tail.r.c

        # Determine resolved entries: a case entry is resolved when ALL state
        # constants that route to it have been resolved.
        resolved_from_states = {from_s for from_s, _to_s in self._resolved_transitions}

        # Invert _jtbl_state_to_handler: entry_serial -> set of state constants
        entry_to_states: dict[int, set[int]] = defaultdict(set)
        for state, entry in self._jtbl_state_to_handler.items():
            entry_to_states[entry].add(state)

        resolved_entries: set[int] = set()
        for entry, states in entry_to_states.items():
            if states <= resolved_from_states:  # all states for this entry resolved
                resolved_entries.add(entry)

        if not resolved_entries:
            return 0

        total_cases = cases.targets.size()

        # If ALL entries resolved, convert m_jtbl to a single m_goto
        if len(resolved_entries) >= total_cases:
            initial_target = self._jtbl_state_to_handler.get(
                self.state_machine.initial_state
                if self.state_machine is not None
                else -1
            )
            if initial_target is None and total_cases > 0:
                initial_target = int(cases.targets[0])
            if initial_target is not None:
                convert_jtbl_to_goto(switch_blk, initial_target, self.mba)
                unflat_logger.info(
                    "_prune_resolved_jtbl_cases: all %d cases resolved, "
                    "converted m_jtbl to goto blk[%d]",
                    total_cases,
                    initial_target,
                )
                return total_cases
            return 0

        # Partial prune: rebuild mcases_t keeping only unresolved entries
        old_succs = {
            int(switch_blk.succset[i]) for i in range(switch_blk.succset.size())
        }

        surviving_groups: dict[int, list[int]] = defaultdict(list)
        for i in range(cases.targets.size()):
            tgt = int(cases.targets[i])
            if tgt not in resolved_entries:
                for j in range(cases.values[i].size()):
                    surviving_groups[tgt].append(int(cases.values[i][j]))

        new_mc = ida_hexrays.mcases_t()
        for tgt in sorted(surviving_groups):
            new_mc.targets.push_back(tgt)
            uv = ida_pro.svalvec_t()
            for val in surviving_groups[tgt]:
                uv.push_back(val)
            new_mc.values.push_back(uv)

        cases.swap(new_mc)  # In-place swap, safe for SWIG

        # Rebuild succset from the new mcases_t
        new_succs: set[int] = {
            int(cases.targets[i]) for i in range(cases.targets.size())
        }
        switch_blk.succset.clear()
        for i in range(cases.targets.size()):
            switch_blk.succset.add_unique(int(cases.targets[i]))

        # Fix predsets for removed successors
        blk_serial = int(switch_blk.serial)
        for removed in old_succs - new_succs:
            r_blk = self.mba.get_mblock(removed)
            if r_blk is not None:
                try:
                    r_blk.predset._del(blk_serial)
                    r_blk.mark_lists_dirty()
                except Exception:
                    pass

        switch_blk.mark_lists_dirty()
        self.mba.mark_chains_dirty()

        removed_count = total_cases - cases.targets.size()
        unflat_logger.info(
            "_prune_resolved_jtbl_cases: pruned %d/%d cases from m_jtbl blk[%d]",
            removed_count,
            total_cases,
            self._jtbl_dispatcher_serial,
        )
        return removed_count

    def _resolve_jtbl_computed_case(
        self,
        case_entry: int,
        tail_serial: int,
        write_info: tuple,  # (insn, blk) from "computed" result
    ) -> int:
        """Resolve a computed state transition using forward eval or MopTracker."""
        from_state = self._jtbl_handler_state_map.get(case_entry)
        if from_state is None:
            return 0
        insn, _blk = write_info
        # Inline evaluation for common patterns: op state_var, CONST, state_var
        # or op CONST, state_var, state_var
        _MASK = 0xFFFFFFFF
        try:
            l_mop = insn.l
            r_mop = insn.r
            opcode = insn.opcode
            imm_val: "int | None" = None
            if l_mop.t == ida_hexrays.mop_n:
                imm_val = l_mop.nnn.value
            elif r_mop.t == ida_hexrays.mop_n:
                imm_val = r_mop.nnn.value
            if imm_val is not None:
                if opcode == ida_hexrays.m_xor:
                    computed = (from_state ^ imm_val) & _MASK
                elif opcode == ida_hexrays.m_sub:
                    computed = (from_state - imm_val) & _MASK
                elif opcode == ida_hexrays.m_add:
                    computed = (from_state + imm_val) & _MASK
                else:
                    return 0
                target = self._jtbl_state_to_handler.get(computed)
                if target is not None:
                    self.deferred.queue_goto_change(
                        tail_serial,
                        target,
                        description=f"jtbl-computed: blk[{case_entry}] state 0x{computed:x} -> blk[{target}]",
                    )
                    self.deferred.queue_insn_nop(
                        tail_serial,
                        insn.ea,
                        description=f"jtbl-computed: nop computed write at ea=0x{insn.ea:x}",
                    )
                    self._resolved_transitions.add((from_state, computed))
                    return 1
        except Exception:
            pass
        return 0

    def _merge_bst_transitions(self, bst_result: TransitionResult) -> None:
        """Merge BST-discovered transitions into state_machine.

        Only adds transitions for states that don't already have resolved
        transitions. Preserves BFS-discovered transitions (they have richer
        metadata like handler_blocks).
        """
        sm = self.state_machine

        # Build set of states that already have transitions
        existing_from_states = {t.from_state for t in sm.transitions}

        # Add BST transitions for states not covered by BFS
        added = 0
        for t in bst_result.transitions:
            if t.from_state not in existing_from_states:
                sm.transitions.append(t)
                # Also add to handler's transitions if handler exists
                handler = sm.handlers.get(t.from_state)
                if handler is not None:
                    handler.transitions.append(t)
                added += 1

        # Update initial_state if BST found one and current is None
        if sm.initial_state is None and bst_result.initial_state is not None:
            sm.initial_state = bst_result.initial_state

        if added > 0:
            unflat_logger.info(
                "Merged %d BST transitions for previously unresolved states", added
            )

    def _queue_transitions_direct(self) -> int:
        """
        Queue direct transition patches: bypass dispatcher and state checks.

        For each transition (from_state -> to_state):
        - The from_block (where state is assigned) currently goes to the dispatcher
        - Queue a change to go directly to to_state's first handler block

        This is more effective than predecessor-based patching which tries to resolve
        state values at check block predecessors, but fails when the predecessor
        is the dispatcher itself (which can have any state value).

        Conditional forks (2-way from_block with two different to_states) are handled
        by grouping transitions per from_block and using queue_create_conditional_redirect
        so both edges are preserved rather than collapsed to a single goto.
        """
        if self.state_machine is None or self.deferred is None:
            return 0

        handlers = list(self.state_machine.handlers.values())
        if not handlers:
            return 0

        analysis = None
        dispatcher_set: set[int] = set()
        state_var = self.state_machine.state_var if self.state_machine else None
        cache = DispatcherCache.get_or_create(self.mba)
        analysis = cache.analyze()
        if (
            analysis is not None
            and analysis.is_conditional_chain
            and analysis.dispatchers
        ):
            dispatcher_set = set(analysis.dispatchers)
            if analysis.state_variable is not None:
                state_var = analysis.state_variable.mop
            elif state_var is None:
                state_var = self.state_machine.state_var
        self._cache_dispatcher_set = dispatcher_set
        self._cache_state_var = state_var

        if self._jtbl_converted and self._resolved_transitions:
            # Filter out transitions already resolved by jtbl phase
            # (leave this as a TODO comment for now, full implementation comes later)
            pass

        check_blocks = {handler.check_block for handler in handlers}
        initial_state = (
            int(self.state_machine.initial_state)
            if self.state_machine.initial_state is not None
            else None
        )
        defer_loopback_to_terminal_fix = self._uses_extended_dispatch_ops()

        # --- Group transitions by from_block so we can detect conditional forks ---
        unflat_logger.debug(
            "_queue_transitions_direct: %d total transitions, defer_loopback=%s",
            len(self.state_machine.transitions),
            defer_loopback_to_terminal_fix,
        )
        transitions_by_block: dict[int, list[StateTransition]] = defaultdict(list)

        for transition in self.state_machine.transitions:
            # Respect loopback deferral for extended dispatch ops
            if (
                defer_loopback_to_terminal_fix
                and initial_state is not None
                and transition.to_state == initial_state
                and transition.from_state != initial_state
            ):
                continue
            # Defensive: skip self-loop transitions (should be filtered at build time,
            # but cache-based path may admit them).
            if (
                transition.from_state is not None
                and transition.from_state == transition.to_state
            ):
                unflat_logger.debug(
                    "_queue_transitions_direct: skipping self-loop transition %s -> %s (block %d)",
                    hex(transition.from_state),
                    hex(transition.to_state),
                    transition.from_block,
                )
                continue
            transitions_by_block[transition.from_block].append(transition)

        queued_patches = 0

        for from_serial, block_transitions in transitions_by_block.items():
            # Skip blocks already linearized by _linearize_handlers
            if from_serial in self._linearized_blocks:
                continue
            from_blk = self.mba.get_mblock(from_serial)
            if from_blk is None:
                continue

            # --- 1-way blocks: simple goto redirect ---
            if from_blk.nsucc() == 1:
                succs = list(from_blk.succset)
                if not succs or succs[0] not in check_blocks:
                    unflat_logger.debug(
                        "Block %d goes to %d, not a dispatcher check block; skipping",
                        from_serial,
                        succs[0] if succs else -1,
                    )
                    continue
                # All transitions from a 1-way block must agree on a single to_state
                # (duplicates from carry-forward are fine; ambiguity is not).
                unique_to = {t.to_state for t in block_transitions}
                if len(unique_to) != 1:
                    unflat_logger.debug(
                        "Block %d (1-way): ambiguous to_states %s, skipping",
                        from_serial,
                        [hex(s) for s in unique_to],
                    )
                    continue
                to_state = next(iter(unique_to))
                to_handler = self.state_machine.handlers.get(to_state)
                if to_handler is None or not to_handler.handler_blocks:
                    continue
                target_block = to_handler.handler_blocks[0]
                if self._queue_transition_redirect(
                    from_blk,
                    target_block,
                    f"transition {hex(block_transitions[0].from_state) if block_transitions[0].from_state is not None else 'unknown'} -> {hex(to_state)}",
                ):
                    for t in block_transitions:
                        if t.from_state is not None:
                            self._resolved_transitions.add((t.from_state, t.to_state))
                    queued_patches += 1
                continue

            # --- 2-way blocks ---
            if from_blk.nsucc() != 2:
                continue
            if not any(s in check_blocks for s in from_blk.succset):
                continue

            unique_to_states = {t.to_state for t in block_transitions}

            if len(unique_to_states) == 1:
                # All transitions from this 2-way block go to the same state —
                # collapse it to an unconditional goto (original behavior).
                transition = block_transitions[0]
                to_handler = self.state_machine.handlers.get(transition.to_state)
                if to_handler is None or not to_handler.handler_blocks:
                    continue
                target_block = to_handler.handler_blocks[0]
                if self._queue_transition_redirect(
                    from_blk,
                    target_block,
                    f"transition-cond {hex(transition.from_state) if transition.from_state is not None else 'unknown'} -> {hex(transition.to_state)}",
                ):
                    if transition.from_state is not None:
                        self._resolved_transitions.add(
                            (transition.from_state, transition.to_state)
                        )
                    queued_patches += 1

            elif len(unique_to_states) == 2:
                # Conditional fork: two different states flow out of one 2-way block.
                # We must preserve both edges — use queue_create_conditional_redirect.
                t_a, t_b = block_transitions[0], block_transitions[-1]
                handler_a = self.state_machine.handlers.get(t_a.to_state)
                handler_b = self.state_machine.handlers.get(t_b.to_state)
                if (
                    handler_a is None
                    or not handler_a.handler_blocks
                    or handler_b is None
                    or not handler_b.handler_blocks
                ):
                    unflat_logger.debug(
                        "Conditional fork at block %d: missing handler(s), skipping",
                        from_serial,
                    )
                    continue

                target_a = handler_a.handler_blocks[0]
                target_b = handler_b.handler_blocks[0]

                # Use the check block to determine which target is jcc-taken vs
                # fallthrough. The check block compares the state variable against
                # state_val; walk it for each to_state to find the final handler.
                # We need a check block serial — use the first successor in check_blocks.
                check_blk_serial = next(
                    (s for s in from_blk.succset if s in check_blocks), None
                )
                if check_blk_serial is None:
                    continue

                resolved_a = self._resolve_conditional_chain_target(
                    check_blk_serial, t_a.to_state
                )
                resolved_b = self._resolve_conditional_chain_target(
                    check_blk_serial, t_b.to_state
                )

                # Try emulation when static walk failed and we have full context
                dispatcher_set = getattr(self, "_cache_dispatcher_set", set())
                state_var = getattr(self, "_cache_state_var", None)
                valid_a = set(handler_a.handler_blocks)
                valid_b = set(handler_b.handler_blocks)
                if (
                    dispatcher_set
                    and state_var is not None
                    and (resolved_a is None or resolved_b is None)
                ):
                    ladder_entry = self._get_successor_into_dispatcher(
                        from_blk, dispatcher_set
                    )
                    if ladder_entry is not None:
                        use_before_def = self._collect_ladder_use_before_def(
                            dispatcher_set, ladder_entry
                        )
                        try:
                            for hist in [1]:  # dummy to preserve indent
                                em_a = self._emulate_chain_exit(
                                    ladder_entry,
                                    int(t_a.to_state),
                                    state_var,
                                    dispatcher_set,
                                    use_before_def,
                                    from_serial,
                                )
                                em_b = self._emulate_chain_exit(
                                    ladder_entry,
                                    int(t_b.to_state),
                                    state_var,
                                    dispatcher_set,
                                    use_before_def,
                                    from_serial,
                                )
                                if (
                                    em_a is not None
                                    and em_a in valid_a
                                    and resolved_a is None
                                ):
                                    resolved_a = em_a
                                if (
                                    em_b is not None
                                    and em_b in valid_b
                                    and resolved_b is None
                                ):
                                    resolved_b = em_b
                        except Exception as exc:
                            unflat_logger.debug(
                                "Emulation failed for cond-fork at blk %d: %s",
                                from_serial,
                                exc,
                            )

                # Prefer resolved targets if available; fall back to direct handler blocks.
                final_a = resolved_a if resolved_a is not None else target_a
                final_b = resolved_b if resolved_b is not None else target_b

                # Determine which is jcc-taken vs fallthrough by inspecting the check
                # block's comparison instruction.
                check_blk = self.mba.get_mblock(check_blk_serial)
                if (
                    check_blk is None
                    or check_blk.tail is None
                    or check_blk.tail.opcode not in HODUR_STATE_CHECK_OPCODES
                ):
                    continue

                # Check which to_state makes the check block's jump taken
                check_info = (
                    HodurStateMachineDetector._extract_check_constant_and_opcode(
                        check_blk.tail
                    )
                )
                if check_info is None:
                    continue
                check_opcode, check_const, check_size = check_info

                jt_a = HodurStateMachineDetector._is_jump_taken_for_state(
                    check_opcode, int(t_a.to_state), check_const, check_size
                )
                if jt_a is None:
                    continue

                # jcc target vs fallthrough target
                jcc_target = final_a if jt_a else final_b
                ft_target = final_b if jt_a else final_a
                jcc_state = t_a.to_state if jt_a else t_b.to_state
                ft_state = t_b.to_state if jt_a else t_a.to_state

                unflat_logger.debug(
                    "Conditional fork at block %d: jcc->%d (state %s), "
                    "fallthrough->%d (state %s)",
                    from_serial,
                    jcc_target,
                    hex(jcc_state),
                    ft_target,
                    hex(ft_state),
                )

                self.deferred.queue_create_conditional_redirect(
                    source_blk_serial=from_serial,
                    ref_blk_serial=check_blk_serial,
                    conditional_target_serial=jcc_target,
                    fallthrough_target_serial=ft_target,
                    description=(
                        f"cond-fork {from_serial}: jcc->{hex(jcc_state)} "
                        f"ft->{hex(ft_state)}"
                    ),
                )
                if t_a.from_state is not None:
                    self._resolved_transitions.add((t_a.from_state, t_a.to_state))
                if t_b.from_state is not None:
                    self._resolved_transitions.add((t_b.from_state, t_b.to_state))
                queued_patches += 1

        # --- Fix 1: Redirect handler-body back-edges to check blocks ---
        # Handler-body intermediate blocks whose only successor is a check block
        # form SCCs that prevent IDA's structurer from linearizing the CFG.
        # For each such block (nsucc==1, successor in check_block_serials), redirect
        # it to the exit target as a safe fallback. Only redirect 1-way blocks to
        # avoid corrupting conditional branches within handler bodies.
        check_block_serials = {handler.check_block for handler in handlers}
        sm_blocks_for_exit = self._collect_state_machine_blocks()
        first_check_serial = handlers[0].check_block if handlers else None
        exit_target = (
            self._find_terminal_exit_target(first_check_serial, sm_blocks_for_exit)
            if first_check_serial is not None
            else None
        )
        if exit_target is not None:
            # Build a map: handler entry serial -> next handler entry serial
            # based on transitions, so we can redirect to the correct successor
            # rather than always falling back to exit_target.
            handler_entry_to_next: dict[int, int] = {}
            for transition in self.state_machine.transitions:
                to_handler = self.state_machine.handlers.get(transition.to_state)
                if to_handler and to_handler.handler_blocks:
                    from_handler = self.state_machine.handlers.get(
                        transition.from_state
                    )
                    if from_handler and from_handler.handler_blocks:
                        handler_entry_to_next[from_handler.handler_blocks[0]] = (
                            to_handler.handler_blocks[0]
                        )

            for handler in handlers:
                for blk_serial in handler.handler_blocks:
                    # Skip the handler entry block -- already handled above as from_blk
                    if blk_serial == handler.handler_blocks[0]:
                        continue
                    # Skip blocks already linearized by _linearize_handlers
                    if blk_serial in self._linearized_blocks:
                        continue
                    blk = self.mba.get_mblock(blk_serial)
                    if blk is None or blk.nsucc() != 1:
                        continue
                    succs = list(blk.succset)
                    if not succs or succs[0] not in check_block_serials:
                        continue
                    # Prefer the known next-handler entry; fall back to exit_target
                    redirect_target = handler_entry_to_next.get(
                        handler.handler_blocks[0], exit_target
                    )
                    # If we fell back to exit_target, try to resolve through
                    # BST default first (handles state values that fall through
                    # all BST comparisons and would otherwise redirect to the
                    # terminal exit block incorrectly).
                    bst_default_target: int | None = None
                    if (
                        redirect_target == exit_target
                        and self._bst_result is not None
                    ):
                        state_var_stkoff = _get_state_var_stkoff(self._detector)
                        if state_var_stkoff is not None:
                            # Scan block for constant state write
                            written_state: int | None = None
                            scan = blk.head
                            while scan is not None:
                                if (
                                    scan.opcode == ida_hexrays.m_mov
                                    and scan.d is not None
                                    and _mop_matches_stkoff(
                                        scan.d, state_var_stkoff, mba=self.mba
                                    )
                                    and scan.l is not None
                                    and scan.l.t == ida_hexrays.mop_n
                                ):
                                    written_state = int(scan.l.nnn.value)
                                scan = scan.next
                            if written_state is not None:
                                bst_default = find_bst_default_block(
                                    self.mba,
                                    self._bst_dispatcher_serial,
                                    self._bst_result.bst_node_blocks,
                                    set(self._bst_result.handler_state_map.keys()),
                                )
                                if bst_default is not None:
                                    resolved = self._resolve_exit_via_bst_default(
                                        bst_default, written_state
                                    )
                                    if resolved is not None:
                                        bst_default_target = resolved
                                        unflat_logger.debug(
                                            "_queue_transitions_direct: handler-body"
                                            " back-edge blk[%d] state %#x resolved"
                                            " via BST default to blk[%d]",
                                            blk_serial,
                                            written_state,
                                            resolved,
                                        )
                    if bst_default_target is not None:
                        self.deferred.queue_goto_change(
                            block_serial=blk_serial,
                            new_target=bst_default_target,
                            description=(
                                "handler-body back-edge blk[%d] -> check blk[%d]"
                                " (BST default resolved)"
                                % (blk_serial, succs[0])
                            ),
                            rule_priority=550,
                        )
                        unflat_logger.debug(
                            "_queue_transitions_direct: handler-body back-edge blk[%d]"
                            " -> check blk[%d] redirected via BST default to blk[%d]",
                            blk_serial,
                            succs[0],
                            bst_default_target,
                        )
                        queued_patches += 1
                    elif self._queue_transition_redirect(
                        blk,
                        redirect_target,
                        "handler-body back-edge blk[%d] -> check blk[%d]"
                        % (blk_serial, succs[0]),
                    ):
                        unflat_logger.debug(
                            "_queue_transitions_direct: handler-body back-edge blk[%d]"
                            " -> check blk[%d] redirected to blk[%d]",
                            blk_serial,
                            succs[0],
                            redirect_target,
                        )
                        queued_patches += 1

        return queued_patches

    def _find_conditional_predecessor(self, start_block: int) -> int | None:
        """Walk backward along single-predecessor chains to find a 2-way block.

        Only follows single-predecessor paths (npred()==1) to avoid crossing
        dispatcher boundaries. Returns the serial of the first 2-way conditional
        block found, or None.
        """
        current = start_block
        visited: set[int] = {current}
        max_depth = self.mba.qty  # Safety bound

        for _ in range(max_depth):
            blk = self.mba.get_mblock(current)
            if blk.npred() != 1:
                return None  # Multi-predecessor — bail

            pred_serial = blk.predset[0]
            if pred_serial in visited:
                return None  # Cycle

            pred_blk = self.mba.get_mblock(pred_serial)
            if (
                pred_blk.nsucc() == 2
                and pred_blk.tail
                and pred_blk.tail.opcode
                in (
                    ida_hexrays.m_jcnd,
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
                )
            ):
                return pred_serial

            visited.add(pred_serial)
            current = pred_serial

        return None

    def _resolve_conditional_forks_via_predecessors(self) -> int:
        """Resolve conditional state forks by walking predecessor chains.

        For unresolved 2-state transitions from the same from_block:
        1. Walk backward from the from_block along single-predecessor chains
        2. Find the 2-way conditional block (jcc)
        3. Evaluate which branch leads to which state value
        4. Queue conditional redirect

        Returns:
            Number of conditional forks resolved.
        """
        if self.state_machine is None or self.deferred is None:
            return 0

        resolved = 0

        # Group conditional transitions by from_block
        conditional_groups: dict[int, list[StateTransition]] = {}
        for t in self.state_machine.transitions:
            if t.is_conditional:
                conditional_groups.setdefault(t.from_block, []).append(t)

        for from_blk_serial, transitions in conditional_groups.items():
            unique_states = list({t.to_state for t in transitions})
            if len(unique_states) != 2:
                continue

            # Walk backward from from_block looking for a 2-way conditional block
            cond_block = self._find_conditional_predecessor(from_blk_serial)
            if cond_block is None:
                if unflat_logger.debug_on:
                    unflat_logger.debug(
                        "No conditional predecessor found for block %d",
                        from_blk_serial,
                    )
                continue

            # Resolve which target block each state leads to through the chain
            state_a, state_b = unique_states[0], unique_states[1]
            target_a = self._resolve_conditional_chain_target(cond_block, state_a)
            target_b = self._resolve_conditional_chain_target(cond_block, state_b)

            if target_a is None or target_b is None:
                # Static walk hit a loop; try emulation fallback
                dispatcher_set = getattr(self, "_cache_dispatcher_set", set())
                state_var = getattr(self, "_cache_state_var", None)
                if dispatcher_set and state_var is not None:
                    use_before_def = self._collect_ladder_use_before_def(
                        dispatcher_set, cond_block
                    )
                    from_blk = self.mba.get_mblock(from_blk_serial)
                    ladder_entry = (
                        self._get_successor_into_dispatcher(from_blk, dispatcher_set)
                        if from_blk is not None
                        else None
                    )
                    if ladder_entry is not None:
                        try:
                            if target_a is None:
                                target_a = self._emulate_chain_exit(
                                    ladder_entry,
                                    int(state_a),
                                    state_var,
                                    dispatcher_set,
                                    use_before_def,
                                    from_blk_serial,
                                )
                            if target_b is None:
                                target_b = self._emulate_chain_exit(
                                    ladder_entry,
                                    int(state_b),
                                    state_var,
                                    dispatcher_set,
                                    use_before_def,
                                    from_blk_serial,
                                )
                        except Exception:
                            pass
                if target_a is None or target_b is None:
                    if unflat_logger.debug_on:
                        unflat_logger.debug(
                            "Chain resolution failed for block %d states 0x%x/0x%x",
                            from_blk_serial,
                            state_a,
                            state_b,
                        )
                    continue

            # Determine jcc taken/fallthrough mapping using the check block comparison
            cond_blk = self.mba.get_mblock(cond_block)
            if (
                cond_blk is None
                or cond_blk.tail is None
                or cond_blk.tail.opcode not in HODUR_STATE_CHECK_OPCODES
            ):
                continue

            check_info = HodurStateMachineDetector._extract_check_constant_and_opcode(
                cond_blk.tail
            )
            if check_info is None:
                continue
            check_opcode, check_const, check_size = check_info

            jt_a = HodurStateMachineDetector._is_jump_taken_for_state(
                check_opcode,
                int(state_a),
                check_const,
                check_size,
            )
            if jt_a is None:
                continue

            taken_target = target_a if jt_a else target_b
            fall_target = target_b if jt_a else target_a

            self.deferred.queue_create_conditional_redirect(
                source_blk_serial=from_blk_serial,
                ref_blk_serial=cond_block,
                conditional_target_serial=taken_target,
                fallthrough_target_serial=fall_target,
                description="Hodur conditional fork: block %d -> %d/%d"
                % (cond_block, taken_target, fall_target),
            )
            resolved += 1

            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Resolved conditional fork at block %d: "
                    "taken->%d, fall->%d (states 0x%x/0x%x)",
                    cond_block,
                    taken_target,
                    fall_target,
                    state_a,
                    state_b,
                )

        return resolved

    def _queue_transition_redirect(
        self,
        from_blk: ida_hexrays.mblock_t,
        target_block: int,
        description: str,
    ) -> bool:
        if self.deferred is None:
            return False

        if from_blk.nsucc() == 1:
            self.deferred.queue_goto_change(
                block_serial=from_blk.serial,
                new_target=target_block,
                description=description,
                rule_priority=50,  # Medium priority - path-based analysis
            )
            self._nop_state_write_in_block(from_blk)
            return True

        if from_blk.nsucc() == 2:
            dispatcher_set = getattr(self, "_cache_dispatcher_set", set())
            if any(succ not in dispatcher_set for succ in from_blk.succset):
                return False
            self.deferred.queue_convert_to_goto(
                block_serial=from_blk.serial,
                goto_target=target_block,
                description=description,
            )
            self._nop_state_write_in_block(from_blk)
            return True

        return False

    def _nop_state_write_in_block(self, blk: ida_hexrays.mblock_t) -> None:
        """NOP any state variable write found in blk (legacy path helper).

        Only acts on blocks with a single predecessor to avoid destroying
        state writes that are shared with exit paths.
        """
        if (
            self.deferred is None
            or self.state_machine is None
            or self.state_machine.state_var is None
        ):
            return
        # With _linearized_blocks coordination, the legacy path only handles
        # blocks the linearizer didn't claim — state writes are dead after
        # the goto redirect regardless of predecessor count.
        write_result = self._find_state_write_in_block(
            blk, self.state_machine.state_var
        )
        if write_result is None:
            return
        write_type, write_data = write_result
        if write_type == "literal":
            _, insn_ea = write_data
        else:  # "computed"
            insn, _ = write_data
            insn_ea = insn.ea
        self.deferred.queue_insn_nop(
            block_serial=blk.serial,
            insn_ea=insn_ea,
            description="hodur: dead state write (legacy path)",
        )

    def _get_primary_check_opcode(self) -> int | None:
        if self.state_machine is None or not self.state_machine.handlers:
            return None
        first_check_block = list(self.state_machine.handlers.values())[0].check_block
        first_check_blk = self.mba.get_mblock(first_check_block)
        if first_check_blk is None or first_check_blk.tail is None:
            return None
        return first_check_blk.tail.opcode

    def _uses_extended_dispatch_ops(self) -> bool:
        """
        Return True when dispatcher checks use non-legacy comparisons.
        """
        check_opcode = self._get_primary_check_opcode()
        return check_opcode in HODUR_STATE_CHECK_OPCODES and check_opcode not in (
            ida_hexrays.m_jnz,
            ida_hexrays.m_jz,
        )

    def _collect_state_machine_blocks(self) -> set[int]:
        if self.state_machine is None:
            return set()

        blocks = set()
        for handler in self.state_machine.handlers.values():
            blocks.add(handler.check_block)
            blocks.update(handler.handler_blocks)
        return blocks

    def _find_terminal_loopback_transition(self) -> StateTransition | None:
        if self.state_machine is None or self.state_machine.initial_state is None:
            return None

        initial_state = int(self.state_machine.initial_state)
        loopbacks = [
            transition
            for transition in self.state_machine.transitions
            if transition.to_state == initial_state
            and transition.from_state != initial_state
        ]
        if len(loopbacks) != 1:
            return None

        transition = loopbacks[0]
        transition_blk = self.mba.get_mblock(transition.from_block)
        if transition_blk is None:
            return None

        # Keep the heuristic conservative: only rewrite "lightweight" terminal
        # transition blocks that only assign a constant to the state variable.
        if not self._is_lightweight_terminal_transition_block(transition_blk):
            return None

        return transition

    def _is_lightweight_terminal_transition_block(
        self,
        blk: ida_hexrays.mblock_t,
    ) -> bool:
        if self.state_machine is None or self.state_machine.state_var is None:
            return False

        state_var = self.state_machine.state_var
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_mov:
                if (
                    insn.d.t == ida_hexrays.mop_z
                    or not self._mops_match_state_var(insn.d, state_var)
                    or insn.l.t != ida_hexrays.mop_n
                ):
                    return False
            elif insn.opcode in (ida_hexrays.m_goto, ida_hexrays.m_nop):
                pass
            else:
                # Allow conditional jump tails on 2-way transition blocks.
                if insn != blk.tail or insn.opcode not in HODUR_STATE_CHECK_OPCODES:
                    return False
            insn = insn.next

        return True

    def _find_terminal_exit_target(
        self,
        first_check_block: int,
        state_machine_blocks: set[int],
    ) -> int | None:
        first_check = self.mba.get_mblock(first_check_block)
        if first_check is None:
            return None

        # Prefer the first-check successor that escapes the state-machine region
        # and can reach a return block.
        outside_successors = [
            succ for succ in first_check.succset if succ not in state_machine_blocks
        ]
        for succ in outside_successors:
            if self._can_reach_return(succ):
                return succ

        # Fallback: redirect directly to a reachable return block.
        for blk_serial in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_serial)
            if blk is None or blk.tail is None:
                continue
            if blk.tail.opcode == ida_hexrays.m_ret and (
                blk.npred() > 0 or self._can_reach_return(blk.serial)
            ):
                return blk.serial

        # Last-resort fallback: use the stop block so terminal loops can be cut
        # even when Hex-Rays has normalized away explicit m_ret blocks.
        stop_blk = self.mba.get_mblock(self.mba.qty - 1)
        if stop_blk is not None and stop_blk.nsucc() == 0:
            return stop_blk.serial

        return None

    def _can_reach_return(self, start_serial: int) -> bool:
        visited = set()
        to_visit = [start_serial]

        while to_visit:
            blk_serial = to_visit.pop(0)
            if blk_serial in visited:
                continue
            visited.add(blk_serial)

            blk = self.mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_ret:
                return True

            for succ in blk.succset:
                if succ not in visited:
                    to_visit.append(succ)

        return False

    def _queue_predecessor_patches(self) -> None:
        """
        Queue predecessor-based patches for state check blocks.

        For each state check block, if we can determine what state the predecessor
        always has, we queue a patch to bypass the check and go directly to the
        appropriate handler.

        Note: This method does NOT use the deferred modifier because it requires
        block duplication which is more complex. Instead, it applies patches
        directly but still benefits from being called after _queue_transitions_direct
        has identified all the transitions.

        TODO: Refactor to use deferred modifications for full queueing.
        """
        # _queue_transitions_direct covers all known transition blocks
        # (from_block -> check_block -> handler_entry redirects) including
        # handler-body intermediate back-edges (see handler-body back-edge loop
        # at the end of _queue_transitions_direct).
        # Predecessor-based patching would require block duplication and
        # is not needed when direct transition data is available.
        # If a future pattern requires predecessor patching, implement it here
        # by walking each state check block's predecessors and resolving state
        # values via _build_transitions_by_scan for unresolved states.
        pass

    def _queue_state_assignment_removals(self) -> None:
        """
        Queue removal of state assignment instructions and fix terminal artifacts.

        After all transition patches are applied:
        1. State variable assignments (mov STATE_CONSTANT, state_var) become dead code
        2. The terminal back-edge (last handler -> first check) should be removed
        3. The first state check becomes unnecessary

        This cleans up the "wrapper while(1)" artifact that remains after unflattening.
        """
        if self.state_machine is None or self.deferred is None:
            return

        initial_state = self.state_machine.initial_state
        if initial_state is None:
            return

        # Get the first check block (entry to state machine)
        first_handler = list(self.state_machine.handlers.values())[0]
        first_check_block = first_handler.check_block

        # Track which blocks we've patched (their gotos were changed)
        patched_blocks = set()
        for mod in self.deferred.modifications:
            if mod.mod_type.name == "BLOCK_GOTO_CHANGE":
                patched_blocks.add(mod.block_serial)

        # Find and queue removal of state assignments in patched blocks
        # These are the "mov STATE_CONSTANT, state_var" instructions
        for blk_serial in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_serial)

            # Only process blocks that were patched or are in handler blocks
            is_handler_block = any(
                blk_serial in h.handler_blocks
                for h in self.state_machine.handlers.values()
            )

            if blk_serial not in patched_blocks and not is_handler_block:
                continue

            pass

        # NOP state variable assignments in resolved handler blocks
        state_var = self.state_machine.state_var
        if state_var is not None:
            state_nops: list[tuple[int, int, int]] = []  # (block_serial, ea, opcode)

            for handler in self.state_machine.handlers.values():
                for blk_serial in handler.handler_blocks:
                    if blk_serial >= self.mba.qty:
                        continue
                    blk = self.mba.get_mblock(blk_serial)
                    insn = blk.head
                    while insn:
                        # Match: mov CONST, state_var (state assignment)
                        if (
                            insn.opcode == ida_hexrays.m_mov
                            and insn.l.t == ida_hexrays.mop_n
                            and insn.l.nnn.value in self.state_machine.state_constants
                            and insn.d.t == state_var.t
                            and insn.d.size == state_var.size
                        ):
                            state_nops.append((blk_serial, insn.ea, insn.opcode))
                        insn = insn.next

            # Apply NOPs — match by EA+opcode to avoid SWIG identity issues
            for blk_serial, target_ea, target_opcode in state_nops:
                blk = self.mba.get_mblock(blk_serial)
                insn = blk.head
                while insn:
                    if insn.ea == target_ea and insn.opcode == target_opcode:
                        blk.make_nop(insn)
                        if unflat_logger.debug_on:
                            unflat_logger.debug(
                                "NOPed state assignment in block %d (ea=0x%x)",
                                blk_serial,
                                target_ea,
                            )
                        break
                    insn = insn.next

        # Find terminal back-edge: a block that goes back to first_check_block
        # after all transitions have been patched.
        # Skip when m_jtbl conversion is active — back-edges to the switch
        # are intentional (unresolved handlers loop through the switch case).
        if not self._jtbl_converted:
            self._queue_terminal_backedge_fix(first_check_block)

    def _queue_terminal_backedge_fix(self, first_check_block: int) -> None:
        """
        Find and fix the terminal back-edge that creates the while(1) wrapper.

        After unflattening, there's typically one back-edge remaining:
        - From the last handler block back to the first state check
        - This creates the while(1) { if(state != INIT) goto success; ... } pattern

        We convert this back-edge to go to the "success" path instead of looping.
        """
        if self.state_machine is None or self.deferred is None:
            return

        if self.state_machine.initial_state is None:
            return

        # Preserve the previously-stable behavior for classic jnz-based Hodur/ABC
        # flattening before attempting broader structural heuristics.
        if self._queue_legacy_terminal_backedge_fix(first_check_block):
            return

        state_machine_blocks = self._collect_state_machine_blocks()
        success_target = self._find_terminal_exit_target(
            first_check_block,
            state_machine_blocks,
        )
        if success_target is None:
            return
        success_blk = self.mba.get_mblock(success_target)
        success_is_stop = (
            success_blk is not None
            and success_blk.nsucc() == 0
            and success_blk.tail is None
        )
        # Redirecting to a synthetic stop block too early can destabilize CFG
        # in some folded-constant pipelines; defer to later maturities.
        if success_is_stop and self.cur_maturity < ida_hexrays.MMAT_GLBOPT1:
            return

        initial_state = int(self.state_machine.initial_state)
        check_blocks = {
            handler.check_block for handler in self.state_machine.handlers.values()
        }
        processed_blocks = set()

        # Primary strategy: rewrite transitions that loop back to INITIAL_STATE.
        loopback_transitions = [
            transition
            for transition in self.state_machine.transitions
            if transition.to_state == initial_state
            and transition.from_state != initial_state
        ]
        candidate_blocks = [
            transition.from_block for transition in loopback_transitions
        ]

        # Fallback: no explicit loopback transition found, use structural back-edges
        # to the dispatcher entry among lightweight state-machine blocks.
        if not candidate_blocks:
            for blk_serial in state_machine_blocks:
                blk = self.mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                if (
                    first_check_block in blk.succset
                    and self._is_lightweight_terminal_transition_block(blk)
                ):
                    candidate_blocks.append(blk_serial)

        for blk_serial in candidate_blocks:
            if blk_serial in processed_blocks:
                continue
            processed_blocks.add(blk_serial)

            blk = self.mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if not any(succ in check_blocks for succ in blk.succset):
                continue

            unflat_logger.info(
                "Redirecting terminal loopback block %d -> exit block %d",
                blk_serial,
                success_target,
            )
            if blk.nsucc() == 1:
                self.deferred.queue_goto_change(
                    block_serial=blk_serial,
                    new_target=success_target,
                    description="terminal loopback -> success path",
                    rule_priority=50,
                )
            elif blk.nsucc() == 2:
                self.deferred.queue_convert_to_goto(
                    block_serial=blk_serial,
                    goto_target=success_target,
                    description="terminal loopback cond -> success path",
                )

    def _queue_legacy_terminal_backedge_fix(self, first_check_block: int) -> bool:
        """
        Legacy Hodur cleanup:
        rewrite direct goto back-edges to first check for jnz wrappers.
        """
        if self.state_machine is None or self.deferred is None:
            return False

        first_check_blk = self.mba.get_mblock(first_check_block)
        if first_check_blk is None or first_check_blk.tail is None:
            return False

        # Default: jnz jump target (next check block in chain)
        jnz_target = None
        if (
            first_check_blk.tail.opcode == ida_hexrays.m_jnz
            and first_check_blk.tail.d.t == ida_hexrays.mop_b
        ):
            jnz_target = first_check_blk.tail.d.b

        # Prefer true exit target when it escapes the state machine region.
        # The jnz target is typically the next check block, which loops back
        # into the dispatcher and creates a residual while(1).
        sm_blocks = self._collect_state_machine_blocks()
        exit_target = self._find_terminal_exit_target(first_check_blk.serial, sm_blocks)
        if exit_target is not None and exit_target not in sm_blocks:
            success_target = exit_target
        else:
            success_target = jnz_target

        if success_target is None:
            return False

        queued_any = False
        for blk_serial in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if first_check_block not in blk.succset:
                continue
            if blk_serial <= first_check_block:
                continue
            if blk.tail is None or blk.tail.opcode != ida_hexrays.m_goto:
                continue
            if blk.tail.l.t != ida_hexrays.mop_b or blk.tail.l.b != first_check_block:
                continue

            self.deferred.queue_goto_change(
                block_serial=blk_serial,
                new_target=success_target,
                description="terminal back-edge -> success path (legacy)",
                rule_priority=50,
            )
            queued_any = True

        return queued_any

    def _fix_degenerate_terminal_loops(self) -> int:
        """
        Redirect trivial terminal loops that can remain after unflattening.
        """
        if self.state_machine is None:
            return 0

        handlers = list(self.state_machine.handlers.values())
        if not handlers:
            return 0

        first_check_block = handlers[0].check_block
        state_machine_blocks = self._collect_state_machine_blocks()
        exit_target = self._find_terminal_exit_target(
            first_check_block, state_machine_blocks
        )
        if exit_target is None:
            return 0

        candidate_blocks = self._collect_nearby_blocks(state_machine_blocks, depth=4)

        # Reset the deferred modifier so it can accept a new round of queued
        # changes (the earlier apply() call in optimize() has already flushed
        # the transition-patch queue and set _applied=True).
        self.deferred.reset()

        nb_fixed = 0
        for blk_serial in sorted(candidate_blocks):
            blk = self.mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if blk.nsucc() != 1 or not self._is_degenerate_loop_block(blk):
                continue

            succ = next(iter(blk.succset))
            if succ == blk.serial and blk.serial != exit_target:
                self.deferred.queue_goto_change(
                    block_serial=blk.serial,
                    new_target=exit_target,
                    description="fix_degenerate_terminal_loop",
                    rule_priority=50,
                )
                nb_fixed += 1
                unflat_logger.info(
                    "Queued redirect: terminal self-loop block %d -> %d",
                    blk.serial,
                    exit_target,
                )
                continue

            succ_blk = self.mba.get_mblock(succ)
            if succ_blk is None or succ_blk.nsucc() != 1:
                continue
            if not self._is_degenerate_loop_block(succ_blk):
                continue
            succ2 = next(iter(succ_blk.succset))
            if (
                succ2 == blk.serial
                and blk.serial != exit_target
                and succ != exit_target
            ):
                self.deferred.queue_goto_change(
                    block_serial=blk.serial,
                    new_target=exit_target,
                    description="fix_degenerate_terminal_loop",
                    rule_priority=50,
                )
                nb_fixed += 1
                unflat_logger.info(
                    "Queued redirect: terminal 2-block loop %d<->%d via %d",
                    blk.serial,
                    succ,
                    exit_target,
                )

        if nb_fixed > 0:
            self.deferred.apply(run_optimize_local=True)

        return nb_fixed

    def _collect_nearby_blocks(self, seed_blocks: set[int], depth: int = 2) -> set[int]:
        nearby = set(seed_blocks)
        frontier = set(seed_blocks)
        for _ in range(max(depth, 0)):
            next_frontier = set()
            for blk_serial in frontier:
                blk = self.mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                for succ in blk.succset:
                    if succ not in nearby:
                        next_frontier.add(succ)
                for pred in blk.predset:
                    if pred not in nearby:
                        next_frontier.add(pred)
            if not next_frontier:
                break
            nearby.update(next_frontier)
            frontier = next_frontier
        return nearby

    def _is_degenerate_loop_block(self, blk: ida_hexrays.mblock_t) -> bool:
        """
        Return True for trivial synthetic loop blocks (nop/goto-only).
        """
        insn = blk.head
        meaningful = 0
        while insn:
            if insn.opcode not in (ida_hexrays.m_nop, ida_hexrays.m_goto):
                meaningful += 1
                if meaningful > 0:
                    return False
            insn = insn.next
        return True

    def _infer_unique_state_at_block_end(
        self,
        blk: ida_hexrays.mblock_t,
        state_var: ida_hexrays.mop_t,
    ) -> int | None:
        """Infer a unique concrete state value at the end of a block."""
        tracker = MopTracker(
            [state_var],
            max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK,
            max_path=self.MOP_TRACKER_MAX_NB_PATH,
        )
        tracker.reset()

        histories = tracker.search_backward(blk, blk.tail)
        values = get_all_possibles_values(histories, [state_var])
        flat_values = [v[0] for v in values if v and v[0] is not None]
        if not flat_values:
            return None

        unique_values = set(flat_values)
        if len(unique_values) != 1:
            return None

        return int(flat_values[0])

    def _collect_ladder_use_before_def(
        self, dispatcher_set: set[int], entry_serial: int
    ) -> list[ida_hexrays.mop_t]:
        """Collect all mops used-before-defined in the ladder (dispatcher) blocks."""
        use_list: list[ida_hexrays.mop_t] = []
        def_list: list[ida_hexrays.mop_t] = []
        use_before_def: list[ida_hexrays.mop_t] = []

        # Find all reachable blocks within dispatcher_set starting from entry_serial
        reachable = set()
        queue = [entry_serial]
        while queue:
            curr = queue.pop(0)
            if curr in reachable or curr not in dispatcher_set:
                continue
            reachable.add(curr)
            blk = self.mba.get_mblock(curr)
            if blk:
                for succ in blk.succset:
                    queue.append(succ)

        # Process reachable blocks in topological order (serial order)
        for serial in sorted(reachable):
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            cur_ins = blk.head
            while cur_ins is not None:
                collector = InstructionDefUseCollector()
                cur_ins.for_all_ops(collector)
                cleaned = remove_segment_registers(collector.unresolved_ins_mops)
                for mop_used in cleaned + list(collector.memory_unresolved_ins_mops):
                    append_mop_if_not_in_list(mop_used, use_list)
                    if get_mop_index(mop_used, def_list) == -1:
                        append_mop_if_not_in_list(mop_used, use_before_def)
                for mop_def in collector.target_mops:
                    append_mop_if_not_in_list(mop_def, def_list)
                cur_ins = cur_ins.next

        return [
            m for m in use_before_def if m.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
        ]

    def _get_successor_into_dispatcher(
        self,
        from_block: ida_hexrays.mblock_t,
        dispatcher_set: set[int],
    ) -> int | None:
        """Return the successor that enters or stays in the dispatcher set."""
        succs = list(from_block.succset)
        if not succs:
            return None
        if from_block.nsucc() == 1:
            return succs[0]
        if from_block.nsucc() == 2:
            in_disp = [s for s in succs if s in dispatcher_set]
            if in_disp:
                return in_disp[0]
            for s in succs:
                succ_blk = self.mba.get_mblock(s)
                if succ_blk is None:
                    continue
                for s2 in succ_blk.succset:
                    if s2 in dispatcher_set:
                        return s
            return None
        return succs[0] if succs else None

    def _emulate_chain_exit(
        self,
        entry_block_serial: int,
        state_value: int,
        state_var: ida_hexrays.mop_t,
        dispatcher_set: set[int],
        use_before_def: list[ida_hexrays.mop_t],
        from_block_serial: int,
        max_instructions: int = 5000,
    ) -> int | None:
        """
        Emulate from entry_block with env built from local definitions until we exit
        the dispatcher set. Returns the block serial we land in, or None on failure.
        """
        cur_blk = self.mba.get_mblock(entry_block_serial)
        if cur_blk is None:
            return None

        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        try:
            env.define(state_var, int(state_value))
        except Exception:
            return None

        from_blk = self.mba.get_mblock(from_block_serial)
        if from_blk is None:
            return None

        for mop in use_before_def:
            if state_var is not None and equal_mops_ignore_size(mop, state_var):
                continue
            ast = _resolve_mop_via_predecessors(mop, from_blk, from_blk.tail)
            if ast is None or not hasattr(ast, "value") or ast.value is None:
                return None
            try:
                env.define(mop, int(ast.value))
            except Exception:
                return None

        cur_ins = cur_blk.head
        visited: set[int] = set()
        nb_emulated = 0

        while cur_blk is not None:
            if cur_ins is None:
                cur_ins = cur_blk.head
            if cur_ins is None:
                return None
            if cur_blk.serial in visited:
                return None
            visited.add(cur_blk.serial)

            is_ok = interpreter.eval_instruction(
                cur_blk, cur_ins, env, raise_exception=False
            )
            if not is_ok:
                return None
            nb_emulated += 1
            if nb_emulated >= max_instructions:
                return None

            next_blk = env.next_blk
            next_ins = env.next_ins
            if next_blk is None:
                return None
            if next_blk.serial not in dispatcher_set:
                return next_blk.serial
            cur_blk = next_blk
            cur_ins = next_ins

        return None

    def _resolve_conditional_chain_target(
        self,
        start_block: int,
        state_value: int,
    ) -> int | None:
        """
        Follow conditional-chain comparisons for a concrete state until a leaf block.
        """
        visited: set[int] = set()
        current = start_block

        for _ in range(self.mba.qty):
            if current in visited:
                return None
            visited.add(current)

            blk = self.mba.get_mblock(current)
            if blk.tail is None or blk.tail.opcode not in HODUR_STATE_CHECK_OPCODES:
                return current
            check_info = HodurStateMachineDetector._extract_check_constant_and_opcode(
                blk.tail
            )
            if check_info is None:
                return current
            check_opcode, check_const, check_size = check_info

            jump_target, fallthrough = (
                HodurStateMachineDetector._get_jump_and_fallthrough_targets(blk)
            )
            if jump_target is None or fallthrough is None:
                return None

            jump_taken = HodurStateMachineDetector._is_jump_taken_for_state(
                check_opcode,
                int(state_value),
                check_const,
                check_size,
            )
            if jump_taken is None:
                return None

            current = jump_target if jump_taken else fallthrough

        return None

    def _log_state_machine(self) -> None:
        """Log the detected state machine structure."""
        if self.state_machine is None:
            return

        unflat_logger.info("=== Hodur State Machine ===")
        unflat_logger.info(
            "State variable: %s",
            (
                format_mop_t(self.state_machine.state_var)
                if self.state_machine.state_var
                else "unknown"
            ),
        )
        unflat_logger.info(
            "Initial state: %s",
            (
                hex(self.state_machine.initial_state)
                if self.state_machine.initial_state
                else "unknown"
            ),
        )
        unflat_logger.info(
            "State constants: %s",
            ", ".join(hex(c) for c in sorted(self.state_machine.state_constants)),
        )
        unflat_logger.info("Transitions:")
        for t in self.state_machine.transitions:
            unflat_logger.info(
                "  %s -> %s (block %d)",
                hex(t.from_state),
                hex(t.to_state),
                t.from_block,
            )

    def _build_state_machine_from_cache(
        self, analysis: DispatcherAnalysis
    ) -> HodurStateMachine | None:
        """
        Build a HodurStateMachine compatible object directly from DispatcherAnalysis.

        Uses _resolve_conditional_chain_target (static comparison-tree walk) as the
        PRIMARY target resolver.  For each non-dispatcher block B that assigns the
        state variable to a concrete constant K, the handler entry is found by walking
        the dispatcher chain statically.  Emulation via _emulate_chain_exit is used
        only as a fallback when the static walk cannot resolve the target.

        This avoids the dummy-StateTransition problem of the predecessor-only approach
        where _queue_transitions_direct received transitions without from_block and
        could not seed MopTracker for emulation, resulting in most transitions going
        unresolved.
        """
        if (
            not analysis.is_conditional_chain
            or not analysis.dispatchers
            or not analysis.state_variable
        ):
            return None

        state_var = analysis.state_variable.mop
        dispatcher_set = set(analysis.dispatchers)
        # The entry of the conditional chain is the lowest-serial dispatcher block.
        disp_entry_serial = min(analysis.dispatchers)
        disp_entry_blk = self.mba.get_mblock(disp_entry_serial)
        if disp_entry_blk is None:
            return None

        machine = HodurStateMachine(
            mba=self.mba,
            state_var=state_var,
            initial_state=analysis.initial_state,
        )
        for c in analysis.state_constants:
            machine.add_state_constant(c)

        # Build a reverse map: handler_block_serial -> state_value that routes there.
        # This lets us identify the "from_state" (entry state) for each handler block.
        block_to_from_state: dict[int, int] = {}
        for sc in analysis.state_constants:
            routed_serial = self._resolve_conditional_chain_target(
                disp_entry_serial, sc
            )
            if routed_serial is not None:
                block_to_from_state[routed_serial] = sc
        unflat_logger.debug(
            "_build_state_machine_from_cache: reverse map has %d entries: %s",
            len(block_to_from_state),
            {hex(v): k for k, v in block_to_from_state.items()},
        )

        handlers_by_state: dict[int, StateHandler] = {}

        # Iterate every non-dispatcher block in the MBA.
        for blk_idx in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_idx)
            if blk is None:
                continue
            if blk.serial in dispatcher_set:
                continue

            # Only process blocks that are direct handler entries (reachable from
            # the dispatcher for a specific state value).
            from_state = block_to_from_state.get(blk.serial)
            if from_state is None:
                continue

            # Resolve the state value that this block assigns (the NEXT state).
            ast = _resolve_mop_via_predecessors(state_var, blk, blk.tail)
            if ast is None or not hasattr(ast, "value") or ast.value is None:
                continue

            next_state = int(ast.value)
            from_block_serial = blk.serial

            # --- PRIMARY: static comparison-tree walk to find the handler block for next_state ---
            target_serial = self._resolve_conditional_chain_target(
                disp_entry_serial, next_state
            )

            # --- FALLBACK: emulation ---
            if target_serial is None:
                unflat_logger.debug(
                    "_build_state_machine_from_cache: static walk failed for next_state %s "
                    "from block %d; trying emulation",
                    hex(next_state),
                    from_block_serial,
                )
                target_serial = self._emulate_chain_exit(
                    entry_block_serial=disp_entry_serial,
                    state_value=next_state,
                    state_var=state_var,
                    dispatcher_set=dispatcher_set,
                    use_before_def=[],
                    from_block_serial=from_block_serial,
                )

            if target_serial is None:
                unflat_logger.debug(
                    "_build_state_machine_from_cache: could not resolve target for "
                    "next_state %s from block %d; skipping",
                    hex(next_state),
                    from_block_serial,
                )
                continue

            unflat_logger.debug(
                "_build_state_machine_from_cache: block %d: from_state=%s -> next_state=%s"
                " (target block %d)",
                from_block_serial,
                hex(from_state),
                hex(next_state),
                target_serial,
            )

            # Register the transition: from_state (entry state) -> next_state (assigned state).
            # from_block is blk.serial so _queue_transitions_direct can seed MopTracker.
            transition = StateTransition(
                from_state=from_state,
                to_state=next_state,
                from_block=from_block_serial,
                is_conditional=(blk.nsucc() > 1),
            )
            machine.add_transition(transition)

            # Register the handler for from_state (this block IS the handler for from_state).
            if from_state not in handlers_by_state:
                handler = StateHandler(
                    state_value=from_state,
                    check_block=disp_entry_serial,
                    handler_blocks=[blk.serial],
                )
                handlers_by_state[from_state] = handler
                machine.add_handler(handler)

            # Also register the handler for next_state so _queue_transitions_direct
            # can look up handlers[next_state].handler_blocks[0] as the redirect target.
            if next_state not in handlers_by_state:
                handler = StateHandler(
                    state_value=next_state,
                    check_block=disp_entry_serial,
                    handler_blocks=[target_serial],
                )
                handlers_by_state[next_state] = handler
                machine.add_handler(handler)

        if not machine.transitions:
            unflat_logger.debug(
                "_build_state_machine_from_cache: no transitions resolved; returning None"
            )
            return None

        return machine

    def _state_machine_still_present(self) -> bool:
        """
        Return True if the CFG still contains Hodur state machine structure.

        Re-runs the state machine detector on the current (possibly modified) CFG.
        Returns False if no state machine is found (fully resolved or never existed).
        When a residual is found, updates self.state_machine with fresh block info.
        """
        if self.mba is None:
            return False

        detector = HodurStateMachineDetector(
            self.mba,
            use_cache=False,
            min_state_constant=self.min_state_constant,
            min_state_constants=self.min_state_constants,
            max_state_constants=self.max_state_constants,
        )
        result = detector.detect()
        if result is None:
            # Fallback to robust cache analysis
            cache = DispatcherCache.get_or_create(self.mba)
            analysis = cache.refresh()
            if analysis.is_conditional_chain:
                result = self._build_state_machine_from_cache(analysis)

        has_structure = result is not None
        if has_structure:
            # Update with fresh handler/check block info from current CFG
            self.state_machine = result
        unflat_logger.debug(
            "HodurUnflattener: _state_machine_still_present -> %s",
            has_structure,
        )
        return has_structure

    def _resolve_remaining_via_assignment_map(self) -> int:
        """Resolve remaining dispatcher back-edges using assignment_map lookup.

        After deferred patches, some handler exit blocks still goto the dispatcher.
        These blocks contain state assignments that identify their target handler.
        Use assignment_map to directly resolve and redirect them, bypassing
        MopTracker backward tracing which fails on modified CFG.
        """
        if self.state_machine is None or not self.state_machine.assignment_map:
            return 0

        state_var = self.state_machine.state_var
        if state_var is None:
            return 0

        if self._detector is None:
            return 0

        assignment_map = self.state_machine.assignment_map
        check_blocks = {h.check_block for h in self.state_machine.handlers.values()}

        resolved = 0

        # Pre-compute state machine block set once for 2-way exit block handling
        sm_blocks = self._collect_state_machine_blocks()

        # Collect predecessors of ALL check blocks (back-edges can target any entry)
        # Each entry is (pred_serial, dispatcher_target) so we know which check block
        # the predecessor currently targets and can pass the correct old_succ to
        # update_blk_successor and the correct start_block to
        # _resolve_conditional_chain_target.
        preds_to_check: set[tuple[int, int]] = set()
        for cb_serial in check_blocks:
            cb_blk = self.mba.get_mblock(cb_serial)
            if cb_blk is None:
                continue
            for pred_serial in cb_blk.predset:
                if pred_serial not in check_blocks:
                    preds_to_check.add((pred_serial, cb_serial))

        for pred_serial, dispatcher_target in preds_to_check:
            pred_blk = self.mba.get_mblock(pred_serial)
            if pred_blk is None:
                continue

            # Handle 2-way exit blocks ONLY outside the state machine region.
            # Convert to 1-way goto targeting the non-check-block successor.
            if pred_blk.nsucc() == 2:
                if pred_serial not in sm_blocks:  # sm_blocks pre-computed
                    # Find the non-check-block successor (the forward path)
                    forward_succs = [
                        s for s in pred_blk.succset if s not in check_blocks
                    ]
                    if forward_succs:
                        forward_target = forward_succs[0]
                        make_2way_block_goto(pred_blk, forward_target)
                        unflat_logger.info(
                            "Assignment-map resolver: converted 2-way exit blk[%d] "
                            "to goto blk[%d]",
                            pred_serial,
                            forward_target,
                        )
                        resolved += 1
                continue

            # Only handle 1-way blocks (goto blocks)
            # 2-way blocks are application conditionals — preserve them
            if pred_blk.nsucc() != 1:
                continue

            # Try to find state assignment in this block
            target_state = self._detector._extract_assigned_state_from_block(
                pred_serial, assignment_map, state_var
            )

            # If not found directly, walk backward along single-pred chains
            if target_state is None:
                walk_serial = pred_serial
                for _ in range(5):  # max backward walk depth
                    walk_blk = self.mba.get_mblock(walk_serial)
                    if walk_blk is None or walk_blk.npred() != 1:
                        break
                    walk_serial = list(walk_blk.predset)[0]
                    target_state = self._detector._extract_assigned_state_from_block(
                        walk_serial, assignment_map, state_var
                    )
                    if target_state is not None:
                        break

            if target_state is None:
                continue

            # Terminal states (no handler) should exit the state machine
            if target_state not in self.state_machine.handlers:
                sm_blocks = self._collect_state_machine_blocks()
                first_ck = min(check_blocks) if check_blocks else None
                exit_tgt = (
                    self._find_terminal_exit_target(first_ck, sm_blocks)
                    if first_ck is not None
                    else None
                )
                if exit_tgt is not None:
                    dispatcher_blk = self.mba.get_mblock(dispatcher_target)
                    exit_blk = self.mba.get_mblock(exit_tgt)
                    if dispatcher_blk is not None and exit_blk is not None:
                        update_blk_successor(pred_blk, dispatcher_blk, exit_blk)
                        unflat_logger.info(
                            "Assignment-map resolver: terminal state 0x%x "
                            "blk[%d] -> exit blk[%d]",
                            target_state,
                            pred_serial,
                            exit_tgt,
                        )
                        resolved += 1
                continue

            # Find the handler entry for the target state, starting resolution
            # from the check block that this predecessor actually targets.
            handler_entry = self._resolve_conditional_chain_target(
                dispatcher_target, target_state
            )
            if handler_entry is None:
                continue

            # Direct CFG surgery: redirect predecessor from the check block it
            # currently targets (dispatcher_target) to the resolved handler entry.
            update_blk_successor(pred_blk, dispatcher_target, handler_entry)

            unflat_logger.info(
                "Assignment-map resolver: block %d (state 0x%x) -> handler block %d"
                " (via check block %d)",
                pred_serial,
                target_state,
                handler_entry,
                dispatcher_target,
            )
            resolved += 1

        return resolved

    def _resolve_and_patch(self) -> int:
        """
        Resolve state transitions and patch the CFG.

        For each state check block, if we can determine what state the predecessor
        always has, we can bypass the check and go directly to the appropriate handler.

        Patching strategy (same as FixPredecessorOfConditionalJumpBlock):
        1. Duplicate the check block
        2. Make the duplicate unconditionally go to the determined target
        3. Redirect the predecessor to go to the duplicate instead

        This preserves the original check block for other predecessors that may still
        need it.
        """
        if self.state_machine is None:
            return 0

        nb_changes = 0
        state_var = self.state_machine.state_var

        if state_var is None:
            return 0

        # Collect all patches to apply (to avoid modifying while iterating)
        patches_fall_through = []  # (pred_blk, check_blk, fall_through_serial)
        patches_jump_taken = []  # (pred_blk, check_blk, jump_target_serial)
        # Track conditional predecessors already queued to avoid duplicate patches
        conditional_preds_patched: set[int] = set()

        # For each state check block
        for state_val, handler in self.state_machine.handlers.items():
            check_blk = self.mba.get_mblock(handler.check_block)

            unflat_logger.debug(
                "Analyzing state check block %d for state %s",
                handler.check_block,
                hex(state_val),
            )

            # For each predecessor of the check block
            pred_list = list(check_blk.predset)
            for pred_serial in pred_list:
                pred_blk = self.mba.get_mblock(pred_serial)

                # Use backward tracking to determine what state value the predecessor has
                tracker = MopTracker(
                    [state_var],
                    max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK,
                    max_path=self.MOP_TRACKER_MAX_NB_PATH,
                )
                tracker.reset()

                histories = tracker.search_backward(pred_blk, pred_blk.tail)
                values = get_all_possibles_values(histories, [state_var])
                flat_values = [v[0] for v in values if v[0] is not None]

                if not flat_values:
                    unflat_logger.debug(
                        "  Pred %d: could not determine state value", pred_serial
                    )
                    continue

                unique_values = set(flat_values)
                if len(unique_values) > 1:
                    unflat_logger.debug(
                        "  Pred %d: multiple possible state values: %s",
                        pred_serial,
                        [hex(v) for v in unique_values],
                    )
                    if (
                        len(unique_values) == 2
                        and pred_serial not in conditional_preds_patched
                    ):
                        # Attempt conditional transition resolution:
                        # The predecessor is a 2-way block where each path sets a
                        # different state value.  Walk the check-block chain for each
                        # value and, if both resolve to a valid handler block, redirect
                        # the two successor edges of pred_blk individually.
                        val_list = list(unique_values)
                        handler_targets = [
                            self._resolve_conditional_chain_target(
                                handler.check_block, v
                            )
                            for v in val_list
                        ]

                        if None not in handler_targets and pred_blk.nsucc() == 2:
                            check_opcode = (
                                check_blk.tail.opcode if check_blk.tail else None
                            )
                            if (
                                check_blk.tail is not None
                                and check_opcode in HODUR_STATE_CHECK_OPCODES
                            ):
                                # Determine which resolved handler corresponds to the
                                # jump-taken vs fall-through edge of pred_blk by using
                                # the check block's comparison against state_val.
                                all_resolved = True
                                for idx, v in enumerate(val_list):
                                    jt_for_v = HodurStateMachineDetector._is_jump_taken_for_state(
                                        check_opcode,
                                        int(v),
                                        int(state_val),
                                        check_blk.tail.r.size,
                                    )
                                    if jt_for_v is None:
                                        all_resolved = False
                                        break
                                    h_tgt = handler_targets[idx]
                                    if jt_for_v:
                                        patches_jump_taken.append(
                                            (pred_blk, check_blk, h_tgt)
                                        )
                                    else:
                                        patches_fall_through.append(
                                            (pred_blk, check_blk, h_tgt)
                                        )
                                if all_resolved:
                                    unflat_logger.debug(
                                        "Conditional fork at pred %d: values %s -> handlers %s",
                                        pred_serial,
                                        [hex(v) for v in val_list],
                                        [hex(h) for h in handler_targets],
                                    )
                                    conditional_preds_patched.add(pred_serial)
                    continue

                pred_state = flat_values[0]
                unflat_logger.debug(
                    "  Pred %d: state value is %s", pred_serial, hex(pred_state)
                )

                check_opcode = check_blk.tail.opcode if check_blk.tail else None
                if (
                    check_blk.tail is None
                    or check_opcode not in HODUR_STATE_CHECK_OPCODES
                ):
                    continue

                jump_target, fall_through = (
                    HodurStateMachineDetector._get_jump_and_fallthrough_targets(
                        check_blk
                    )
                )
                if jump_target is None or fall_through is None:
                    continue

                jump_taken = HodurStateMachineDetector._is_jump_taken_for_state(
                    check_opcode,
                    int(pred_state),
                    int(state_val),
                    check_blk.tail.r.size,
                )
                if jump_taken is None:
                    continue

                if jump_taken:
                    unflat_logger.info(
                        "Patching pred %d -> skip check %d -> jump target %d",
                        pred_serial,
                        handler.check_block,
                        jump_target,
                    )
                    patches_jump_taken.append((pred_blk, check_blk, jump_target))
                else:
                    unflat_logger.info(
                        "Patching pred %d -> skip check %d -> fall through %d",
                        pred_serial,
                        handler.check_block,
                        fall_through,
                    )
                    patches_fall_through.append((pred_blk, check_blk, fall_through))

        # Apply patches: jump never taken (fall through)
        for pred_blk, check_blk, fall_through in patches_fall_through:
            try:
                new_jmp_block, new_default_block = duplicate_block(
                    check_blk, verify=False
                )
                make_2way_block_goto(new_jmp_block, fall_through, verify=False)
                update_blk_successor(
                    pred_blk, check_blk.serial, new_jmp_block.serial, verify=False
                )
                nb_changes += 1
                unflat_logger.debug(
                    "Applied fall-through patch: pred %d -> new block %d -> %d",
                    pred_blk.serial,
                    new_jmp_block.serial,
                    fall_through,
                )
            except Exception as e:
                unflat_logger.warning(
                    "Failed to apply fall-through patch for pred %d: %s",
                    pred_blk.serial,
                    e,
                )

        # Apply patches: jump always taken
        for pred_blk, check_blk, jump_target in patches_jump_taken:
            try:
                new_jmp_block, new_default_block = duplicate_block(
                    check_blk, verify=False
                )
                make_2way_block_goto(new_jmp_block, jump_target, verify=False)
                update_blk_successor(
                    pred_blk, check_blk.serial, new_jmp_block.serial, verify=False
                )
                nb_changes += 1
                unflat_logger.debug(
                    "Applied jump-taken patch: pred %d -> new block %d -> %d",
                    pred_blk.serial,
                    new_jmp_block.serial,
                    jump_target,
                )
            except Exception as e:
                unflat_logger.warning(
                    "Failed to apply jump-taken patch for pred %d: %s",
                    pred_blk.serial,
                    e,
                )

        return nb_changes
