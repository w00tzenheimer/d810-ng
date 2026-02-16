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

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core.bits import unsigned_to_signed
from d810.core import getLogger
from d810.expr.ast import minsn_to_ast
from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.hexrays.cfg_utils import (
    change_1way_block_successor,
    duplicate_block,
    make_2way_block_goto,
    safe_verify,
    update_blk_successor,
)
from d810.hexrays.deferred_modifier import DeferredGraphModifier
from d810.hexrays.hexrays_formatters import format_minsn_t, format_mop_t
from d810.hexrays.hexrays_helpers import extract_num_mop
from d810.hexrays.tracker import MopTracker
from d810.optimizers.microcode.flow.flattening.dispatcher_detection import (
    DispatcherCache,
    DispatcherStrategy,
)
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.flow.flattening.utils import get_all_possibles_values

if TYPE_CHECKING:
    pass

unflat_logger = getLogger("D810.unflat.hodur")

# State values must exceed this threshold to be considered dispatcher constants.
# Real obfuscators use values from 0x1000+ (hardened OLLVM) to 0xDEAD0000+ (Hodur).
MIN_STATE_CONSTANT = 0x100
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
class StateTransition:
    """Represents a state transition in the Hodur state machine."""
    from_state: int
    to_state: int
    from_block: int  # Block serial where transition originates
    condition_block: int | None = None  # Block serial with state check (if conditional)
    is_conditional: bool = False  # True if this is a conditional transition


@dataclass
class StateUpdateSite:
    """Represents an instruction that writes the dispatcher state variable."""
    block_serial: int
    instruction: ida_hexrays.minsn_t


@dataclass
class StateHandler:
    """Represents a handler for a specific state value."""
    state_value: int
    check_block: int  # Block with jnz state, CONSTANT
    handler_blocks: list[int] = field(default_factory=list)  # Blocks executed when state matches
    transitions: list[StateTransition] = field(default_factory=list)


@dataclass
class HodurStateMachine:
    """Represents the complete Hodur state machine structure."""
    mba: ida_hexrays.mba_t
    state_var: ida_hexrays.mop_t | None = None
    initial_state: int | None = None
    state_constants: set[int] = field(default_factory=set)
    handlers: dict[int, StateHandler] = field(default_factory=dict)  # state_value -> handler
    transitions: list[StateTransition] = field(default_factory=list)

    def add_state_constant(self, const: int) -> None:
        self.state_constants.add(const)

    def add_handler(self, handler: StateHandler) -> None:
        self.handlers[handler.state_value] = handler

    def add_transition(self, transition: StateTransition) -> None:
        self.transitions.append(transition)
        if transition.from_state in self.handlers:
            self.handlers[transition.from_state].transitions.append(transition)


class HodurStateMachineDetector:
    """Detects Hodur-style while-loop state machines in microcode."""

    def __init__(self, mba: ida_hexrays.mba_t, use_cache: bool = True):
        self.mba = mba
        self.state_machine: HodurStateMachine | None = None
        self.use_cache = use_cache
        self._cache: DispatcherCache | None = None

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
                # Fall back to manual detection anyway
                pass
            else:
                unflat_logger.debug(
                    "Dispatcher cache confirms Hodur-style: %d state constants, initial=%s",
                    len(analysis.state_constants),
                    hex(analysis.initial_state) if analysis.initial_state else "unknown",
                )

        # Step 1: Find all state comparison blocks (jnz with large constants)
        state_check_blocks = self._find_state_check_blocks()
        if len(state_check_blocks) < MIN_STATE_CONSTANTS:
            unflat_logger.debug(
                "Not enough state check blocks found: %d < %d",
                len(state_check_blocks), MIN_STATE_CONSTANTS
            )
            return None

        # Step 1.5: Check if this looks more like OLLVM FLA than Hodur
        # OLLVM FLA typically has many more state constants (50+)
        # Hodur typically has ~10-20 states
        if len(state_check_blocks) > MAX_STATE_CONSTANTS_HODUR:
            unflat_logger.info(
                "Too many state check blocks (%d > %d) - likely OLLVM FLA, not Hodur",
                len(state_check_blocks), MAX_STATE_CONSTANTS_HODUR
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
            hex(initial_state) if initial_state else "unknown"
        )

        return self.state_machine

    def _find_state_check_blocks(self) -> list[tuple[int, int, int]]:
        """Find blocks with conditional comparisons against large constants."""
        state_blocks = []
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.tail and blk.tail.opcode in HODUR_STATE_CHECK_OPCODES:
                if blk.tail.r.t == ida_hexrays.mop_n:
                    const_val = blk.tail.r.nnn.value
                    if const_val > MIN_STATE_CONSTANT:
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
            # The state variable is the left operand of the conditional jump.
            return ida_hexrays.mop_t(first_blk.tail.l)
        return None

    @staticmethod
    def _is_jump_taken_for_state(
        opcode: int,
        left_value: int,
        right_value: int,
        right_value_size: int,
    ) -> bool | None:
        """Evaluate whether a conditional jump is taken for a known state value."""
        if opcode == ida_hexrays.m_jnz:
            return left_value != right_value
        if opcode == ida_hexrays.m_jz:
            return left_value == right_value
        if opcode == ida_hexrays.m_jae:
            return left_value >= right_value
        if opcode == ida_hexrays.m_jb:
            return left_value < right_value
        if opcode == ida_hexrays.m_ja:
            return left_value > right_value
        if opcode == ida_hexrays.m_jbe:
            return left_value <= right_value
        if opcode == ida_hexrays.m_jg:
            return unsigned_to_signed(left_value, right_value_size) > unsigned_to_signed(
                right_value, right_value_size
            )
        if opcode == ida_hexrays.m_jge:
            return unsigned_to_signed(left_value, right_value_size) >= unsigned_to_signed(
                right_value, right_value_size
            )
        if opcode == ida_hexrays.m_jl:
            return unsigned_to_signed(left_value, right_value_size) < unsigned_to_signed(
                right_value, right_value_size
            )
        if opcode == ida_hexrays.m_jle:
            return unsigned_to_signed(left_value, right_value_size) <= unsigned_to_signed(
                right_value, right_value_size
            )
        return None

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
        """Compare state mops with structural and semantic fallback."""
        if candidate is None:
            return False

        try:
            if candidate.equal_mops(state_var, ida_hexrays.EQ_IGNSIZE):
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
        while cur is not None:
            ok = interpreter.eval_instruction(
                blk,
                cur,
                environment=env,
                raise_exception=False,
            )
            if cur is insn:
                if not ok:
                    return None
                value = env.lookup(state_var, raise_exception=False)
                if value is not None:
                    return int(value)
                value = interpreter.eval_mop(insn.d, environment=env, raise_exception=False)
                return int(value) if value is not None else None
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

        # Create a map: state_constant -> check_block serial
        check_map = {const: blk_serial for blk_serial, _, const in state_check_blocks}

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
            for succ_serial in check_blk.succset:
                # Skip the jump target (that's the "break" path)
                if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                    if succ_serial == check_blk.tail.d.b:
                        continue
                to_visit.append(succ_serial)

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
                        transition = StateTransition(
                            from_state=state_val,
                            to_state=next_state,
                            from_block=curr_serial,
                        )
                        self.state_machine.add_transition(transition)

                # Continue BFS but stop at state check blocks
                curr_blk = self.mba.get_mblock(curr_serial)
                for succ_serial in curr_blk.succset:
                    if succ_serial not in visited and succ_serial not in check_map.values():
                        to_visit.append(succ_serial)


class HodurUnflattener(GenericUnflatteningRule):
    """
    Unflattener for Hodur-style while-loop state machines.

    This rule detects and removes control flow flattening that uses nested while(1)
    loops with a state variable, as seen in Hodur malware.
    """

    DESCRIPTION = "Remove Hodur-style while-loop control flow flattening"
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]
    DEFAULT_MAX_PASSES = 10
    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100

    def __init__(self):
        super().__init__()
        self.state_machine: HodurStateMachine | None = None
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.deferred: DeferredGraphModifier | None = None

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        """Check if this rule should be applied."""
        if not super().check_if_rule_should_be_used(blk):
            return False

        # Only run once per maturity level (on first block we see)
        # Note: blk.serial != 0 doesn't work because IDA starts from block 1
        # We use cur_maturity_pass which is reset to 0 when maturity changes
        if self.cur_maturity_pass > 0:
            return False

        # Check pass limits (for future multi-pass support)
        if self.cur_maturity_pass >= self.max_passes:
            return False

        return True

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Main optimization entry point."""
        self.mba = blk.mba

        if not self.check_if_rule_should_be_used(blk):
            return 0

        unflat_logger.info(
            "HodurUnflattener: Starting pass %d at maturity %d",
            self.cur_maturity_pass,
            self.cur_maturity,
        )

        # Detect state machine
        detector = HodurStateMachineDetector(self.mba)
        self.state_machine = detector.detect()

        if self.state_machine is None:
            unflat_logger.info("No Hodur state machine detected")
            return 0

        # Log the detected structure
        self._log_state_machine()

        # Initialize deferred modifier - queue all changes first, apply later
        self.deferred = DeferredGraphModifier(self.mba)

        # Queue direct transition patches (more effective for Hodur-style)
        direct_transition_patches = self._queue_transitions_direct()

        # Queue predecessor-based patches for any remaining cases
        self._queue_predecessor_patches()

        # Also queue removal of state assignment instructions
        self._queue_state_assignment_removals()

        # Apply all queued modifications at once
        nb_changes = 0

        if self.deferred.has_modifications():
            from d810.optimizers.microcode.flow.flattening.safeguards import should_apply_cfg_modifications
            num_redirected = len(self.deferred.modifications)
            total_handlers = len(self.state_machine.handlers)
            if not should_apply_cfg_modifications(num_redirected, total_handlers, "hodur"):
                pass  # skip apply
            else:
                unflat_logger.info(
                    "Applying %d queued modifications",
                    len(self.deferred.modifications)
                )
                nb_changes += self.deferred.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )

        # Fallback path: some Hodur variants do not terminate transition blocks
        # with m_goto, so direct queueing won't patch anything. Use the legacy
        # predecessor/path-based strategy as backup in that case.
        if direct_transition_patches == 0:
            unflat_logger.info(
                "No direct transition patches queued; falling back to path-based "
                "Hodur patching"
            )
            nb_changes += self._resolve_and_patch()

        # Final cleanup for residual infinite-loop artifacts.
        # Keep it limited to extended comparison dispatchers; legacy jnz/jz
        # Hodur shapes are handled by direct back-edge rewrites.
        if self._uses_extended_dispatch_ops():
            nb_changes += self._fix_degenerate_terminal_loops()

        self.last_pass_nb_patch_done = nb_changes
        unflat_logger.info(
            "HodurUnflattener: Pass %d made %d changes",
            self.cur_maturity_pass,
            nb_changes,
        )

        return nb_changes

    def _queue_transitions_direct(self) -> int:
        """
        Queue direct transition patches: bypass dispatcher and state checks.

        For each transition (from_state -> to_state):
        - The from_block (where state is assigned) currently goes to the dispatcher
        - Queue a change to go directly to to_state's first handler block

        This is more effective than predecessor-based patching which tries to resolve
        state values at check block predecessors, but fails when the predecessor
        is the dispatcher itself (which can have any state value).
        """
        if self.state_machine is None or self.deferred is None:
            return 0

        queued_patches = 0
        handlers = list(self.state_machine.handlers.values())
        if not handlers:
            return 0

        check_blocks = {handler.check_block for handler in handlers}
        initial_state = (
            int(self.state_machine.initial_state)
            if self.state_machine.initial_state is not None
            else None
        )
        defer_loopback_to_terminal_fix = self._uses_extended_dispatch_ops()

        for transition in self.state_machine.transitions:
            from_blk = self.mba.get_mblock(transition.from_block)
            if from_blk is None:
                continue

            # Handle loopback-to-initial transitions in terminal cleanup where we
            # can map them to an exit target, avoiding conflicting queued rewrites.
            if (
                defer_loopback_to_terminal_fix
                and
                initial_state is not None
                and transition.to_state == initial_state
                and transition.from_state != initial_state
            ):
                continue

            to_handler = self.state_machine.handlers.get(transition.to_state)

            if to_handler is None:
                unflat_logger.debug(
                    "No handler found for to_state %s", hex(transition.to_state)
                )
                continue

            # Get the target: first handler block (skip the check block)
            if not to_handler.handler_blocks:
                unflat_logger.debug(
                    "No handler blocks for state %s", hex(transition.to_state)
                )
                continue

            target_block = to_handler.handler_blocks[0]
            if from_blk.nsucc() == 1:
                succs = [s for s in from_blk.succset]
                if not succs:
                    continue
                current_dest = succs[0]
                if current_dest not in check_blocks:
                    unflat_logger.debug(
                        "Block %d goes to %d, not a dispatcher check block; skipping",
                        transition.from_block,
                        current_dest,
                    )
                    continue

                if self._queue_transition_redirect(
                    from_blk,
                    target_block,
                    f"transition {hex(transition.from_state)} -> {hex(transition.to_state)}",
                ):
                    queued_patches += 1
                continue

            if from_blk.nsucc() == 2 and any(s in check_blocks for s in from_blk.succset):
                if self._queue_transition_redirect(
                    from_blk,
                    target_block,
                    f"transition-cond {hex(transition.from_state)} -> {hex(transition.to_state)}",
                ):
                    queued_patches += 1

        return queued_patches

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
            return True

        if from_blk.nsucc() == 2:
            self.deferred.queue_convert_to_goto(
                block_serial=from_blk.serial,
                goto_target=target_block,
                description=description,
            )
            return True

        return False

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
        return (
            check_opcode in HODUR_STATE_CHECK_OPCODES
            and check_opcode not in (ida_hexrays.m_jnz, ida_hexrays.m_jz)
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
            if transition.to_state == initial_state and transition.from_state != initial_state
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
                    or not insn.d.equal_mops(state_var, ida_hexrays.EQ_IGNSIZE)
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
            if blk.tail.opcode == ida_hexrays.m_ret and (blk.npred() > 0 or self._can_reach_return(blk.serial)):
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
        # For now, call the existing _resolve_and_patch logic
        # The key benefit is that _queue_transitions_direct runs first
        # and queues the main transition patches before this runs
        pass  # Predecessor patching is optional and handled by direct patching

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

            # NOTE: We skip NOPing state assignments for now because:
            # 1. insn.ea is not unique - multiple instructions can share the same EA
            # 2. NOPing by EA can accidentally remove unrelated instructions
            # 3. The state assignments become dead code anyway after unflattening
            # 4. IDA's optimizer will clean them up during subsequent passes
            #
            # The terminal back-edge fix is more important and safer.
            # TODO: Implement proper instruction identity tracking for safe NOPing
            pass

        # Find terminal back-edge: a block that goes back to first_check_block
        # after all transitions have been patched
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
        check_blocks = {handler.check_block for handler in self.state_machine.handlers.values()}
        processed_blocks = set()

        # Primary strategy: rewrite transitions that loop back to INITIAL_STATE.
        loopback_transitions = [
            transition
            for transition in self.state_machine.transitions
            if transition.to_state == initial_state and transition.from_state != initial_state
        ]
        candidate_blocks = [transition.from_block for transition in loopback_transitions]

        # Fallback: no explicit loopback transition found, use structural back-edges
        # to the dispatcher entry among lightweight state-machine blocks.
        if not candidate_blocks:
            for blk_serial in state_machine_blocks:
                blk = self.mba.get_mblock(blk_serial)
                if blk is None:
                    continue
                if first_check_block in blk.succset and self._is_lightweight_terminal_transition_block(blk):
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

        success_target = None
        if first_check_blk.tail.opcode == ida_hexrays.m_jnz and first_check_blk.tail.d.t == ida_hexrays.mop_b:
            success_target = first_check_blk.tail.d.b
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
        exit_target = self._find_terminal_exit_target(first_check_block, state_machine_blocks)
        if exit_target is None:
            return 0

        candidate_blocks = self._collect_nearby_blocks(state_machine_blocks, depth=4)

        nb_fixed = 0
        for blk_serial in sorted(candidate_blocks):
            blk = self.mba.get_mblock(blk_serial)
            if blk is None:
                continue
            if blk.nsucc() != 1 or not self._is_degenerate_loop_block(blk):
                continue

            succ = next(iter(blk.succset))
            if succ == blk.serial and blk.serial != exit_target:
                if change_1way_block_successor(blk, exit_target, verify=False):
                    nb_fixed += 1
                    unflat_logger.info(
                        "Redirected terminal self-loop block %d -> %d",
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
            if succ2 == blk.serial and blk.serial != exit_target and succ != exit_target:
                if change_1way_block_successor(blk, exit_target, verify=False):
                    nb_fixed += 1
                    unflat_logger.info(
                        "Redirected terminal 2-block loop %d<->%d via %d",
                        blk.serial,
                        succ,
                        exit_target,
                    )

        if nb_fixed > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)

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
                return current
            visited.add(current)

            blk = self.mba.get_mblock(current)
            if blk.tail is None or blk.tail.opcode not in HODUR_STATE_CHECK_OPCODES:
                return current
            if blk.tail.r.t != ida_hexrays.mop_n:
                return current

            jump_target, fallthrough = HodurStateMachineDetector._get_jump_and_fallthrough_targets(
                blk
            )
            if jump_target is None or fallthrough is None:
                return None

            jump_taken = HodurStateMachineDetector._is_jump_taken_for_state(
                blk.tail.opcode,
                int(state_value),
                int(blk.tail.r.nnn.value),
                blk.tail.r.size,
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
            format_mop_t(self.state_machine.state_var) if self.state_machine.state_var else "unknown"
        )
        unflat_logger.info(
            "Initial state: %s",
            hex(self.state_machine.initial_state) if self.state_machine.initial_state else "unknown"
        )
        unflat_logger.info(
            "State constants: %s",
            ", ".join(hex(c) for c in sorted(self.state_machine.state_constants))
        )
        unflat_logger.info("Transitions:")
        for t in self.state_machine.transitions:
            unflat_logger.info(
                "  %s -> %s (block %d)",
                hex(t.from_state), hex(t.to_state), t.from_block
            )

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

        # For each state check block
        for state_val, handler in self.state_machine.handlers.items():
            check_blk = self.mba.get_mblock(handler.check_block)

            unflat_logger.debug(
                "Analyzing state check block %d for state %s",
                handler.check_block, hex(state_val)
            )

            # For each predecessor of the check block
            pred_list = [p for p in check_blk.predset]
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
                        "  Pred %d: could not determine state value",
                        pred_serial
                    )
                    continue

                unique_values = set(flat_values)
                if len(unique_values) > 1:
                    unflat_logger.debug(
                        "  Pred %d: multiple possible state values: %s",
                        pred_serial,
                        [hex(v) for v in unique_values]
                    )
                    continue

                pred_state = flat_values[0]
                unflat_logger.debug(
                    "  Pred %d: state value is %s",
                    pred_serial, hex(pred_state)
                )

                check_opcode = check_blk.tail.opcode if check_blk.tail else None
                if check_blk.tail is None or check_opcode not in HODUR_STATE_CHECK_OPCODES:
                    continue

                jump_target, fall_through = HodurStateMachineDetector._get_jump_and_fallthrough_targets(
                    check_blk
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
                new_jmp_block, new_default_block = duplicate_block(check_blk, verify=False)
                make_2way_block_goto(new_jmp_block, fall_through, verify=False)
                update_blk_successor(pred_blk, check_blk.serial, new_jmp_block.serial, verify=False)
                nb_changes += 1
                unflat_logger.debug(
                    "Applied fall-through patch: pred %d -> new block %d -> %d",
                    pred_blk.serial, new_jmp_block.serial, fall_through
                )
            except Exception as e:
                unflat_logger.warning(
                    "Failed to apply fall-through patch for pred %d: %s",
                    pred_blk.serial, e
                )

        # Apply patches: jump always taken
        for pred_blk, check_blk, jump_target in patches_jump_taken:
            try:
                new_jmp_block, new_default_block = duplicate_block(check_blk, verify=False)
                make_2way_block_goto(new_jmp_block, jump_target, verify=False)
                update_blk_successor(pred_blk, check_blk.serial, new_jmp_block.serial, verify=False)
                nb_changes += 1
                unflat_logger.debug(
                    "Applied jump-taken patch: pred %d -> new block %d -> %d",
                    pred_blk.serial, new_jmp_block.serial, jump_target
                )
            except Exception as e:
                unflat_logger.warning(
                    "Failed to apply jump-taken patch for pred %d: %s",
                    pred_blk.serial, e
                )

        return nb_changes
