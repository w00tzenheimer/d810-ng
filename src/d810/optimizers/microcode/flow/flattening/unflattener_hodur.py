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
from typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger
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

# Hodur uses large 32-bit constants as state values
MIN_STATE_CONSTANT = 0x10000
# Minimum number of unique state constants to consider it a state machine
MIN_STATE_CONSTANTS = 3
# Maximum number of state constants - if more, it's likely OLLVM FLA not Hodur
# Hodur typically has ~10-20 states, OLLVM FLA can have 50+
MAX_STATE_CONSTANTS_HODUR = 30


@dataclass
class StateTransition:
    """Represents a state transition in the Hodur state machine."""
    from_state: int
    to_state: int
    from_block: int  # Block serial where transition originates
    condition_block: int | None = None  # Block serial with state check (if conditional)
    is_conditional: bool = False  # True if this is a conditional transition


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
        state_assignments = self._find_state_assignments(state_constants)

        # Step 4.5: Check for bitwise state modifications (OR-based patterns)
        # If state is modified via OR/XOR/AND, this is not a pure Hodur state machine
        # because state depends on input, not just control flow
        if self._has_bitwise_state_modifications(state_var):
            unflat_logger.info(
                "Found bitwise state modifications (OR/XOR/AND) on state var - "
                "skipping OR-based state machine pattern"
            )
            return None

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
        """Find blocks with jnz/jz comparisons against large constants."""
        state_blocks = []
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.tail and blk.tail.opcode in [ida_hexrays.m_jnz, ida_hexrays.m_jz]:
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
            # The state variable is the left operand of jnz/jz
            return ida_hexrays.mop_t(first_blk.tail.l)
        return None

    def _find_state_assignments(
        self, state_constants: set[int]
    ) -> list[tuple[int, int]]:
        """Find mov instructions that assign state constants."""
        assignments = []
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            insn = blk.head
            while insn:
                if insn.opcode == ida_hexrays.m_mov:
                    if insn.l.t == ida_hexrays.mop_n:
                        const_val = insn.l.nnn.value
                        if const_val in state_constants:
                            assignments.append((blk.serial, const_val))
                insn = insn.next
        return assignments

    def _has_bitwise_state_modifications(
        self, state_var: ida_hexrays.mop_t
    ) -> bool:
        """Check if state variable is modified via bitwise operations.

        Returns True if any m_or, m_xor, or m_and instruction writes to
        the state variable. This indicates an OR-based state machine pattern
        where state depends on input, not suitable for Hodur unflattening.

        In OR-based patterns like ABC (state = state | input), the final state
        depends on the input value, not just control flow. HodurUnflattener
        assumes pure state assignments (state = CONST) and will produce
        incorrect results for bitwise state patterns.
        """
        if state_var is None:
            return False

        BITWISE_OPCODES = [ida_hexrays.m_or, ida_hexrays.m_xor, ida_hexrays.m_and]

        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            insn = blk.head
            while insn:
                if insn.opcode in BITWISE_OPCODES:
                    # Check if destination is the state variable
                    if insn.d and insn.d.equal_mops(state_var, ida_hexrays.EQ_IGNSIZE):
                        unflat_logger.debug(
                            "Block %d: bitwise op %d modifies state var - "
                            "detected OR-based pattern",
                            blk.serial, insn.opcode
                        )
                        return True
                insn = insn.next
        return False

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
        state_assignments: list[tuple[int, int]],
        state_check_blocks: list[tuple[int, int, int]],
    ) -> None:
        """Build state transitions based on assignments and checks."""
        if self.state_machine is None:
            return

        # Create a map: block_serial -> state_constant for assignments
        assignment_map = {}
        for blk_serial, const in state_assignments:
            if blk_serial not in assignment_map:
                assignment_map[blk_serial] = []
            assignment_map[blk_serial].append(const)

        # Create a map: state_constant -> check_block
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
                succ_blk = self.mba.get_mblock(succ_serial)
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
                    for next_state in assignment_map[curr_serial]:
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
        self._queue_transitions_direct()

        # Queue predecessor-based patches for any remaining cases
        self._queue_predecessor_patches()

        # Also queue removal of state assignment instructions
        self._queue_state_assignment_removals()

        # Apply all queued modifications at once
        nb_changes = 0
        if self.deferred.has_modifications():
            unflat_logger.info(
                "Applying %d queued modifications",
                len(self.deferred.modifications)
            )
            nb_changes = self.deferred.apply(
                run_optimize_local=True,
                run_deep_cleaning=False,
            )

        self.last_pass_nb_patch_done = nb_changes
        unflat_logger.info(
            "HodurUnflattener: Pass %d made %d changes",
            self.cur_maturity_pass,
            nb_changes,
        )

        return nb_changes

    def _queue_transitions_direct(self) -> None:
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
            return

        for transition in self.state_machine.transitions:
            from_blk = self.mba.get_mblock(transition.from_block)
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

            # Check if from_blk ends with a goto to the dispatcher
            if from_blk.tail is None:
                continue

            if from_blk.tail.opcode != ida_hexrays.m_goto:
                # Not a simple goto - might be a conditional, skip for now
                unflat_logger.debug(
                    "Block %d doesn't end with goto, skipping", transition.from_block
                )
                continue

            # Get current destination
            if from_blk.tail.l.t != ida_hexrays.mop_b:
                continue

            current_dest = from_blk.tail.l.b

            # Only patch if going to the first check block (dispatcher entry)
            first_check = list(self.state_machine.handlers.values())[0].check_block
            if current_dest != first_check:
                unflat_logger.debug(
                    "Block %d goes to %d, not dispatcher %d, skipping",
                    transition.from_block, current_dest, first_check
                )
                continue

            # Queue: change goto destination to target handler block
            unflat_logger.info(
                "Queueing block %d: goto %d -> goto %d (transition %s -> %s)",
                transition.from_block, current_dest, target_block,
                hex(transition.from_state), hex(transition.to_state)
            )

            self.deferred.queue_goto_change(
                block_serial=transition.from_block,
                new_target=target_block,
                description=f"transition {hex(transition.from_state)} -> {hex(transition.to_state)}",
                rule_priority=50,  # Medium priority - path-based analysis
            )

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

        first_check_blk = self.mba.get_mblock(first_check_block)
        if first_check_blk is None:
            return

        # Find the "success" target from the first check block
        # For jnz state, INIT_STATE, @success_path:
        #   - If state == INIT_STATE: fall through (continue loop)
        #   - If state != INIT_STATE: jump to success_path
        success_target = None
        if first_check_blk.tail and first_check_blk.tail.opcode == ida_hexrays.m_jnz:
            if first_check_blk.tail.d.t == ida_hexrays.mop_b:
                success_target = first_check_blk.tail.d.b
                unflat_logger.debug(
                    "First check block %d: success path is block %d",
                    first_check_block, success_target
                )

        if success_target is None:
            unflat_logger.debug("Could not determine success path from first check block")
            return

        # Find blocks that have a back-edge to first_check_block
        for blk_serial in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_serial)

            # Check if this block goes back to the first check block
            if first_check_block not in blk.succset:
                continue

            # This block has an edge to the first check block
            # Check if it's a back-edge (blk_serial > first_check_block)
            if blk_serial <= first_check_block:
                continue

            # Found a back-edge! Check if it ends with a goto
            if blk.tail and blk.tail.opcode == ida_hexrays.m_goto:
                if blk.tail.l.t == ida_hexrays.mop_b and blk.tail.l.b == first_check_block:
                    unflat_logger.info(
                        "Found terminal back-edge: block %d -> block %d, redirecting to success path %d",
                        blk_serial, first_check_block, success_target
                    )
                    # Redirect this back-edge to the success path
                    self.deferred.queue_goto_change(
                        block_serial=blk_serial,
                        new_target=success_target,
                        description=f"terminal back-edge -> success path",
                        rule_priority=50,  # Medium priority - path-based analysis
                    )

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

                # Determine if the check will match or not
                # For jnz: jump if state != STATE_N, fall through if state == STATE_N
                check_opcode = check_blk.tail.opcode if check_blk.tail else None

                if check_opcode == ida_hexrays.m_jnz:
                    # jnz state, STATE_N, target
                    # If pred_state == STATE_N: fall through (state matches, execute handler)
                    # If pred_state != STATE_N: take jump (state doesn't match, skip handler)
                    if pred_state == state_val:
                        # State matches - should fall through
                        # Find the fall-through target (not the jump target)
                        fall_through = handler.check_block + 1  # Default: next block
                        if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                            jump_target = check_blk.tail.d.b
                            for succ in check_blk.succset:
                                if succ != jump_target:
                                    fall_through = succ
                                    break

                        unflat_logger.info(
                            "Patching pred %d -> skip check %d -> handler %d (state match)",
                            pred_serial, handler.check_block, fall_through
                        )
                        patches_fall_through.append((pred_blk, check_blk, fall_through))
                    else:
                        # State doesn't match - should take jump
                        if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                            jump_target = check_blk.tail.d.b
                            unflat_logger.info(
                                "Patching pred %d -> skip check %d -> break target %d (state mismatch)",
                                pred_serial, handler.check_block, jump_target
                            )
                            patches_jump_taken.append((pred_blk, check_blk, jump_target))

                elif check_opcode == ida_hexrays.m_jz:
                    # jz state, STATE_N, target
                    # If pred_state == STATE_N: take jump
                    # If pred_state != STATE_N: fall through
                    if pred_state == state_val:
                        # State matches - should take jump
                        if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                            jump_target = check_blk.tail.d.b
                            unflat_logger.info(
                                "Patching pred %d -> skip check %d -> jump target %d (jz state match)",
                                pred_serial, handler.check_block, jump_target
                            )
                            patches_jump_taken.append((pred_blk, check_blk, jump_target))
                    else:
                        # State doesn't match - should fall through
                        fall_through = handler.check_block + 1
                        if check_blk.tail and check_blk.tail.d.t == ida_hexrays.mop_b:
                            jump_target = check_blk.tail.d.b
                            for succ in check_blk.succset:
                                if succ != jump_target:
                                    fall_through = succ
                                    break

                        unflat_logger.info(
                            "Patching pred %d -> skip check %d -> fall through %d (jz state mismatch)",
                            pred_serial, handler.check_block, fall_through
                        )
                        patches_fall_through.append((pred_blk, check_blk, fall_through))

        # Apply patches: jump never taken (fall through)
        for pred_blk, check_blk, fall_through in patches_fall_through:
            try:
                new_jmp_block, new_default_block = duplicate_block(check_blk)
                make_2way_block_goto(new_jmp_block, fall_through)
                update_blk_successor(pred_blk, check_blk.serial, new_jmp_block.serial)
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
                new_jmp_block, new_default_block = duplicate_block(check_blk)
                make_2way_block_goto(new_jmp_block, jump_target)
                update_blk_successor(pred_blk, check_blk.serial, new_jmp_block.serial)
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
