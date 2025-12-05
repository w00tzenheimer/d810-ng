"""
Generic unflattening base classes for control flow deobfuscation.

CFG MODIFICATION APPROACH
=========================
This module handles ABC (Arithmetic/Bitwise/Constant) patterns that use magic
numbers in the range 1010000-1011999 (0xF6950-0xF719F).

All CFG modifications now use deferred patterns:

1. `fix_fathers_from_mop_history()` -> ABCBlockSplitter
   - Analysis phase: collect all split operations without modifying CFG
   - Apply phase: perform all splits atomically after analysis

2. `resolve_dispatcher_father()` -> DeferredGraphModifier
   - Queues goto changes and block creation operations
   - Applied after all dispatcher fathers are resolved in `remove_flattening()`

Legacy code paths (`father_patcher_abc_create_blocks`, `father_history_patcher_abc`)
are retained for reference but no longer called from the main code path.

See: docs/cfg-modification-audit.md for details.
"""
from __future__ import annotations

import abc

import ida_hexrays

from d810.core import getLogger
from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.hexrays.cfg_utils import (
    change_1way_block_successor,
    create_block,
    ensure_child_has_an_unconditional_father,
    ensure_last_block_is_goto,
    mba_deep_cleaning,
    safe_verify,
)
from d810.hexrays.hexrays_formatters import (
    dump_microcode_for_debug,
    format_minsn_t,
    format_mop_list,
    format_mop_t,
)
from d810.hexrays.hexrays_helpers import (
    CONDITIONAL_JUMP_OPCODES,
    CONTROL_FLOW_OPCODES,
    append_mop_if_not_in_list,
    extract_num_mop,
    get_mop_index,
)
from d810.hexrays.tracker import (
    InstructionDefUseCollector,
    MopHistory,
    MopTracker,
    duplicate_histories,
    remove_segment_registers,
)
from d810.optimizers.microcode.flow.flattening.utils import (
    NotDuplicableFatherException,
    NotResolvableFatherException,
    check_if_all_values_are_found,
    get_all_possibles_values,
)
from d810.core.registry import EventEmitter
from d810.hexrays.deferred_modifier import DeferredGraphModifier, GraphModification
from d810.optimizers.microcode.flow.flattening.abc_block_splitter import (
    ABCBlockSplitter,
    ConditionalStateResolver,
)
from d810.optimizers.microcode.flow.flattening.loop_prover import (
    SingleIterationLoopTracker,
    prove_single_iteration,
)
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule


class UnflatteningEvent:
    """Event types for unflattening optimizer coordination.

    These events enable cross-maturity scheduling and future cross-optimizer
    coordination via the EventEmitter pattern.

    Flow
    ----
    ::

        MMAT_CALLS → optimize()
            ├── _apply_scheduled_modifications()  # Apply anything queued for MMAT_CALLS
            └── ... normal processing ...
                 └── schedule_for_maturity(MMAT_GLBOPT1, mod)  # Queue cleanup

        MMAT_GLBOPT1 → optimize()
            ├── _apply_scheduled_modifications()  # Applies the queued mod
            └── ... normal processing ...

    Example: Scheduling modifications for a future maturity
    -------------------------------------------------------
    ::

        from d810.hexrays.deferred_modifier import GraphModification, ModificationType

        # During MMAT_CALLS, schedule cleanup for GLBOPT1
        mod = GraphModification(
            mod_type=ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=42,
            new_target=50,
            description="cleanup residual edge"
        )
        self.schedule_for_maturity(ida_hexrays.MMAT_GLBOPT1, mod)

    Example: Hooking into events for cross-optimizer coordination
    -------------------------------------------------------------
    ::

        def my_handler(maturity, applied_count, optimizer):
            print(f"Applied {applied_count} mods at maturity {maturity}")

        self.events.on(UnflatteningEvent.MODIFICATIONS_APPLIED, my_handler)

    Event Payloads
    --------------
    MODIFICATIONS_SCHEDULED:
        target_maturity (int): Target maturity level
        modification (GraphModification): The queued modification
        optimizer: The optimizer instance

    MODIFICATIONS_APPLYING:
        maturity (int): Current maturity level
        modifications (list[GraphModification]): Modifications about to apply
        optimizer: The optimizer instance

    MODIFICATIONS_APPLIED:
        maturity (int): Current maturity level
        applied_count (int): Number of successfully applied modifications
        optimizer: The optimizer instance
    """
    # Emitted when modifications are scheduled for a future maturity
    MODIFICATIONS_SCHEDULED = "modifications_scheduled"
    # Emitted when scheduled modifications are about to be applied
    MODIFICATIONS_APPLYING = "modifications_applying"
    # Emitted after scheduled modifications have been applied
    MODIFICATIONS_APPLIED = "modifications_applied"
    # Emitted when a dispatcher is resolved
    DISPATCHER_RESOLVED = "dispatcher_resolved"

unflat_logger = getLogger("D810.unflat")


class GenericDispatcherBlockInfo(object):

    def __init__(self, blk, father=None):
        self.blk = blk
        self._serial: int = blk.serial  # Cache serial to avoid SWIG overhead
        self.ins = []
        self.use_list = []
        self.use_before_def_list = []
        self.def_list = []
        self.assume_def_list = []
        self.comparison_value = None
        self.compared_mop = None

        self.father = None
        if father is not None:
            self.register_father(father)

    @property
    def serial(self) -> int:
        return self._serial

    def register_father(self, father: GenericDispatcherBlockInfo):
        self.father = father
        self.assume_def_list = [x for x in father.assume_def_list]

    def update_use_def_lists(
        self, ins_mops_used: list[ida_hexrays.mop_t], ins_mops_def: list[ida_hexrays.mop_t]
    ):
        for mop_used in ins_mops_used:
            append_mop_if_not_in_list(mop_used, self.use_list)
            mop_used_index = get_mop_index(mop_used, self.def_list)
            if mop_used_index == -1:
                append_mop_if_not_in_list(mop_used, self.use_before_def_list)
        for mop_def in ins_mops_def:
            append_mop_if_not_in_list(mop_def, self.def_list)

    def update_with_ins(self, ins: ida_hexrays.minsn_t):
        ins_mop_info = InstructionDefUseCollector()
        ins.for_all_ops(ins_mop_info)
        cleaned_unresolved_ins_mops = remove_segment_registers(
            ins_mop_info.unresolved_ins_mops
        )
        self.update_use_def_lists(
            cleaned_unresolved_ins_mops + ins_mop_info.memory_unresolved_ins_mops,
            ins_mop_info.target_mops,
        )
        self.ins.append(ins)
        if ins.opcode in CONDITIONAL_JUMP_OPCODES:
            num_mop, other_mop = extract_num_mop(ins)
            if num_mop is not None:
                self.comparison_value = num_mop.nnn.value
                self.compared_mop = other_mop

    def parse(self, o_dispatch=None, first=None):
        curins = self.blk.head
        while curins is not None:
            self.update_with_ins(curins)
            curins = curins.next
        for mop_def in self.def_list:
            append_mop_if_not_in_list(mop_def, self.assume_def_list)

    def does_only_need(self, prerequisite_mop_list: list[ida_hexrays.mop_t]) -> bool:
        for used_before_def_mop in self.use_before_def_list:
            mop_index = get_mop_index(used_before_def_mop, prerequisite_mop_list)
            if mop_index == -1:
                return False
        return True

    def recursive_get_father(self) -> list[GenericDispatcherBlockInfo]:
        if self.father is None:
            return [self]
        else:
            return self.father.recursive_get_father() + [self]

    def show_history(self):
        full_father_list = self.recursive_get_father()
        unflat_logger.info("    Show history of Block %s", self.serial)
        for father in full_father_list[:-1]:
            for ins in father.ins:
                unflat_logger.info(
                    "      %s.%s", father.serial, format_minsn_t(ins)
                )

    def print_info(self):
        unflat_logger.info("Block %s information:", self.serial)
        unflat_logger.info("  USE list: %s", format_mop_list(self.use_list))
        unflat_logger.info("  DEF list: %s", format_mop_list(self.def_list))
        unflat_logger.info(
            "  USE BEFORE DEF list: %s", format_mop_list(self.use_before_def_list)
        )
        unflat_logger.info(
            "  ASSUME DEF list: %s", format_mop_list(self.assume_def_list)
        )


class GenericDispatcherInfo(object):
    def __init__(self, mba: ida_hexrays.mba_t):
        self.mba = mba
        self.mop_compared: ida_hexrays.mop_t | None = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

        # Used for o-llvm unflattening
        self.outmost_dispatch_num = self.guess_outmost_dispatcher_blk()
        self.last_num_in_first_blks = self.get_last_blk_in_first_blks()

    def get_last_blk_in_first_blks(self) -> int:
        return -1

    def guess_outmost_dispatcher_blk(self) -> int:
        return -1

    def reset(self):
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def explore(self, blk: ida_hexrays.mblock_t) -> bool:
        return False

    def get_shared_internal_blocks(
        self, other_dispatcher: GenericDispatcherInfo
    ) -> list[ida_hexrays.mblock_t]:
        my_dispatcher_block_serial = [
            blk_info.serial for blk_info in self.dispatcher_internal_blocks
        ]
        other_dispatcher_block_serial = [
            blk_info.serial
            for blk_info in other_dispatcher.dispatcher_internal_blocks
        ]
        return [
            self.mba.get_mblock(blk_serial)
            for blk_serial in my_dispatcher_block_serial
            if blk_serial in other_dispatcher_block_serial
        ]

    def is_sub_dispatcher(self, other_dispatcher: GenericDispatcherInfo) -> bool:
        shared_blocks = self.get_shared_internal_blocks(other_dispatcher)
        if (len(shared_blocks) > 0) and (
            self.entry_block.blk.npred() < other_dispatcher.entry_block.blk.npred()
        ):
            return True
        return False

    def should_emulation_continue(self, cur_blk: ida_hexrays.mblock_t) -> bool:
        exit_block_serial_list = [
            exit_block.serial for exit_block in self.dispatcher_exit_blocks
        ]
        if (cur_blk is not None) and (cur_blk.serial not in exit_block_serial_list):
            return True
        return False

    def emulate_dispatcher_with_father_history(
        self, father_history: MopHistory
    ) -> tuple[ida_hexrays.mblock_t, list[ida_hexrays.minsn_t]]:
        # Use concrete values from tracker - do NOT use symbolic mode here
        # Symbolic mode would generate fake values instead of using tracked values
        microcode_interpreter = MicroCodeInterpreter(symbolic_mode=False)
        microcode_environment = MicroCodeEnvironment()
        dispatcher_input_info = []
        # First, we setup the MicroCodeEnvironment with the state variables (self.entry_block.use_before_def_list)
        # used by the dispatcher
        for initialization_mop in self.entry_block.use_before_def_list:
            # We recover the value of each state variable from the dispatcher father
            initialization_mop_value = father_history.get_mop_constant_value(
                initialization_mop
            )
            if initialization_mop_value is None:
                raise NotResolvableFatherException(
                    "Can't emulate dispatcher {0} with history {1}".format(
                        self.entry_block.serial,
                        father_history.block_serial_path,
                    )
                )
            # We store this value in the MicroCodeEnvironment
            microcode_environment.define(initialization_mop, initialization_mop_value)
            dispatcher_input_info.append(
                f"{format_mop_t(initialization_mop)} = {initialization_mop_value:x}"
            )

        unflat_logger.info(
            "Executing dispatcher %s with: %s",
            self.entry_block.serial,
            ", ".join(dispatcher_input_info),
        )

        # Now, we start the emulation of the code at the dispatcher entry block
        instructions_executed = []
        cur_blk = self.entry_block.blk
        cur_ins = cur_blk.head
        # We will continue emulation while we are in one of the dispatcher blocks
        while self.should_emulation_continue(cur_blk):
            unflat_logger.debug(
                "  Executing: %s.%s", cur_blk.serial, format_minsn_t(cur_ins)
            )
            # We evaluate the current instruction of the dispatcher to determine
            # which block and instruction should be executed next
            is_ok = microcode_interpreter.eval_instruction(
                cur_blk, cur_ins, microcode_environment
            )
            if not is_ok:
                return cur_blk, instructions_executed
            instructions_executed.append(cur_ins)
            cur_blk = microcode_environment.next_blk
            cur_ins = microcode_environment.next_ins
        # We return the first block executed which is not part of the dispatcher
        # and all instructions which have been executed by the dispatcher
        return cur_blk, instructions_executed

    def print_info(self, verbose=False):
        unflat_logger.info("Dispatcher information: ")
        unflat_logger.info(
            "  Entry block: %s.%s: ",
            self.entry_block.serial,
            format_minsn_t(self.entry_block.blk.tail),
        )
        unflat_logger.info(
            "  Entry block predecessors: %s: ",
            [blk_serial for blk_serial in self.entry_block.blk.predset],
        )
        unflat_logger.info(
            "    Compared mop: %s ",
            format_mop_t(self.mop_compared),
        )
        unflat_logger.info(
            "    Comparison values: %s ",
            ", ".join([hex(x) for x in self.comparison_values]),
        )
        self.entry_block.print_info()
        unflat_logger.info(
            "  Number of internal blocks: %s (%s)",
            len(self.dispatcher_internal_blocks),
            [blk_info.serial for blk_info in self.dispatcher_internal_blocks],
        )
        if verbose:
            for disp_blk in self.dispatcher_internal_blocks:
                unflat_logger.info(
                    "    Internal block: %s.%s ",
                    disp_blk.serial,
                    format_minsn_t(disp_blk.blk.tail),
                )
                disp_blk.show_history()
        unflat_logger.info(
            "  Number of Exit blocks: %s (%s)",
            len(self.dispatcher_exit_blocks),
            [blk_info.serial for blk_info in self.dispatcher_exit_blocks],
        )
        if verbose:
            for exit_blk in self.dispatcher_exit_blocks:
                unflat_logger.info(
                    "    Exit block: %s.%s ",
                    exit_blk.serial,
                    format_minsn_t(exit_blk.blk.head),
                )
                exit_blk.show_history()


class GenericDispatcherCollector(ida_hexrays.minsn_visitor_t):
    DISPATCHER_CLASS = GenericDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2

    def __init__(self):
        super().__init__()
        self.dispatcher_list = []
        self.explored_blk_serials = []
        self.dispatcher_min_internal_block = self.DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK
        self.dispatcher_min_exit_block = self.DEFAULT_DISPATCHER_MIN_EXIT_BLOCK
        self.dispatcher_min_comparison_value = (
            self.DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE
        )

    def configure(self, kwargs):
        if "min_dispatcher_internal_block" in kwargs.keys():
            self.dispatcher_min_internal_block = kwargs["min_dispatcher_internal_block"]
        if "min_dispatcher_exit_block" in kwargs.keys():
            self.dispatcher_min_exit_block = kwargs["min_dispatcher_exit_block"]
        if "min_dispatcher_comparison_value" in kwargs.keys():
            self.dispatcher_min_comparison_value = kwargs[
                "min_dispatcher_comparison_value"
            ]

    def specific_checks(self, disp_info: GenericDispatcherInfo) -> bool:
        unflat_logger.debug(
            "DispatcherInfo %s : %s internals, %s exits, %s comparison",
            self.blk.serial,
            len(disp_info.dispatcher_internal_blocks),
            len(disp_info.dispatcher_exit_blocks),
            len(set(disp_info.comparison_values)),
        )
        if (
            len(disp_info.dispatcher_internal_blocks)
            < self.dispatcher_min_internal_block
        ):
            return False
        if len(disp_info.dispatcher_exit_blocks) < self.dispatcher_min_exit_block:
            return False
        if len(set(disp_info.comparison_values)) < self.dispatcher_min_comparison_value:
            return False
        self.dispatcher_list.append(disp_info)
        return True

    def visit_minsn(self):
        if self.blk.serial in self.explored_blk_serials:
            return 0
        self.explored_blk_serials.append(self.blk.serial)
        disp_info = self.DISPATCHER_CLASS(self.blk.mba)
        # Pass entropy thresholds if available
        kwargs = {}
        if hasattr(self, "min_entropy"):
            kwargs["min_entropy"] = self.min_entropy
        if hasattr(self, "max_entropy"):
            kwargs["max_entropy"] = self.max_entropy
        is_good_candidate = disp_info.explore(self.blk, **kwargs)
        if not is_good_candidate:
            return 0
        if not self.specific_checks(disp_info):
            return 0
        self.dispatcher_list.append(disp_info)
        return 0

    def remove_sub_dispatchers(self):
        main_dispatcher_list = []
        for dispatcher_1 in self.dispatcher_list:
            is_dispatcher_1_sub_dispatcher = False
            for dispatcher_2 in self.dispatcher_list:
                if dispatcher_1.is_sub_dispatcher(dispatcher_2):
                    is_dispatcher_1_sub_dispatcher = True
                    break
            if not is_dispatcher_1_sub_dispatcher:
                main_dispatcher_list.append(dispatcher_1)
        self.dispatcher_list = [x for x in main_dispatcher_list]

    def reset(self):
        self.dispatcher_list = []
        self.explored_blk_serials = []

    def get_dispatcher_list(self) -> list[GenericDispatcherInfo]:
        self.remove_sub_dispatchers()
        return self.dispatcher_list


class GenericUnflatteningRule(FlowOptimizationRule):

    # Practical maturities - MMAT_GLBOPT3 is rarely/never called by Hex-Rays
    # MMAT_GLBOPT2 is the latest practical maturity level
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]

    def __init__(self):
        super().__init__()
        self.mba: ida_hexrays.mba_t
        self.cur_maturity = ida_hexrays.MMAT_ZERO
        self.cur_maturity_pass = 0
        self.last_pass_nb_patch_done = 0
        self.maturities = self.DEFAULT_UNFLATTENING_MATURITIES
        # Scheduled modifications for future maturity levels
        # Key: maturity level (e.g., MMAT_GLBOPT1), Value: list of GraphModification
        self.scheduled_modifications: dict[int, list[GraphModification]] = {}
        # Event emitter for cross-optimizer coordination (future use)
        self.events: EventEmitter = EventEmitter()
        # Tracker for provably single-iteration loops to schedule for cleanup
        self.single_iteration_loop_tracker: SingleIterationLoopTracker = SingleIterationLoopTracker()

    def schedule_for_maturity(
        self,
        target_maturity: int,
        modification: GraphModification,
    ) -> None:
        """Schedule a modification to be applied at a future maturity level.

        Args:
            target_maturity: The maturity level at which to apply (e.g., MMAT_GLBOPT1)
            modification: The GraphModification to apply
        """
        self.scheduled_modifications.setdefault(target_maturity, []).append(modification)
        unflat_logger.debug(
            "Scheduled %s for maturity %s: %s",
            modification.mod_type.name,
            target_maturity,
            modification.description,
        )
        self.events.emit(
            UnflatteningEvent.MODIFICATIONS_SCHEDULED,
            target_maturity=target_maturity,
            modification=modification,
            optimizer=self,
        )

    def _apply_scheduled_modifications(self) -> int:
        """Apply any modifications scheduled for the current maturity level.

        Returns:
            Number of modifications applied.
        """
        maturity = self.mba.maturity
        pending = self.scheduled_modifications.pop(maturity, [])
        if not pending:
            return 0

        unflat_logger.info(
            "Applying %d scheduled modifications for maturity %s",
            len(pending),
            maturity,
        )
        self.events.emit(
            UnflatteningEvent.MODIFICATIONS_APPLYING,
            maturity=maturity,
            modifications=pending,
            optimizer=self,
        )

        modifier = DeferredGraphModifier(self.mba)
        modifier.modifications = pending
        applied = modifier.apply(run_optimize_local=True, run_deep_cleaning=False)

        self.events.emit(
            UnflatteningEvent.MODIFICATIONS_APPLIED,
            maturity=maturity,
            applied_count=applied,
            optimizer=self,
        )
        return applied

    def scan_for_single_iteration_loops(self) -> int:
        """Scan the CFG for provably single-iteration loops.

        After unflattening, residual loops may remain with pattern::

            Block A (predecessor):
                mov #INIT, state
                goto B

            Block B (loop header):
                jz state, #CHECK, @exit
                ; fall-through to body

            Block C (loop body):
                ...
                mov #UPDATE, state
                goto B  ; back edge

        If INIT == CHECK and UPDATE != CHECK, the loop executes exactly once.
        This method records such loops for later cleanup.

        Returns:
            Number of single-iteration loops found
        """
        loops_found = 0

        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk is None or blk.tail is None:
                continue

            # Look for conditional jump blocks that could be loop headers
            if blk.tail.opcode not in CONDITIONAL_JUMP_OPCODES:
                continue

            # Need a comparison against a constant
            check_const = None
            state_mop = None
            if blk.tail.r and blk.tail.r.t == ida_hexrays.mop_n:
                check_const = blk.tail.r.signed_value()
                state_mop = blk.tail.l
            elif blk.tail.l and blk.tail.l.t == ida_hexrays.mop_n:
                check_const = blk.tail.l.signed_value()
                state_mop = blk.tail.r
            else:
                continue

            # Only consider magic constants (Approov-style)
            if check_const is None or not (0xF6000 <= check_const <= 0xF6FFF):
                continue

            # Look for back edges (predecessors that are also successors)
            for pred_serial in blk.predset:
                if pred_serial not in blk.succset:
                    continue  # Not a back edge

                # Found a potential loop: check for init/update pattern
                pred_blk = self.mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.tail is None:
                    continue

                # Look for update assignment in predecessor (back edge source)
                update_const = self._find_state_assignment(pred_blk, state_mop)
                if update_const is None:
                    continue

                # Look for init assignment in other predecessors (loop entry)
                for entry_serial in blk.predset:
                    if entry_serial == pred_serial:
                        continue  # Skip the back edge
                    entry_blk = self.mba.get_mblock(entry_serial)
                    if entry_blk is None:
                        continue

                    init_const = self._find_state_assignment(entry_blk, state_mop)
                    if init_const is None:
                        continue

                    # Try to prove single-iteration
                    if prove_single_iteration(init_const, check_const, update_const):
                        loop = self.single_iteration_loop_tracker.record_loop(
                            block_serial=blk.serial,
                            init_value=init_const,
                            check_value=check_const,
                            update_value=update_const,
                        )
                        if loop:
                            loops_found += 1
                            unflat_logger.info(
                                "Detected single-iteration loop at block %d: "
                                "init=0x%X, check=0x%X, update=0x%X. "
                                "Consider running BadWhileLoop unflattener.",
                                blk.serial, init_const, check_const, update_const,
                            )

        return loops_found

    def _find_state_assignment(
        self,
        blk: ida_hexrays.mblock_t,
        state_mop: ida_hexrays.mop_t,
    ) -> int | None:
        """Find assignment to state variable in a block.

        Args:
            blk: Block to search
            state_mop: The state variable mop to look for

        Returns:
            Constant value assigned, or None if not found
        """
        # Walk backwards through instructions
        insn = blk.tail
        while insn:
            if insn.opcode == ida_hexrays.m_mov:
                # Check if this assigns to our state variable
                if state_mop and insn.d and insn.d.equal_mops(state_mop, ida_hexrays.EQ_IGNSIZE):
                    if insn.l and insn.l.t == ida_hexrays.mop_n:
                        return insn.l.signed_value()
            insn = insn.prev
        return None

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        if self.cur_maturity == self.mba.maturity:
            self.cur_maturity_pass += 1
        else:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            return False
        return True

    @abc.abstractmethod
    def optimize(self, blk):
        """Perform the optimization on *blk* and return the number of changes."""
        raise NotImplementedError


class GenericDispatcherUnflatteningRule(GenericUnflatteningRule):

    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5

    def __init__(self):
        super().__init__()
        self.dispatcher_collector = self.DISPATCHER_COLLECTOR_CLASS()
        self.dispatcher_list = []
        self.max_duplication_passes = self.DEFAULT_MAX_DUPLICATION_PASSES
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.non_significant_changes = 0
        # Track processed (source_block, target) pairs to prevent duplicates
        self._processed_dispatcher_fathers: set[tuple[int, int]] = set()

    @property
    @abc.abstractmethod
    def DISPATCHER_COLLECTOR_CLASS(self) -> type[GenericDispatcherCollector]:
        """Return the class of the dispatcher collector."""
        raise NotImplementedError

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        if not super().check_if_rule_should_be_used(blk):
            return False
        if (self.cur_maturity_pass >= 1) and (self.last_pass_nb_patch_done == 0):
            return False
        if (self.max_passes is not None) and (
            self.cur_maturity_pass >= self.max_passes
        ):
            return False
        return True

    def configure(self, kwargs):
        super().configure(kwargs)
        if "max_passes" in self.config.keys():
            self.max_passes = self.config["max_passes"]
        if "max_duplication_passes" in self.config.keys():
            self.max_duplication_passes = self.config["max_duplication_passes"]
        self.dispatcher_collector.configure(kwargs)

    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        self.dispatcher_collector.reset()
        self.mba.for_all_topinsns(self.dispatcher_collector)
        self.dispatcher_list = [
            x for x in self.dispatcher_collector.get_dispatcher_list()
        ]

    def ensure_all_dispatcher_fathers_are_direct(self) -> int:
        nb_change = 0
        for dispatcher_info in self.dispatcher_list:
            nb_change += self.ensure_dispatcher_fathers_are_direct(dispatcher_info)
            dispatcher_father_list = [
                self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset
            ]
            for dispatcher_father in dispatcher_father_list:
                nb_change += ensure_child_has_an_unconditional_father(
                    dispatcher_father, dispatcher_info.entry_block.blk
                )
        return nb_change

    def ensure_dispatcher_fathers_are_direct(
        self, dispatcher_info: GenericDispatcherInfo
    ) -> int:
        nb_change = 0
        dispatcher_father_list = [
            self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset
        ]
        for dispatcher_father in dispatcher_father_list:
            nb_change += ensure_child_has_an_unconditional_father(
                dispatcher_father, dispatcher_info.entry_block.blk
            )
        return nb_change

    def register_initialization_variables(self, mop_tracker):
        pass

    def get_dispatcher_father_histories(
        self,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_entry_block: GenericDispatcherBlockInfo,
        dispatcher_info: GenericDispatcherInfo,
    ) -> list[MopHistory]:
        father_tracker = MopTracker(
            dispatcher_entry_block.use_before_def_list,
            max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK,
            max_path=self.MOP_TRACKER_MAX_NB_PATH,
            dispatcher_info=dispatcher_info,
        )
        father_tracker.reset()
        self.register_initialization_variables(father_tracker)
        father_histories = father_tracker.search_backward(dispatcher_father, None)
        unflat_logger.debug(
            "Histories (dispatcher %s, predecessor %s): %s",
            dispatcher_entry_block.serial,
            dispatcher_father.serial,
            father_histories,
        )
        return father_histories

    def check_if_histories_are_resolved(self, mop_histories: list[MopHistory]) -> bool:
        return all([mop_history.is_resolved() for mop_history in mop_histories])

    def ensure_dispatcher_father_is_resolvable(
        self,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_entry_block: GenericDispatcherBlockInfo,
        dispatcher_info: GenericDispatcherInfo,
    ) -> int:
        father_histories = self.get_dispatcher_father_histories(
            dispatcher_father, dispatcher_entry_block, dispatcher_info
        )

        father_histories_cst = get_all_possibles_values(
            father_histories,
            dispatcher_entry_block.use_before_def_list,
            verbose=False,
            # verbose=True,
        )
        father_is_resolvable = self.check_if_histories_are_resolved(father_histories)
        if not father_is_resolvable:
            raise NotDuplicableFatherException(
                "Dispatcher {0} predecessor {1} is not duplicable: {2}".format(
                    dispatcher_entry_block.serial,
                    dispatcher_father.serial,
                    father_histories_cst,
                )
            )
        for father_history_cst in father_histories_cst:
            if None in father_history_cst:
                raise NotDuplicableFatherException(
                    "Dispatcher {0} predecessor {1} has None value: {2}".format(
                        dispatcher_entry_block.serial,
                        dispatcher_father.serial,
                        father_histories_cst,
                    )
                )

        unflat_logger.info(
            "Dispatcher %s predecessor %s is resolvable: %s",
            dispatcher_entry_block.serial,
            dispatcher_father.serial,
            father_histories_cst,
        )
        nb_duplication, nb_change = duplicate_histories(
            father_histories, max_nb_pass=self.max_duplication_passes
        )
        unflat_logger.info(
            "Dispatcher %s predecessor %s duplication: %s blocks created, %s changes made",
            dispatcher_entry_block.serial,
            dispatcher_father.serial,
            nb_duplication,
            nb_change,
        )
        return 0

    # =========================================================================
    # LEGACY ABC CODE - COMMENTED OUT (NOT DELETED)
    # =========================================================================
    #
    # STATUS: These methods are NO LONGER CALLED by any code path.
    #
    # REPLACEMENT: ABCBlockSplitter (abc_block_splitter.py) now handles all
    #              ABC pattern splitting via fix_fathers_from_mop_history().
    #
    # WHY COMMENTED OUT:
    #   1. All system tests pass without this code (137 passed, Dec 2024)
    #   2. No call sites exist - grep confirms only self-recursive calls remain
    #   3. The replacement ABCBlockSplitter uses deferred CFG modification,
    #      which is safer than the direct mba.insert_block() approach here
    #
    # WHY NOT DELETED:
    #   - Preserving for reference in case edge cases are discovered
    #   - The logic for ABC pattern detection (constants 1010000-1011999)
    #     may be useful for understanding the original algorithm
    #
    # METHODS IN THIS BLOCK:
    #   - father_patcher_abc_extract_mop()
    #   - father_patcher_abc_check_instruction()
    #   - father_patcher_abc_create_blocks()
    #   - father_history_patcher_abc()
    #   - dispatcher_fixer_abc()
    #
    # TO RE-ENABLE: Remove the leading '# ' from each line below
    # =========================================================================
    #
    # def father_patcher_abc_extract_mop(self, target_instruction):
    #     cnst = None
    #     compare_mop = None
    #     if target_instruction.opcode == ida_hexrays.m_sub:
    #         if target_instruction.l.t == 2:
    #             cnst = target_instruction.l.signed_value()
    #             compare_mop = ida_hexrays.mop_t(target_instruction.r)
    #     elif target_instruction.opcode == ida_hexrays.m_add:
    #         if target_instruction.r.t == 2:
    #             cnst = target_instruction.r.signed_value()
    #             compare_mop = ida_hexrays.mop_t(target_instruction.l)
    #     elif target_instruction.opcode == ida_hexrays.m_or:
    #         if target_instruction.r.t == 2:
    #             cnst = target_instruction.r.signed_value()
    #             compare_mop = ida_hexrays.mop_t(target_instruction.l)
    #     elif target_instruction.opcode == ida_hexrays.m_xor:
    #         if target_instruction.r.t == 2:
    #             cnst = target_instruction.r.signed_value()
    #             compare_mop = ida_hexrays.mop_t(target_instruction.l)
    #     return cnst, compare_mop, target_instruction.opcode
    #
    # def father_patcher_abc_check_instruction(
    #     self, target_instruction
    # ) -> tuple[int | None, ida_hexrays.mop_t | None, ida_hexrays.mop_t | None, int | None]:
    #     # TODO reimplement here
    #     compare_mop_left = None
    #     compare_mop_right = None
    #     cnst = None
    #     instruction_opcode = None
    #     opcodes_interested_in = [ida_hexrays.m_add, ida_hexrays.m_sub, ida_hexrays.m_or, ida_hexrays.m_xor, ida_hexrays.m_xdu, ida_hexrays.m_high]
    #     # if target_instruction.d.r != jtbl_r:
    #     # return cnst,compare_mop_left,compare_mop_right,instruction_opcode
    #     if target_instruction.opcode in opcodes_interested_in:
    #         trgt_opcode = target_instruction.opcode
    #         # check add or sub
    #         if trgt_opcode == ida_hexrays.m_xdu:
    #             if target_instruction.l.t == ida_hexrays.mop_d:
    #                 if target_instruction.l.d.opcode == ida_hexrays.m_high:
    #                     high_i = target_instruction.l.d
    #                     if high_i.l.t == ida_hexrays.mop_d:
    #                         sub_instruction = high_i.l.d
    #                         if sub_instruction.opcode == ida_hexrays.m_sub:
    #                             if sub_instruction.l.t == ida_hexrays.mop_d:
    #                                 compare_mop_right = ida_hexrays.mop_t(sub_instruction.r)
    #                                 sub_sub_instruction = sub_instruction.l.d
    #                                 if sub_sub_instruction.opcode == ida_hexrays.m_or:
    #                                     if sub_sub_instruction.r.t == 2:
    #                                         cnst = sub_sub_instruction.r.signed_value()
    #                                         cnst = cnst >> 32
    #                                         compare_mop_left = ida_hexrays.mop_t(
    #                                             sub_sub_instruction.l
    #                                         )
    #                                         instruction_opcode = ida_hexrays.m_sub
    #                             elif sub_instruction.l.t == ida_hexrays.mop_n:
    #                                 # 9. 0 high   (#0xF6A120000005F.8-xdu.8(ebx.4)), ecx.4{11}
    #                                 compare_mop_right = ida_hexrays.mop_t(sub_instruction.r)
    #                                 cnst = sub_instruction.l.signed_value()
    #                                 cnst = cnst >> 32
    #                                 compare_mop_left = ida_hexrays.mop_t()
    #                                 compare_mop_left.make_number(
    #                                     sub_instruction.l.signed_value() & 0xFFFFFFFF,
    #                                     8,
    #                                     target_instruction.ea,
    #                                 )
    #                                 instruction_opcode = ida_hexrays.m_sub
    #                 else:
    #                     sub_instruction = target_instruction.l.d
    #                     cnst, compare_mop_left, trgt_opcode = (
    #                         self.father_patcher_abc_extract_mop(sub_instruction)
    #                     )
    #                     compare_mop_right = ida_hexrays.mop_t()
    #                     compare_mop_right.make_number(0, 4, target_instruction.ea)
    #                     instruction_opcode = trgt_opcode
    #             else:
    #                 return cnst, compare_mop_left, compare_mop_right, instruction_opcode
    #         elif trgt_opcode == ida_hexrays.m_high:
    #             if target_instruction.l.t == ida_hexrays.mop_d:
    #                 sub_instruction = target_instruction.l.d
    #                 if sub_instruction.opcode == ida_hexrays.m_sub:
    #                     if sub_instruction.l.t == ida_hexrays.mop_d:
    #                         compare_mop_right = ida_hexrays.mop_t(sub_instruction.r)
    #                         sub_sub_instruction = sub_instruction.l.d
    #                         if sub_sub_instruction.opcode == ida_hexrays.m_or:
    #                             if sub_sub_instruction.r.t == 2:
    #                                 cnst = sub_sub_instruction.r.signed_value()
    #                                 cnst = cnst >> 32
    #                                 compare_mop_left = ida_hexrays.mop_t(sub_sub_instruction.l)
    #                                 instruction_opcode = ida_hexrays.m_sub
    #                     elif sub_instruction.l.t == ida_hexrays.mop_n:
    #                         # 9. 0 high   (#0xF6A120000005F.8-xdu.8(ebx.4)), ecx.4{11}
    #                         compare_mop_right = ida_hexrays.mop_t(sub_instruction.r)
    #                         cnst = sub_instruction.l.signed_value()
    #                         cnst = cnst >> 32
    #                         compare_mop_left = ida_hexrays.mop_t()
    #                         compare_mop_left.make_number(
    #                             sub_instruction.l.signed_value() & 0xFFFFFFFF,
    #                             8,
    #                             target_instruction.ea,
    #                         )
    #                         instruction_opcode = ida_hexrays.m_sub
    #                     else:
    #                         pass
    #         else:
    #             cnst, compare_mop_left, trgt_opcode = (
    #                 self.father_patcher_abc_extract_mop(target_instruction)
    #             )
    #             compare_mop_right = ida_hexrays.mop_t()
    #             compare_mop_right.make_number(0, 4, target_instruction.ea)
    #             instruction_opcode = trgt_opcode
    #
    #     return cnst, compare_mop_left, compare_mop_right, instruction_opcode
    #
    # def father_patcher_abc_create_blocks(
    #     self,
    #     dispatcher_father: ida_hexrays.mblock_t,
    #     curr_inst: ida_hexrays.minsn_t,
    #     cnst: int,
    #     compare_mop_left: ida_hexrays.mop_t,
    #     compare_mop_right: ida_hexrays.mop_t,
    #     opcode: int,
    # ) -> tuple[ida_hexrays.mblock_t, ida_hexrays.mblock_t]:
    #     """
    #     Create two new blocks to split a dispatcher father based on a condition.
    #
    #     WARNING: This function performs direct CFG modifications without using
    #     DeferredGraphModifier. It directly manipulates predset/succset and calls
    #     mba.insert_block(). This works for the specific obfuscation patterns
    #     targeted but is not the recommended pattern for new code.
    #
    #     See: docs/cfg-modification-audit.md
    #     """
    #     mba = dispatcher_father.mba
    #     if dispatcher_father.tail.opcode == ida_hexrays.m_goto:
    #         dispatcher_father.remove_from_block(dispatcher_father.tail)
    #     new_id0_serial = dispatcher_father.serial + 1
    #     new_id1_serial = dispatcher_father.serial + 2
    #     dispatcher_reg0 = ida_hexrays.mop_t(curr_inst.d)
    #     dispatcher_reg0.size = 4
    #     dispatcher_reg1 = ida_hexrays.mop_t(curr_inst.d)
    #     dispatcher_reg1.size = 4
    #     if dispatcher_father.type != ida_hexrays.BLT_1WAY:
    #         raise RuntimeError("father is not 1 way")
    #
    #     ea = curr_inst.ea
    #     block0_const = 0
    #     block1_const = 0
    #     if opcode == ida_hexrays.m_sub:
    #         block0_const = cnst - 0
    #         block1_const = cnst - 1
    #     elif opcode == ida_hexrays.m_add:
    #         block0_const = cnst + 0
    #         block1_const = cnst + 1
    #     elif opcode == ida_hexrays.m_or:
    #         block0_const = cnst | 0
    #         block1_const = cnst | 1
    #     elif opcode == ida_hexrays.m_xor:
    #         block0_const = cnst ^ 0
    #         block1_const = cnst ^ 1
    #
    #     # create first block
    #     new_block0 = mba.insert_block(new_id0_serial)
    #     new_block1 = mba.insert_block(new_id1_serial)
    #
    #     # get father succset after creation of new childs, since it will increase auto
    #     childs_goto0 = ida_hexrays.mop_t()
    #     childs_goto1 = ida_hexrays.mop_t()
    #     childs_goto_serial = dispatcher_father.succset[0]
    #     childs_goto0.make_blkref(childs_goto_serial)
    #     childs_goto_serial = dispatcher_father.succset[0]
    #     childs_goto1.make_blkref(childs_goto_serial)
    #     dispatcher_tail = dispatcher_father.tail
    #     while dispatcher_tail.dstr() != curr_inst.dstr():
    #         innsert_inst0 = ida_hexrays.minsn_t(dispatcher_tail)
    #         innsert_inst1 = ida_hexrays.minsn_t(dispatcher_tail)
    #         innsert_inst0.setaddr(ea)
    #         innsert_inst1.setaddr(ea)
    #
    #         new_block0.insert_into_block(innsert_inst0, new_block0.head)
    #         new_block1.insert_into_block(innsert_inst1, new_block1.head)
    #         dispatcher_tail = dispatcher_tail.prev
    #     # generate block0 instructions
    #     if new_block0.tail != None and new_block1.tail != None:
    #         new_block0.tail.next = None
    #         new_block1.tail.next = None
    #
    #     mov_inst0 = ida_hexrays.minsn_t(ea)
    #     mov_inst0.opcode = ida_hexrays.m_mov
    #     mov_inst0.l = ida_hexrays.mop_t()
    #     mov_inst0.l.make_number(block0_const, 4, ea)
    #     mov_inst0.d = dispatcher_reg0
    #     new_block0.insert_into_block(mov_inst0, new_block0.tail)
    #
    #     goto_inst0 = ida_hexrays.minsn_t(ea)
    #     goto_inst0.opcode = ida_hexrays.m_goto
    #     goto_inst0.l = childs_goto0
    #     new_block0.insert_into_block(goto_inst0, new_block0.tail)
    #
    #     # generate block1 instructions
    #     mov_inst1 = ida_hexrays.minsn_t(ea)
    #     mov_inst1.opcode = ida_hexrays.m_mov
    #     mov_inst1.l = ida_hexrays.mop_t()
    #     mov_inst1.l.make_number(block1_const, 4, ea)
    #     mov_inst1.d = dispatcher_reg1
    #     new_block1.insert_into_block(mov_inst1, new_block1.tail)
    #
    #     goto_inst1 = ida_hexrays.minsn_t(ea)
    #     goto_inst1.opcode = ida_hexrays.m_goto
    #     goto_inst1.l = childs_goto1
    #     new_block1.insert_into_block(goto_inst1, new_block1.tail)
    #     #
    #     while curr_inst:
    #         n = curr_inst.next
    #         dispatcher_father.remove_from_block(curr_inst)
    #         curr_inst = n
    #
    #     # add jz to end of block
    #     jz_to_childs = ida_hexrays.minsn_t(ea)
    #     jz_to_childs.opcode = ida_hexrays.m_jz
    #     jz_to_childs.l = compare_mop_left
    #     jz_to_childs.r = compare_mop_right
    #     jz_to_childs.d = ida_hexrays.mop_t()
    #     jz_to_childs.d.make_blkref(new_id1_serial)
    #     dispatcher_father.insert_into_block(jz_to_childs, dispatcher_father.tail)
    #
    #     # housekeeping
    #     prev_successor_serials = [x for x in dispatcher_father.succset]
    #     for prev_successor_serial in prev_successor_serials:
    #         prev_succ = mba.get_mblock(prev_successor_serial)
    #         prev_succ.predset._del(dispatcher_father.serial)
    #         prev_succ.predset.add_unique(new_id0_serial)
    #         prev_succ.predset.add_unique(new_id1_serial)
    #         if prev_succ.serial != mba.qty - 1:
    #             prev_succ.mark_lists_dirty()
    #
    #     # clean block0
    #     succset_serials = [x for x in new_block0.succset]
    #     for succ in succset_serials:
    #         new_block0.succset._del(succ)
    #     predset_serials = [x for x in new_block0.predset]
    #     for pred in predset_serials:
    #         new_block0.predset._del(pred)
    #
    #     # clean block1
    #     succset_serials = [x for x in new_block1.succset]
    #     for succ in succset_serials:
    #         new_block1.succset._del(succ)
    #     predset_serials = [x for x in new_block1.predset]
    #     for pred in predset_serials:
    #         new_block1.predset._del(pred)
    #
    #     # add father as pred to new blocks
    #     new_block0.predset.add_unique(dispatcher_father.serial)
    #     new_block1.predset.add_unique(dispatcher_father.serial)
    #
    #     # add dispatcher block as succset
    #     new_block0.succset.add_unique(childs_goto_serial)
    #     new_block1.succset.add_unique(childs_goto_serial)
    #
    #     # mark lists dirty
    #     new_block0.mark_lists_dirty()
    #     new_block1.mark_lists_dirty()
    #
    #     # clean father succset
    #     succset_serials = [x for x in dispatcher_father.succset]
    #     for succ_serial in succset_serials:
    #         dispatcher_father.succset._del(succ_serial)
    #
    #     # add childs to father succset
    #     dispatcher_father.succset.add_unique(new_id0_serial)
    #     dispatcher_father.succset.add_unique(new_id1_serial)
    #     dispatcher_father.mark_lists_dirty()
    #
    #     dispatcher_father.type = ida_hexrays.BLT_2WAY
    #     new_block0.type = ida_hexrays.BLT_1WAY
    #     new_block1.type = ida_hexrays.BLT_1WAY
    #     new_block0.start = dispatcher_father.start
    #     new_block1.start = dispatcher_father.start
    #     new_block0.end = dispatcher_father.end
    #     new_block1.end = dispatcher_father.end
    #
    #     mba.mark_chains_dirty()
    #     safe_verify(
    #         mba,
    #         "optimizing GenericDispatcherUnflatteningRule.father_patcher_abc_create_blocks",
    #         logger_func=unflat_logger.error,
    #     )
    #     return new_block0, new_block1
    #
    # def father_history_patcher_abc(self, father_history: ida_hexrays.mblock_t) -> int:
    #     curr_inst: ida_hexrays.minsn_t | None = father_history.head
    #     while curr_inst:
    #         cnst, compare_mop_left, compare_mop_right, instruction_opcode = (
    #             self.father_patcher_abc_check_instruction(curr_inst)
    #         )
    #         if (
    #             cnst is not None
    #             and compare_mop_left is not None
    #             and compare_mop_right is not None
    #             and instruction_opcode is not None
    #         ):
    #             if cnst > 1010000 and cnst < 1011999:
    #                 try:
    #                     block0, block1 = self.father_patcher_abc_create_blocks(
    #                         father_history,
    #                         curr_inst,
    #                         cnst,
    #                         compare_mop_left,
    #                         compare_mop_right,
    #                         instruction_opcode,
    #                     )
    #                     bblock0_n = self.father_history_patcher_abc(block0)
    #                     bblock1_n = self.father_history_patcher_abc(block1)
    #                     return 1 + bblock0_n + bblock1_n
    #                 except Exception as e:
    #                     unflat_logger.error(e, exc_info=True)
    #                     raise e
    #         curr_inst = curr_inst.next
    #     return 0
    #
    # def dispatcher_fixer_abc(self, dispatcher_list):
    #     for dispatcher in dispatcher_list:
    #         if dispatcher.entry_block.blk.tail.opcode == ida_hexrays.m_jtbl:
    #             jtbl_minst = dispatcher.entry_block.blk.tail
    #             if jtbl_minst.l.t == ida_hexrays.mop_d:
    #                 if jtbl_minst.l.d.opcode == ida_hexrays.m_sub:
    #                     sub_minst = jtbl_minst.l.d
    #                     if sub_minst.l.t == 2:
    #                         cnst = jtbl_minst.l.signed_value()
    #                         compare_mop = ida_hexrays.mop_t(jtbl_minst.r)
    #                 if jtbl_minst.l.d.opcode == ida_hexrays.m_xdu:
    #                     sub_minst = jtbl_minst.l.d
    #                     if sub_minst.l.t == 2:
    #                         cnst = jtbl_minst.l.signed_value()
    #                         compare_mop = ida_hexrays.mop_t(jtbl_minst.r)
    #
    # =========================================================================
    # END OF LEGACY ABC CODE
    # =========================================================================

    def resolve_dispatcher_father(
        self,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_info: GenericDispatcherInfo,
        deferred_modifier: DeferredGraphModifier | None = None,
    ) -> int:
        """Resolve a dispatcher father block by redirecting it to the target.

        Args:
            dispatcher_father: The predecessor block to resolve
            dispatcher_info: Information about the dispatcher
            deferred_modifier: If provided, queue CFG modifications instead of
                applying them directly. This enables safer deferred patching.

        Returns:
            2 on success (for historical reasons)

        Raises:
            NotResolvableFatherException: If the block cannot be resolved
        """
        dispatcher_father_histories = self.get_dispatcher_father_histories(
            dispatcher_father,
            dispatcher_info.entry_block,
            dispatcher_info,
        )
        father_is_resolvable = self.check_if_histories_are_resolved(
            dispatcher_father_histories
        )
        if not father_is_resolvable:
            raise NotResolvableFatherException(
                "Can't fix block {0}".format(dispatcher_father.serial)
            )
        mop_searched_values_list = get_all_possibles_values(
            dispatcher_father_histories,
            dispatcher_info.entry_block.use_before_def_list,
            verbose=False,
        )
        all_values_found = check_if_all_values_are_found(mop_searched_values_list)
        if not all_values_found:
            raise NotResolvableFatherException(
                "Can't fix block {0}".format(dispatcher_father.serial)
            )

        ref_mop_searched_values = mop_searched_values_list[0]
        for tmp_mop_searched_values in mop_searched_values_list:
            if tmp_mop_searched_values != ref_mop_searched_values:
                raise NotResolvableFatherException(
                    "Dispatcher {0} predecessor {1} is not resolvable: {2}".format(
                        dispatcher_info.entry_block.serial,
                        dispatcher_father.serial,
                        mop_searched_values_list,
                    )
                )

        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(
            dispatcher_father_histories[0]
        )
        if target_blk is not None:
            # Check if this (source, target) pair has already been processed
            pair_key = (dispatcher_father.serial, target_blk.serial)
            if pair_key in self._processed_dispatcher_fathers:
                unflat_logger.info(
                    "Skipping already-processed dispatcher father: %s -> %s",
                    dispatcher_father.serial,
                    target_blk.serial,
                )
                return 0

            # Mark this pair as processed
            self._processed_dispatcher_fathers.add(pair_key)

            if unflat_logger.debug_on:
                unflat_logger.debug(
                    "Unflattening graph: Making %s goto %s",
                    dispatcher_father.serial,
                    target_blk.serial,
                )
            ins_to_copy = [
                ins
                for ins in disp_ins
                if ((ins is not None) and (ins.opcode not in CONTROL_FLOW_OPCODES))
            ]

            if deferred_modifier is not None:
                # Use deferred CFG modifications
                if len(ins_to_copy) > 0:
                    unflat_logger.info(
                        "Queuing create_and_redirect: %s instructions from block %s -> %s",
                        len(ins_to_copy),
                        dispatcher_father.serial,
                        target_blk.serial,
                    )
                    deferred_modifier.queue_create_and_redirect(
                        source_block_serial=dispatcher_father.serial,
                        final_target_serial=target_blk.serial,
                        instructions_to_copy=ins_to_copy,
                        is_0_way=(target_blk.type == ida_hexrays.BLT_0WAY),
                        description=f"resolve_dispatcher_father {dispatcher_father.serial} -> {target_blk.serial}",
                    )
                else:
                    unflat_logger.info(
                        "Queuing goto change: block %s -> %s",
                        dispatcher_father.serial,
                        target_blk.serial,
                    )
                    deferred_modifier.queue_goto_change(
                        block_serial=dispatcher_father.serial,
                        new_target=target_blk.serial,
                        description=f"resolve_dispatcher_father {dispatcher_father.serial} -> {target_blk.serial}",
                        rule_priority=100,  # High priority - proven constant analysis
                    )
            else:
                # Legacy direct CFG modifications
                if len(ins_to_copy) > 0:
                    unflat_logger.info(
                        "Instruction copied: %s: %s",
                        len(ins_to_copy),
                        ", ".join(
                            [format_minsn_t(ins_copied) for ins_copied in ins_to_copy]
                        ),
                    )
                    tail_serial = self.mba.qty - 1
                    block_to_copy = self.mba.get_mblock(tail_serial)
                    while block_to_copy.type == ida_hexrays.BLT_XTRN or block_to_copy.type == ida_hexrays.BLT_STOP:
                        block_to_copy = self.mba.get_mblock(tail_serial)
                        tail_serial -= 1
                    dispatcher_side_effect_blk = create_block(
                        block_to_copy, ins_to_copy, is_0_way=(target_blk.type == ida_hexrays.BLT_0WAY)
                    )
                    change_1way_block_successor(
                        dispatcher_father, dispatcher_side_effect_blk.serial
                    )
                    change_1way_block_successor(
                        dispatcher_side_effect_blk, target_blk.serial
                    )
                else:
                    change_1way_block_successor(dispatcher_father, target_blk.serial)
            return 2

        raise NotResolvableFatherException(
            "Can't fix block {0}: no block for key: {1}".format(
                dispatcher_father.serial,
                mop_searched_values_list,
            )
        )

    def fix_fathers_from_mop_history(
        self,
        dispatcher_father,
        dispatcher_entry_block,
        dispatcher_info: GenericDispatcherInfo,
    ):
        """Fix dispatcher fathers with ABC patterns using in-place transformation.

        This method uses ConditionalStateResolver for direct target resolution:
        1. Collect all blocks to analyze from father histories
        2. For each ABC pattern (state = x + magic where magic in 1010000-1011999):
           - Resolve both possible targets via dispatcher emulation
           - Create conditional jump directly to targets
        3. No new blocks are created - avoids insert_block() issues

        This is the "directed graph" approach that avoids IDA internal state corruption.
        """
        father_histories = self.get_dispatcher_father_histories(
            dispatcher_father, dispatcher_entry_block, dispatcher_info
        )

        # Use ConditionalStateResolver for direct target resolution (no new blocks)
        handler = ConditionalStateResolver(self.mba, dispatcher_info)

        total_n = 0
        # Process each block in the father histories
        for father_history in father_histories:
            for block in father_history.block_path:
                total_n += handler.analyze_and_apply(block)

        return total_n

    def find_bad_while_loops(self, blk):
        # find from mov x,eax
        if blk.tail.opcode == ida_hexrays.m_mov and blk.tail.l.t == ida_hexrays.mop_n:
            left_cnst = blk.tail.l.signed_value()
            if left_cnst > 0xF6000 and left_cnst < 0xF6FFF:
                if blk.next.opcode == ida_hexrays.m_jz and blk.next.tail.r.t == ida_hexrays.mop_n:
                    jz0_cnst = blk.next.tail.r.signed_value()
                    if blk.next.next.opcode == ida_hexrays.m_jz and blk.next.next.tail.r.t == ida_hexrays.mop_n:
                        jz1_cnst = blk.next.ntext.tail.r.signed_value()
                        if (
                            jz1_cnst > 0xF6000
                            and jz1_cnst < 0xF6FFF
                            and jz0_cnst > 0xF6000
                            and jz0_cnst < 0xF6FFF
                        ):
                            unflat_logger.info("whoo found it!!!")

    def remove_flattening(self) -> int:
        total_nb_change = 0
        self.non_significant_changes = ensure_last_block_is_goto(self.mba)
        self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()

        # Reset tracking for this optimization pass
        self._processed_dispatcher_fathers.clear()

        # Create deferred modifier for all resolve_dispatcher_father operations
        deferred_modifier = DeferredGraphModifier(self.mba)

        for dispatcher_info in self.dispatcher_list:
            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba,
                    self.log_dir,
                    "unflat_{0}_dispatcher_{1}_after_fix_abc_before_duplication".format(
                        self.cur_maturity_pass, dispatcher_info.entry_block.serial
                    ),
                )
            unflat_logger.info(
                "Searching dispatcher for entry block %s %s ->  with variables (%s)...",
                dispatcher_info.entry_block.serial,
                format_mop_t(dispatcher_info.mop_compared),
                format_mop_list(dispatcher_info.entry_block.use_before_def_list),
            )

            # editing dispatcher fathers:
            # for dispatcher_father in tmp_dispatcher_father_list:
            # self.father_patcher_abc(dispatcher_father,dispatcher_info.entry_block)

            # redine dispatcher father since we changed entry block succ/pred sets
            dispatcher_father_list = [
                self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset
            ]
            for dispatcher_father in dispatcher_father_list:

                try:
                    total_nb_change += self.ensure_dispatcher_father_is_resolvable(
                        dispatcher_father, dispatcher_info.entry_block, dispatcher_info
                    )
                except NotDuplicableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba,
                    self.log_dir,
                    "unflat_{0}_dispatcher_{1}_after_duplication".format(
                        self.cur_maturity_pass, dispatcher_info.entry_block.serial
                    ),
                )
            # During the previous step we changed dispatcher entry block fathers, so we need to reload them
            dispatcher_father_list = [
                self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset
            ]
            nb_flattened_branches = 0
            for dispatcher_father in dispatcher_father_list:
                try:
                    nb_flattened_branches += self.resolve_dispatcher_father(
                        dispatcher_father, dispatcher_info, deferred_modifier
                    )
                except NotResolvableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    self.mba,
                    self.log_dir,
                    "unflat_{0}_dispatcher_{1}_after_unflattening".format(
                        self.cur_maturity_pass, dispatcher_info.entry_block.serial
                    ),
                )

        # Apply all deferred CFG modifications after analysis is complete
        if deferred_modifier.has_modifications():
            unflat_logger.info(
                "Applying %d deferred CFG modifications from resolve_dispatcher_father",
                len(deferred_modifier.modifications),
            )
            deferred_modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

        # Scan for residual single-iteration loops and record for cleanup
        loops_found = self.scan_for_single_iteration_loops()
        if loops_found > 0:
            unflat_logger.info(
                "Found %d provable single-iteration loops after unflattening", loops_found
            )

        unflat_logger.info("Unflattening removed %s branch", nb_flattened_branches)
        total_nb_change += nb_flattened_branches
        return total_nb_change

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0

        # Apply any modifications scheduled for this maturity level
        scheduled_changes = self._apply_scheduled_modifications()
        if scheduled_changes > 0:
            unflat_logger.info(
                "Applied %d scheduled modifications at maturity %s",
                scheduled_changes,
                self.cur_maturity,
            )

        self.last_pass_nb_patch_done = 0
        unflat_logger.info(
            "Unflattening at maturity %s pass %s",
            self.cur_maturity,
            self.cur_maturity_pass,
        )
        if self.dump_intermediate_microcode:
            dump_microcode_for_debug(
                self.mba,
                self.log_dir,
                "unflat_{0}_start".format(self.cur_maturity_pass),
            )
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            unflat_logger.info("No dispatcher found at maturity %s", self.mba.maturity)
            return 0
        else:
            unflat_logger.info(
                "Unflattening: %s dispatcher(s) found", len(self.dispatcher_list)
            )
            # self.dispatcher_fixer_abc(self.dispatcher_list)
            for dispatcher_info in self.dispatcher_list:
                dispatcher_info.print_info()
                dispatcher_father_list = [
                    self.mba.get_mblock(x)
                    for x in dispatcher_info.entry_block.blk.predset
                ]
                total_fixed_father_block = 0
                if self.dump_intermediate_microcode:
                    dump_microcode_for_debug(
                        self.mba,
                        self.log_dir,
                        "unflat_{0}_dispatcher_{1}_before_fix_abc".format(
                            self.cur_maturity_pass, dispatcher_info.entry_block.serial
                        ),
                    )
                for dispatcher_father in dispatcher_father_list:
                    try:
                        total_fixed_father_block += self.fix_fathers_from_mop_history(
                            dispatcher_father,
                            dispatcher_info.entry_block,
                            dispatcher_info,
                        )
                    except Exception as e:
                        print(e)
                unflat_logger.info(
                    "Fixed %s instructions in father history",
                    total_fixed_father_block,
                )
            self.last_pass_nb_patch_done = self.remove_flattening()
        unflat_logger.info(
            "Unflattening at maturity %s pass %s: %s changes",
            self.cur_maturity,
            self.cur_maturity_pass,
            self.last_pass_nb_patch_done,
        )
        nb_clean = mba_deep_cleaning(self.mba, False)
        if self.dump_intermediate_microcode:
            dump_microcode_for_debug(
                self.mba,
                self.log_dir,
                "unflat_{0}_after_cleaning".format(self.cur_maturity_pass),
            )
        if self.last_pass_nb_patch_done + nb_clean + self.non_significant_changes > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
        safe_verify(
            self.mba,
            "optimizing GenericDispatcherUnflatteningRule.optimize",
            logger_func=unflat_logger.error,
        )
        return self.last_pass_nb_patch_done
