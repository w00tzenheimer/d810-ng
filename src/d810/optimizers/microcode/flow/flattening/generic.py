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
import os
from d810.core.typing import Any

import idaapi
import ida_hexrays
import idc

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
from d810.optimizers.microcode.flow.flattening.conditional_exit import (
    classify_exit_block,
    ExitBlockType,
    get_loopback_successor,
    get_exit_successor,
    resolve_loopback_target,
)
from d810.optimizers.microcode.flow.flattening.loop_prover import (
    SingleIterationLoopTracker,
    prove_single_iteration,
)
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule, FlowRulePriority


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

    LAYOUT_SIGNALS:
        maturity (int): Current maturity level
        signals (dict[str, Any]): Aggregated dispatcher layout metrics
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
    # Emitted when dispatcher layout signals are collected
    LAYOUT_SIGNALS = "layout_signals"

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
        self,
        father_history: MopHistory,
        resolve_conditional_exits: bool = False,
        max_emulated_instructions: int = 10000,
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
        nb_emulated = 0
        while cur_blk is not None:
            if cur_ins is None:
                cur_ins = cur_blk.head
            if cur_ins is None:
                break
            should_continue = self.should_emulation_continue(cur_blk)
            # Optional semantic refinement: if we reached a dispatcher exit
            # block that is conditional, execute that conditional as well to
            # recover the concrete successor instead of returning the
            # intermediate 2-way block.
            if not should_continue:
                can_refine_exit = (
                    resolve_conditional_exits
                    and cur_blk.nsucc() == 2
                    and cur_blk.tail is not None
                    and ida_hexrays.is_mcode_jcond(cur_blk.tail.opcode)
                )
                if not can_refine_exit:
                    break
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
            nb_emulated += 1
            if nb_emulated >= int(max_emulated_instructions):
                unflat_logger.warning(
                    "Stopping dispatcher emulation after %d instructions "
                    "(entry=%d, father=%d)",
                    nb_emulated,
                    self.entry_block.serial,
                    father_history.block_serial_path[0]
                    if len(father_history.block_serial_path) > 0
                    else -1,
                )
                break
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

    CATEGORY = "OLLVM Unflattening"
    PRIORITY = FlowRulePriority.UNFLATTEN
    REQUIRES_DISPATCHER_ANALYSIS = True

    # Practical maturities - MMAT_GLBOPT3 is rarely/never called by Hex-Rays.
    # Keep unflattening out of MMAT_CALLS by default because large CFG rewrite
    # batches at that maturity are the most crash-prone in practice.
    DEFAULT_UNFLATTENING_MATURITIES = [
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
        is_calls_maturity = self.mba.maturity == ida_hexrays.MMAT_CALLS
        applied = modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=is_calls_maturity,
            rollback_on_verify_failure=is_calls_maturity,
            continue_on_verify_failure=is_calls_maturity,
        )

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
        if self.flow_context is not None:
            gate = self.flow_context.evaluate_unflattening_gate()
            if not gate.allowed:
                unflat_logger.debug(
                    "Skipping %s via flow context gate: %s",
                    self.__class__.__name__,
                    gate.reason,
                )
                return False
        return True

    @abc.abstractmethod
    def optimize(self, blk):
        """Perform the optimization on *blk* and return the number of changes."""
        raise NotImplementedError


class GenericDispatcherUnflatteningRule(GenericUnflatteningRule):

    CONFIG_SCHEMA = GenericUnflatteningRule.CONFIG_SCHEMA + (
        ConfigParam("max_passes", int, 5, "Maximum optimization passes"),
        ConfigParam("max_duplication_passes", int, 20, "Maximum duplication passes"),
        ConfigParam("min_dispatcher_internal_block", int, 2, "Minimum internal blocks for dispatcher detection"),
        ConfigParam("min_dispatcher_exit_block", int, 2, "Minimum exit blocks for dispatcher detection"),
        ConfigParam("min_dispatcher_comparison_value", int, 2, "Minimum comparison values for dispatcher"),
        ConfigParam(
            "max_calls_entry_preds",
            int,
            24,
            "MMAT_CALLS guard: skip unflattening when dispatcher entry predecessor count exceeds this value",
        ),
        ConfigParam(
            "max_calls_exit_blocks",
            int,
            24,
            "MMAT_CALLS guard: skip unflattening when dispatcher exit block count exceeds this value",
        ),
        ConfigParam(
            "defer_calls_on_conditional_entry_father",
            bool,
            True,
            "MMAT_CALLS guard: defer to later maturities when dispatcher entry has conditional predecessor(s)",
        ),
        ConfigParam(
            "log_calls_layout_signals",
            bool,
            True,
            "Emit detailed MMAT_CALLS dispatcher layout signals for triage",
        ),
        ConfigParam(
            "min_cfg_edges_required",
            int,
            -1,
            "Override deferred CFG-apply minimum resolved edges (<=0 keeps default safeguard heuristic)",
        ),
        ConfigParam(
            "per_function_overrides",
            dict,
            {},
            "Per-function runtime overrides keyed by function EA (e.g. {'0x1de2': {'max_calls_exit_blocks': 500}})",
        ),
        ConfigParam(
            "pre_unflatten_optimize_local_rounds",
            int,
            0,
            "Run bounded optimize_local() rounds before dispatcher collection in each unflatten pass",
        ),
        ConfigParam(
            "pre_unflatten_verify",
            bool,
            True,
            "Run safe_verify() after each pre-unflatten optimize_local() round",
        ),
    )

    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5
    # MMAT_CALLS guard defaults.
    #
    # Why these values exist:
    # - We previously had a blanket MMAT_CALLS disable to stop Hex-Rays crashes,
    #   but that regressed legitimate small dispatcher patterns
    #   (mixed_dispatcher_pattern).
    # - Crash repros showed failures in very "wide" dispatcher graphs where
    #   entry predecessor count and exit-block count are both large.
    # - These thresholds keep MMAT_CALLS enabled for normal/compact cases while
    #   routing only pathological graphs to later maturities (GLBOPT*), where
    #   rewrites are materially more stable.
    #
    # These are defaults (not constants): they are exposed in CONFIG_SCHEMA and
    # can be tuned per project from the GUI/config files.
    DEFAULT_MAX_CALLS_ENTRY_PREDS = 24
    DEFAULT_MAX_CALLS_EXIT_BLOCKS = 24
    DEFAULT_DEFER_CALLS_ON_CONDITIONAL_ENTRY_FATHER = True
    DEFAULT_LOG_CALLS_LAYOUT_SIGNALS = True
    DEFAULT_PRE_UNFLATTEN_OPTIMIZE_LOCAL_ROUNDS = 0
    DEFAULT_PRE_UNFLATTEN_VERIFY = True

    def __init__(self):
        super().__init__()
        self.dispatcher_collector = self.DISPATCHER_COLLECTOR_CLASS()
        self.dispatcher_list = []
        self.max_duplication_passes = self.DEFAULT_MAX_DUPLICATION_PASSES
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.max_calls_entry_preds = self.DEFAULT_MAX_CALLS_ENTRY_PREDS
        self.max_calls_exit_blocks = self.DEFAULT_MAX_CALLS_EXIT_BLOCKS
        self.defer_calls_on_conditional_entry_father = (
            self.DEFAULT_DEFER_CALLS_ON_CONDITIONAL_ENTRY_FATHER
        )
        self.log_calls_layout_signals = self.DEFAULT_LOG_CALLS_LAYOUT_SIGNALS
        self.min_cfg_edges_required = -1
        self.per_function_overrides_by_ea: dict[int, dict[str, Any]] = {}
        self.per_function_overrides_by_name: dict[str, dict[str, Any]] = {}
        self._base_override_values: dict[str, Any] = {}
        self.pre_unflatten_optimize_local_rounds = (
            self.DEFAULT_PRE_UNFLATTEN_OPTIMIZE_LOCAL_ROUNDS
        )
        self.pre_unflatten_verify = self.DEFAULT_PRE_UNFLATTEN_VERIFY
        self.non_significant_changes = 0
        # Track processed (source_block, target) pairs to prevent duplicates
        self._processed_dispatcher_fathers: set[tuple[int, int]] = set()
        # Track deferred direct edge rewrites per dispatcher entry:
        # {dispatcher_entry_serial: {(source_serial, target_serial), ...}}
        # Used for post-apply jtbl overlap canonicalization.
        self._deferred_case_overlap_edges: dict[int, set[tuple[int, int]]] = {}
        # Set when deferred modifier verify fails -- prevents further
        # processing on a corrupted MBA that would cause IDA hangs.
        self._verify_failed: bool = False
        # Last collected dispatcher layout signals (for debug tooling/tests).
        self._last_layout_signals: dict[str, Any] = {}

    @property
    @abc.abstractmethod
    def DISPATCHER_COLLECTOR_CLASS(self) -> type[GenericDispatcherCollector]:
        """Return the class of the dispatcher collector."""
        raise NotImplementedError

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        if self._verify_failed:
            unflat_logger.debug(
                "Skipping rule -- MBA verify previously failed"
            )
            return False
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
        if "max_calls_entry_preds" in self.config.keys():
            self.max_calls_entry_preds = self.config["max_calls_entry_preds"]
        if "max_calls_exit_blocks" in self.config.keys():
            self.max_calls_exit_blocks = self.config["max_calls_exit_blocks"]
        if "defer_calls_on_conditional_entry_father" in self.config.keys():
            self.defer_calls_on_conditional_entry_father = self.config[
                "defer_calls_on_conditional_entry_father"
            ]
        if "log_calls_layout_signals" in self.config.keys():
            self.log_calls_layout_signals = self.config["log_calls_layout_signals"]
        if "min_cfg_edges_required" in self.config.keys():
            self.min_cfg_edges_required = int(self.config["min_cfg_edges_required"])
        (
            self.per_function_overrides_by_ea,
            self.per_function_overrides_by_name,
        ) = self._normalize_per_function_overrides(
            self.config.get("per_function_overrides", {})
        )
        if "pre_unflatten_optimize_local_rounds" in self.config.keys():
            self.pre_unflatten_optimize_local_rounds = int(
                self.config["pre_unflatten_optimize_local_rounds"]
            )
        if "pre_unflatten_verify" in self.config.keys():
            self.pre_unflatten_verify = bool(self.config["pre_unflatten_verify"])
        self._snapshot_base_override_values()
        self.dispatcher_collector.configure(kwargs)

    OVERRIDABLE_ATTRS = (
        "max_passes",
        "max_duplication_passes",
        "max_calls_entry_preds",
        "max_calls_exit_blocks",
        "defer_calls_on_conditional_entry_father",
        "log_calls_layout_signals",
        "min_cfg_edges_required",
        "pre_unflatten_optimize_local_rounds",
        "pre_unflatten_verify",
        "max_exit_blocks_for_additional_passes",
    )

    def _snapshot_base_override_values(self) -> None:
        self._base_override_values = {}
        for attr_name in self.OVERRIDABLE_ATTRS:
            if hasattr(self, attr_name):
                self._base_override_values[attr_name] = getattr(self, attr_name)

    @staticmethod
    def _parse_function_ea(value: Any) -> int | None:
        try:
            if isinstance(value, str):
                text = value.strip()
                if text.startswith(("0x", "0X")):
                    return int(text, 16)
                return int(text, 10)
            return int(value)
        except (TypeError, ValueError):
            return None

    def _normalize_per_function_overrides(
        self, raw: Any
    ) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]]]:
        if not isinstance(raw, dict):
            return {}, {}
        normalized_ea: dict[int, dict[str, Any]] = {}
        normalized_name: dict[str, dict[str, Any]] = {}
        for raw_ea, raw_override in raw.items():
            if not isinstance(raw_override, dict):
                continue
            ea = self._parse_function_ea(raw_ea)
            if ea is not None:
                normalized_ea[ea] = dict(raw_override)
                continue
            key_name = str(raw_ea).strip().lower()
            if key_name:
                normalized_name[key_name] = dict(raw_override)
        return normalized_ea, normalized_name

    def _apply_function_overrides(self) -> None:
        # Reset to configured base values first so one function's overrides do
        # not leak into another function on the shared rule instance.
        for attr_name, attr_value in self._base_override_values.items():
            setattr(self, attr_name, attr_value)

        if self.mba is None:
            return
        func_ea = int(getattr(self.mba, "entry_ea", 0) or 0)
        merged_override: dict[str, Any] = {}
        exact_override = self.per_function_overrides_by_ea.get(func_ea)
        if exact_override:
            merged_override.update(exact_override)

        try:
            imagebase = int(idaapi.get_imagebase())
        except Exception:
            imagebase = 0
        if imagebase:
            rebase_ea = func_ea - imagebase
            if rebase_ea >= 0:
                rebase_override = self.per_function_overrides_by_ea.get(rebase_ea)
                if rebase_override:
                    merged_override.update(rebase_override)

        func_name = str(idc.get_func_name(func_ea) or "").strip()
        if func_name:
            name_override = self.per_function_overrides_by_name.get(func_name.lower())
            if name_override:
                merged_override.update(name_override)
            if func_name.startswith("_"):
                stripped_override = self.per_function_overrides_by_name.get(
                    func_name[1:].lower()
                )
                if stripped_override:
                    merged_override.update(stripped_override)

        if not merged_override:
            return
        for attr_name, attr_value in merged_override.items():
            if hasattr(self, attr_name):
                setattr(self, attr_name, attr_value)
        if unflat_logger.debug_on:
            unflat_logger.debug(
                "Applied per-function overrides for 0x%x: %s",
                func_ea,
                sorted(merged_override.keys()),
            )

    def _run_pre_unflatten_local_optimization(self) -> int:
        rounds = int(max(0, self.pre_unflatten_optimize_local_rounds))
        if rounds <= 0:
            return 0
        total_changes = 0
        for round_index in range(rounds):
            nb_changes = int(self.mba.optimize_local(0))
            if nb_changes <= 0:
                break
            total_changes += nb_changes
            if self.pre_unflatten_verify:
                safe_verify(
                    self.mba,
                    "pre-unflatten optimize_local round %d (%s)" % (
                        round_index + 1,
                        self.__class__.__name__,
                    ),
                    logger_func=unflat_logger.error,
                )
        if total_changes > 0:
            self.mba.mark_chains_dirty()
            unflat_logger.info(
                "Pre-unflatten local optimization applied %d change(s) at maturity %s pass %s",
                total_changes,
                self.cur_maturity,
                self.cur_maturity_pass,
            )
        return total_changes

    def should_skip_pass_for_layout(
        self, layout_signals: dict[str, Any]
    ) -> tuple[bool, str | None]:
        """Optional per-rule guard to skip risky passes based on layout shape.

        Subclasses can override this to reject a pass (typically pass>0) when
        dispatcher topology is known to be unstable for that rule.
        """
        return False, None

    def _collect_dispatcher_layout_signals(self) -> dict[str, Any]:
        """Collect dispatcher layout signals used by MMAT_CALLS gating.

        Why this exists:
        - Our recent regressions were driven by CFG *shape* more than raw size.
        - `high_fan_in_pattern` / `switch_case_ollvm_pattern` share this trait:
          dispatcher entry has a conditional predecessor requiring brittle
          MMAT_CALLS rewrites.
        - `mixed_dispatcher_pattern` does not share that entry-father shape and
          is stable at MMAT_CALLS.

        Signal semantics used by this rule:
        - ``max_entry_preds``:
          upper bound used by the wide-dispatcher guard.
        - ``max_exit_blocks``:
          upper bound used by the wide-dispatcher guard.
        - ``has_conditional_entry_father``:
          shape guard for brittle MMAT_CALLS rewrites where dispatcher entry
          is fed by a 2-way conditional predecessor.
        - ``dispatchers``:
          per-dispatcher detail retained for triage/debug tooling.

        The returned structure is intentionally JSON-like (plain ints/lists/dicts)
        so it can be logged, emitted via events, or persisted by tooling.
        """
        per_dispatcher: list[dict[str, Any]] = []
        for dispatcher_info in self.dispatcher_list:
            entry_blk = (
                dispatcher_info.entry_block.blk
                if dispatcher_info.entry_block is not None
                else None
            )
            if entry_blk is None:
                continue
            pred_serials = [int(x) for x in entry_blk.predset]
            conditional_entry_preds: list[int] = []
            for pred_serial in pred_serials:
                pred_blk = self.mba.get_mblock(pred_serial)
                if (
                    pred_blk is not None
                    and pred_blk.nsucc() == 2
                    and pred_blk.tail is not None
                    and pred_blk.tail.opcode in CONDITIONAL_JUMP_OPCODES
                ):
                    conditional_entry_preds.append(pred_serial)
            per_dispatcher.append(
                {
                    "entry_block": int(entry_blk.serial),
                    "entry_pred_count": len(pred_serials),
                    "entry_preds": pred_serials,
                    "conditional_entry_preds": conditional_entry_preds,
                    "internal_block_count": len(dispatcher_info.dispatcher_internal_blocks),
                    "exit_block_count": len(dispatcher_info.dispatcher_exit_blocks),
                }
            )

        signals: dict[str, Any] = {
            "dispatcher_count": len(per_dispatcher),
            "max_entry_preds": max(
                (item["entry_pred_count"] for item in per_dispatcher),
                default=0,
            ),
            "max_exit_blocks": max(
                (item["exit_block_count"] for item in per_dispatcher),
                default=0,
            ),
            "max_internal_blocks": max(
                (item["internal_block_count"] for item in per_dispatcher),
                default=0,
            ),
            "has_conditional_entry_father": any(
                item["conditional_entry_preds"] for item in per_dispatcher
            ),
            "dispatchers": per_dispatcher,
        }
        return signals

    def _emit_layout_signals(self, signals: dict[str, Any]) -> None:
        """Emit layout signals via logs and event bus for downstream tooling."""
        self._last_layout_signals = signals
        self.events.emit(
            UnflatteningEvent.LAYOUT_SIGNALS,
            maturity=int(self.mba.maturity),
            signals=signals,
            optimizer=self,
        )
        if not self.log_calls_layout_signals:
            return
        unflat_logger.info(
            "Dispatcher layout signals (maturity=%s): dispatchers=%d "
            "max_entry_preds=%d max_exit_blocks=%d max_internal_blocks=%d "
            "has_conditional_entry_father=%s",
            self.mba.maturity,
            signals["dispatcher_count"],
            signals["max_entry_preds"],
            signals["max_exit_blocks"],
            signals["max_internal_blocks"],
            signals["has_conditional_entry_father"],
        )
        for item in signals["dispatchers"]:
            unflat_logger.info(
                "  layout entry_blk=%d preds=%s conditional_preds=%s internal=%d exits=%d",
                item["entry_block"],
                item["entry_preds"],
                item["conditional_entry_preds"],
                item["internal_block_count"],
                item["exit_block_count"],
            )

    # Maximum blocks for which retrieve_all_dispatchers will attempt
    # full exploration.  Beyond this, the dispatcher search is skipped
    # to prevent quadratic/exponential blowup in subsequent analysis.
    MAX_BLOCKS_FOR_DISPATCHER_SEARCH = 400

    def retrieve_all_dispatchers(self):
        self.dispatcher_list = []
        if self.mba.qty > self.MAX_BLOCKS_FOR_DISPATCHER_SEARCH:
            unflat_logger.warning(
                "Skipping dispatcher search: MBA has %d blocks (limit %d)",
                self.mba.qty,
                self.MAX_BLOCKS_FOR_DISPATCHER_SEARCH,
            )
            return
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
                    dispatcher_father, dispatcher_info.entry_block.blk, verify=False
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
                dispatcher_father, dispatcher_info.entry_block.blk, verify=False
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

    # Maximum number of histories allowed per dispatcher father before
    # we skip duplication.  Beyond this threshold duplicate_histories()
    # becomes prohibitively expensive (exponential block creation).
    MAX_HISTORIES_PER_FATHER = 100

    def _is_past_deadline(self) -> bool:
        """Check if the current optimize() call has exceeded its time budget."""
        import time as _time
        deadline = getattr(self, '_optimize_deadline', None)
        return deadline is not None and _time.monotonic() > deadline

    def ensure_dispatcher_father_is_resolvable(
        self,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_entry_block: GenericDispatcherBlockInfo,
        dispatcher_info: GenericDispatcherInfo,
    ) -> int:
        if self._is_past_deadline():
            unflat_logger.warning(
                "ensure_dispatcher_father_is_resolvable: time budget exceeded, skipping"
            )
            return 0

        father_histories = self.get_dispatcher_father_histories(
            dispatcher_father, dispatcher_entry_block, dispatcher_info
        )

        if len(father_histories) > self.MAX_HISTORIES_PER_FATHER:
            unflat_logger.warning(
                "Skipping father blk %d: %d histories exceed limit %d",
                dispatcher_father.serial,
                len(father_histories),
                self.MAX_HISTORIES_PER_FATHER,
            )
            return 0

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

    def _collect_instruction_uses_defs(
        self, ins: ida_hexrays.minsn_t
    ) -> tuple[list[ida_hexrays.mop_t], list[ida_hexrays.mop_t]]:
        """Collect unresolved uses and defs for one instruction."""
        # Some unit/runtime tests feed generic mocks as "instructions".
        # Running DefUse collection on those can cross into SWIG-backed helpers
        # with invalid objects and crash the process.
        # Treat non-IDA/mock instructions as side-effect opaque: no def/use info.
        if ins.__class__.__module__.startswith("unittest.mock"):
            return [], []
        collector = InstructionDefUseCollector()
        ins.for_all_ops(collector)
        uses = (
            remove_segment_registers(collector.unresolved_ins_mops)
            + collector.memory_unresolved_ins_mops
        )
        defs = collector.target_mops
        return uses, defs

    def _collect_block_liveins_and_defs(
        self, blk: ida_hexrays.mblock_t
    ) -> tuple[list[ida_hexrays.mop_t], list[ida_hexrays.mop_t]]:
        """Collect source-block live-ins (use-before-def) and defs."""
        if blk.__class__.__module__.startswith("unittest.mock"):
            return [], []
        liveins: list[ida_hexrays.mop_t] = []
        defs: list[ida_hexrays.mop_t] = []
        cur_ins = blk.head
        while cur_ins is not None:
            if cur_ins.__class__.__module__.startswith("unittest.mock"):
                break
            ins_uses, ins_defs = self._collect_instruction_uses_defs(cur_ins)
            for ins_use in ins_uses:
                if get_mop_index(ins_use, defs) == -1:
                    append_mop_if_not_in_list(ins_use, liveins)
            for ins_def in ins_defs:
                append_mop_if_not_in_list(ins_def, defs)
            cur_ins = cur_ins.next
        return liveins, defs

    def _record_deferred_case_overlap_edge(
        self,
        dispatcher_entry_serial: int,
        source_serial: int,
        target_serial: int,
    ) -> None:
        edges = self._deferred_case_overlap_edges.setdefault(
            int(dispatcher_entry_serial), set()
        )
        edges.add((int(source_serial), int(target_serial)))

    @staticmethod
    def _serial_in_set(serial_set, serial: int) -> bool:
        for cur in serial_set:
            if int(cur) == int(serial):
                return True
        return False

    def _canonicalize_jtbl_cross_case_overlaps(self) -> int:
        """Retarget overlapping jtbl entries to avoid shared case-entry headers.

        Deferred rewrites can create edges from one switch case target to
        another. If both remain direct jtbl targets, Hex-Rays may crash while
        structuring due to shared case-entry headers. This post-pass rewrites
        only overlaps introduced by this pass.
        """
        if not self._deferred_case_overlap_edges:
            return 0

        total_case_retargets = 0
        for dispatcher_serial, rewrite_edges in self._deferred_case_overlap_edges.items():
            dispatcher_blk = self.mba.get_mblock(dispatcher_serial)
            if dispatcher_blk is None or dispatcher_blk.tail is None:
                continue
            if dispatcher_blk.tail.opcode != ida_hexrays.m_jtbl:
                continue
            if (
                dispatcher_blk.tail.r is None
                or dispatcher_blk.tail.r.t != ida_hexrays.mop_c
                or dispatcher_blk.tail.r.c is None
            ):
                continue

            cases = dispatcher_blk.tail.r.c
            targets = cases.targets
            if targets is None:
                continue

            old_target_set: set[int] = set()
            target_to_indices: dict[int, list[int]] = {}
            for i in range(targets.size()):
                target_serial = int(targets[i])
                old_target_set.add(target_serial)
                target_to_indices.setdefault(target_serial, []).append(i)
            if not old_target_set:
                continue

            dispatcher_changed = False
            case_targets = set(old_target_set)
            for target_serial in sorted(old_target_set):
                target_blk = self.mba.get_mblock(target_serial)
                if target_blk is None:
                    continue

                overlap_preds: list[int] = []
                for pred_serial in target_blk.predset:
                    pred_serial_int = int(pred_serial)
                    if pred_serial_int in (dispatcher_serial, target_serial):
                        continue
                    if pred_serial_int not in case_targets:
                        continue
                    pred_blk = self.mba.get_mblock(pred_serial_int)
                    if pred_blk is None:
                        continue
                    if not self._serial_in_set(pred_blk.succset, target_serial):
                        continue
                    overlap_preds.append(pred_serial_int)

                if not overlap_preds:
                    continue

                # Canonicalize only overlaps introduced by the current pass.
                rewritten_overlap_preds = [
                    pred
                    for pred in overlap_preds
                    if (pred, target_serial) in rewrite_edges
                ]
                if not rewritten_overlap_preds:
                    continue

                chosen_pred = min(rewritten_overlap_preds)
                rewired_count = 0
                for idx in target_to_indices.get(target_serial, []):
                    if int(targets[idx]) == chosen_pred:
                        continue
                    targets[idx] = chosen_pred
                    rewired_count += 1

                if rewired_count == 0:
                    continue

                dispatcher_changed = True
                total_case_retargets += rewired_count
                unflat_logger.warning(
                    "Canonicalized jtbl overlap in dispatcher %d: "
                    "retargeted %d case(s) %d -> %d (overlap_preds=%s)",
                    dispatcher_serial,
                    rewired_count,
                    target_serial,
                    chosen_pred,
                    sorted(overlap_preds),
                )

            if not dispatcher_changed:
                continue

            new_target_set = set(int(targets[i]) for i in range(targets.size()))

            removed_targets = sorted(old_target_set - new_target_set)
            for removed_target in removed_targets:
                if self._serial_in_set(dispatcher_blk.succset, removed_target):
                    dispatcher_blk.succset._del(removed_target)
                removed_blk = self.mba.get_mblock(removed_target)
                if removed_blk is not None and self._serial_in_set(
                    removed_blk.predset, dispatcher_serial
                ):
                    removed_blk.predset._del(dispatcher_serial)
                    removed_blk.mark_lists_dirty()

            added_targets = sorted(new_target_set - old_target_set)
            for added_target in added_targets:
                if not self._serial_in_set(dispatcher_blk.succset, added_target):
                    dispatcher_blk.succset.push_back(added_target)
                added_blk = self.mba.get_mblock(added_target)
                if added_blk is not None and not self._serial_in_set(
                    added_blk.predset, dispatcher_serial
                ):
                    added_blk.predset.push_back(dispatcher_serial)
                    added_blk.mark_lists_dirty()

            dispatcher_blk.mark_lists_dirty()

        if total_case_retargets > 0:
            self.mba.mark_chains_dirty()
        return total_case_retargets

    def _filter_dependency_safe_copies(
        self,
        source_blk: ida_hexrays.mblock_t,
        instructions_to_copy: list[ida_hexrays.minsn_t],
    ) -> list[ida_hexrays.minsn_t]:
        """Keep only copied instructions whose uses are available at source.

        `BLOCK_CREATE_WITH_REDIRECT` inserts copied dispatcher instructions on a
        new edge out of `source_blk`. If a copied instruction reads a mop that
        is only produced inside dispatcher internals (and therefore absent on
        this edge), Hex-Rays verify can fail (for example INTERR 50860).

        We conservatively allow only instructions whose uses are satisfied by:
        1. source block live-ins,
        2. source block defs,
        3. defs produced by previously-accepted copied instructions.

        Why this exists (root-cause context):
        - In MMAT_CALLS we observed verify failures (INTERR 50860 / unknown
          exception) after queueing BLOCK_CREATE_WITH_REDIRECT for some
          dispatcher fathers.
        - The created helper block was CFG-correct but carried copied
          instructions that read mops unavailable on the new edge.
        - Hex-Rays verify rejects that dataflow shape, and continuing from that
          state may lead to downstream corruption/segfaults in later pipeline
          stages.

        This filter intentionally prefers safety over aggressiveness: if we
        cannot prove copied instruction dependencies are available at insertion,
        we do not copy that instruction.
        """
        if not instructions_to_copy:
            return []

        source_liveins, source_defs = self._collect_block_liveins_and_defs(source_blk)

        available: list[ida_hexrays.mop_t] = []
        for source_mop in source_liveins:
            append_mop_if_not_in_list(source_mop, available)
        for source_mop in source_defs:
            append_mop_if_not_in_list(source_mop, available)

        safe_copy_insns: list[ida_hexrays.minsn_t] = []
        dropped_count = 0
        for ins in instructions_to_copy:
            ins_uses, ins_defs = self._collect_instruction_uses_defs(ins)
            missing_uses = [used for used in ins_uses if get_mop_index(used, available) == -1]
            if missing_uses:
                dropped_count += 1
                if unflat_logger.debug_on:
                    unflat_logger.debug(
                        "Dropping unsafe copied instruction in blk %d: %s (missing=%s)",
                        source_blk.serial,
                        format_minsn_t(ins),
                        format_mop_list(missing_uses),
                    )
                continue
            safe_copy_insns.append(ins)
            for ins_def in ins_defs:
                append_mop_if_not_in_list(ins_def, available)

        if dropped_count > 0:
            unflat_logger.info(
                "Dropped %d/%d copied instruction(s) for blk %d due to missing producers",
                dropped_count,
                len(instructions_to_copy),
                source_blk.serial,
            )

        return safe_copy_insns

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
            dispatcher_father_histories[0],
            resolve_conditional_exits=True,
        )
        if target_blk is not None:
            watch_edge_raw = os.environ.get("D810_DEFERRED_WATCH_EDGE", "").strip()
            if watch_edge_raw and ":" in watch_edge_raw:
                try:
                    watch_src_s, watch_dst_s = watch_edge_raw.split(":", 1)
                    watch_src = int(watch_src_s, 0)
                    watch_dst = int(watch_dst_s, 0)
                except ValueError:
                    watch_src = -1
                    watch_dst = -1
                if (
                    dispatcher_father.serial == watch_src
                    and target_blk.serial == watch_dst
                ):
                    unflat_logger.warning(
                        "DEBUG WATCH resolve_dispatcher_father hit edge %d -> %d "
                        "(father_path=%s, target_type=%d nsucc=%d tail_opcode=%s)",
                        dispatcher_father.serial,
                        target_blk.serial,
                        dispatcher_father_histories[0].block_serial_path,
                        target_blk.type,
                        target_blk.nsucc(),
                        target_blk.tail.opcode if target_blk.tail else None,
                    )

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
            raw_ins_to_copy = [
                ins
                for ins in disp_ins
                if ((ins is not None) and (ins.opcode not in CONTROL_FLOW_OPCODES))
            ]
            # MMAT_CALLS safety rule:
            # If this rewrite requires replaying dispatcher side-effect
            # instructions (create+redirect path), defer it to later maturities.
            #
            # Rationale:
            # - We have observed cases where MMAT_CALLS accepts the immediate
            #   deferred modification sequence (incremental verify succeeds) but
            #   Hex-Rays later crashes during full decompilation.
            # - Those cases involved repeated BLOCK_CREATE_WITH_REDIRECT with
            #   copied side-effect instructions in flattened while/switch and
            #   nested-shared-block layouts.
            # - At later maturities (GLBOPT*), the same structural rewrites are
            #   materially more stable.
            #
            # Therefore, MMAT_CALLS only handles direct edge rewrites that do
            # not require instruction replay; side-effect-carrying rewrites are
            # intentionally deferred.
            if (
                self.mba.maturity == ida_hexrays.MMAT_CALLS
                and len(raw_ins_to_copy) > 0
            ):
                unflat_logger.info(
                    "Skipping side-effect create+redirect for blk %d at MMAT_CALLS; "
                    "deferring to later maturities",
                    dispatcher_father.serial,
                )
                return 0
            # Copying dispatcher instructions onto a new edge is only valid when
            # their producer dependencies exist at the insertion point.
            ins_to_copy = self._filter_dependency_safe_copies(
                dispatcher_father, raw_ins_to_copy
            )
            # If dispatcher simulation says side effects are required but none
            # can be safely materialized at this insertion point, do not force
            # a redirect. Forcing a plain goto in this case can produce invalid
            # MMAT_CALLS MBA state (verify failure) because the target path may
            # depend on those side effects.
            #
            # Important: "no safe copy" is not equivalent to "no side effects".
            # It means "required side effects exist but cannot be replayed here
            # without broken dependencies". In that case, the least harmful
            # action at MMAT_CALLS is to skip this father rewrite and let later
            # maturities attempt safer restructuring.
            if len(raw_ins_to_copy) > 0 and len(ins_to_copy) == 0:
                unflat_logger.info(
                    "Skipping rewrite for blk %d at maturity %s: required dispatcher "
                    "side effects are not dependency-safe to copy",
                    dispatcher_father.serial,
                    self.mba.maturity,
                )
                return 0

            # Check if this is a conditional exit block that needs special handling
            dispatcher_blk_serials_set = {
                blk_info.serial for blk_info in dispatcher_info.dispatcher_internal_blocks
            }
            exit_type = classify_exit_block(dispatcher_father, dispatcher_blk_serials_set)

            # Handle conditional exit blocks (one path loops back, one exits)
            if exit_type == ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK and deferred_modifier is not None:
                loopback_serial = get_loopback_successor(dispatcher_father, dispatcher_blk_serials_set)
                exit_serial = get_exit_successor(dispatcher_father, dispatcher_blk_serials_set)

                if loopback_serial is not None and exit_serial is not None:
                    # Try to resolve where the loopback path actually leads
                    loopback_result = resolve_loopback_target(
                        dispatcher_father,
                        loopback_serial,
                        dispatcher_info,
                        dispatcher_info.mop_compared
                    )

                    if loopback_result is not None:
                        resolved_target, state_value = loopback_result

                        # Successfully resolved both paths - use conditional redirect
                        unflat_logger.info(
                            "Detected conditional exit block %d: loopback->blk%d (state=0x%x), exit->blk%d",
                            dispatcher_father.serial,
                            resolved_target,
                            state_value,
                            exit_serial
                        )

                        deferred_modifier.queue_create_conditional_redirect(
                            source_blk_serial=dispatcher_father.serial,
                            ref_blk_serial=dispatcher_father.serial,
                            conditional_target_serial=resolved_target,
                            fallthrough_target_serial=exit_serial,
                            description=f"Conditional exit: loopback->blk{resolved_target} (state=0x{state_value:x}), exit->blk{exit_serial}"
                        )

                        # Skip the normal 1-way redirect logic below
                        return 2
                    else:
                        unflat_logger.debug(
                            "Conditional exit block %d: could not resolve loopback target, falling back to 1-way redirect",
                            dispatcher_father.serial
                        )
                else:
                    unflat_logger.debug(
                        "Conditional exit block %d: missing loopback or exit successor, falling back to 1-way redirect",
                        dispatcher_father.serial
                    )

            if deferred_modifier is not None:
                queued_change = False
                source_nsucc = dispatcher_father.nsucc()
                tail_opcode = dispatcher_father.tail.opcode if dispatcher_father.tail else None
                copy_insns = ins_to_copy

                # Use deferred CFG modifications
                if len(copy_insns) > 0:
                    if source_nsucc != 1:
                        # create_and_redirect rewires a single outgoing edge.
                        # Skip non-1way sources to avoid queuing invalid edits
                        # that fail deferred apply and poison the pass.
                        unflat_logger.warning(
                            "Skipping create_and_redirect for non-1way father blk %d "
                            "(nsucc=%d) toward blk %d",
                            dispatcher_father.serial,
                            source_nsucc,
                            target_blk.serial,
                        )
                    else:
                        unflat_logger.info(
                            "Queuing create_and_redirect: %s instructions from block %s -> %s",
                            len(copy_insns),
                            dispatcher_father.serial,
                            target_blk.serial,
                        )
                        deferred_modifier.queue_create_and_redirect(
                            source_block_serial=dispatcher_father.serial,
                            final_target_serial=target_blk.serial,
                            instructions_to_copy=copy_insns,
                            is_0_way=(target_blk.type == ida_hexrays.BLT_0WAY),
                            description=f"resolve_dispatcher_father {dispatcher_father.serial} -> {target_blk.serial}",
                        )
                        queued_change = True
                else:
                    if source_nsucc == 1:
                        clone_conditional_targets = (
                            os.environ.get("D810_UNFLAT_CLONE_COND_TARGET", "").strip().lower()
                            in ("1", "true", "yes", "on")
                        )
                        # When the resolved target is itself a conditional 2-way
                        # block, redirecting many new predecessors directly into
                        # that shared block can produce unstable CFGs for some
                        # large flattened functions (AntiDebug case). Instead,
                        # clone the conditional shape and redirect the father to
                        # the clone, following the same proven pattern used by
                        # FixPredecessorOfConditionalJumpBlock.
                        target_is_conditional = (
                            target_blk.nsucc() == 2
                            and target_blk.tail is not None
                            and ida_hexrays.is_mcode_jcond(target_blk.tail.opcode)
                            and target_blk.nextb is not None
                        )
                        if target_is_conditional and clone_conditional_targets:
                            cond_target_serial = int(target_blk.tail.d.b)
                            fallthrough_target_serial = int(target_blk.nextb.serial)
                            unflat_logger.info(
                                "Queuing conditional redirect clone: father %s via ref %s "
                                "(jcc->%s, fallthrough->%s)",
                                dispatcher_father.serial,
                                target_blk.serial,
                                cond_target_serial,
                                fallthrough_target_serial,
                            )
                            deferred_modifier.queue_create_conditional_redirect(
                                source_blk_serial=dispatcher_father.serial,
                                ref_blk_serial=target_blk.serial,
                                conditional_target_serial=cond_target_serial,
                                fallthrough_target_serial=fallthrough_target_serial,
                                description=(
                                    "resolve_dispatcher_father(cond-clone) "
                                    f"{dispatcher_father.serial} -> ref {target_blk.serial} "
                                    f"(jcc:{cond_target_serial}, ft:{fallthrough_target_serial})"
                                ),
                            )
                            queued_change = True
                        else:
                            # [SAFETY] Triangle check:
                            # If target is conditional AND a direct dispatcher successor,
                            # enforce a trampoline to break the "Switch Case -> Switch Case" edge.
                            #
                            # This prevents Hex-Rays crashes (INTERR/segfault) caused by
                            # "Triangle with Shared Conditional Header" topology where a
                            # conditional block is entered both from the switch (as a case)
                            # and from another case block (via unflattening).
                            is_target_in_dispatcher = False
                            dispatcher_head = dispatcher_info.entry_block.blk
                            if dispatcher_head:
                                for i in range(dispatcher_head.nsucc()):
                                    if dispatcher_head.succ(i) == target_blk.serial:
                                        is_target_in_dispatcher = True
                                        break

                            # We use a relaxed definition of conditional here (ignoring nextb requirement)
                            # because create_and_redirect works fine even for the last block.
                            is_risky_conditional = (
                                target_blk.nsucc() == 2
                                and target_blk.tail is not None
                                and ida_hexrays.is_mcode_jcond(target_blk.tail.opcode)
                            )

                            if is_risky_conditional and is_target_in_dispatcher:
                                unflat_logger.info(
                                    "Queuing trampoline for triangle edge: block %s -> %s",
                                    dispatcher_father.serial,
                                    target_blk.serial,
                                )
                                nop = ida_hexrays.minsn_t(dispatcher_father.tail.ea)
                                nop.opcode = ida_hexrays.m_nop
                                deferred_modifier.queue_create_and_redirect(
                                    source_block_serial=dispatcher_father.serial,
                                    final_target_serial=target_blk.serial,
                                    instructions_to_copy=[nop],
                                    is_0_way=(target_blk.type == ida_hexrays.BLT_0WAY),
                                    description=f"resolve_dispatcher_father(trampoline) {dispatcher_father.serial} -> {target_blk.serial}",
                                )
                                queued_change = True
                            else:
                                unflat_logger.info(
                                    "Queuing goto change: block %s -> %s",
                                    dispatcher_father.serial,
                                    target_blk.serial,
                                )
                                self._record_deferred_case_overlap_edge(
                                    dispatcher_info.entry_block.serial,
                                    dispatcher_father.serial,
                                    target_blk.serial,
                                )
                                deferred_modifier.queue_goto_change(
                                    block_serial=dispatcher_father.serial,
                                    new_target=target_blk.serial,
                                    description=f"resolve_dispatcher_father {dispatcher_father.serial} -> {target_blk.serial}",
                                    rule_priority=100,  # High priority - proven constant analysis
                                )
                                queued_change = True
                    elif source_nsucc == 2 and tail_opcode in CONDITIONAL_JUMP_OPCODES:
                        unflat_logger.info(
                            "Queuing convert_to_goto for conditional father: block %s -> %s",
                            dispatcher_father.serial,
                            target_blk.serial,
                        )
                        self._record_deferred_case_overlap_edge(
                            dispatcher_info.entry_block.serial,
                            dispatcher_father.serial,
                            target_blk.serial,
                        )
                        deferred_modifier.queue_convert_to_goto(
                            block_serial=dispatcher_father.serial,
                            goto_target=target_blk.serial,
                            description=(
                                "resolve_dispatcher_father(convert) "
                                f"{dispatcher_father.serial} -> {target_blk.serial}"
                            ),
                        )
                        queued_change = True
                    else:
                        unflat_logger.warning(
                            "Skipping father rewrite for blk %d: nsucc=%d opcode=%s target=%d",
                            dispatcher_father.serial,
                            source_nsucc,
                            tail_opcode,
                            target_blk.serial,
                        )
                if not queued_change:
                    return 0
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
                        block_to_copy, ins_to_copy, is_0_way=(target_blk.type == ida_hexrays.BLT_0WAY), verify=False
                    )
                    if dispatcher_father.nsucc() != 1:
                        unflat_logger.warning(
                            "Skipping legacy create_and_redirect for non-1way father blk %d (nsucc=%d)",
                            dispatcher_father.serial,
                            dispatcher_father.nsucc(),
                        )
                        return 0
                    change_1way_block_successor(
                        dispatcher_father, dispatcher_side_effect_blk.serial, verify=False
                    )
                    change_1way_block_successor(
                        dispatcher_side_effect_blk, target_blk.serial, verify=False
                    )
                else:
                    if dispatcher_father.nsucc() == 1:
                        change_1way_block_successor(dispatcher_father, target_blk.serial, verify=False)
                    else:
                        unflat_logger.warning(
                            "Skipping legacy rewrite for non-1way father blk %d (nsucc=%d)",
                            dispatcher_father.serial,
                            dispatcher_father.nsucc(),
                        )
                        return 0
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
        if self._is_past_deadline():
            unflat_logger.warning(
                "fix_fathers_from_mop_history: time budget exceeded, skipping"
            )
            return 0

        father_histories = self.get_dispatcher_father_histories(
            dispatcher_father, dispatcher_entry_block, dispatcher_info
        )

        if len(father_histories) > self.MAX_HISTORIES_PER_FATHER:
            unflat_logger.warning(
                "fix_fathers: skipping father blk %d: %d histories exceed limit %d",
                dispatcher_father.serial,
                len(father_histories),
                self.MAX_HISTORIES_PER_FATHER,
            )
            return 0

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

    # Maximum cumulative blocks that may be created by duplicate_histories()
    # across all dispatcher fathers in a single remove_flattening() pass.
    MAX_CUMULATIVE_DUPLICATIONS = 500

    def remove_flattening(self) -> int:
        total_nb_change = 0
        self.non_significant_changes = ensure_last_block_is_goto(self.mba, verify=False)
        self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()

        # Reset tracking for this optimization pass
        self._processed_dispatcher_fathers.clear()
        self._deferred_case_overlap_edges.clear()

        # Create deferred modifier for all resolve_dispatcher_father operations
        deferred_modifier = DeferredGraphModifier(self.mba)

        total_duplications = 0
        duplication_budget_exceeded = False

        for dispatcher_info in self.dispatcher_list:
            if duplication_budget_exceeded:
                break
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
            previous_block_count = self.mba.qty
            for dispatcher_father in dispatcher_father_list:
                if dispatcher_father is None:
                    continue

                try:
                    total_nb_change += self.ensure_dispatcher_father_is_resolvable(
                        dispatcher_father, dispatcher_info.entry_block, dispatcher_info
                    )
                except NotDuplicableFatherException as e:
                    unflat_logger.warning(e)
                    pass

                # Track cumulative block creation and enforce budget
                current_block_count = self.mba.qty
                total_duplications += max(0, current_block_count - previous_block_count)
                previous_block_count = current_block_count
                if total_duplications > self.MAX_CUMULATIVE_DUPLICATIONS:
                    unflat_logger.warning(
                        "Cumulative duplication budget exceeded (%d blocks created, "
                        "limit %d), stopping further duplication",
                        total_duplications,
                        self.MAX_CUMULATIVE_DUPLICATIONS,
                    )
                    duplication_budget_exceeded = True
                    break
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
                if dispatcher_father is None:
                    continue
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
            from d810.optimizers.microcode.flow.flattening.safeguards import should_apply_cfg_modifications
            num_redirected = len(deferred_modifier.modifications)
            total_exit_blocks = sum(
                len(d.dispatcher_exit_blocks) for d in self.dispatcher_list
            )
            min_cfg_edges_required = (
                self.min_cfg_edges_required
                if int(self.min_cfg_edges_required) > 0
                else None
            )
            if not should_apply_cfg_modifications(
                num_redirected,
                total_exit_blocks,
                "generic",
                min_required_override=min_cfg_edges_required,
            ):
                deferred_modifier.reset()
            else:
                unflat_logger.info(
                    "Applying %d deferred CFG modifications from resolve_dispatcher_father",
                    len(deferred_modifier.modifications),
                )
                deferred_modifier.apply(
                    run_optimize_local=False,
                    run_deep_cleaning=False,
                    verify_each_mod=(self.mba.maturity == ida_hexrays.MMAT_CALLS),
                    rollback_on_verify_failure=(self.mba.maturity == ida_hexrays.MMAT_CALLS),
                    continue_on_verify_failure=(self.mba.maturity == ida_hexrays.MMAT_CALLS),
                    defer_post_apply_maintenance=True,
                )
                if not deferred_modifier.verify_failed:
                    unflat_logger.info(
                        "Post-apply jtbl overlap scan: %d dispatcher edge-set(s)",
                        len(self._deferred_case_overlap_edges),
                    )
                    canonicalized_cases = self._canonicalize_jtbl_cross_case_overlaps()
                    if canonicalized_cases > 0:
                        unflat_logger.info(
                            "Applied jtbl overlap canonicalization: %d case target retarget(s)",
                            canonicalized_cases,
                        )
                        safe_verify(
                            self.mba,
                            "after jtbl cross-case overlap canonicalization",
                            logger_func=unflat_logger.error,
                        )
                        total_nb_change += canonicalized_cases
                    # DeferredGraphModifier maintenance is deferred so we can
                    # canonicalize switch-case overlaps first.
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                    safe_verify(
                        self.mba,
                        "after deferred modifications (generic post-maintenance)",
                        logger_func=unflat_logger.error,
                    )

            if deferred_modifier.verify_failed:
                self._verify_failed = True
                unflat_logger.warning(
                    "MBA verify failed after %d deferred modifications in "
                    "remove_flattening -- aborting this pass to prevent "
                    "IDA from continuing with a corrupted MBA",
                    len(deferred_modifier.modifications),
                )
                # Return what we have so IDA knows the MBA was modified,
                # but skip further processing that would compound corruption.
                total_nb_change += nb_flattened_branches
                return total_nb_change

        # Scan for residual single-iteration loops and record for cleanup
        loops_found = self.scan_for_single_iteration_loops()
        if loops_found > 0:
            unflat_logger.info(
                "Found %d provable single-iteration loops after unflattening", loops_found
            )

        unflat_logger.info("Unflattening removed %s branch", nb_flattened_branches)
        total_nb_change += nb_flattened_branches
        return total_nb_change

    # Maximum wall-clock seconds for a single optimize() call.
    MAX_OPTIMIZE_SECONDS = 30.0

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        import time as _time
        self.mba = blk.mba
        self._apply_function_overrides()
        if not self.check_if_rule_should_be_used(blk):
            return 0

        self._optimize_deadline = _time.monotonic() + self.MAX_OPTIMIZE_SECONDS

        # Apply any modifications scheduled for this maturity level
        scheduled_changes = self._apply_scheduled_modifications()
        if scheduled_changes > 0:
            unflat_logger.info(
                "Applied %d scheduled modifications at maturity %s",
                scheduled_changes,
                self.cur_maturity,
            )
        pre_unflatten_changes = self._run_pre_unflatten_local_optimization()
        initial_changes = scheduled_changes + pre_unflatten_changes

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
            return initial_changes

        layout_signals = self._collect_dispatcher_layout_signals()
        self._emit_layout_signals(layout_signals)

        if self.mba.maturity == ida_hexrays.MMAT_CALLS:
            # Selective MMAT_CALLS guard:
            # We only skip the risky shape (high fan-in + large dispatcher) and
            # preserve MMAT_CALLS behavior for common compact dispatchers.
            #
            # Historical context:
            # - Full MMAT_CALLS disable prevented capture crashes but regressed
            #   legitimate deobfuscation (mixed_dispatcher_pattern).
            # - Purely re-enabling MMAT_CALLS recovered that case but regressed
            #   high_fan_in_pattern / switch_case_ollvm_pattern with verify
            #   failures during deferred CFG edits.
            # - So we keep MMAT_CALLS enabled by default and apply targeted
            #   shape guards for known-unstable topologies.
            max_entry_preds = layout_signals["max_entry_preds"]
            max_exit_blocks = layout_signals["max_exit_blocks"]
            if (
                max_entry_preds > self.max_calls_entry_preds
                or max_exit_blocks > self.max_calls_exit_blocks
            ):
                unflat_logger.warning(
                    "Skipping MMAT_CALLS unflattening for complex dispatcher "
                    "(max_entry_preds=%d limit=%d, max_exit_blocks=%d limit=%d); "
                    "continuing at later maturities",
                    max_entry_preds,
                    self.max_calls_entry_preds,
                    max_exit_blocks,
                    self.max_calls_exit_blocks,
                )
                return initial_changes

            # Additional MMAT_CALLS safety gate:
            # A conditional predecessor directly feeding the dispatcher entry
            # can require structural rewrites that are brittle at this
            # maturity. We defer such functions to later maturities where CFG
            # surgery is more stable.
            #
            # This specifically avoids an MMAT_CALLS failure mode where
            # ensure_all_dispatcher_fathers_are_direct()/redirect operations
            # attempt to rewire around a 2-way father and trigger
            # change_1way_block_successor/verify exceptions. Deferring this
            # shape preserves stability while keeping compact 1-way dispatcher
            # cases (for example mixed_dispatcher_pattern) unflattened early.
            if (
                self.defer_calls_on_conditional_entry_father
                and layout_signals["has_conditional_entry_father"]
            ):
                unflat_logger.warning(
                    "Skipping MMAT_CALLS unflattening: dispatcher entry has "
                    "conditional predecessor(s); deferring to later maturities"
                )
                return initial_changes
        skip_pass, skip_reason = self.should_skip_pass_for_layout(layout_signals)
        if skip_pass:
            if skip_reason:
                unflat_logger.warning(skip_reason)
            else:
                unflat_logger.warning("Skipping unflattening pass via layout guard")
            return initial_changes
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
                if self._is_past_deadline():
                    unflat_logger.warning(
                        "fix_fathers: time budget exceeded, skipping remaining fathers"
                    )
                    break
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

        # If deferred modifier verify failed, the MBA is in a suspect state.
        # Skip deep cleaning / optimize_local / safe_verify which would either
        # fail or compound the corruption, causing IDA to hang at later
        # maturity levels.  Return the patch count so IDA knows the MBA was
        # touched and doesn't silently reuse the bad state.
        if self._verify_failed:
            unflat_logger.warning(
                "Skipping post-unflattening cleanup because MBA verify "
                "failed during deferred modifications"
            )
            return self.last_pass_nb_patch_done + initial_changes

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
        return self.last_pass_nb_patch_done + initial_changes
