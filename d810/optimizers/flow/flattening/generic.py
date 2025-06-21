from __future__ import annotations
from copy import deepcopy
import logging
from typing import List, Union, Tuple

from ida_hexrays import *

from d810.optimizers.flow.handler import FlowOptimizationRule

from d810.tracker import MopTracker, MopHistory, remove_segment_registers, duplicate_histories
from d810.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.hexrays_hooks import InstructionDefUseCollector
from d810.hexrays_helpers import extract_num_mop, get_mop_index, append_mop_if_not_in_list, CONTROL_FLOW_OPCODES, \
    CONDITIONAL_JUMP_OPCODES
from d810.hexrays_formatters import format_minsn_t, format_mop_t, dump_microcode_for_debug, format_mop_list
from d810.cfg_utils import mba_deep_cleaning, ensure_child_has_an_unconditional_father, ensure_last_block_is_goto, \
    change_1way_block_successor, create_block
from d810.optimizers.flow.flattening.utils import NotResolvableFatherException, NotDuplicableFatherException, \
    DispatcherUnflatteningException, get_all_possibles_values, check_if_all_values_are_found

unflat_logger = logging.getLogger('D810.unflat')


class GenericDispatcherBlockInfo(object):

    def __init__(self, blk, father=None):
        self.blk = blk
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
        return self.blk.serial

    def register_father(self, father: GenericDispatcherBlockInfo):
        self.father = father
        self.assume_def_list = [x for x in father.assume_def_list]

    def update_use_def_lists(self, ins_mops_used: List[mop_t], ins_mops_def: List[mop_t]):
        for mop_used in ins_mops_used:
            append_mop_if_not_in_list(mop_used, self.use_list)
            mop_used_index = get_mop_index(mop_used, self.def_list)
            if mop_used_index == -1:
                append_mop_if_not_in_list(mop_used, self.use_before_def_list)
        for mop_def in ins_mops_def:
            append_mop_if_not_in_list(mop_def, self.def_list)

    def update_with_ins(self, ins: minsn_t):
        ins_mop_info = InstructionDefUseCollector()
        ins.for_all_ops(ins_mop_info)
        cleaned_unresolved_ins_mops = remove_segment_registers(ins_mop_info.unresolved_ins_mops)
        self.update_use_def_lists(cleaned_unresolved_ins_mops + ins_mop_info.memory_unresolved_ins_mops,
                                  ins_mop_info.target_mops)
        self.ins.append(ins)
        if ins.opcode in CONDITIONAL_JUMP_OPCODES:
            num_mop, other_mop = extract_num_mop(ins)
            if num_mop is not None:
                self.comparison_value = num_mop.nnn.value
                self.compared_mop = other_mop

    def parse(self):
        curins = self.blk.head
        while curins is not None:
            self.update_with_ins(curins)
            curins = curins.next
        for mop_def in self.def_list:
            append_mop_if_not_in_list(mop_def, self.assume_def_list)

    def does_only_need(self, prerequisite_mop_list: List[mop_t]) -> bool:
        for used_before_def_mop in self.use_before_def_list:
            mop_index = get_mop_index(used_before_def_mop, prerequisite_mop_list)
            if mop_index == -1:
                return False
        return True

    def recursive_get_father(self) -> List[GenericDispatcherBlockInfo]:
        if self.father is None:
            return [self]
        else:
            return self.father.recursive_get_father() + [self]

    def show_history(self):
        full_father_list = self.recursive_get_father()
        unflat_logger.info("    Show history of Block {0}".format(self.blk.serial))
        for father in full_father_list[:-1]:
            for ins in father.ins:
                unflat_logger.info("      {0}.{1}".format(father.blk.serial, format_minsn_t(ins)))

    def print_info(self):
        unflat_logger.info("Block {0} information:".format(self.blk.serial))
        unflat_logger.info("  USE list: {0}".format(format_mop_list(self.use_list)))
        unflat_logger.info("  DEF list: {0}".format(format_mop_list(self.def_list)))
        unflat_logger.info("  USE BEFORE DEF list: {0}".format(format_mop_list(self.use_before_def_list)))
        unflat_logger.info("  ASSUME DEF list: {0}".format(format_mop_list(self.assume_def_list)))


class GenericDispatcherInfo(object):
    def __init__(self, mba: mbl_array_t):
        self.mba = mba
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def reset(self):
        self.mop_compared = None
        self.entry_block = None
        self.comparison_values = []
        self.dispatcher_internal_blocks = []
        self.dispatcher_exit_blocks = []

    def explore(self, blk: mblock_t) -> bool:
        return False

    def get_shared_internal_blocks(self, other_dispatcher: GenericDispatcherInfo) -> List[mblock_t]:
        my_dispatcher_block_serial = [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]
        other_dispatcher_block_serial = [blk_info.blk.serial
                                         for blk_info in other_dispatcher.dispatcher_internal_blocks]
        return [self.mba.get_mblock(blk_serial) for blk_serial in my_dispatcher_block_serial
                if blk_serial in other_dispatcher_block_serial]

    def is_sub_dispatcher(self, other_dispatcher: GenericDispatcherInfo) -> bool:
        shared_blocks = self.get_shared_internal_blocks(other_dispatcher)
        if (len(shared_blocks) > 0) and (self.entry_block.blk.npred() < other_dispatcher.entry_block.blk.npred()):
            return True
        return False

    def should_emulation_continue(self, cur_blk: mblock_t) -> bool:
        exit_block_serial_list = [exit_block.serial for exit_block in self.dispatcher_exit_blocks]
        if (cur_blk is not None) and (cur_blk.serial not in exit_block_serial_list):
            return True
        return False

    def emulate_dispatcher_with_father_history(self, father_history: MopHistory) -> Tuple[mblock_t, List[minsn_t]]:
        microcode_interpreter = MicroCodeInterpreter()
        microcode_environment = MicroCodeEnvironment()
        dispatcher_input_info = []
        # First, we setup the MicroCodeEnvironment with the state variables (self.entry_block.use_before_def_list)
        # used by the dispatcher
        for initialization_mop in self.entry_block.use_before_def_list:
            # We recover the value of each state variable from the dispatcher father
            initialization_mop_value = father_history.get_mop_constant_value(initialization_mop)
            if initialization_mop_value is None:
                raise NotResolvableFatherException("Can't emulate dispatcher {0} with history {1}"
                                                   .format(self.entry_block.serial, father_history.block_serial_path))
            # We store this value in the MicroCodeEnvironment
            microcode_environment.define(initialization_mop, initialization_mop_value)
            dispatcher_input_info.append("{0} = {1:x}".format(format_mop_t(initialization_mop),
                                                              initialization_mop_value))

        unflat_logger.info("Executing dispatcher {0} with: {1}"
                           .format(self.entry_block.blk.serial, ", ".join(dispatcher_input_info)))

        # Now, we start the emulation of the code at the dispatcher entry block
        instructions_executed = []
        cur_blk = self.entry_block.blk
        cur_ins = cur_blk.head
        # We will continue emulation while we are in one of the dispatcher blocks
        while self.should_emulation_continue(cur_blk):
            unflat_logger.debug("  Executing: {0}.{1}".format(cur_blk.serial, format_minsn_t(cur_ins)))
            # We evaluate the current instruction of the dispatcher to determine
            # which block and instruction should be executed next
            is_ok = microcode_interpreter.eval_instruction(cur_blk, cur_ins, microcode_environment)
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
        unflat_logger.info("  Entry block: {0}.{1}: ".format(self.entry_block.blk.serial,
                                                             format_minsn_t(self.entry_block.blk.tail)))
        unflat_logger.info("  Entry block predecessors: {0}: "
                           .format([blk_serial for blk_serial in self.entry_block.blk.predset]))
        unflat_logger.info("    Compared mop: {0} ".format(format_mop_t(self.mop_compared)))
        unflat_logger.info("    Comparison values: {0} ".format(", ".join([hex(x) for x in self.comparison_values])))
        self.entry_block.print_info()
        unflat_logger.info("  Number of internal blocks: {0} ({1})"
                           .format(len(self.dispatcher_internal_blocks),
                                   [blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks]))
        if verbose:
            for disp_blk in self.dispatcher_internal_blocks:
                unflat_logger.info("    Internal block: {0}.{1} ".format(disp_blk.blk.serial,
                                                                         format_minsn_t(disp_blk.blk.tail)))
                disp_blk.show_history()
        unflat_logger.info("  Number of Exit blocks: {0} ({1})"
                           .format(len(self.dispatcher_exit_blocks),
                                   [blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks]))
        if verbose:
            for exit_blk in self.dispatcher_exit_blocks:
                unflat_logger.info("    Exit block: {0}.{1} ".format(exit_blk.blk.serial,
                                                                     format_minsn_t(exit_blk.blk.head)))
                exit_blk.show_history()


class GenericDispatcherCollector(minsn_visitor_t):
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
        self.dispatcher_min_comparison_value = self.DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE

    def configure(self, kwargs):
        if "min_dispatcher_internal_block" in kwargs.keys():
            self.dispatcher_min_internal_block = kwargs["min_dispatcher_internal_block"]
        if "min_dispatcher_exit_block" in kwargs.keys():
            self.dispatcher_min_exit_block = kwargs["min_dispatcher_exit_block"]
        if "min_dispatcher_comparison_value" in kwargs.keys():
            self.dispatcher_min_comparison_value = kwargs["min_dispatcher_comparison_value"]

    def specific_checks(self, disp_info: GenericDispatcherInfo) -> bool:
        unflat_logger.debug("DispatcherInfo {0} : {1} internals, {2} exits, {3} comparison"
                            .format(self.blk.serial, len(disp_info.dispatcher_internal_blocks),
                                    len(disp_info.dispatcher_exit_blocks), len(set(disp_info.comparison_values))))
        if len(disp_info.dispatcher_internal_blocks) < self.dispatcher_min_internal_block:
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
        is_good_candidate = disp_info.explore(self.blk)
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

    def get_dispatcher_list(self) -> List[GenericDispatcherInfo]:
        self.remove_sub_dispatchers()
        return self.dispatcher_list


class GenericUnflatteningRule(FlowOptimizationRule):
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2,MMAT_GLBOPT3]

    def __init__(self):
        super().__init__()
        self.mba = None
        self.cur_maturity = MMAT_ZERO
        self.cur_maturity_pass = 0
        self.last_pass_nb_patch_done = 0
        self.maturities = self.DEFAULT_UNFLATTENING_MATURITIES

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if self.cur_maturity == self.mba.maturity:
            self.cur_maturity_pass += 1
        else:
            self.cur_maturity = self.mba.maturity
            self.cur_maturity_pass = 0
        if self.cur_maturity not in self.maturities:
            return False
        return True


class GenericDispatcherUnflatteningRule(GenericUnflatteningRule):
    DISPATCHER_COLLECTOR_CLASS = GenericDispatcherCollector
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

    def check_if_rule_should_be_used(self, blk: mblock_t) -> bool:
        if not super().check_if_rule_should_be_used(blk):
            return False
        if (self.cur_maturity_pass >= 1) and (self.last_pass_nb_patch_done == 0):
            return False
        if (self.max_passes is not None) and (self.cur_maturity_pass >= self.max_passes):
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
        self.dispatcher_list = [x for x in self.dispatcher_collector.get_dispatcher_list()]

    def ensure_all_dispatcher_fathers_are_direct(self) -> int:
        nb_change = 0
        for dispatcher_info in self.dispatcher_list:
            nb_change += self.ensure_dispatcher_fathers_are_direct(dispatcher_info)
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:
                nb_change += ensure_child_has_an_unconditional_father(dispatcher_father,
                                                                      dispatcher_info.entry_block.blk)
        return nb_change

    def ensure_dispatcher_fathers_are_direct(self, dispatcher_info: GenericDispatcherInfo) -> int:
        nb_change = 0
        dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
        for dispatcher_father in dispatcher_father_list:
            nb_change += ensure_child_has_an_unconditional_father(dispatcher_father, dispatcher_info.entry_block.blk)
        return nb_change

    def register_initialization_variables(self, mop_tracker):
        pass

    def get_dispatcher_father_histories(self, dispatcher_father: mblock_t,
                                        dispatcher_entry_block: GenericDispatcherBlockInfo) -> List[MopHistory]:
        father_tracker = MopTracker(dispatcher_entry_block.use_before_def_list,
                                    max_nb_block=self.MOP_TRACKER_MAX_NB_BLOCK, max_path=self.MOP_TRACKER_MAX_NB_PATH)
        father_tracker.reset()
        self.register_initialization_variables(father_tracker)
        father_histories = father_tracker.search_backward(dispatcher_father, None)
        return father_histories

    def check_if_histories_are_resolved(self, mop_histories: List[MopHistory]) -> bool:
        return all([mop_history.is_resolved() for mop_history in mop_histories])

    def ensure_dispatcher_father_is_resolvable(self, dispatcher_father: mblock_t,
                                               dispatcher_entry_block: GenericDispatcherBlockInfo) -> int:
        father_histories = self.get_dispatcher_father_histories(dispatcher_father, dispatcher_entry_block)

        father_histories_cst = get_all_possibles_values(father_histories, dispatcher_entry_block.use_before_def_list,
                                                        verbose=False)
        father_is_resolvable = self.check_if_histories_are_resolved(father_histories)
        if not father_is_resolvable:
            raise NotDuplicableFatherException("Dispatcher {0} predecessor {1} is not duplicable: {2}"
                                               .format(dispatcher_entry_block.serial, dispatcher_father.serial,
                                                       father_histories_cst))
        for father_history_cst in father_histories_cst:
            if None in father_history_cst:
                raise NotDuplicableFatherException("Dispatcher {0} predecessor {1} has None value: {2}"
                                                   .format(dispatcher_entry_block.serial, dispatcher_father.serial,
                                                           father_histories_cst))

        unflat_logger.info("Dispatcher {0} predecessor {1} is resolvable: {2}"
                           .format(dispatcher_entry_block.serial, dispatcher_father.serial, father_histories_cst))
        nb_duplication, nb_change = duplicate_histories(father_histories, max_nb_pass=self.max_duplication_passes)
        unflat_logger.info("Dispatcher {0} predecessor {1} duplication: {2} blocks created, {3} changes made"
                           .format(dispatcher_entry_block.serial, dispatcher_father.serial, nb_duplication, nb_change))
        return 0

    def father_patcher_abc_extract_mop(self,target_instruction):
        cnst = None
        compare_mop = None
        if target_instruction.opcode == m_sub:
            if target_instruction.l.t == 2:
                cnst = target_instruction.l.signed_value()
                compare_mop = mop_t(target_instruction.r)
        elif target_instruction.opcode == m_add:
            if target_instruction.r.t == 2:
                cnst = target_instruction.r.signed_value()
                compare_mop = mop_t(target_instruction.l)
        elif target_instruction.opcode == m_or:
            if target_instruction.r.t == 2:
                cnst = target_instruction.r.signed_value()
                compare_mop = mop_t(target_instruction.l)
        elif target_instruction.opcode == m_xor:
            if target_instruction.r.t == 2:
                cnst = target_instruction.r.signed_value()
                compare_mop = mop_t(target_instruction.l)
        return cnst,compare_mop,target_instruction.opcode

    def father_patcher_abc_check_instruction(self,target_instruction)->bool:
        #TODO reimplement here
        compare_mop_left = None
        compare_mop_right = None
        cnst = None
        instruction_opcode = None
        opcodes_interested_in = [m_add,m_sub,m_or,m_xor,m_xdu,m_high]
        # if target_instruction.d.r != jtbl_r:
        # return cnst,compare_mop_left,compare_mop_right,instruction_opcode
        if target_instruction.opcode in opcodes_interested_in:
            trgt_opcode = target_instruction.opcode
            #check add or sub
            if trgt_opcode == m_xdu:
                if target_instruction.l.t == mop_d:
                    if target_instruction.l.d.opcode == m_high:
                        high_i = target_instruction.l.d
                        if high_i.l.t == mop_d:
                            sub_instruction = high_i.l.d
                            if sub_instruction.opcode == m_sub:
                                if sub_instruction.l.t == mop_d:
                                    compare_mop_right = mop_t(sub_instruction.r)
                                    sub_sub_instruction = sub_instruction.l.d
                                    if sub_sub_instruction.opcode == m_or:
                                        if sub_sub_instruction.r.t == 2:
                                            cnst = sub_sub_instruction.r.signed_value()
                                            cnst = cnst >> 32
                                            compare_mop_left = mop_t(sub_sub_instruction.l)
                                            instruction_opcode = m_sub
                                elif sub_instruction.l.t == mop_n:
                                    #9. 0 high   (#0xF6A120000005F.8-xdu.8(ebx.4)), ecx.4{11}
                                    compare_mop_right = mop_t(sub_instruction.r)
                                    cnst = sub_instruction.l.signed_value()
                                    cnst = cnst >> 32
                                    compare_mop_left = mop_t()
                                    compare_mop_left.make_number(sub_instruction.l.signed_value()&0xffffffff,8,target_instruction.ea)
                                    instruction_opcode = m_sub
                    else:
                        sub_instruction = target_instruction.l.d
                        cnst,compare_mop_left,trgt_opcode = self.father_patcher_abc_extract_mop(sub_instruction)
                        compare_mop_right = mop_t()
                        compare_mop_right.make_number(0,4,target_instruction.ea)
                        instruction_opcode = trgt_opcode
                else:
                    return cnst,compare_mop_left,compare_mop_right,instruction_opcode
            elif trgt_opcode == m_high:
                if target_instruction.l.t == mop_d:
                    sub_instruction = target_instruction.l.d
                    if sub_instruction.opcode == m_sub:
                        if sub_instruction.l.t == mop_d:
                            compare_mop_right = mop_t(sub_instruction.r)
                            sub_sub_instruction = sub_instruction.l.d
                            if sub_sub_instruction.opcode == m_or:
                                if sub_sub_instruction.r.t == 2:
                                    cnst = sub_sub_instruction.r.signed_value()
                                    cnst = cnst >> 32
                                    compare_mop_left = mop_t(sub_sub_instruction.l)
                                    instruction_opcode = m_sub
                        elif sub_instruction.l.t == mop_n:
                            #9. 0 high   (#0xF6A120000005F.8-xdu.8(ebx.4)), ecx.4{11}
                            compare_mop_right = mop_t(sub_instruction.r)
                            cnst = sub_instruction.l.signed_value()
                            cnst = cnst >> 32
                            compare_mop_left = mop_t()
                            compare_mop_left.make_number(sub_instruction.l.signed_value()&0xffffffff,8,target_instruction.ea)
                            instruction_opcode = m_sub
                        else:
                            pass
            else:
                cnst,compare_mop_left,trgt_opcode = self.father_patcher_abc_extract_mop(target_instruction)
                compare_mop_right = mop_t()
                compare_mop_right.make_number(0,4,target_instruction.ea)
                instruction_opcode = trgt_opcode

        return cnst,compare_mop_left,compare_mop_right,instruction_opcode

    def father_patcher_abc_create_blocks(self,dispatcher_father,curr_inst,cnst,compare_mop_left,compare_mop_right,opcode):

        mba = dispatcher_father.mba
        if dispatcher_father.tail.opcode == m_goto:
            dispatcher_father.remove_from_block(dispatcher_father.tail)
        new_id0_serial = dispatcher_father.serial + 1
        new_id1_serial = dispatcher_father.serial + 2
        dispatcher_reg0 = mop_t(curr_inst.d)
        dispatcher_reg0.size = 4
        dispatcher_reg1 = mop_t(curr_inst.d)
        dispatcher_reg1.size = 4
        if dispatcher_father.type != BLT_1WAY:
            print('father is not 1 way')
            return

        ea = curr_inst.ea
        block0_const = 0
        block1_const = 0
        if opcode == m_sub:
            block0_const = cnst-0
            block1_const = cnst-1
        elif opcode == m_add:
            block0_const = cnst+0
            block1_const = cnst+1
        elif opcode == m_or:
            block0_const = cnst|0
            block1_const = cnst|1
        elif opcode == m_xor:
            block0_const = cnst^0
            block1_const = cnst^1

        #create first block
        new_block0 = mba.insert_block(new_id0_serial)
        new_block1 = mba.insert_block(new_id1_serial)

        #get father succset after creation of new childs, since it will increase auto
        childs_goto0 = mop_t()
        childs_goto1 = mop_t()
        childs_goto_serial = dispatcher_father.succset[0]
        childs_goto0.make_blkref(childs_goto_serial)
        childs_goto_serial = dispatcher_father.succset[0]
        childs_goto1.make_blkref(childs_goto_serial)
        dispatcher_tail = dispatcher_father.tail
        while dispatcher_tail.dstr() != curr_inst.dstr():
            innsert_inst0 = minsn_t(dispatcher_tail)
            innsert_inst1 = minsn_t(dispatcher_tail)
            innsert_inst0.setaddr(ea)
            innsert_inst1.setaddr(ea)

            new_block0.insert_into_block(innsert_inst0,new_block0.head)
            new_block1.insert_into_block(innsert_inst1,new_block1.head)
            dispatcher_tail = dispatcher_tail.prev
        #generate block0 instructions
        if new_block0.tail != None and new_block1.tail != None:
            new_block0.tail.next = None
            new_block1.tail.next = None

        mov_inst0 = minsn_t(ea)
        mov_inst0.opcode = m_mov
        mov_inst0.l = mop_t()
        mov_inst0.l.make_number(block0_const,4,ea)
        mov_inst0.d = dispatcher_reg0
        new_block0.insert_into_block(mov_inst0,new_block0.tail)

        goto_inst0 = minsn_t(ea)
        goto_inst0.opcode = m_goto
        goto_inst0.l = childs_goto0
        new_block0.insert_into_block(goto_inst0,new_block0.tail)

        #generate block1 instructions
        mov_inst1 = minsn_t(ea)
        mov_inst1.opcode = m_mov
        mov_inst1.l = mop_t()
        mov_inst1.l.make_number(block1_const,4,ea)
        mov_inst1.d = dispatcher_reg1
        new_block1.insert_into_block(mov_inst1,new_block1.tail)

        goto_inst1 = minsn_t(ea)
        goto_inst1.opcode = m_goto
        goto_inst1.l = childs_goto1
        new_block1.insert_into_block(goto_inst1,new_block1.tail)
        #
        while curr_inst:
            n = curr_inst.next
            dispatcher_father.remove_from_block(curr_inst)
            curr_inst = n
        # ┌──────────────┐
        # │x             │
        # │y             │
        # │z             │
        # │add k+0xff,eax│
        # │a             │
        # │b             │
        # │c             │
        # └──────────────┘
        # remove after add
        # we alread copied those instructions to childs

        # add jz to end of block
        # dispatcher_father.tail = minsn_t(curr_inst.ea) # do not create new instruction to keep references to earlier instructions
        jz_to_childs = minsn_t(ea)
        jz_to_childs.opcode = m_jz
        jz_to_childs.l = compare_mop_left
        jz_to_childs.r = compare_mop_right
        jz_to_childs.d = mop_t()
        jz_to_childs.d.make_blkref(new_id1_serial)
        dispatcher_father.insert_into_block(jz_to_childs, dispatcher_father.tail)


        #housekeeping
        #replace father serial with childs serial in dispatcher block
        prev_successor_serials = [x for x in dispatcher_father.succset]
        for prev_successor_serial in prev_successor_serials:
            prev_succ = mba.get_mblock(prev_successor_serial)
            prev_succ.predset._del(dispatcher_father.serial)
            prev_succ.predset.add_unique(new_id0_serial)
            prev_succ.predset.add_unique(new_id1_serial)
            if prev_succ.serial != mba.qty - 1:
                prev_succ.mark_lists_dirty()

        #clean block0
        succset_serials = [x for x in new_block0.succset]
        for succ in succset_serials:
            new_block0.succset._del(succ)
        predset_serials = [x for x in new_block0.predset]
        for pred in predset_serials:
            new_block0.predset._del(pred)

        #clean block1
        succset_serials = [x for x in new_block1.succset]
        for succ in succset_serials:
            new_block1.succset._del(succ)
        predset_serials = [x for x in new_block1.predset]
        for pred in predset_serials:
            new_block1.predset._del(pred)

        #add father as pred to new blocks
        new_block0.predset.add_unique(dispatcher_father.serial)
        new_block1.predset.add_unique(dispatcher_father.serial)

        #add dispatcher block as succset
        new_block0.succset.add_unique(childs_goto_serial)
        new_block1.succset.add_unique(childs_goto_serial)

        #mark lists dirty
        new_block0.mark_lists_dirty()
        new_block1.mark_lists_dirty()

        #clean father succset
        succset_serials = [x for x in dispatcher_father.succset]
        for succ_serial in succset_serials:
            dispatcher_father.succset._del(succ_serial)

        #add childs to father succset
        dispatcher_father.succset.add_unique(new_id0_serial)
        dispatcher_father.succset.add_unique(new_id1_serial)
        dispatcher_father.mark_lists_dirty()

        dispatcher_father.type = BLT_2WAY
        new_block0.type = BLT_1WAY
        new_block1.type = BLT_1WAY
        new_block0.start = dispatcher_father.start
        new_block1.start = dispatcher_father.start
        new_block0.end = dispatcher_father.end
        new_block1.end = dispatcher_father.end


        mba.mark_chains_dirty()
        try:
            mba.verify(True)
            return new_block0,new_block1
        except RuntimeError as e:
            print(e)
            raise e


    def father_history_patcher_abc(self, father_history: mblock_t) -> List[MopHistory]:
        # father can have instructions that we are not interested in but need to copy and remove from generated childs.
        curr_inst = father_history.head
        while curr_inst:
            cnst,compare_mop_left,compare_mop_right,instruction_opcode = self.father_patcher_abc_check_instruction(curr_inst)
            l = [cnst,compare_mop_left,compare_mop_right,instruction_opcode]
            if all([x != None for x in l]):
                if cnst > 1010000 and cnst < 1011999:
                    try:
                        block0, block1 = self.father_patcher_abc_create_blocks(father_history,curr_inst,cnst,compare_mop_left,compare_mop_right,instruction_opcode)
                        bblock0_n = self.father_history_patcher_abc(block0)
                        bblock1_n = self.father_history_patcher_abc(block1)
                        return 1 + bblock0_n + bblock1_n
                    except Exception as e:
                        raise e
            curr_inst = curr_inst.next
        return 0


    def dispatcher_fixer_abc(self,dispatcher_list):
        for dispatcher in dispatcher_list:
            if dispatcher.entry_block.blk.tail.opcode == m_jtbl:
                # check jtbl have 3 case where one is default to itsel
                jtbl_minst = dispatcher.entry_block.blk.tail
                #jtbl left is mop_d -> minst
                if jtbl_minst.l.t == mop_d:
                    # jtbl left is m_sub
                    # jtbl   (#0xF6BBE.4-xdu.4((rax17.8 == #0.8))), {0xF6BBB => 22, 0xF6BBD => 19, 0xF6BBE => 20, def => 18}
                    if jtbl_minst.l.d.opcode == m_sub:
                        sub_minst = jtbl_minst.l.d
                        #sub left is constant
                        if sub_minst.l.t == 2:
                            cnst = jtbl_minst.l.signed_value()
                            compare_mop = mop_t(jtbl_minst.r)
                    # jtbl left is m_xdu
                    # jtbl   xdu.4((rax17.4{26} == varD8.4)), {-2,1 => 22, 0 => 21, def => 20}
                    if jtbl_minst.l.d.opcode == m_xdu:
                        sub_minst = jtbl_minst.l.d
                        #sub left is constant
                        if sub_minst.l.t == 2:
                            cnst = jtbl_minst.l.signed_value()
                            compare_mop = mop_t(jtbl_minst.r)
                            # remove jtbl
                            # create jz with compare mop
                            # get 2 case from jtbl cases
                            # create 2 block with goto to jtbl case



    def resolve_dispatcher_father(self, dispatcher_father: mblock_t, dispatcher_info: GenericDispatcherInfo) -> int:
        dispatcher_father_histories = self.get_dispatcher_father_histories(dispatcher_father,
                                                                           dispatcher_info.entry_block)
        father_is_resolvable = self.check_if_histories_are_resolved(dispatcher_father_histories)
        if not father_is_resolvable:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))
        mop_searched_values_list = get_all_possibles_values(dispatcher_father_histories,
                                                            dispatcher_info.entry_block.use_before_def_list,
                                                            verbose=False)
        all_values_found = check_if_all_values_are_found(mop_searched_values_list)
        if not all_values_found:
            raise NotResolvableFatherException("Can't fix block {0}".format(dispatcher_father.serial))

        ref_mop_searched_values = mop_searched_values_list[0]
        for tmp_mop_searched_values in mop_searched_values_list:
            if tmp_mop_searched_values != ref_mop_searched_values:
                raise NotResolvableFatherException("Dispatcher {0} predecessor {1} is not resolvable: {2}"
                                                   .format(dispatcher_info.entry_block.serial, dispatcher_father.serial,
                                                           mop_searched_values_list))

        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(dispatcher_father_histories[0])
        if target_blk is not None:
            unflat_logger.debug("Unflattening graph: Making {0} goto {1}"
                                .format(dispatcher_father.serial, target_blk.serial))
            ins_to_copy = [ins for ins in disp_ins if ((ins is not None) and (ins.opcode not in CONTROL_FLOW_OPCODES))]
            if len(ins_to_copy) > 0:
                unflat_logger.info("Instruction copied: {0}: {1}"
                                   .format(len(ins_to_copy),
                                           ", ".join([format_minsn_t(ins_copied) for ins_copied in ins_to_copy])))
                tail_serial = self.mba.qty-1
                block_to_copy = self.mba.get_mblock(tail_serial)
                while block_to_copy.type == BLT_XTRN or block_to_copy.type == BLT_STOP:
                    block_to_copy = self.mba.get_mblock(tail_serial)
                    tail_serial -= 1
                dispatcher_side_effect_blk = create_block(block_to_copy, ins_to_copy,
                                                          is_0_way=(target_blk.type == BLT_0WAY))
                change_1way_block_successor(dispatcher_father, dispatcher_side_effect_blk.serial)
                change_1way_block_successor(dispatcher_side_effect_blk, target_blk.serial)
            else:
                change_1way_block_successor(dispatcher_father, target_blk.serial)
            return 2

        raise NotResolvableFatherException("Can't fix block {0}: no block for key: {1}"
                                           .format(dispatcher_father.serial, mop_searched_values_list))
    def fix_fathers_from_mop_history(self,dispatcher_father,dispatcher_entry_block):
        father_histories = self.get_dispatcher_father_histories(dispatcher_father, dispatcher_entry_block)
        total_n = 0
        for father_history in father_histories:
            for block in father_history.block_path:
                total_n += self.father_history_patcher_abc(block)
        return total_n

    def find_bad_while_loops(self,blk):
        # find from mov x,eax
        if blk.tail.opcode == m_mov and blk.tail.l.t == mop_n:
            left_cnst = blk.tail.l.signed_value()
            if left_cnst > 0xf6000 and left_cnst < 0xf6fff:
                if blk.next.opcode == m_jz and blk.next.tail.r.t == mop_n:
                    jz0_cnst = blk.next.tail.r.signed_value()
                    if blk.next.next.opcode == m_jz and blk.next.next.tail.r.t == mop_n:
                        jz1_cnst = blk.next.ntext.tail.r.signed_value()
                        if jz1_cnst > 0xf6000 and jz1_cnst < 0xf6fff and jz0_cnst > 0xf6000 and jz0_cnst < 0xf6fff:
                            print('whoo found it')





    def remove_flattening(self) -> int:
        total_nb_change = 0
        breakpoint()
        self.non_significant_changes = ensure_last_block_is_goto(self.mba)
        self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()


        for dispatcher_info in self.dispatcher_list:
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_fix_abc_before_duplication"
                                     .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
            unflat_logger.info("Searching dispatcher for entry block {0} {1} ->  with variables ({2})..."
                               .format(dispatcher_info.entry_block.serial, format_mop_t(dispatcher_info.mop_compared),
                                       format_mop_list(dispatcher_info.entry_block.use_before_def_list)))
            #editing dispatcher fathers:
            # for dispatcher_father in tmp_dispatcher_father_list:
            # self.father_patcher_abc(dispatcher_father,dispatcher_info.entry_block)

            #redine dispatcher father since we changed entry block succ/pred sets
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            for dispatcher_father in dispatcher_father_list:

                try:
                    total_nb_change += self.ensure_dispatcher_father_is_resolvable(dispatcher_father,
                                                                                   dispatcher_info.entry_block)
                except NotDuplicableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_duplication"
                                     .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
            # During the previous step we changed dispatcher entry block fathers, so we need to reload them
            dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
            nb_flattened_branches = 0
            for dispatcher_father in dispatcher_father_list:
                try:
                    nb_flattened_branches += self.resolve_dispatcher_father(dispatcher_father, dispatcher_info)
                except NotResolvableFatherException as e:
                    unflat_logger.warning(e)
                    pass
            dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_after_unflattening"
                                     .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))

        unflat_logger.info("Unflattening removed {0} branch".format(nb_flattened_branches))
        total_nb_change += nb_flattened_branches
        return total_nb_change

    def optimize(self, blk: mblock_t) -> int:
        self.mba = blk.mba
        if not self.check_if_rule_should_be_used(blk):
            return 0
        self.last_pass_nb_patch_done = 0
        unflat_logger.info("Unflattening at maturity {0} pass {1}".format(self.cur_maturity, self.cur_maturity_pass))
        dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_start".format(self.cur_maturity_pass))
        self.retrieve_all_dispatchers()
        if len(self.dispatcher_list) == 0:
            unflat_logger.info("No dispatcher found at maturity {0}".format(self.mba.maturity))
            return 0
        else:
            unflat_logger.info("Unflattening: {0} dispatcher(s) found".format(len(self.dispatcher_list)))
            # self.dispatcher_fixer_abc(self.dispatcher_list)
            for dispatcher_info in self.dispatcher_list:
                dispatcher_info.print_info()
                dispatcher_father_list = [self.mba.get_mblock(x) for x in dispatcher_info.entry_block.blk.predset]
                total_fixed_father_block = 0
                dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_dispatcher_{1}_before_fix_abc"
                                            .format(self.cur_maturity_pass, dispatcher_info.entry_block.serial))
                for dispatcher_father in dispatcher_father_list:
                    try:
                        total_fixed_father_block += self.fix_fathers_from_mop_history(dispatcher_father,dispatcher_info.entry_block)
                    except Exception as e:
                        print(e)
                unflat_logger.info(f"Fixed {total_fixed_father_block} instructions in father history")
            self.last_pass_nb_patch_done = self.remove_flattening()
        unflat_logger.info("Unflattening at maturity {0} pass {1}: {2} changes"
                           .format(self.cur_maturity, self.cur_maturity_pass, self.last_pass_nb_patch_done))
        nb_clean = mba_deep_cleaning(self.mba, False)
        dump_microcode_for_debug(self.mba, self.log_dir, "unflat_{0}_after_cleaning".format(self.cur_maturity_pass))
        if self.last_pass_nb_patch_done + nb_clean + self.non_significant_changes > 0:
            self.mba.mark_chains_dirty()
            self.mba.optimize_local(0)
        self.mba.verify(True)
        return self.last_pass_nb_patch_done
