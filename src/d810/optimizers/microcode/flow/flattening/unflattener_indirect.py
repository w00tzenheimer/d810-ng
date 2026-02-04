import idaapi
import ida_hexrays

from d810.core import getLogger
from d810.hexrays.hexrays_helpers import AND_TABLE, append_mop_if_not_in_list
from d810.hexrays.tracker import MopHistory, MopTracker
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherBlockInfo,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    GenericDispatcherUnflatteningRule,
)

unflat_logger = getLogger("D810.unflat")
FLATTENING_JUMP_OPCODES = [ida_hexrays.m_jtbl]


class TigressIndirectDispatcherBlockInfo(GenericDispatcherBlockInfo):
    pass


class TigressIndirectDispatcherInfo(GenericDispatcherInfo):
    def explore(self, blk: ida_hexrays.mblock_t):
        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(blk):
            return False
        self.mop_compared = self._get_comparison_info(blk)
        self.entry_block = TigressIndirectDispatcherBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        self.dispatcher_exit_blocks = []
        self.comparison_values = []
        return True

    def _get_comparison_info(self, blk: ida_hexrays.mblock_t):
        if (blk.tail is None) or (blk.tail.opcode != ida_hexrays.m_ijmp):
            return None
        return blk.tail.l

    def _is_candidate_for_dispatcher_entry_block(self, blk: ida_hexrays.mblock_t):
        if (blk.tail is None) or (blk.tail.opcode != ida_hexrays.m_ijmp):
            return False
        return True

    def should_emulation_continue(self, cur_blk: ida_hexrays.mblock_t):
        if (cur_blk is not None) and (cur_blk.serial == self.entry_block.serial):
            return True
        return False


class TigressIndirectDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = TigressIndirectDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 0
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 0


class LabelTableInfo(object):
    def __init__(self, sp_offset, mem_offset, nb_elt, ptr_size=8):
        self.sp_offset = sp_offset
        self.mem_offset = mem_offset
        self.nb_elt = nb_elt
        self.ptr_size = ptr_size

    def update_mop_tracker(self, mba: ida_hexrays.mbl_array_t, mop_tracker: MopTracker):
        stack_array_base_address = mba.stkoff_ida2vd(self.sp_offset)
        for i in range(self.nb_elt):
            tmp_mop = ida_hexrays.mop_t()
            tmp_mop.erase()
            tmp_mop._make_stkvar(mba, stack_array_base_address + self.ptr_size * i)
            tmp_mop.size = self.ptr_size
            mem_val = (
                idaapi.get_qword(self.mem_offset + self.ptr_size * i)
                & AND_TABLE[self.ptr_size]
            )
            mop_tracker.add_mop_definition(tmp_mop, mem_val)


class UnflattenerTigressIndirect(GenericDispatcherUnflatteningRule):
    DESCRIPTION = ""
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_LOCOPT]
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 1

    def __init__(self):
        super().__init__()
        self.label_info = None
        self.goto_table_info = {}

    @property
    def DISPATCHER_COLLECTOR_CLASS(self) -> type[GenericDispatcherCollector]:
        """Return the class of the dispatcher collector."""
        return TigressIndirectDispatcherCollector

    def configure(self, kwargs):
        super().configure(kwargs)
        if "goto_table_info" in self.config.keys():
            for ea_str, table_info in self.config["goto_table_info"].items():
                self.goto_table_info[int(ea_str, 16)] = LabelTableInfo(
                    sp_offset=int(table_info["stack_table_offset"], 16),
                    mem_offset=int(table_info["table_address"], 16),
                    nb_elt=table_info["table_nb_elt"],
                )

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t):
        if not super().check_if_rule_should_be_used(blk):
            return False
        if self.mba.entry_ea not in self.goto_table_info:
            return False
        if (self.cur_maturity_pass >= 1) and (self.last_pass_nb_patch_done == 0):
            return False
        self.label_info = self.goto_table_info[self.mba.entry_ea]
        return True

    def register_initialization_variables(self, mop_tracker: MopTracker):
        self.label_info.update_mop_tracker(self.mba, mop_tracker)

    def check_if_histories_are_resolved(self, mop_histories: list[MopHistory]):
        return True
