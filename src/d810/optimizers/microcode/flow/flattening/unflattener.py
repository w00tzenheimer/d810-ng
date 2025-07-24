import logging

from ida_hexrays import *

from d810.hexrays.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherBlockInfo,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    GenericDispatcherUnflatteningRule,
)

unflat_logger = logging.getLogger("D810.unflat")
FLATTENING_JUMP_OPCODES = [
    m_jnz,
    m_jz,
    m_jae,
    m_jb,
    m_ja,
    m_jbe,
    m_jg,
    m_jge,
    m_jl,
    m_jle,
]
MIN_NUM_COMPARISONS = 4


class OllvmDispatcherBlockInfo(GenericDispatcherBlockInfo):
    pass


class OllvmDispatcherInfo(GenericDispatcherInfo):

    def get_last_blk_in_first_blks(
        self,
    ) -> int:  # to track variables in the first blocks
        lif = -1

        # version 2 (ported from HexRaysDeob APT10 ANEL version)
        dispatch = self.outmost_dispatch_num
        if dispatch != -1:
            lif = self.mba.get_mblock(dispatch).pred(0)
            mb_lif = self.mba.get_mblock(lif)
            if lif >= dispatch or not mb_lif.tail or is_mcode_jcond(mb_lif.tail.opcode):
                min_num = dispatch
                for curr in self.mba.get_mblock(dispatch).predset:
                    mb_curr = self.mba.get_mblock(curr)
                    # if mb.npred():
                    # serial = mb.pred(0) # lazy tracking -> infinite loop :-(
                    if (
                        curr < min_num
                        and mb_curr.tail
                        and not is_mcode_jcond(mb_curr.tail.opcode)
                    ):
                        min_num = curr
                lif = min_num

        if lif != -1 and lif != dispatch:
            unflat_logger.debug(
                "mblock %s is likely the last block in first ones before the outmost dispatcher",
                lif,
            )
            return lif
        else:
            return -1

    def guess_outmost_dispatcher_blk(
        self,
    ) -> int:  # just return a mblock with the biggest npred
        dispatch = -1
        npred_max = MIN_NUM_COMPARISONS

        mb = self.mba.get_mblock(0)
        while mb.nextb:
            if (
                npred_max < mb.npred()
                and mb.tail
                and mb.tail.opcode in FLATTENING_JUMP_OPCODES
            ):
                if mb.tail.r.t != mop_n:
                    continue
                if mb.tail.l.t == mop_r or (
                    mb.tail.l.t == mop_d and mb.tail.l.d.opcode == m_and
                ):
                    npred_max = mb.npred()
                    dispatch = mb.serial
            mb = mb.nextb

        # if dispatch != -1:
        #    unflat_logger.debug(f'mblock {dispatch} is likely a CFF dispatcher based on the biggest npred value')

        return dispatch

    def get_entropy(self, cmp_val_size, dispatch) -> float:
        # Count the number of 1-bits in the constant values used for comparison
        num_bits = 0
        num_ones = 0
        for cmp_value in self.comparison_values:
            num_bits += cmp_val_size * 8
            for i in range(cmp_val_size * 8):
                if cmp_value & (1 << i):
                    num_ones += 1

        # Compute the percentage of 1-bits. Given that these constants seem to be
        # created pseudorandomly, the percentage should be roughly 1/2.
        entropy = 0.0 if num_bits == 0 else num_ones / float(num_bits)
        unflat_logger.debug(
            "dispatcher %s contains block comparison values (%s) whose entropy value is %f",
            dispatch,
            self.comparison_values,
            entropy,
        )

        return entropy

    def explore(self, blk: mblock_t) -> bool:  # Detect dispatcher entry blocks
        unflat_logger.debug(
            "mblock %s: exploring dispatcher (guessed outmost dispatcher %s)",
            blk.serial,
            self.outmost_dispatch_num,
        )
        self.reset()
        # if not self._is_candidate_for_dispatcher_entry_block(blk):
        if (
            not self._is_candidate_for_dispatcher_entry_block(blk)
            and blk.serial != self.outmost_dispatch_num
        ):
            return False
        self.entry_block = OllvmDispatcherBlockInfo(blk)
        self.entry_block.parse(
            o_dispatch=self.outmost_dispatch_num, first=self.last_num_in_first_blks
        )
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)
        num_mop, self.mop_compared = self._get_comparison_info(self.entry_block.blk)
        assert num_mop is not None
        assert num_mop.nnn is not None
        self.comparison_values.append(num_mop.nnn.value)
        self._explore_children(self.entry_block)
        dispatcher_blk_with_external_father = (
            self._get_dispatcher_blocks_with_external_father()
        )
        # TODO: I think this can be wrong because we are too permissive in detection of dispatcher blocks
        # if len(dispatcher_blk_with_external_father) != 0: # All internal blocks (except the entry block) should not have fathers outside the CFF loop
        entropy = self.get_entropy(
            num_mop.size, blk.serial
        )  # additional check by entropy (only effective for O-LLVM)
        if len(dispatcher_blk_with_external_father) != 0 or (
            entropy < 0.3 or entropy > 0.7
        ):  # validate the comparison value's entropy
            unflat_logger.debug(
                "mblock %s is excluded as a CFF dispatcher (%s, %f)",
                blk.serial,
                len(dispatcher_blk_with_external_father),
                entropy,
            )
            return False
        unflat_logger.debug(
            "mblock %s is detected as a CFF dispatcher entry block",
            blk.serial,
        )
        return True

    def _is_candidate_for_dispatcher_entry_block(self, blk: mblock_t) -> bool:
        # blk must be a condition branch with one numerical operand
        num_mop, mop_compared = self._get_comparison_info(blk)
        if (num_mop is None) or (mop_compared is None):
            return False
        # Its fathers are not conditional branch with this mop -> Sometimes they can be :-(
        for father_serial in blk.predset:
            father_blk = self.mba.get_mblock(father_serial)
            father_num_mop, father_mop_compared = self._get_comparison_info(father_blk)
            if (father_num_mop is not None) and (father_mop_compared is not None):
                if mop_compared.equal_mops(father_mop_compared, EQ_IGNSIZE):
                    return False
        unflat_logger.debug(
            "mblock %s is candidate for dispatcher entry block",
            blk.serial,
        )
        return True

    def _get_comparison_info(self, blk: mblock_t) -> tuple[mop_t | None, mop_t | None]:
        # We check if blk is a good candidate for dispatcher entry block: blk.tail must be a conditional branch
        if (blk.tail is None) or (blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return None, None
        # One operand must be numerical
        num_mop, mop_compared = extract_num_mop(blk.tail)
        if num_mop is None or mop_compared is None:
            return None, None
        return num_mop, mop_compared

    def is_part_of_dispatcher(self, block_info: OllvmDispatcherBlockInfo) -> bool:
        assert block_info.father is not None
        assert block_info.father.assume_def_list is not None
        is_ok = block_info.does_only_need(block_info.father.assume_def_list)
        if not is_ok:
            return False
        if (block_info.blk.tail is not None) and (
            block_info.blk.tail.opcode not in FLATTENING_JUMP_OPCODES
        ):
            return False
        return True

    def _explore_children(self, father_info: OllvmDispatcherBlockInfo):
        for child_serial in father_info.blk.succset:
            if child_serial in [
                blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks
            ]:
                return
            if child_serial in [
                blk_info.blk.serial for blk_info in self.dispatcher_exit_blocks
            ]:
                return
            child_blk = self.mba.get_mblock(child_serial)
            child_info = OllvmDispatcherBlockInfo(child_blk, father_info)
            child_info.parse()
            if not self.is_part_of_dispatcher(child_info):
                self.dispatcher_exit_blocks.append(child_info)
            else:
                self.dispatcher_internal_blocks.append(child_info)
                if child_info.comparison_value is not None:
                    self.comparison_values.append(child_info.comparison_value)
                self._explore_children(child_info)

    def _get_external_fathers(
        self, block_info: OllvmDispatcherBlockInfo
    ) -> list[mblock_t]:
        internal_serials = [
            blk_info.blk.serial for blk_info in self.dispatcher_internal_blocks
        ]
        external_fathers = [
            blk_father
            for blk_father in block_info.blk.predset
            if blk_father not in internal_serials
        ]
        return external_fathers

    def _get_dispatcher_blocks_with_external_father(self) -> list[mblock_t]:
        dispatcher_blocks_with_external_father = []
        for blk_info in self.dispatcher_internal_blocks:
            if blk_info.blk.serial != self.entry_block.blk.serial:
                external_fathers = self._get_external_fathers(blk_info)
                if len(external_fathers) > 0:
                    dispatcher_blocks_with_external_father.append(blk_info)
        return dispatcher_blocks_with_external_father


class OllvmDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = OllvmDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 3
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2


class Unflattener(GenericDispatcherUnflatteningRule):
    DESCRIPTION = "Remove control flow flattening generated by OLLVM"
    DISPATCHER_COLLECTOR_CLASS = OllvmDispatcherCollector
    DEFAULT_UNFLATTENING_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2]
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5
