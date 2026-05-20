"""OLLVM dispatcher collector and father-history resolver backend."""
from __future__ import annotations

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.utils.hexrays_helpers import append_mop_if_not_in_list, extract_num_mop
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherBlockInfo,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    GenericDispatcherUnflatteningRule,
)

unflat_logger = getLogger("D810.unflat.ollvm_dispatcher")

FLATTENING_JUMP_OPCODES = [
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
MIN_NUM_COMPARISONS = 4


class OllvmDispatcherBlockInfo(GenericDispatcherBlockInfo):
    pass


class OllvmDispatcherInfo(GenericDispatcherInfo):
    def get_last_blk_in_first_blks(self) -> int:
        """Return the last initialization block before the outer dispatcher."""
        lif = -1
        dispatch = self.outmost_dispatch_num
        if dispatch != -1:
            lif = self.mba.get_mblock(dispatch).pred(0)
            mb_lif = self.mba.get_mblock(lif)
            if (
                lif >= dispatch
                or not mb_lif.tail
                or ida_hexrays.is_mcode_jcond(mb_lif.tail.opcode)
            ):
                min_num = dispatch
                for curr in self.mba.get_mblock(dispatch).predset:
                    mb_curr = self.mba.get_mblock(curr)
                    if (
                        curr < min_num
                        and mb_curr.tail
                        and not ida_hexrays.is_mcode_jcond(mb_curr.tail.opcode)
                    ):
                        min_num = curr
                lif = min_num

        if lif != -1 and lif != dispatch:
            unflat_logger.debug(
                "mblock %s is likely the last initialization block before dispatcher",
                lif,
            )
            return lif
        return -1

    def guess_outmost_dispatcher_blk(self) -> int:
        """Return the likely outer dispatcher block by predecessor fan-in."""
        dispatch = -1
        npred_max = MIN_NUM_COMPARISONS

        mb = self.mba.get_mblock(0)
        while mb.nextb:
            if (
                npred_max < mb.npred()
                and mb.tail
                and mb.tail.opcode in FLATTENING_JUMP_OPCODES
            ):
                if mb.tail.r.t != ida_hexrays.mop_n:
                    mb = mb.nextb
                    continue
                if mb.tail.l.t == ida_hexrays.mop_r or (
                    mb.tail.l.t == ida_hexrays.mop_d
                    and mb.tail.l.d.opcode == ida_hexrays.m_and
                ):
                    npred_max = mb.npred()
                    dispatch = mb.serial
            mb = mb.nextb
        return dispatch

    def get_entropy(self, cmp_val_size: int, dispatch: int) -> float:
        """Return bit entropy for dispatcher comparison constants."""
        num_bits = 0
        num_ones = 0
        for cmp_value in self.comparison_values:
            num_bits += cmp_val_size * 8
            for i in range(cmp_val_size * 8):
                if cmp_value & (1 << i):
                    num_ones += 1

        entropy = 0.0 if num_bits == 0 else num_ones / float(num_bits)
        unflat_logger.debug(
            "dispatcher %s comparison entropy=%f values=%s",
            dispatch,
            entropy,
            self.comparison_values,
        )
        return entropy

    def explore(
        self,
        blk: ida_hexrays.mblock_t,
        min_entropy: float | None = None,
        max_entropy: float | None = None,
    ) -> bool:
        """Detect whether *blk* is an OLLVM dispatcher entry block."""
        unflat_logger.debug(
            "mblock %s: exploring dispatcher (guessed outer dispatcher %s)",
            blk.serial,
            self.outmost_dispatch_num,
        )
        self.reset()
        if (
            not self._is_candidate_for_dispatcher_entry_block(blk)
            and blk.serial != self.outmost_dispatch_num
        ):
            return False
        self.entry_block = OllvmDispatcherBlockInfo(blk)
        self.entry_block.parse(
            o_dispatch=self.outmost_dispatch_num,
            first=self.last_num_in_first_blks,
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
        entropy = self.get_entropy(num_mop.size, blk.serial)

        min_threshold = min_entropy if min_entropy is not None else 0.3
        max_threshold = max_entropy if max_entropy is not None else 0.7

        if len(dispatcher_blk_with_external_father) != 0 or (
            entropy < min_threshold or entropy > max_threshold
        ):
            unflat_logger.debug(
                "mblock %s is excluded as an OLLVM dispatcher (%s external fathers, "
                "entropy=%f not in [%f, %f])",
                blk.serial,
                len(dispatcher_blk_with_external_father),
                entropy,
                min_threshold,
                max_threshold,
            )
            return False
        unflat_logger.debug(
            "mblock %s is detected as an OLLVM dispatcher entry block",
            blk.serial,
        )
        return True

    def _is_candidate_for_dispatcher_entry_block(
        self,
        blk: ida_hexrays.mblock_t,
    ) -> bool:
        num_mop, mop_compared = self._get_comparison_info(blk)
        if (num_mop is None) or (mop_compared is None):
            return False
        for father_serial in blk.predset:
            father_blk = self.mba.get_mblock(father_serial)
            father_num_mop, father_mop_compared = self._get_comparison_info(father_blk)
            if (father_num_mop is not None) and (father_mop_compared is not None):
                if mop_compared.equal_mops(father_mop_compared, ida_hexrays.EQ_IGNSIZE):
                    return False
        unflat_logger.debug(
            "mblock %s is candidate for OLLVM dispatcher entry block",
            blk.serial,
        )
        return True

    def _get_comparison_info(
        self,
        blk: ida_hexrays.mblock_t,
    ) -> tuple[ida_hexrays.mop_t | None, ida_hexrays.mop_t | None]:
        if (blk.tail is None) or (blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
            return None, None
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

    def _explore_children(self, father_info: OllvmDispatcherBlockInfo) -> None:
        for child_serial in father_info.blk.succset:
            if child_serial in [
                blk_info.serial for blk_info in self.dispatcher_internal_blocks
            ]:
                continue
            if child_serial in [
                blk_info.serial for blk_info in self.dispatcher_exit_blocks
            ]:
                continue
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
        self,
        block_info: OllvmDispatcherBlockInfo,
    ) -> list[ida_hexrays.mblock_t]:
        internal_serials = [
            blk_info.serial for blk_info in self.dispatcher_internal_blocks
        ]
        return [
            blk_father
            for blk_father in block_info.blk.predset
            if blk_father not in internal_serials
        ]

    def _get_dispatcher_blocks_with_external_father(self) -> list[ida_hexrays.mblock_t]:
        dispatcher_blocks_with_external_father = []
        for blk_info in self.dispatcher_internal_blocks:
            if blk_info.serial != self.entry_block.serial:
                external_fathers = self._get_external_fathers(blk_info)
                if len(external_fathers) > 0:
                    dispatcher_blocks_with_external_father.append(blk_info)
        return dispatcher_blocks_with_external_father


class OllvmDispatcherCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = OllvmDispatcherInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 3
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2
    DEFAULT_MIN_ENTROPY = 0.3
    DEFAULT_MAX_ENTROPY = 0.7

    def __init__(self) -> None:
        super().__init__()
        self.min_entropy = self.DEFAULT_MIN_ENTROPY
        self.max_entropy = self.DEFAULT_MAX_ENTROPY

    def configure(self, kwargs) -> None:
        self.min_entropy = self.DEFAULT_MIN_ENTROPY
        self.max_entropy = self.DEFAULT_MAX_ENTROPY
        super().configure(kwargs)
        if "min_entropy" in kwargs.keys():
            self.min_entropy = kwargs["min_entropy"]
        if "max_entropy" in kwargs.keys():
            self.max_entropy = kwargs["max_entropy"]


class OllvmFatherHistoryResolver(GenericDispatcherUnflatteningRule):
    """Father-history resolver backend used by the OLLVM engine profile."""

    DESCRIPTION = "Resolve OLLVM dispatcher fathers for the engine profile"
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5

    @property
    def DISPATCHER_COLLECTOR_CLASS(self) -> type[GenericDispatcherCollector]:
        return OllvmDispatcherCollector


__all__ = [
    "OllvmDispatcherBlockInfo",
    "OllvmDispatcherCollector",
    "OllvmDispatcherInfo",
    "OllvmFatherHistoryResolver",
]
