"""Single-iteration loop unflattener.

Handles residual loops after main unflattening:

    Block 1: mov #INIT, state  ->  Block 2
    Block 2: jnz state, #CHECK, @exit  ->  Block 3 (body) or Block 4 (exit)
    Block 3: body; mov #UPDATE, state; goto @2

If INIT == CHECK and UPDATE != CHECK, this loop runs exactly once.
"""

import ida_hexrays

from d810.hexrays.hexrays_helpers import append_mop_if_not_in_list
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherBlockInfo,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    GenericDispatcherUnflatteningRule,
)

# Default: accept any large constant as potential state variable
# These can be overridden via config
DEFAULT_MIN_MAGIC = 0x1000  # Skip small constants (likely not state vars)
DEFAULT_MAX_MAGIC = 0xFFFFFFFF


class SingleIterationBlockInfo(GenericDispatcherBlockInfo):
    pass


class SingleIterationDispatcherInfo(GenericDispatcherInfo):
    """Dispatcher info for simple jnz-based residual loops."""

    # Configurable magic constant range
    min_magic: int = DEFAULT_MIN_MAGIC
    max_magic: int = DEFAULT_MAX_MAGIC

    def _is_magic_constant(self, val: int) -> bool:
        """Check if value is within the magic constant range."""
        # Handle both signed and unsigned interpretations
        unsigned_val = val & 0xFFFFFFFF
        return self.min_magic <= unsigned_val <= self.max_magic

    def explore(self, blk: ida_hexrays.mblock_t) -> bool:
        self.reset()

        # Must end with jnz (the residual loop pattern)
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_jnz:
            return False

        # Get comparison constant from jnz
        check_const = None
        if blk.tail.r and blk.tail.r.t == ida_hexrays.mop_n:
            check_const = blk.tail.r.signed_value()
            self.mop_compared = blk.tail.l
        elif blk.tail.l and blk.tail.l.t == ida_hexrays.mop_n:
            check_const = blk.tail.l.signed_value()
            self.mop_compared = blk.tail.r

        if check_const is None or not self._is_magic_constant(check_const):
            return False

        # Set up entry block
        self.entry_block = SingleIterationBlockInfo(blk)
        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        self.comparison_values.append(check_const)

        # Add both successors as exit blocks
        for succ_serial in blk.succset:
            succ_blk = blk.mba.get_mblock(succ_serial)
            if succ_blk is None:
                continue

            exit_block = SingleIterationBlockInfo(succ_blk, self.entry_block)
            self.dispatcher_exit_blocks.append(exit_block)

            # Find state assignment in this successor
            val = self._find_magic_assignment(succ_blk)
            if val is not None and val not in self.comparison_values:
                self.comparison_values.append(val)

        # Must have at least 2 comparison values (init/check and update)
        return len(self.comparison_values) >= 2 and len(self.dispatcher_exit_blocks) >= 2

    def _find_magic_assignment(self, blk: ida_hexrays.mblock_t) -> int | None:
        """Find magic constant assignment in block."""
        insn = blk.head
        while insn:
            if insn.opcode == ida_hexrays.m_mov:
                if insn.l and insn.l.t == ida_hexrays.mop_n:
                    val = insn.l.signed_value()
                    if self._is_magic_constant(val):
                        return val
            insn = insn.next
        return None


class SingleIterationCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = SingleIterationDispatcherInfo
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 2
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 1


class SingleIterationLoopUnflattener(GenericDispatcherUnflatteningRule):
    DESCRIPTION = "Remove residual single-iteration loops"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    DEFAULT_MAX_PASSES = 3
    DEFAULT_MAX_DUPLICATION_PASSES = 5

    @property
    def DISPATCHER_COLLECTOR_CLASS(self):
        return SingleIterationCollector
