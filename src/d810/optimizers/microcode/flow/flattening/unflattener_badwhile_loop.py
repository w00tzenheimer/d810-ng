"""
Unflattener for Bad While Loop
TODO:

# - Accept m_jz and m_jnz (plus support for == or != with non-zero constants).
# - Allow the state register to be either l or r operand (code should not assume only l).
# - Add an optional alias check: for example, if there is 'mov eax, tmp', look back for an earlier 'mov tmp, #CONST'.
# - If possible, do not rely only on prevb/nextb; make sure selected exits are actual successors using the CFG (succset) to avoid incorrect matches after layout changes.
# - Keep 'min_constant' and 'max_constant' as configuration options; these are important to filter out irrelevant matches.

"""

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.hexrays_helpers import append_mop_if_not_in_list
from d810.optimizers.microcode.flow.flattening.generic import (
    GenericDispatcherBlockInfo,
    GenericDispatcherCollector,
    GenericDispatcherInfo,
    GenericDispatcherUnflatteningRule,
)

unflat_logger = getLogger(__name__)

# Supported conditional jump opcodes for flattening detection
# m_jz: jump if zero (==)
# m_jnz: jump if not zero (!=)
# m_jle: jump if less or equal (signed)
# m_jge: jump if greater or equal (signed)
# m_jl: jump if less (signed)
# m_jg: jump if greater (signed)
FLATTENING_JUMP_OPCODES = [
    ida_hexrays.m_jz,
    ida_hexrays.m_jnz,
    ida_hexrays.m_jle,
    ida_hexrays.m_jge,
    ida_hexrays.m_jl,
    ida_hexrays.m_jg,
]


class BadWhileLoopBlockInfo(GenericDispatcherBlockInfo):
    pass


class BadWhileLoopInfo(GenericDispatcherInfo):
    def explore(self, blk: ida_hexrays.mblock_t, min_constant=None, max_constant=None) -> bool:
        """
        ; 1WAY-BLOCK 13 [START=0000E1BE END=0000E1D0] STK=48/ARG=250, MAXBSP: 0
        ; - INBOUND: [12, 24, 25, 8] OUTBOUND: [14]
        13. 0 mov    #0xF6A1F.4, eax.4                    ; 0000E1BE
        goto 16

        ; 2WAY-BLOCK 14 [START=0000E1D0 END=0000E1DB] STK=48/ARG=250, MAXBSP: 0
        ; - INBOUND: [13, 18] OUTBOUND: [15, 21]
        14. 0 jz     eax.4, #0xF6A1E.4, @21               ; 0000E1D5

        ; 2WAY-BLOCK 15 [START=0000E1DB END=0000E1E2] STK=48/ARG=250, MAXBSP: 0
        ; - INBOUND: [14] OUTBOUND: [16, 19]
        15. 0 jz     eax.4, #0xF6A20.4, @19

        ; 2WAY-BLOCK 16 [START=0000E204 END=0000E213] STK=48/ARG=250, MAXBSP: 0
        ; - INBOUND: [15] OUTBOUND: [17, 26]
        16. 0 mov    #0xF6A25.8, rcx.8                    ; 0000E21F
        16. 1 jz     [ds.2:r12.8].1, #0.1, @26

        17. 0 mov    #0xF6A1E.4, eax.4

        18. 0 mov    #0.8, rdx.8{18}                      ; 0000E0FD
        18. 1 goto   @21

        ; - INBOUND: [16] OUTBOUND: [18]
        26. 0 mov    #0xF6A20.4, eax.4                    ; 0000E218
        26. 1 goto   @19


        entry_block = 14
        exit_blocks = 21 & 16 & 19


        """
        # Use provided values or defaults (Approov obfuscator range)
        if min_constant is None:
            min_constant = 0xF6000
        if max_constant is None:
            max_constant = 0xF6FFF

        self.reset()
        if not self._is_candidate_for_dispatcher_entry_block(
            blk, min_constant, max_constant
        ):
            return False

        self.entry_block = BadWhileLoopBlockInfo(blk)
        # Get the compared operand (state register) - check both l and r
        if blk.tail.l and blk.tail.l.t != ida_hexrays.mop_n:
            self.mop_compared = blk.tail.l
        elif blk.tail.r and blk.tail.r.t != ida_hexrays.mop_n:
            self.mop_compared = blk.tail.r
        else:
            self.mop_compared = blk.tail.l  # fallback

        self.entry_block.parse()
        for used_mop in self.entry_block.use_list:
            append_mop_if_not_in_list(used_mop, self.entry_block.assume_def_list)
        self.dispatcher_internal_blocks.append(self.entry_block)

        # Collect exit blocks and comparison values
        self._collect_exit_blocks(blk, min_constant, max_constant)

        return True

    def _collect_exit_blocks(self, blk, min_constant, max_constant):
        """Collect dispatcher exit blocks and their associated comparison values.

        Relaxed pattern for ABC support:
        - entry jz/jnz and nextb jz/jnz MUST have magic constants
        - prevb mov with magic constant is OPTIONAL (adds Exit 2 if present)

        Minimum 2 exits are collected from nextb (jump target + fall-through).
        """
        # Get entry block constant
        entry_const = self._get_jump_constant(blk.tail)

        # Get previous block constant (from mov instruction) - optional for ABC
        prevb_const = None
        if blk.prevb and blk.prevb.tail and blk.prevb.tail.opcode == ida_hexrays.m_mov:
            if blk.prevb.tail.l and blk.prevb.tail.l.t == ida_hexrays.mop_n:
                prevb_const = blk.prevb.tail.l.signed_value()

        # Get nextb constant
        nextb_const = None
        if blk.nextb and blk.nextb.tail and self._is_conditional_jump(blk.nextb.tail.opcode):
            nextb_const = self._get_jump_constant(blk.nextb.tail)

        # Entry and nextb MUST have magic constants
        if not (
            self._is_constant_in_range(entry_const, min_constant, max_constant)
            and self._is_constant_in_range(nextb_const, min_constant, max_constant)
        ):
            return

        # Exit 0: nextb's jump target
        exit_block0 = BadWhileLoopBlockInfo(
            blk.mba.get_mblock(blk.nextb.tail.d.b), self.entry_block
        )
        self.dispatcher_exit_blocks.append(exit_block0)
        self.comparison_values.append(nextb_const)

        # Exit 1: nextb's fall-through (nextb.nextb)
        if blk.nextb.nextb:
            exit_block1 = BadWhileLoopBlockInfo(
                blk.mba.get_mblock(blk.nextb.nextb.serial), self.entry_block
            )
            self.dispatcher_exit_blocks.append(exit_block1)
            self.comparison_values.append(entry_const)

        # Exit 2: prevb (OPTIONAL - only if it has magic constant)
        # This is the original "Approov-style" pattern; ABC patterns skip this
        if blk.prevb and self._is_constant_in_range(prevb_const, min_constant, max_constant):
            exit_block2 = BadWhileLoopBlockInfo(
                blk.mba.get_mblock(blk.prevb.serial), self.entry_block
            )
            self.dispatcher_exit_blocks.append(exit_block2)
            self.comparison_values.append(prevb_const)
            unflat_logger.debug(
                "Block %d: full pattern matched (3 exits with prevb)",
                blk.serial
            )
        else:
            unflat_logger.debug(
                "Block %d: ABC pattern matched (2 exits without prevb)",
                blk.serial
            )

    def _is_conditional_jump(self, opcode):
        """Check if opcode is a conditional jump we support."""
        return opcode in FLATTENING_JUMP_OPCODES

    def _get_jump_constant(self, insn):
        """Extract the constant from a conditional jump instruction.

        Checks both l and r operands since the state register can be either.
        Returns the constant value if found, None otherwise.
        """
        if insn is None:
            return None

        # Check r operand first (most common: jz reg, #const)
        if insn.r and insn.r.t == ida_hexrays.mop_n:
            return insn.r.signed_value()

        # Check l operand (less common: jz #const, reg)
        if insn.l and insn.l.t == ida_hexrays.mop_n:
            return insn.l.signed_value()

        return None

    def _is_constant_in_range(self, const_val, min_constant, max_constant):
        """Check if a constant is within the magic range."""
        if const_val is None:
            return False
        return min_constant < const_val < max_constant

    def _is_candidate_for_dispatcher_entry_block(self, blk, min_constant, max_constant):
        """Check if block could be a dispatcher entry.

        Pattern requirements:
        1. Block ends with conditional jump (jz/jnz/jle/jge/jl/jg)
        2. Jump compares against constant in magic range (0xF6000-0xF6FFF)
        3. Next block ends with conditional jump with constant in range
        4. Previous block with mov #magic, reg is OPTIONAL (for ABC pattern support)

        The ABC patterns (from abc_f6_constants.c) may have prevb with mov #0, reg
        instead of mov #F6xxx, reg, but entry and nextb still have F6xxx constants.
        """
        if blk.tail is None:
            return False

        # 1. Block must end with supported conditional jump
        if not self._is_conditional_jump(blk.tail.opcode):
            return False

        # 2. Must have next block (prevb is optional for ABC patterns)
        if blk.nextb is None:
            return False

        # 3. Jump constant must be in magic range
        entry_const = self._get_jump_constant(blk.tail)
        if not self._is_constant_in_range(entry_const, min_constant, max_constant):
            return False

        # 4. Next block must have conditional jump with magic constant
        if blk.nextb.tail is None:
            return False
        if not self._is_conditional_jump(blk.nextb.tail.opcode):
            return False
        nextb_const = self._get_jump_constant(blk.nextb.tail)
        if not self._is_constant_in_range(nextb_const, min_constant, max_constant):
            return False

        # 5. Optional: Check prevb for additional confidence (log if missing)
        if blk.prevb is not None and blk.prevb.tail is not None:
            if blk.prevb.tail.opcode == ida_hexrays.m_mov:
                if blk.prevb.tail.l and blk.prevb.tail.l.t == ida_hexrays.mop_n:
                    prevb_const = blk.prevb.tail.l.signed_value()
                    if self._is_constant_in_range(prevb_const, min_constant, max_constant):
                        unflat_logger.debug(
                            "Block %d: prevb has magic constant 0x%X (full pattern)",
                            blk.serial, prevb_const
                        )
                    else:
                        unflat_logger.debug(
                            "Block %d: prevb has non-magic constant 0x%X (ABC pattern)",
                            blk.serial, prevb_const
                        )

        return True

    def _get_comparison_info(self, blk: ida_hexrays.mblock_t):
        # blk.tail must be a jtbl
        if (blk.tail is None) or (blk.tail.opcode != ida_hexrays.m_jtbl):
            return None, None
        return blk.tail.l, blk.tail.r


class BadWhileLoopCollector(GenericDispatcherCollector):
    DISPATCHER_CLASS = BadWhileLoopInfo
    DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK = 1
    DEFAULT_DISPATCHER_MIN_EXIT_BLOCK = 2  # Reduced from 3 for ABC pattern support
    DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE = 2  # Reduced from 3 for ABC pattern support
    DEFAULT_MIN_CONSTANT = 0xF6000
    DEFAULT_MAX_CONSTANT = 0xF6FFF

    def __init__(self):
        super().__init__()
        self.min_constant = self.DEFAULT_MIN_CONSTANT
        self.max_constant = self.DEFAULT_MAX_CONSTANT

    def configure(self, kwargs):
        super().configure(kwargs)
        if "min_constant" in kwargs:
            self.min_constant = kwargs["min_constant"]
            unflat_logger.debug(
                "BadWhileLoopCollector: min_constant set to 0x%X", self.min_constant
            )
        if "max_constant" in kwargs:
            self.max_constant = kwargs["max_constant"]
            unflat_logger.debug(
                "BadWhileLoopCollector: max_constant set to 0x%X", self.max_constant
            )

    def visit_minsn(self):
        """Override to pass min/max constant parameters to explore."""

        if self.blk.serial in self.explored_blk_serials:
            return 0
        self.explored_blk_serials.append(self.blk.serial)
        if self.curins.opcode not in FLATTENING_JUMP_OPCODES:
            return 0
        disp_info = self.DISPATCHER_CLASS(self.blk.mba)

        # Pass constants as kwargs
        kwargs = {}
        if hasattr(self, "min_constant"):
            kwargs["min_constant"] = self.min_constant
        if hasattr(self, "max_constant"):
            kwargs["max_constant"] = self.max_constant

        is_good_candidate = disp_info.explore(self.blk, **kwargs)
        if not is_good_candidate:
            return 0
        if not self.specific_checks(disp_info):
            return 0
        # Note: specific_checks already appends to dispatcher_list, so don't append again
        return 0


class BadWhileLoop(GenericDispatcherUnflatteningRule):
    DESCRIPTION = "Remove control flow flattening generated by approov"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    DEFAULT_MAX_DUPLICATION_PASSES = 20
    DEFAULT_MAX_PASSES = 5

    @property
    def DISPATCHER_COLLECTOR_CLASS(self) -> type[GenericDispatcherCollector]:
        """Return the class of the dispatcher collector."""
        return BadWhileLoopCollector



"""
# BadWhileLoop recognizes a very specific "Approov-style" dispatcher head by looking for:
#   - a jz on a magic constant,
#   - a previous mov #magic, eax,
#   - a next jz on another magic constant,
# and then it collects 3 exits from (next jz target, next fall-through, previous block).
# The generic unflattening framework then uses those to rewire the CFG and remove the flattened while loop.
"""
