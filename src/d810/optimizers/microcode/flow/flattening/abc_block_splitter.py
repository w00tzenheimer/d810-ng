"""
ABC Block Splitter - Deferred block creation for ABC pattern handling.

This module provides approaches for handling ABC (Arithmetic/Bitwise/Constant)
patterns in control flow unflattening:

1. ABCBlockSplitter (legacy, disabled): Creates new blocks via insert_block()
   - Causes IDA mba.verify() failures due to internal state corruption

2. ConditionalStateResolver (new): Resolves targets directly without new blocks
   - Detects ABC patterns: state = x + magic (where magic in 1010000-1011999)
   - Resolves both possible targets (x=0 and x!=0) via dispatcher emulation
   - Creates conditional jump in-place: jnz x, 0, target1; goto target0
   - Avoids insert_block() entirely - "directed graph" approach

This replaces the inline father_patcher_abc_create_blocks approach.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.cfg_utils import safe_verify, change_1way_block_successor
from d810.hexrays.hexrays_helpers import dup_mop

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.generic import GenericDispatcherInfo
    from d810.hexrays.tracker import MopHistory

logger = getLogger("D810.abc_splitter")


@dataclass
class BlockSplitOperation:
    """Represents a single block split operation to be applied."""

    block_serial: int
    instruction_ea: int  # EA of instruction that triggers the split
    cnst: int
    compare_mop_left: ida_hexrays.mop_t
    compare_mop_right: ida_hexrays.mop_t
    opcode: int
    # NOTE: We intentionally do NOT store instructions_to_copy here.
    # Storing live minsn_t pointers during analysis causes stale pointer bugs
    # when other CFG passes modify the graph before apply() runs.
    # Instead, we collect instructions fresh at apply time.


@dataclass
class ABCPatternInfo:
    """Info about an ABC pattern found in a block."""
    block_serial: int
    instruction_ea: int
    cnst: int  # Magic constant
    condition_mop: ida_hexrays.mop_t | None  # The x in "state = x + magic"
    opcode: int  # m_add, m_sub, m_or, m_xor
    state_mop: ida_hexrays.mop_t  # The destination (state variable)
    pattern_kind: str = "conditional"
    resolved_state: int | None = None


@dataclass
class ConditionalStateResolver:
    """
    Resolves conditional state patterns directly to targets without new blocks.

    Detects patterns where state is computed from a binary condition:
        state = x OP magic_constant  (where OP is add/sub/or/xor)

    Instead of creating intermediate blocks, resolves both possible outcomes
    (x=0 and x=1) via dispatcher emulation and creates a direct conditional jump.

    Example transformation:
        Before: state = x + 1010123; goto dispatcher
        After:  jnz x, 0, target_for_1010124; goto target_for_1010123

    This "directed graph" approach avoids insert_block() which causes IDA
    mba.verify() failures due to internal state corruption.

    Usage:
        resolver = ConditionalStateResolver(mba, dispatcher_info)
        for block in blocks_to_analyze:
            resolver.analyze_and_apply(block)
    """

    mba: ida_hexrays.mba_t
    dispatcher_info: GenericDispatcherInfo

    # Magic number range for ABC patterns
    ABC_CONST_MIN: int = 1010000
    ABC_CONST_MAX: int = 1011999
    rewritten_blocks: set[int] = field(default_factory=set)

    def _is_abc_state(self, value: int) -> bool:
        return self.ABC_CONST_MIN < int(value) < self.ABC_CONST_MAX

    @staticmethod
    def _mask_for_size(size: int) -> int:
        nbits = max(1, int(size)) * 8
        if nbits >= 64:
            return 0xFFFFFFFFFFFFFFFF
        return (1 << nbits) - 1

    def _resolve_dispatcher_case_value(self, block_serial: int) -> int | None:
        """Resolve the dispatcher case value that reaches *block_serial*."""
        entry_blk = self.dispatcher_info.entry_block.blk
        if entry_blk is None or entry_blk.tail is None:
            return None
        if entry_blk.tail.opcode != ida_hexrays.m_jtbl:
            return None
        if (
            entry_blk.tail.r is None
            or entry_blk.tail.r.t != ida_hexrays.mop_c
            or entry_blk.tail.r.c is None
        ):
            return None

        candidate_values: list[int] = []
        mcases = entry_blk.tail.r.c
        for possible_values, target_serial in zip(mcases.values, mcases.targets):
            if int(target_serial) != int(block_serial):
                continue
            if len(possible_values) == 0:
                continue
            candidate_values.append(int(possible_values[0]))

        if not candidate_values:
            return None
        unique_values = set(candidate_values)
        if len(unique_values) != 1:
            return None
        return candidate_values[0]

    def _is_dispatcher_state_mop(self, mop: ida_hexrays.mop_t) -> bool:
        for init_mop in self.dispatcher_info.entry_block.use_before_def_list:
            if mop.equal_mops(init_mop, ida_hexrays.EQ_IGNSIZE):
                return True
        return False

    def _resolve_state_from_history(
        self,
        father_history: MopHistory | None,
        state_mop: ida_hexrays.mop_t,
    ) -> int | None:
        if father_history is None:
            return None
        try:
            value = father_history.get_mop_constant_value(state_mop)
        except Exception:
            return None
        if value is None:
            return None
        return int(value)

    def analyze_and_apply(
        self,
        block: ida_hexrays.mblock_t,
        father_history: MopHistory | None = None,
    ) -> int:
        """
        Analyze a block for ABC patterns and apply in-place fix.

        Returns number of patterns fixed.
        """
        if block.serial in self.rewritten_blocks:
            return 0

        pattern = self._find_abc_pattern(block, father_history)
        if pattern is None:
            return 0

        logger.debug(
            "ConditionalStateResolver: Found %s ABC pattern in block %d, "
            "const=%d, opcode=%d, resolved_state=%s",
            pattern.pattern_kind,
            block.serial,
            pattern.cnst,
            pattern.opcode,
            pattern.resolved_state,
        )

        applied = self._apply_inplace(block, pattern)
        if applied > 0:
            self.rewritten_blocks.add(block.serial)
        return applied

    def _find_abc_pattern(
        self,
        block: ida_hexrays.mblock_t,
        father_history: MopHistory | None = None,
    ) -> ABCPatternInfo | None:
        """Find ABC pattern in block. Returns info or None."""
        curr_inst = block.head
        while curr_inst is not None:
            result = self._check_instruction_for_abc(curr_inst)
            if result is not None:
                cnst, condition_mop, state_mop, opcode = result
                if self._is_abc_state(cnst):
                    return ABCPatternInfo(
                        block_serial=block.serial,
                        instruction_ea=curr_inst.ea,
                        cnst=cnst,
                        condition_mop=condition_mop,
                        opcode=opcode,
                        state_mop=state_mop,
                    )

            self_update_pattern = self._check_instruction_for_self_update(
                curr_inst,
                block.serial,
                father_history,
            )
            if self_update_pattern is not None:
                return self_update_pattern

            curr_inst = curr_inst.next
        return None

    def _check_instruction_for_self_update(
        self,
        inst: ida_hexrays.minsn_t,
        block_serial: int,
        father_history: MopHistory | None,
    ) -> ABCPatternInfo | None:
        """Detect self-referential transitions like state = state ^ K."""
        # Start with XOR self-updates (state = state ^ K), which are the
        # stable/validated case for ABC F6 dispatchers.
        # Other self-referential ops (OR/AND/ADD/SUB) need stronger
        # per-path state validation to avoid over-redirection.
        if inst.opcode != ida_hexrays.m_xor:
            return None

        state_src: ida_hexrays.mop_t | None = None
        transition_const: int | None = None
        if inst.l.t == ida_hexrays.mop_n:
            transition_const = int(inst.l.signed_value())
            state_src = inst.r
        elif inst.r.t == ida_hexrays.mop_n:
            transition_const = int(inst.r.signed_value())
            state_src = inst.l

        if state_src is None or transition_const is None:
            return None
        if not inst.d.equal_mops(state_src, ida_hexrays.EQ_IGNSIZE):
            return None

        state_mop = dup_mop(inst.d)
        if not self._is_dispatcher_state_mop(state_mop):
            return None

        current_state = self._resolve_dispatcher_case_value(block_serial)
        if current_state is None:
            # Fallback for non-jtbl dispatchers where case-value mapping is unavailable.
            current_state = self._resolve_state_from_history(father_history, state_mop)
        if current_state is None:
            return None

        mask = self._mask_for_size(state_mop.size)
        resolved_state = (int(current_state) ^ int(transition_const)) & mask
        if resolved_state is None or not self._is_abc_state(resolved_state):
            return None

        return ABCPatternInfo(
            block_serial=block_serial,
            instruction_ea=inst.ea,
            cnst=transition_const,
            condition_mop=None,
            opcode=inst.opcode,
            state_mop=state_mop,
            pattern_kind="self_update",
            resolved_state=resolved_state,
        )

    def _check_instruction_for_abc(
        self, inst: ida_hexrays.minsn_t
    ) -> tuple[int, ida_hexrays.mop_t, ida_hexrays.mop_t, int] | None:
        """
        Check if instruction is ABC pattern.

        Returns (magic_const, condition_mop, state_mop, opcode) or None.
        """
        if inst.opcode not in [ida_hexrays.m_add, ida_hexrays.m_sub,
                                ida_hexrays.m_or, ida_hexrays.m_xor]:
            return None

        # Pattern: state = x op magic  OR  state = magic op x
        cnst = None
        condition_mop = None

        if inst.r.t == ida_hexrays.mop_n:  # Right operand is constant
            cnst = inst.r.signed_value()
            condition_mop = dup_mop(inst.l)
        elif inst.l.t == ida_hexrays.mop_n:  # Left operand is constant
            cnst = inst.l.signed_value()
            condition_mop = dup_mop(inst.r)

        if cnst is None or condition_mop is None:
            return None

        state_mop = dup_mop(inst.d)
        return (cnst, condition_mop, state_mop, inst.opcode)

    def _calculate_state_values(self, pattern: ABCPatternInfo) -> tuple[int, int]:
        """Calculate state values for x=0 and x=1."""
        magic = pattern.cnst
        opcode = pattern.opcode

        if opcode == ida_hexrays.m_add:
            return (magic + 0, magic + 1)
        elif opcode == ida_hexrays.m_sub:
            return (magic - 0, magic - 1)
        elif opcode == ida_hexrays.m_or:
            return (magic | 0, magic | 1)
        elif opcode == ida_hexrays.m_xor:
            return (magic ^ 0, magic ^ 1)
        else:
            return (magic, magic)

    def _resolve_target_for_state(self, state_value: int) -> ida_hexrays.mblock_t | None:
        """Resolve dispatcher target for a given state value."""
        from d810.expr.emulator import (
            MicroCodeInterpreter, MicroCodeEnvironment
        )

        microcode_interpreter = MicroCodeInterpreter(symbolic_mode=False)
        microcode_environment = MicroCodeEnvironment()

        # Set up state variable with the given value
        for init_mop in self.dispatcher_info.entry_block.use_before_def_list:
            microcode_environment.define(init_mop, state_value)

        # Emulate dispatcher
        cur_blk = self.dispatcher_info.entry_block.blk
        cur_ins = cur_blk.head

        max_iterations = 100
        for _ in range(max_iterations):
            if not self.dispatcher_info.should_emulation_continue(cur_blk):
                return cur_blk

            is_ok = microcode_interpreter.eval_instruction(
                cur_blk, cur_ins, microcode_environment
            )
            if not is_ok:
                return None

            cur_blk = microcode_environment.next_blk
            cur_ins = microcode_environment.next_ins

        return None

    def _apply_inplace(
        self, block: ida_hexrays.mblock_t, pattern: ABCPatternInfo
    ) -> int:
        """Apply in-place transformation: create conditional jump to targets."""
        if pattern.pattern_kind == "self_update":
            if pattern.resolved_state is None:
                return 0
            target = self._resolve_target_for_state(pattern.resolved_state)
            if target is None:
                logger.warning(
                    "ABC self-update: Could not resolve target for block %d, state=%d",
                    block.serial,
                    pattern.resolved_state,
                )
                return 0
            if block.nsucc() != 1:
                logger.warning(
                    "ABC self-update: block %d has %d successors (expected 1), skipping",
                    block.serial,
                    block.nsucc(),
                )
                return 0
            change_1way_block_successor(block, target.serial, verify=False)
            self.mba.mark_chains_dirty()
            logger.info(
                "ABC self-update: redirected block %d -> %d (state=%d)",
                block.serial,
                target.serial,
                pattern.resolved_state,
            )
            return 1

        state0, state1 = self._calculate_state_values(pattern)

        logger.info(
            "ABC in-place: block %d, magic=%d, states=(%d, %d)",
            block.serial, pattern.cnst, state0, state1
        )

        # Resolve targets for both state values
        target0 = self._resolve_target_for_state(state0)
        target1 = self._resolve_target_for_state(state1)

        if target0 is None or target1 is None:
            logger.warning(
                "ABC in-place: Could not resolve targets for block %d (state0=%d->%s, state1=%d->%s)",
                block.serial, state0, target0, state1, target1
            )
            return 0

        if target0.serial == target1.serial:
            # Both states lead to same target - just redirect
            logger.info(
                "ABC in-place: block %d -> same target %d",
                block.serial, target0.serial
            )
            change_1way_block_successor(block, target0.serial, verify=False)
            return 1

        logger.info(
            "ABC in-place: block %d -> targets (%d, %d)",
            block.serial, target0.serial, target1.serial
        )

        # Create conditional jump: jnz condition_mop, 0, target1; goto target0
        ea = pattern.instruction_ea

        # Remove instructions from ABC pattern onwards (including goto)
        curr_inst = block.head
        while curr_inst is not None:
            if curr_inst.ea == pattern.instruction_ea:
                break
            curr_inst = curr_inst.next

        if curr_inst is None:
            logger.warning("ABC in-place: pattern instruction not found")
            return 0

        # Remove from pattern instruction to end
        to_remove = []
        while curr_inst is not None:
            to_remove.append(curr_inst)
            curr_inst = curr_inst.next

        for inst in to_remove:
            block.remove_from_block(inst)

        # Add conditional jump: jnz condition, 0, target1
        jnz_inst = ida_hexrays.minsn_t(ea)
        jnz_inst.opcode = ida_hexrays.m_jnz
        jnz_inst.l = pattern.condition_mop
        jnz_inst.r = ida_hexrays.mop_t()
        jnz_inst.r.make_number(0, pattern.condition_mop.size, ea)
        jnz_inst.d = ida_hexrays.mop_t()
        jnz_inst.d.make_blkref(target1.serial)
        block.insert_into_block(jnz_inst, block.tail)

        # Update block type and successors
        block.type = ida_hexrays.BLT_2WAY

        # Clear old successors
        old_succs = list(block.succset)
        for old_succ in old_succs:
            old_blk = self.mba.get_mblock(old_succ)
            old_blk.predset._del(block.serial)
            block.succset._del(old_succ)

        # Add new successors: target0 (fallthrough) and target1 (jump)
        block.succset.add_unique(target0.serial)
        block.succset.add_unique(target1.serial)
        target0.predset.add_unique(block.serial)
        target1.predset.add_unique(block.serial)

        block.mark_lists_dirty()
        target0.mark_lists_dirty()
        target1.mark_lists_dirty()

        self.mba.mark_chains_dirty()

        logger.info(
            "ABC in-place: block %d transformed to 2-way: jnz -> %d, fallthrough -> %d",
            block.serial, target1.serial, target0.serial
        )

        return 1


@dataclass
class ABCBlockSplitter:
    """
    Queue-based block splitter for ABC patterns.

    Usage:
        splitter = ABCBlockSplitter(mba)

        # Analysis phase - find all patterns
        for block in blocks_to_analyze:
            splitter.analyze_block(block)

        # Apply phase - create all new blocks
        num_splits = splitter.apply()
    """

    mba: ida_hexrays.mba_t
    pending_splits: list[BlockSplitOperation] = field(default_factory=list)

    # Magic number range for ABC patterns (specific to target obfuscator)
    ABC_CONST_MIN = 1010000
    ABC_CONST_MAX = 1011999

    def reset(self) -> None:
        """Clear all pending splits."""
        self.pending_splits.clear()

    def analyze_block(self, block: ida_hexrays.mblock_t) -> int:
        """
        Analyze a block for ABC split patterns.

        Returns the number of patterns found.
        """
        patterns_found = 0
        curr_inst = block.head

        while curr_inst is not None:
            result = self._check_instruction(curr_inst)
            if result is not None:
                cnst, compare_mop_left, compare_mop_right, opcode = result
                if self.ABC_CONST_MIN < cnst < self.ABC_CONST_MAX:
                    # Record the split operation - DO NOT store instruction pointers
                    # Instructions will be collected fresh at apply time
                    self.pending_splits.append(BlockSplitOperation(
                        block_serial=block.serial,
                        instruction_ea=curr_inst.ea,
                        cnst=cnst,
                        compare_mop_left=compare_mop_left,
                        compare_mop_right=compare_mop_right,
                        opcode=opcode,
                    ))
                    patterns_found += 1
                    logger.debug(
                        "Found ABC pattern in block %d at %#x, cnst=%d",
                        block.serial, curr_inst.ea, cnst
                    )
            curr_inst = curr_inst.next

        return patterns_found

    def _check_instruction(
        self,
        target_instruction: ida_hexrays.minsn_t
    ) -> tuple[int, ida_hexrays.mop_t, ida_hexrays.mop_t, int] | None:
        """
        Check if an instruction matches ABC split pattern.

        Returns (cnst, compare_mop_left, compare_mop_right, opcode) or None.

        This is adapted from father_patcher_abc_check_instruction.
        """
        opcodes_interested_in = [
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_or,
            ida_hexrays.m_xor,
            ida_hexrays.m_xdu,
            ida_hexrays.m_high
        ]

        if target_instruction.opcode not in opcodes_interested_in:
            return None

        trgt_opcode = target_instruction.opcode

        # Pattern: m_xdu with nested m_high -> m_sub
        if trgt_opcode == ida_hexrays.m_xdu:
            if target_instruction.l.t != ida_hexrays.mop_d:
                return None

            if target_instruction.l.d.opcode == ida_hexrays.m_high:
                high_i = target_instruction.l.d
                if high_i.l.t == ida_hexrays.mop_d:
                    sub_instruction = high_i.l.d
                    if sub_instruction.opcode == ida_hexrays.m_sub:
                        return self._extract_sub_pattern(sub_instruction, target_instruction)
            else:
                # Direct xdu pattern
                sub_instruction = target_instruction.l.d
                result = self._extract_mop(sub_instruction)
                if result is not None:
                    cnst, compare_mop_left, trgt_opcode = result
                    compare_mop_right = ida_hexrays.mop_t()
                    compare_mop_right.make_number(0, 4, target_instruction.ea)
                    return (cnst, compare_mop_left, compare_mop_right, trgt_opcode)

        # Pattern: m_high with nested patterns
        elif trgt_opcode == ida_hexrays.m_high:
            if target_instruction.l.t == ida_hexrays.mop_d:
                sub_instruction = target_instruction.l.d
                if sub_instruction.opcode == ida_hexrays.m_sub:
                    return self._extract_sub_pattern(sub_instruction, target_instruction)

        # Direct add/sub/or/xor patterns
        else:
            result = self._extract_mop(target_instruction)
            if result is not None:
                cnst, compare_mop_left, trgt_opcode = result
                compare_mop_right = ida_hexrays.mop_t()
                compare_mop_right.make_number(0, 4, target_instruction.ea)
                return (cnst, compare_mop_left, compare_mop_right, trgt_opcode)

        return None

    def _extract_sub_pattern(
        self,
        sub_instruction: ida_hexrays.minsn_t,
        target_instruction: ida_hexrays.minsn_t,
    ) -> tuple[int, ida_hexrays.mop_t, ida_hexrays.mop_t, int] | None:
        """Extract pattern from sub instruction."""
        if sub_instruction.l.t == ida_hexrays.mop_d:
            compare_mop_right = dup_mop(sub_instruction.r)
            sub_sub_instruction = sub_instruction.l.d
            if sub_sub_instruction.opcode == ida_hexrays.m_or:
                if sub_sub_instruction.r.t == 2:  # mop_n (number)
                    cnst = sub_sub_instruction.r.signed_value() >> 32
                    compare_mop_left = dup_mop(sub_sub_instruction.l)
                    return (cnst, compare_mop_left, compare_mop_right, ida_hexrays.m_sub)

        elif sub_instruction.l.t == ida_hexrays.mop_n:
            compare_mop_right = dup_mop(sub_instruction.r)
            cnst = sub_instruction.l.signed_value() >> 32
            compare_mop_left = ida_hexrays.mop_t()
            compare_mop_left.make_number(
                sub_instruction.l.signed_value() & 0xFFFFFFFF,
                8,
                target_instruction.ea,
            )
            return (cnst, compare_mop_left, compare_mop_right, ida_hexrays.m_sub)

        return None

    def _extract_mop(
        self,
        target_instruction: ida_hexrays.minsn_t
    ) -> tuple[int, ida_hexrays.mop_t, int] | None:
        """
        Extract constant and compare operand from instruction.

        Adapted from father_patcher_abc_extract_mop.
        """
        cnst = None
        compare_mop = None

        if target_instruction.opcode in [ida_hexrays.m_add, ida_hexrays.m_sub]:
            if target_instruction.r.t == 2:  # mop_n
                cnst = target_instruction.r.signed_value()
                compare_mop = dup_mop(target_instruction.l)
            elif target_instruction.l.t == 2:  # mop_n
                cnst = target_instruction.l.signed_value()
                compare_mop = dup_mop(target_instruction.r)

        elif target_instruction.opcode in [ida_hexrays.m_or, ida_hexrays.m_xor]:
            if target_instruction.r.t == 2:  # mop_n
                cnst = target_instruction.r.signed_value()
                compare_mop = dup_mop(target_instruction.l)

        if cnst is not None and compare_mop is not None:
            return (cnst, compare_mop, target_instruction.opcode)

        return None

    def apply(self) -> int:
        """
        Apply all pending block splits.

        NOTE: Block insertion via insert_block() causes IDA mba.verify() failures
        due to internal state corruption. This is tracked in bead d810ng-8me.

        Alternative approaches being considered:
        1. Edge-only rewiring (no new blocks)
        2. In-place conditional select instead of block split
        3. Deferred batch insertion with single verify

        Returns 0 until a working approach is implemented.
        """
        if not self.pending_splits:
            return 0

        # Log pending work for debugging, but don't apply
        logger.debug(
            "ABC splitter: %d pending splits (disabled due to verify failure)",
            len(self.pending_splits)
        )
        self.pending_splits.clear()
        return 0

    def _apply_single_split(
        self,
        split_op: BlockSplitOperation
    ) -> list[ida_hexrays.mblock_t]:
        """
        Apply a single block split operation.

        Returns the list of newly created blocks.
        """
        dispatcher_father = self.mba.get_mblock(split_op.block_serial)
        if dispatcher_father is None:
            logger.warning("Block %d not found", split_op.block_serial)
            return []

        # ABC pattern only works on single-successor blocks
        if dispatcher_father.nsucc() != 1:
            logger.warning(
                "Block %d has %d successors (expected 1), skipping ABC split",
                split_op.block_serial, dispatcher_father.nsucc()
            )
            return []

        # Find the trigger instruction
        curr_inst = dispatcher_father.head
        while curr_inst is not None:
            if curr_inst.ea == split_op.instruction_ea:
                break
            curr_inst = curr_inst.next

        if curr_inst is None:
            logger.warning("Instruction at %#x not found in block %d",
                         split_op.instruction_ea, split_op.block_serial)
            return []

        # Collect instructions to copy NOW (at apply time, not during analysis)
        # This avoids stale pointer bugs from storing minsn_t references
        instructions_to_copy = []
        tail_inst = dispatcher_father.tail
        while tail_inst is not None and tail_inst.dstr() != curr_inst.dstr():
            instructions_to_copy.append(tail_inst)
            tail_inst = tail_inst.prev

        # Remove goto if present
        if dispatcher_father.tail is not None and dispatcher_father.tail.opcode == ida_hexrays.m_goto:
            dispatcher_father.remove_from_block(dispatcher_father.tail)

        # Insert new blocks at the END of the mba to avoid shifting issues
        # Inserting in the middle causes IDA internal state corruption
        end_serial = self.mba.qty - 1  # Before exit block

        logger.info("=== INSERTING AT END (before exit block %d) ===", end_serial)
        logger.info("dispatcher_father.serial=%d, succset=%s",
                   dispatcher_father.serial, list(dispatcher_father.succset))

        # Create new blocks at the end (before exit block)
        new_block0 = self.mba.insert_block(end_serial)
        new_id0_serial = new_block0.serial

        logger.info("After first insert: new_block0.serial=%d", new_id0_serial)

        new_block1 = self.mba.insert_block(end_serial + 1)  # Next position (previous position shifted)
        new_id1_serial = new_block1.serial

        logger.info("After second insert: new_block1.serial=%d", new_id1_serial)
        logger.info("dispatcher_father.succset=%s (after inserts)", list(dispatcher_father.succset))

        # Calculate constants based on opcode
        block0_const, block1_const = self._calculate_block_constants(
            split_op.cnst, split_op.opcode
        )

        # Get successor info
        childs_goto_serial = dispatcher_father.succset[0]
        logger.info("childs_goto_serial=%d (original successor)", childs_goto_serial)

        # Copy instructions to both new blocks
        ea = split_op.instruction_ea
        for inst in instructions_to_copy:
            insert_inst0 = ida_hexrays.minsn_t(inst)
            insert_inst1 = ida_hexrays.minsn_t(inst)
            insert_inst0.setaddr(ea)
            insert_inst1.setaddr(ea)
            new_block0.insert_into_block(insert_inst0, new_block0.head)
            new_block1.insert_into_block(insert_inst1, new_block1.head)

        # Fix tail pointers
        if new_block0.tail is not None and new_block1.tail is not None:
            new_block0.tail.next = None
            new_block1.tail.next = None

        # Add mov instruction to block0
        dispatcher_reg0 = ida_hexrays.mop_t(curr_inst.d)
        dispatcher_reg0.size = 4
        mov_inst0 = ida_hexrays.minsn_t(ea)
        mov_inst0.opcode = ida_hexrays.m_mov
        mov_inst0.l = ida_hexrays.mop_t()
        mov_inst0.l.make_number(block0_const, 4, ea)
        mov_inst0.d = dispatcher_reg0
        new_block0.insert_into_block(mov_inst0, new_block0.tail)

        # Add goto to block0
        goto_inst0 = ida_hexrays.minsn_t(ea)
        goto_inst0.opcode = ida_hexrays.m_goto
        goto_inst0.l = ida_hexrays.mop_t()
        goto_inst0.l.make_blkref(childs_goto_serial)
        new_block0.insert_into_block(goto_inst0, new_block0.tail)

        # Add mov instruction to block1
        dispatcher_reg1 = ida_hexrays.mop_t(curr_inst.d)
        dispatcher_reg1.size = 4
        mov_inst1 = ida_hexrays.minsn_t(ea)
        mov_inst1.opcode = ida_hexrays.m_mov
        mov_inst1.l = ida_hexrays.mop_t()
        mov_inst1.l.make_number(block1_const, 4, ea)
        mov_inst1.d = dispatcher_reg1
        new_block1.insert_into_block(mov_inst1, new_block1.tail)

        # Add goto to block1
        goto_inst1 = ida_hexrays.minsn_t(ea)
        goto_inst1.opcode = ida_hexrays.m_goto
        goto_inst1.l = ida_hexrays.mop_t()
        goto_inst1.l.make_blkref(childs_goto_serial)
        new_block1.insert_into_block(goto_inst1, new_block1.tail)

        # Remove instructions after trigger from dispatcher_father
        while curr_inst:
            n = curr_inst.next
            dispatcher_father.remove_from_block(curr_inst)
            curr_inst = n

        # Add jz instruction to dispatcher_father
        jz_to_childs = ida_hexrays.minsn_t(ea)
        jz_to_childs.opcode = ida_hexrays.m_jz
        jz_to_childs.l = split_op.compare_mop_left
        jz_to_childs.r = split_op.compare_mop_right
        jz_to_childs.d = ida_hexrays.mop_t()
        jz_to_childs.d.make_blkref(new_id1_serial)
        dispatcher_father.insert_into_block(jz_to_childs, dispatcher_father.tail)

        # Update CFG - using helper to do this cleanly
        self._update_cfg_for_split(
            dispatcher_father, new_block0, new_block1,
            new_id0_serial, new_id1_serial, childs_goto_serial
        )

        self.mba.mark_chains_dirty()

        # Log CFG state before verify
        logger.info("=== CFG STATE BEFORE VERIFY ===")
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            tail_str = blk.tail.dstr() if blk.tail else "None"
            logger.info("Block %d: type=%d, preds=%s, succs=%s, tail=%s",
                       i, blk.type, list(blk.predset), list(blk.succset), tail_str)

        safe_verify(
            self.mba,
            f"ABCBlockSplitter.apply_single_split block {split_op.block_serial}",
            logger_func=logger.error,
        )

        return [new_block0, new_block1]

    def _calculate_block_constants(self, cnst: int, opcode: int) -> tuple[int, int]:
        """Calculate the constants for block0 and block1 based on opcode."""
        if opcode == ida_hexrays.m_sub:
            return (cnst - 0, cnst - 1)
        elif opcode == ida_hexrays.m_add:
            return (cnst + 0, cnst + 1)
        elif opcode == ida_hexrays.m_or:
            return (cnst | 0, cnst | 1)
        elif opcode == ida_hexrays.m_xor:
            return (cnst ^ 0, cnst ^ 1)
        else:
            return (cnst, cnst)

    def _update_cfg_for_split(
        self,
        dispatcher_father: ida_hexrays.mblock_t,
        new_block0: ida_hexrays.mblock_t,
        new_block1: ida_hexrays.mblock_t,
        new_id0_serial: int,
        new_id1_serial: int,
        childs_goto_serial: int,
    ) -> None:
        """Update CFG after block split - all edge modifications in one place."""
        mba = self.mba

        logger.debug(
            "CFG update: father=%d, new0=%d (serial=%d), new1=%d (serial=%d), goto=%d",
            dispatcher_father.serial, new_id0_serial, new_block0.serial,
            new_id1_serial, new_block1.serial, childs_goto_serial
        )
        logger.debug(
            "Before update - father preds=%s, succs=%s",
            list(dispatcher_father.predset), list(dispatcher_father.succset)
        )

        # Update old successors: replace father with new blocks as predecessor
        prev_successor_serials = list(dispatcher_father.succset)
        for prev_successor_serial in prev_successor_serials:
            prev_succ = mba.get_mblock(prev_successor_serial)
            logger.debug(
                "  Updating successor %d: old preds=%s",
                prev_successor_serial, list(prev_succ.predset)
            )
            prev_succ.predset._del(dispatcher_father.serial)
            prev_succ.predset.add_unique(new_id0_serial)
            prev_succ.predset.add_unique(new_id1_serial)
            logger.debug(
                "  Updating successor %d: new preds=%s",
                prev_successor_serial, list(prev_succ.predset)
            )
            if prev_succ.serial != mba.qty - 1:
                prev_succ.mark_lists_dirty()

        # Clean new block0 pred/succ sets
        for succ in list(new_block0.succset):
            new_block0.succset._del(succ)
        for pred in list(new_block0.predset):
            new_block0.predset._del(pred)

        # Clean new block1 pred/succ sets
        for succ in list(new_block1.succset):
            new_block1.succset._del(succ)
        for pred in list(new_block1.predset):
            new_block1.predset._del(pred)

        # Set up new block relationships
        new_block0.predset.add_unique(dispatcher_father.serial)
        new_block1.predset.add_unique(dispatcher_father.serial)
        new_block0.succset.add_unique(childs_goto_serial)
        new_block1.succset.add_unique(childs_goto_serial)
        new_block0.mark_lists_dirty()
        new_block1.mark_lists_dirty()

        # Clean and update dispatcher_father successors
        for succ_serial in list(dispatcher_father.succset):
            dispatcher_father.succset._del(succ_serial)
        dispatcher_father.succset.add_unique(new_id0_serial)
        dispatcher_father.succset.add_unique(new_id1_serial)
        dispatcher_father.mark_lists_dirty()

        # Update block types and ranges
        dispatcher_father.type = ida_hexrays.BLT_2WAY
        new_block0.type = ida_hexrays.BLT_1WAY
        new_block1.type = ida_hexrays.BLT_1WAY
        new_block0.start = dispatcher_father.start
        new_block1.start = dispatcher_father.start
        new_block0.end = dispatcher_father.end
        new_block1.end = dispatcher_father.end

        logger.debug(
            "After update - father preds=%s, succs=%s",
            list(dispatcher_father.predset), list(dispatcher_father.succset)
        )
        logger.debug(
            "After update - new0 preds=%s, succs=%s",
            list(new_block0.predset), list(new_block0.succset)
        )
        logger.debug(
            "After update - new1 preds=%s, succs=%s",
            list(new_block1.predset), list(new_block1.succset)
        )
        logger.debug(
            "After update - goto block %d preds=%s, succs=%s",
            childs_goto_serial,
            list(mba.get_mblock(childs_goto_serial).predset),
            list(mba.get_mblock(childs_goto_serial).succset)
        )
