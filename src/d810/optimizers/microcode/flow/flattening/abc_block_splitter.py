"""
ABC conditional-state resolver for ABC pattern handling.

This module provides approaches for handling ABC (Arithmetic/Bitwise/Constant)
patterns in control flow unflattening. ConditionalStateResolver resolves targets
directly without creating new blocks:

- Detects ABC patterns: state = x + magic (where magic in 1010000-1011999)
- Resolves both possible targets (x=0 and x!=0) via dispatcher emulation
- Creates conditional jump in-place: jnz x, 0, target1; goto target0

The retired ABCBlockSplitter block-insertion path is intentionally absent from
this module. New ABC materialization should go through typed CFG primitives and
Hex-Rays materialization, not direct insert_block() helpers here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.mutation.cfg_mutations import change_1way_block_successor
from d810.hexrays.utils.hexrays_helpers import dup_mop

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.generic import GenericDispatcherInfo
    from d810.evaluator.hexrays_microcode.tracker import MopHistory

logger = getLogger("D810.abc_splitter")


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
        from d810.evaluator.hexrays_microcode.emulator import (
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
