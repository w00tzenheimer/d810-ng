"""
ABC conditional-state resolver for ABC pattern handling.

This module provides approaches for handling ABC (Arithmetic/Bitwise/Constant)
patterns in control flow unflattening. ConditionalStateResolver discovers targets
directly without creating new blocks:

- Detects ABC patterns: state = x + magic (where magic in 1010000-1011999)
- Resolves both possible targets (x=0 and x!=0) via dispatcher emulation

The retired ABCBlockSplitter block-insertion path is intentionally absent from
this module. New ABC materialization should go through typed CFG primitives and
Hex-Rays materialization, not direct live-CFG helpers here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.utils.hexrays_helpers import dup_mop

if TYPE_CHECKING:
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


@dataclass(frozen=True)
class ABCResolutionEvidence:
    """Read-only ABC pattern evidence resolved against the dispatcher."""

    pattern: ABCPatternInfo
    target0_serial: int | None = None
    target1_serial: int | None = None
    resolved_target_serial: int | None = None


@dataclass
class ConditionalStateResolver:
    """
    Resolves conditional state patterns to target evidence without new blocks.

    Detects patterns where state is computed from a binary condition:
        state = x OP magic_constant  (where OP is add/sub/or/xor)

    Instead of creating intermediate blocks or mutating live Hex-Rays CFG,
    resolves possible outcomes via dispatcher emulation and returns evidence.

    Usage:
        resolver = ConditionalStateResolver(mba, dispatcher_info)
        for block in blocks_to_analyze:
            resolver.collect_resolution(block)
    """

    mba: ida_hexrays.mba_t
    dispatcher_info: object

    # Magic number range for ABC patterns
    ABC_CONST_MIN: int = 1010000
    ABC_CONST_MAX: int = 1011999
    observed_blocks: set[int] = field(default_factory=set)

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
        predecessor_history: MopHistory | None,
        state_mop: ida_hexrays.mop_t,
    ) -> int | None:
        if predecessor_history is None:
            return None
        try:
            value = predecessor_history.get_mop_constant_value(state_mop)
        except Exception:
            return None
        if value is None:
            return None
        return int(value)

    def collect_resolution(
        self,
        block: ida_hexrays.mblock_t,
        predecessor_history: MopHistory | None = None,
    ) -> ABCResolutionEvidence | None:
        """Analyze a block for ABC patterns and return read-only target evidence."""
        if block.serial in self.observed_blocks:
            return None

        pattern = self._find_abc_pattern(block, predecessor_history)
        if pattern is None:
            return None

        logger.debug(
            "ConditionalStateResolver: Found %s ABC pattern in block %d, "
            "const=%d, opcode=%d, resolved_state=%s",
            pattern.pattern_kind,
            block.serial,
            pattern.cnst,
            pattern.opcode,
            pattern.resolved_state,
        )
        evidence = self._resolve_pattern_targets(pattern)
        if evidence is not None:
            self.observed_blocks.add(block.serial)
        return evidence

    def _find_abc_pattern(
        self,
        block: ida_hexrays.mblock_t,
        predecessor_history: MopHistory | None = None,
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
                predecessor_history,
            )
            if self_update_pattern is not None:
                return self_update_pattern

            curr_inst = curr_inst.next
        return None

    def _check_instruction_for_self_update(
        self,
        inst: ida_hexrays.minsn_t,
        block_serial: int,
        predecessor_history: MopHistory | None,
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
            current_state = self._resolve_state_from_history(
                predecessor_history,
                state_mop,
            )
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

    def _resolve_pattern_targets(
        self,
        pattern: ABCPatternInfo,
    ) -> ABCResolutionEvidence | None:
        """Resolve pattern targets without mutating live CFG."""
        if pattern.pattern_kind == "self_update":
            if pattern.resolved_state is None:
                return None
            target = self._resolve_target_for_state(pattern.resolved_state)
            if target is None:
                logger.warning(
                    "ABC self-update: Could not resolve target for block %d, state=%d",
                    pattern.block_serial,
                    pattern.resolved_state,
                )
                return None
            return ABCResolutionEvidence(
                pattern=pattern,
                resolved_target_serial=int(target.serial),
            )

        state0, state1 = self._calculate_state_values(pattern)

        logger.info(
            "ABC evidence: block %d, magic=%d, states=(%d, %d)",
            pattern.block_serial, pattern.cnst, state0, state1
        )

        # Resolve targets for both state values
        target0 = self._resolve_target_for_state(state0)
        target1 = self._resolve_target_for_state(state1)

        if target0 is None or target1 is None:
            logger.warning(
                "ABC evidence: Could not resolve targets for block %d (state0=%d->%s, state1=%d->%s)",
                pattern.block_serial, state0, target0, state1, target1
            )
            return None

        logger.info(
            "ABC evidence: block %d -> targets (%d, %d)",
            pattern.block_serial, target0.serial, target1.serial
        )
        return ABCResolutionEvidence(
            pattern=pattern,
            target0_serial=int(target0.serial),
            target1_serial=int(target1.serial),
        )
