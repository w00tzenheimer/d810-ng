from __future__ import annotations

import dataclasses
import functools
import typing

import ida_hexrays
import idaapi

from d810.core import getLogger
from d810.core import bits as rotate_helpers
from d810.core.bits import (
    get_add_cf,
    get_add_of,
    get_parity_flag,
    get_sub_of,
    signed_to_unsigned,
    unsigned_to_signed,
)
from d810.core.cymode import CythonMode

# Try to import Cython speedups if CythonMode is enabled
get_stack_or_reg_name = None
cy_hash_mop = None
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr._chexrays_api import get_stack_or_reg_name
        from d810.speedups.cythxr._chexrays_api import hash_mop as cy_hash_mop
    except ImportError:
        pass

# Pure Python fallback when Cython is disabled or failed to import
if get_stack_or_reg_name is None:
    from d810.hexrays.cfg_utils import get_stack_var_name as get_stack_or_reg_name
from d810.errors import (
    EmulationException,
    EmulationIndirectJumpException,
    UnresolvedMopException,
    WritableMemoryReadException,
)
from d810.hexrays.cfg_utils import get_block_serials_by_address
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    mop_type_to_string,
    opcode_to_string,
)
from d810.hexrays.hexrays_helpers import (
    AND_TABLE,
    CONDITIONAL_JUMP_OPCODES,
    CONTROL_FLOW_OPCODES,
    equal_mops_ignore_size,
    get_mop_index,
)

emulator_log = getLogger(__name__)


# Extracted class
class SyntheticCallReturnCache:
    """
    Provides stable, synthetic return values for calls based on (EA, dest_size).

    Also tracks provenance: chained synthetic values can be traced back to their origin.
    """

    DEFAULT_TAG = 0xD810000000000000
    DEFAULT_MASK = 0xFFFFFFFFFFFF

    def __init__(self, tag: int = DEFAULT_TAG, mask: int = DEFAULT_MASK):
        self.tag = tag
        self.mask = mask
        self._cache: dict[tuple[int, ...], int] = {}
        # Track provenance: maps synthetic value -> origin synthetic value
        self._provenance: dict[int, int] = {}

    def _ensure_nonzero(self, value: int, dest_size: int) -> int:
        """Ensure value is non-zero after masking to dest_size."""
        mask = AND_TABLE.get(dest_size, AND_TABLE[8])
        val = value & mask
        if val == 0:
            val = (value | 1) & mask
            if val == 0:
                val = 1  # final fallback
        return val

    def _get_or_create(
        self,
        key: tuple[int, ...],
        dest_size: int,
        base_value: int,
        origin: int,
    ) -> int:
        """Common caching logic: check cache, compute if needed, track provenance."""
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        val = self._ensure_nonzero(base_value, dest_size)
        self._cache[key] = val
        self._provenance[val] = origin
        return val

    @functools.singledispatchmethod
    def get(self, ins: ida_hexrays.minsn_t) -> int:
        """Return a stable, non-zero synthetic value for a call result.

        Keyed by (EA, dest_size). Ensures non-zero after masking to dest size.
        """
        dest_size = getattr(ins.d, "size", 0) or 8
        ea = getattr(ins, "ea", 0) or id(ins)
        key = (ea, dest_size)

        # Construct a high-tagged synthetic pointer-like value
        base = self.tag ^ (ea & self.mask)
        # Root synthetic values are their own origin (pass base as origin placeholder)
        val = self._get_or_create(key, dest_size, base, origin=0)
        # Update origin after creation for root values
        if val not in self._provenance or self._provenance[val] == 0:
            self._provenance[val] = val
        return val

    @get.register(ida_hexrays.mop_t)
    def _(self, mop: ida_hexrays.mop_t) -> int:
        """Return a stable, non-zero synthetic value for an unresolved mop.

        Uses structural info when available to keep values stable across runs.
        """
        try:
            if cy_hash_mop is not None:
                h = int(cy_hash_mop(mop, 0)) & self.mask
            else:
                h = hash(format_mop_t(mop)) & self.mask
        except Exception:
            h = id(mop) & self.mask
        dest_size = getattr(mop, "size", 0) or 8
        key = (h, dest_size)
        tag = self.tag
        base = tag ^ h
        val = self._get_or_create(key, dest_size, base, origin=0)
        # Update origin after creation for root values
        if val not in self._provenance or self._provenance[val] == 0:
            self._provenance[val] = val
        return val

    def chain(self, ins: ida_hexrays.minsn_t, from_address: int) -> int:
        """Return a cached, stable synthetic value derived from from_address.

        This allows symbolic propagation through pointer chains while maintaining
        provenance tracking back to the original synthetic value.

        Args:
            ins: The instruction (used for dest_size and optional EA)
            from_address: The synthetic address being dereferenced

        Returns:
            A new synthetic value that is tracked and cacheable
        """
        dest_size = ins.d.size
        key = (from_address, dest_size, getattr(ins, "ea", 0) or id(ins))

        # Compute a new synthetic value based on the address + dest size
        base = from_address ^ (dest_size << 48)
        if (base & AND_TABLE[dest_size]) == 0:
            base = (from_address & 0xFFFFFFFF) | self.tag

        # Track provenance: find the origin of from_address and propagate it
        origin = self._provenance.get(from_address, from_address)

        val = self._get_or_create(key, dest_size, base, origin)

        if emulator_log.debug_on:
            emulator_log.debug(
                "ldx %x (synthetic sentinel -> chained %x, origin %x)",
                from_address,
                val,
                origin,
            )
        return val

    def get_origin(self, synthetic_value: int) -> int | None:
        """Return the original synthetic value that this value was derived from.

        Args:
            synthetic_value: A synthetic value (either root or chained)

        Returns:
            The original synthetic value, or None if not tracked
        """
        return self._provenance.get(synthetic_value)

    def is_synthetic_address(self, addr: int) -> bool:
        """
        Returns True if 'addr' matches the synthetic call/TEB/PEB sentinel pattern.
        this is used to avoid spurious MEMORY[0] issues, rather than erroring out.
        """
        # TODO: make the mask configurable or derived from the passed in tag
        if (addr & 0xFFF0000000000000) == self.tag:
            emulator_log.debug("ldx %x (synthetic sentinel, skip deref)", addr)
            return True
        return False


class MicroCodeInterpreter(object):
    def __init__(self, global_environment=None, symbolic_mode=False):
        self.global_environment = (
            MicroCodeEnvironment() if global_environment is None else global_environment
        )
        # Stable synthetic return values for calls (per EA, per size)
        self.synthetic_call = SyntheticCallReturnCache()
        # Enable symbolic fallback for unresolved variables
        self.symbolic_mode: bool = symbolic_mode

    def _eval_instruction_and_update_environment(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        environment: MicroCodeEnvironment,
    ) -> int | None:
        environment.set_cur_flow(blk, ins)
        res = self._eval_instruction(ins, environment)
        if res is not None:
            if (ins.d is not None) and ins.d.t != ida_hexrays.mop_z:
                environment.assign(ins.d, res, auto_define=True)
        return res

    def _eval_instruction(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        is_flow_instruction = self._eval_control_flow_instruction(ins, environment)
        if is_flow_instruction:
            return None
        call_helper_res = self._eval_call_helper(ins, environment)
        if call_helper_res is not None:
            return call_helper_res
        if ins.opcode == ida_hexrays.m_call:
            return self._eval_call(ins, environment)
        elif ins.opcode == ida_hexrays.m_icall:
            return self._eval_call(ins, environment)
        res_mask = AND_TABLE[ins.d.size]
        if ins.opcode == ida_hexrays.m_ldx:
            return self._eval_load(ins, environment)
        elif ins.opcode == ida_hexrays.m_stx:
            return self._eval_store(ins, environment)
        elif ins.opcode == ida_hexrays.m_mov:
            return (self.eval(ins.l, environment)) & res_mask
        elif ins.opcode == ida_hexrays.m_neg:
            return (-self.eval(ins.l, environment)) & res_mask
        elif ins.opcode == ida_hexrays.m_lnot:
            return self.eval(ins.l, environment) != 0
        elif ins.opcode == ida_hexrays.m_bnot:
            return (self.eval(ins.l, environment) ^ res_mask) & res_mask
        elif ins.opcode == ida_hexrays.m_xds:
            left_value_signed = unsigned_to_signed(
                self.eval(ins.l, environment), ins.l.size
            )
            return signed_to_unsigned(left_value_signed, ins.d.size) & res_mask
        elif ins.opcode == ida_hexrays.m_xdu:
            return (self.eval(ins.l, environment)) & res_mask
        elif ins.opcode == ida_hexrays.m_low:
            return (self.eval(ins.l, environment)) & res_mask
        elif ins.opcode == ida_hexrays.m_high:
            # Extract the upper half of the operand. We shift by the size
            # of the destination (in bytes) converted to bits, then mask.
            shift_bits = ins.d.size * 8 if ins.d and ins.d.size else 0
            return (self.eval(ins.l, environment) >> shift_bits) & res_mask
        elif ins.opcode == ida_hexrays.m_add:
            return (
                self.eval(ins.l, environment) + self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_sub:
            return (
                self.eval(ins.l, environment) - self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_mul:
            return (
                self.eval(ins.l, environment) * self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_udiv:
            return (
                self.eval(ins.l, environment) // self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_sdiv:
            return (
                self.eval(ins.l, environment) // self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_umod:
            return (
                self.eval(ins.l, environment) % self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_smod:
            return (
                self.eval(ins.l, environment) % self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_or:
            return (
                self.eval(ins.l, environment) | self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_and:
            return (
                self.eval(ins.l, environment) & self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_xor:
            return (
                self.eval(ins.l, environment) ^ self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_shl:
            return (
                self.eval(ins.l, environment) << self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_shr:
            return (
                self.eval(ins.l, environment) >> self.eval(ins.r, environment)
            ) & res_mask
        elif ins.opcode == ida_hexrays.m_sar:
            res_signed = unsigned_to_signed(
                self.eval(ins.l, environment), ins.l.size
            ) >> self.eval(ins.r, environment)
            return signed_to_unsigned(res_signed, ins.d.size) & res_mask
        elif ins.opcode == ida_hexrays.m_cfadd:
            tmp = get_add_cf(
                self.eval(ins.l, environment), self.eval(ins.r, environment), ins.l.size
            )
            return tmp & res_mask
        elif ins.opcode == ida_hexrays.m_ofadd:
            tmp = get_add_of(
                self.eval(ins.l, environment), self.eval(ins.r, environment), ins.l.size
            )
            return tmp & res_mask
        elif ins.opcode == ida_hexrays.m_sets:
            left_value_signed = unsigned_to_signed(
                self.eval(ins.l, environment), ins.l.size
            )
            res = 1 if left_value_signed < 0 else 0
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_seto:
            left_value_signed = unsigned_to_signed(
                self.eval(ins.l, environment), ins.l.size
            )
            right_value_signed = unsigned_to_signed(
                self.eval(ins.r, environment), ins.r.size
            )
            sub_overflow = get_sub_of(left_value_signed, right_value_signed, ins.l.size)
            return sub_overflow & res_mask
        elif ins.opcode == ida_hexrays.m_setnz:
            res = (
                1
                if self.eval(ins.l, environment) != self.eval(ins.r, environment)
                else 0
            )
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setz:
            res = (
                1
                if self.eval(ins.l, environment) == self.eval(ins.r, environment)
                else 0
            )
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setae:
            res = (
                1
                if self.eval(ins.l, environment) >= self.eval(ins.r, environment)
                else 0
            )
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setb:
            res = (
                1
                if self.eval(ins.l, environment) < self.eval(ins.r, environment)
                else 0
            )
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_seta:
            res = (
                1
                if self.eval(ins.l, environment) > self.eval(ins.r, environment)
                else 0
            )
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setbe:
            res = (
                1
                if self.eval(ins.l, environment) <= self.eval(ins.r, environment)
                else 0
            )
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setg:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            res = 1 if left_value > right_value else 0
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setge:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            res = 1 if left_value >= right_value else 0
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setl:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            res = 1 if left_value < right_value else 0
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setle:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            res = 1 if left_value <= right_value else 0
            return res & res_mask
        elif ins.opcode == ida_hexrays.m_setp:
            res = get_parity_flag(
                self.eval(ins.l, environment), self.eval(ins.r, environment), ins.l.size
            )
            return res & res_mask
        raise EmulationException(
            "Unsupported instruction opcode '{0}': '{1}'".format(
                opcode_to_string(ins.opcode), format_minsn_t(ins)
            )
        )

    @staticmethod
    def _get_blk_serial(mop: ida_hexrays.mop_t) -> int:
        if mop.t == ida_hexrays.mop_b:
            return mop.b
        raise EmulationException(
            "Get block serial with an unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)
            )
        )

    def _eval_conditional_jump(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        if ins.opcode not in CONDITIONAL_JUMP_OPCODES:
            return None
        if ins.opcode == ida_hexrays.m_jtbl:
            # This is not handled the same way
            return None
        cur_blk = environment.cur_blk
        if cur_blk is None:
            raise EmulationException(
                "Can't evaluate conditional jump with null block:  '{0}'".format(
                    format_minsn_t(ins)
                )
            )
        direct_child_serial = cur_blk.serial + 1
        if ins.opcode == ida_hexrays.m_jcnd:
            jump_taken = self.eval(ins.l, environment) != 0
        elif ins.opcode == ida_hexrays.m_jnz:
            jump_taken = self.eval(ins.l, environment) != self.eval(ins.r, environment)
        elif ins.opcode == ida_hexrays.m_jz:
            jump_taken = self.eval(ins.l, environment) == self.eval(ins.r, environment)
        elif ins.opcode == ida_hexrays.m_jae:
            jump_taken = self.eval(ins.l, environment) >= self.eval(ins.r, environment)
        elif ins.opcode == ida_hexrays.m_jb:
            jump_taken = self.eval(ins.l, environment) < self.eval(ins.r, environment)
        elif ins.opcode == ida_hexrays.m_ja:
            jump_taken = self.eval(ins.l, environment) > self.eval(ins.r, environment)
        elif ins.opcode == ida_hexrays.m_jbe:
            jump_taken = self.eval(ins.l, environment) <= self.eval(ins.r, environment)
        elif ins.opcode == ida_hexrays.m_jg:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            jump_taken = left_value > right_value
        elif ins.opcode == ida_hexrays.m_jge:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            jump_taken = left_value >= right_value
        elif ins.opcode == ida_hexrays.m_jl:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            jump_taken = left_value < right_value
        elif ins.opcode == ida_hexrays.m_jle:
            left_value = unsigned_to_signed(self.eval(ins.l, environment), ins.l.size)
            right_value = unsigned_to_signed(self.eval(ins.r, environment), ins.r.size)
            jump_taken = left_value <= right_value
        else:
            # This should never happen
            raise EmulationException(
                "Unhandled conditional jump:  '{0}'".format(format_minsn_t(ins))
            )
        return self._get_blk_serial(ins.d) if jump_taken else direct_child_serial

    def _eval_control_flow_instruction(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> bool:
        if ins.opcode not in CONTROL_FLOW_OPCODES:
            return False
        cur_blk = environment.cur_blk
        if cur_blk is None:
            raise EmulationException(
                "Can't evaluate control flow instruction with null block:  '{0}'".format(
                    format_minsn_t(ins)
                )
            )

        next_blk_serial = self._eval_conditional_jump(ins, environment)
        if next_blk_serial is not None:
            next_blk = cur_blk.mba.get_mblock(next_blk_serial)
            next_ins = next_blk.head
            environment.set_next_flow(next_blk, next_ins)
            return True

        if ins.opcode == ida_hexrays.m_goto:
            next_blk_serial = self._get_blk_serial(ins.l)
        elif ins.opcode == ida_hexrays.m_jtbl:
            left_value = self.eval(ins.l, environment)
            cases = ins.r.c
            # Initialize to default case
            next_blk_serial = [x for x in cases.targets][-1]
            for possible_values, target_block_serial in zip(
                cases.values, cases.targets
            ):
                for test_value in possible_values:
                    if left_value == test_value:
                        next_blk_serial = target_block_serial
                        break
        elif ins.opcode == ida_hexrays.m_ijmp:
            if environment.cur_blk is None:
                raise EmulationException(
                    "Can't evaluate indirect jump with null block:  '{0}'".format(
                        format_minsn_t(ins)
                    )
                )
            ijmp_dest_ea = self.eval(ins.d, environment)
            dest_block_serials = get_block_serials_by_address(
                environment.cur_blk.mba, ijmp_dest_ea
            )
            if len(dest_block_serials) == 0:
                raise EmulationIndirectJumpException(
                    "No blocks found at address {0:x}".format(ijmp_dest_ea),
                    ijmp_dest_ea,
                    dest_block_serials,
                )

            if len(dest_block_serials) > 1:
                raise EmulationIndirectJumpException(
                    "Multiple blocks at address {0:x}: {1}".format(
                        ijmp_dest_ea, dest_block_serials
                    ),
                    ijmp_dest_ea,
                    dest_block_serials,
                )
            next_blk_serial = dest_block_serials[0]

        if next_blk_serial is None:
            return False
        next_blk = cur_blk.mba.get_mblock(next_blk_serial)
        next_ins = next_blk.head
        environment.set_next_flow(next_blk, next_ins)
        return True

    def _eval_call_helper(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        # Currently, we only support helper calls, (but end goal is to allow to hook calls)
        if ins.opcode != ida_hexrays.m_call or ins.l.t != ida_hexrays.mop_h:
            return None
        res_mask = AND_TABLE[ins.d.size]
        helper_name = ins.l.helper
        args_list = ins.d

        if emulator_log.debug_on:
            emulator_log.debug("Call helper for %s", helper_name)
        # and we support only __RORX__/__ROLX__
        if helper_name.startswith("__ROR") or helper_name.startswith("__ROL"):
            # Helper name is already complete, e.g., "__ROL8__" or "__ROR4__"
            helper_func = getattr(rotate_helpers, helper_name, None)
            if helper_func is None:
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "Call helper for %s: helper not found in rotate_helpers",
                        helper_name,
                    )
                return None
            data_1 = self.eval(args_list.f.args[0], environment)
            data_2 = self.eval(args_list.f.args[1], environment)
            if data_1 is None or data_2 is None:
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "Call helper for %s: data_1 (%s) or data_2 (%s) is None",
                        helper_name,
                        data_1,
                        data_2,
                    )
                return None
            return helper_func(data_1, data_2) & res_mask
        elif helper_name in ("__readfsqword", "__readgsqword"):
            # These helpers read from FS/GS: they are known to be non-null in practice.
            # Return a stable non-zero synthetic value to avoid null folding.
            return self.synthetic_call.get(ins) & res_mask
        return None

    def _eval_load(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        res_mask = AND_TABLE[ins.d.size]
        if ins.opcode != ida_hexrays.m_ldx or environment.cur_blk is None:
            return None

        load_address = self.eval(ins.r, environment)
        formatted_seg_register = format_mop_t(ins.l)
        # formatted segment register: <mop_t type=mop_r size=2 dstr=ds.2>
        if formatted_seg_register == "ss.2":
            stack_mop = ida_hexrays.mop_t()
            stack_mop.erase()
            stack_mop._make_stkvar(environment.cur_blk.mba, load_address)
            if emulator_log.debug_on:
                emulator_log.debug(
                    "Searching for stack mop {0}".format(format_mop_t(stack_mop))
                )
            if (
                stack_mop_value := environment.lookup(
                    stack_mop, raise_exception=not self.symbolic_mode
                )
            ) is None:
                if self.symbolic_mode:
                    stack_mop_value = self.synthetic_call.get(stack_mop)
                    environment.define(stack_mop, stack_mop_value)
                    if emulator_log.info_on:
                        emulator_log.info(
                            " synthetic stack mop {0} @ address {1:x} defined as: {2:x}".format(
                                get_stack_or_reg_name(stack_mop),
                                load_address,
                                stack_mop_value,
                            )
                        )
                else:
                    # Avoid dstr/format_mop_t in exception text (hot path)
                    _name = get_stack_or_reg_name(stack_mop)
                    raise EmulationException(
                        "Variable {0} is not defined for mop_r or mop_S".format(_name)
                    )
            if emulator_log.debug_on:
                emulator_log.debug(
                    "  stack mop {0} value : {1}".format(
                        format_mop_t(stack_mop), stack_mop_value
                    )
                )
            return stack_mop_value & res_mask
        else:
            if emulator_log.debug_on:
                # formatted segment register: <mop_t type=mop_r size=2 dstr=ds.2>
                emulator_log.debug(
                    "formatted segment register: {0}".format(formatted_seg_register)
                )
            mem_seg = idaapi.getseg(load_address)
            if mem_seg is None:
                # If this address looks like a synthetic call/TEB/PEB sentinel, treat as unknown
                # to avoid spurious MEMORY[0] issues, rather than erroring out.
                if self.synthetic_call.is_synthetic_address(load_address):
                    # Return a cached, stable synthetic value based on the address + dest size
                    # This allows symbolic propagation through pointer chains
                    return self.synthetic_call.chain(ins, load_address)
                # Treat null deref as unknown to avoid spurious MEMORY[0]
                if load_address == 0:
                    emulator_log.warning(
                        "ldx 0 @ {0:x} (null deref, returning None)".format(
                            load_address
                        )
                    )
                    return None
                raise EmulationException(
                    "ldx {0:x} (no segment -> return None)".format(load_address)
                )
            seg_perm = mem_seg.perm
            if (seg_perm & idaapi.SEGPERM_WRITE) != 0:
                raise WritableMemoryReadException(
                    "ldx {0:x} (writable -> return None)".format(load_address)
                )
            else:
                memory_value = idaapi.get_qword(load_address)
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "ldx %x (non writable -> return %x)",
                        load_address,
                        memory_value & res_mask,
                    )
                return memory_value & res_mask

    def _eval_store(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        """Evaluate store to memory (stx) instruction.

        Format: stx source, segment, address
        - ins.l = value to store (source)
        - ins.d = segment register (typically ds.2 or ss.2)
        - ins.r = address to store to

        For stack stores (ss.2), we convert the address to a stack variable and store it.
        For other segments, we currently don't track memory writes (would need memory model).
        """
        res_mask = AND_TABLE[ins.l.size]
        if ins.opcode != ida_hexrays.m_stx or environment.cur_blk is None:
            return None

        try:
            # Evaluate the value to store
            store_value = self.eval(ins.l, environment)

            # Evaluate the address
            store_address = self.eval(ins.r, environment)
        except EmulationException as e:
            # If we can't evaluate operands and symbolic mode is off, bypass
            if not self.symbolic_mode:
                emulator_log.warning("Can't evaluate stx operands: %s, bypassing", e)
                return None
            raise

        # Get segment register (formatted like "ss.2" or "ds.2")
        formatted_seg_register = format_mop_t(ins.d)

        if formatted_seg_register == "ss.2":
            # Stack store - create a stack mop and store the value in the environment
            stack_mop = ida_hexrays.mop_t()
            stack_mop.erase()
            stack_mop._make_stkvar(environment.cur_blk.mba, store_address)

            if emulator_log.debug_on:
                emulator_log.debug(
                    "Storing stack mop {0} @ address {1:x} with value: {2:x}".format(
                        format_mop_t(stack_mop), store_address, store_value & res_mask
                    )
                )
            environment.define(stack_mop, store_value & res_mask)
        else:
            # Non-stack memory write - we don't track writes to global memory
            # but we shouldn't fail either (this is common in real code)
            if emulator_log.debug_on:
                emulator_log.debug(
                    "Ignoring store to non-stack memory (segment: {0}) @ address {1:x}".format(
                        formatted_seg_register, store_address
                    )
                )
        return store_value & res_mask

    def _eval_call(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        # call   ld   l is mop_v or mop_b or mop_h
        if ins.l.t in [ida_hexrays.mop_v, ida_hexrays.mop_b]:
            # TODO: implement
            emulator_log.warning(
                "Evaluation of call with unsupported mop type %s (%s): bypassing",
                mop_type_to_string(ins.l.t),
                format_minsn_t(ins),
            )
            return None
        # we only support ida_hexrays.mop_h for calls atm
        res_mask = AND_TABLE[ins.d.size]
        insn_helper: ida_hexrays.mop_t = ins.l
        # extract helper name and width from helper string (e.g., __ROL4__)
        helper_name = (insn_helper.helper or "").lstrip("!")
        # Windows-specific helpers sometimes show up as named helpers (e.g., !NtCurrentPeb <fast:>)
        hname = (helper_name or "").lstrip("!")
        if hname.startswith("NtCurrentPeb"):
            return self.synthetic_call.get(ins) & res_mask

        emulator_log.warning(
            "Evaluation of helper %s (%s) not implemented: bypassing",
            helper_name,
            format_minsn_t(ins),
        )
        return

    def eval(self, mop: ida_hexrays.mop_t, environment: MicroCodeEnvironment) -> int:
        # Check for invalid mop sizes (e.g., function references have size=-1)
        if mop.size < 0:
            raise EmulationException(
                "Cannot evaluate mop with invalid size ({0}): {1}".format(
                    mop.size, mop_type_to_string(mop.t)
                )
            )

        if mop.t == ida_hexrays.mop_n:
            return mop.nnn.value
        elif mop.t in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
            if (
                value := environment.lookup(mop, raise_exception=not self.symbolic_mode)
            ) is not None:
                return value
            if self.symbolic_mode:
                value = self.synthetic_call.get(mop)
                environment.define(mop, value)
                if emulator_log.info_on:
                    emulator_log.info(
                        " synthetic mop_r/mop_S {0} defined as: {1:x}".format(
                            get_stack_or_reg_name(mop),
                            value,
                        )
                    )
                return value
            else:
                # Avoid dstr/format_mop_t in exception text (hot path)
                _name = get_stack_or_reg_name(mop)
                # Dump environment for debugging
                if emulator_log.debug_on:
                    environment.dump(f"Environment when looking up {_name}")
                raise EmulationException(
                    "Variable {0} is not defined for mop_r or mop_S".format(_name)
                )
        elif mop.t == ida_hexrays.mop_d:
            res = self._eval_instruction(mop.d, environment)
            if res is None:
                raise EmulationException(
                    "Can't evaluate load with null value:  '{0}'".format(
                        format_minsn_t(mop.d)
                    )
                )
            return res
        elif mop.t == ida_hexrays.mop_a:
            if mop.a.t == ida_hexrays.mop_v:
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "Reading a mop_a '%s' -> %x", format_mop_t(mop), mop.a.g
                    )
                return mop.a.g
            elif mop.a.t == ida_hexrays.mop_S:
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "Reading a mop_a '%s' -> %x", format_mop_t(mop), mop.a.s.off
                    )
                return mop.a.s.off
            # Keep message compact and avoid dstr
            raise UnresolvedMopException(
                "Calling get_cst with unsupported mop type {0} - {1}".format(
                    mop_type_to_string(mop.t), mop_type_to_string(mop.a.t)
                )
            )
        elif mop.t == ida_hexrays.mop_v:
            mem_seg = idaapi.getseg(mop.g)
            if mem_seg is None:
                raise EmulationException(
                    "Reading a mop_v at 0x{0:X} (no segment)".format(mop.g)
                )
            seg_perm = mem_seg.perm
            if (seg_perm & idaapi.SEGPERM_WRITE) != 0:
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "Reading a (writable) mop_v %s", format_mop_t(mop)
                    )
                if (value := environment.lookup(mop)) is not None:
                    return value
                raise EmulationException(
                    "Variable for mop_v at 0x{0:X} (size={1}) is not defined".format(
                        mop.g, mop.size
                    )
                )
            else:
                memory_value = idaapi.get_qword(mop.g)
                if emulator_log.debug_on:
                    emulator_log.debug(
                        "Reading a mop_v %x (non writable -> return %x)",
                        mop.g,
                        memory_value,
                    )
                return memory_value & AND_TABLE[mop.size]
        # Avoid dstr in exception text
        raise EmulationException(
            "Unsupported mop type '{0}'".format(mop_type_to_string(mop.t))
        )

    def eval_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        environment: MicroCodeEnvironment | None = None,
        raise_exception: bool = False,
    ) -> bool:
        if environment is None:
            environment = self.global_environment
        if ins is None:
            return False
        if emulator_log.debug_on:
            emulator_log.debug(
                "Evaluating microcode instruction : '%s'", format_minsn_t(ins)
            )
        try:
            self._eval_instruction_and_update_environment(blk, ins, environment)
            return True
        except EmulationException as e:
            emulator_log.warning(
                "Can't evaluate instruction: '%s': %s", format_minsn_t(ins), e
            )
            if raise_exception:
                raise e
        except Exception as e:
            emulator_log.warning(
                "Error during evaluation of: '%s': %s", format_minsn_t(ins), e
            )
            if raise_exception:
                raise e
        return False

    def eval_mop(
        self,
        mop: ida_hexrays.mop_t,
        environment: MicroCodeEnvironment | None = None,
        raise_exception: bool = False,
    ) -> int | None:
        try:
            if environment is None:
                environment = self.global_environment
            res = self.eval(mop, environment)
            return res
        except EmulationException as e:
            # Prefer canonical name for registers/stack vars; fall back to hash
            name = get_stack_or_reg_name(mop)
            emulator_log.warning(
                "Can't get constant mop value: %s for mop '%s': %s",
                name,
                mop_type_to_string(mop.t),
                e,
            )
            # Dump environment for debugging
            if emulator_log.debug_on and environment is not None:
                environment.dump("Environment at lookup failure")
            if raise_exception:
                raise e
            else:
                return None
        except Exception as e:
            emulator_log.error(
                "Unexpected exception while computing constant mop value: '%s': %s",
                format_mop_t(mop),
                e,
            )
            if raise_exception:
                raise e
            else:
                return None


class MopMapping(typing.MutableMapping[ida_hexrays.mop_t, int]):
    def __init__(self):
        self.mops = []
        self.mops_values = []

    def __setitem__(self, mop: ida_hexrays.mop_t, mop_value: int):
        mop_index = get_mop_index(mop, self.mops)
        mop_value &= AND_TABLE[mop.size]
        if mop_index != -1:
            self.mops_values[mop_index] = mop_value
            return
        self.mops.append(mop)
        self.mops_values.append(mop_value)

    def __getitem__(self, mop: ida_hexrays.mop_t) -> int:
        mop_index = get_mop_index(mop, self.mops)
        if mop_index == -1:
            raise KeyError
        return self.mops_values[mop_index]

    def __len__(self):
        return len(self.mops)

    def __delitem__(self, mop: ida_hexrays.mop_t):
        mop_index = get_mop_index(mop, self.mops)
        if mop_index == -1:
            raise KeyError
        del self.mops[mop_index]
        del self.mops_values[mop_index]

    def clear(self):
        self.mops = []
        self.mops_values = []

    def copy(self):
        new_mapping = MopMapping()
        for mop, mop_value in self.items():
            new_mapping[mop] = mop_value
        return new_mapping

    def has_key(self, mop: ida_hexrays.mop_t):
        mop_index = get_mop_index(mop, self.mops)
        return mop_index != -1

    def keys(self) -> list[ida_hexrays.mop_t]:
        return self.mops

    def values(self) -> list[int]:
        return self.mops_values

    def items(self):
        return [(x, y) for x, y in zip(self.mops, self.mops_values)]

    def __contains__(self, mop: ida_hexrays.mop_t):
        return self.has_key(mop)

    def __iter__(self):
        return iter(self.mops)


@dataclasses.dataclass
class MicroCodeEnvironment:
    parent: MicroCodeEnvironment | None = dataclasses.field(default=None)
    mop_r_record: MopMapping = dataclasses.field(default_factory=MopMapping)
    mop_S_record: MopMapping = dataclasses.field(default_factory=MopMapping)

    cur_blk: ida_hexrays.mblock_t | None = dataclasses.field(init=False, default=None)
    cur_ins: ida_hexrays.minsn_t | None = dataclasses.field(init=False, default=None)
    next_blk: ida_hexrays.mblock_t | None = dataclasses.field(init=False, default=None)
    next_ins: ida_hexrays.minsn_t | None = dataclasses.field(init=False, default=None)

    def items(self):
        return [x for x in self.mop_r_record.items() + self.mop_S_record.items()]

    def get_copy(self, copy_parent=True) -> MicroCodeEnvironment:
        parent_copy = self.parent
        if self.parent is not None and copy_parent:
            parent_copy = self.parent.get_copy(copy_parent=True)
        new_env = MicroCodeEnvironment(parent_copy)
        for mop, mop_value in self.mop_r_record.items():
            new_env.define(mop, mop_value)
        for mop, mop_value in self.mop_S_record.items():
            new_env.define(mop, mop_value)
        new_env.cur_blk = self.cur_blk
        new_env.cur_ins = self.cur_ins
        new_env.next_blk = self.next_blk
        new_env.next_ins = self.next_ins
        return new_env

    def set_cur_flow(self, cur_blk: ida_hexrays.mblock_t, cur_ins: ida_hexrays.minsn_t):
        self.cur_blk = cur_blk
        self.cur_ins = cur_ins
        self.next_blk = cur_blk
        if self.cur_ins is None:
            self.next_blk = typing.cast(
                ida_hexrays.mblock_t,
                self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1),
            )
            self.next_ins = typing.cast(ida_hexrays.minsn_t, self.next_blk.head)
        else:
            self.next_ins = self.cur_ins.next
            if self.next_ins is None:
                self.next_blk = typing.cast(
                    ida_hexrays.mblock_t,
                    self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1),
                )
                self.next_ins = typing.cast(ida_hexrays.minsn_t, self.next_blk.head)
        if emulator_log.debug_on:
            emulator_log.debug(
                "Setting next block %d and next ins %s",
                self.next_blk.serial,
                format_minsn_t(self.next_ins),
            )

    def set_next_flow(
        self, next_blk: ida_hexrays.mblock_t, next_ins: ida_hexrays.minsn_t
    ):
        self.next_blk = next_blk
        self.next_ins = next_ins

    def define(self, mop: ida_hexrays.mop_t, value: int) -> int:
        if mop.t == ida_hexrays.mop_r:
            self.mop_r_record[mop] = value
            return value
        elif mop.t == ida_hexrays.mop_S:
            self.mop_S_record[mop] = value
            return value
        raise EmulationException(
            "Defining an unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)
            )
        )

    def _lookup_mop(
        self,
        searched_mop: ida_hexrays.mop_t,
        mop_value_dict: MopMapping,
        new_mop_value: int | None = None,
        auto_define: bool = True,
        raise_exception: bool = True,
    ) -> int | None:
        for known_mop, mop_value in mop_value_dict.items():
            if equal_mops_ignore_size(searched_mop, known_mop):
                if new_mop_value is not None:
                    mop_value_dict[searched_mop] = new_mop_value
                    return new_mop_value
                return mop_value
        if (new_mop_value is not None) and auto_define:
            self.define(searched_mop, new_mop_value)
            return new_mop_value
        if raise_exception:
            _name = get_stack_or_reg_name(searched_mop)
            raise EmulationException(
                "Variable {0} of type {1} is not defined".format(
                    _name, mop_type_to_string(searched_mop.t)
                )
            )

    def lookup(
        self, mop: ida_hexrays.mop_t, raise_exception: bool = True
    ) -> int | None:
        if mop.t == ida_hexrays.mop_r:
            return self._lookup_mop(
                mop, self.mop_r_record, raise_exception=raise_exception
            )
        elif mop.t == ida_hexrays.mop_S:
            return self._lookup_mop(
                mop, self.mop_S_record, raise_exception=raise_exception
            )

    def assign(
        self, mop: ida_hexrays.mop_t, value: int, auto_define: bool = True
    ) -> int | None:
        if mop.t == ida_hexrays.mop_r:
            return self._lookup_mop(mop, self.mop_r_record, value, auto_define)
        elif mop.t == ida_hexrays.mop_S:
            return self._lookup_mop(mop, self.mop_S_record, value, auto_define)
        raise EmulationException(
            "Assigning an unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)
            )
        )

    def dump(self, header: str = "Environment dump"):
        """Dump the current environment state for debugging."""
        emulator_log.debug("=== %s ===", header)
        emulator_log.debug("  mop_r records (%d):", len(self.mop_r_record))
        for mop, value in self.mop_r_record.items():
            emulator_log.debug("    %s = 0x%x", format_mop_t(mop), value)
        emulator_log.debug("  mop_S records (%d):", len(self.mop_S_record))
        for mop, value in self.mop_S_record.items():
            emulator_log.debug("    %s = 0x%x", format_mop_t(mop), value)
        emulator_log.debug("=== End %s ===", header)
