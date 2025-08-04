from __future__ import annotations

import ida_hexrays
import idaapi

from d810.conf.loggers import getLogger
from d810.errors import (
    EmulationException,
    EmulationIndirectJumpException,
    UnresolvedMopException,
    WritableMemoryReadException,
)
from d810.expr.utils import (
    get_add_cf,
    get_add_of,
    get_parity_flag,
    get_sub_of,
    ror,
    signed_to_unsigned,
    unsigned_to_signed,
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


class MicroCodeInterpreter(object):
    def __init__(self, global_environment=None):
        self.global_environment = (
            MicroCodeEnvironment() if global_environment is None else global_environment
        )

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

        emulator_log.debug("Call helper for {0}".format(helper_name))
        # and we support only __ROR4__ (we should add other Hex-Rays created helper calls)
        if helper_name == "__ROR4__":
            data_1 = self.eval(args_list.f.args[0], environment)
            data_2 = self.eval(args_list.f.args[1], environment)
            return ror(data_1, data_2, 8 * args_list.f.args[0].size) & res_mask
        elif helper_name == "__readfsqword":
            return 0
        return None

    def _eval_load(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        res_mask = AND_TABLE[ins.d.size]
        if ins.opcode == ida_hexrays.m_ldx and environment.cur_blk is not None:
            load_address = self.eval(ins.r, environment)
            formatted_seg_register = format_mop_t(ins.l)
            if formatted_seg_register == "ss.2":
                stack_mop = ida_hexrays.mop_t()
                stack_mop.erase()
                stack_mop._make_stkvar(environment.cur_blk.mba, load_address)
                emulator_log.debug(
                    "Searching for stack mop {0}".format(format_mop_t(stack_mop))
                )
                if (stack_mop_value := environment.lookup(stack_mop)) is None:
                    raise EmulationException(
                        "Variable '{0}' is not defined for mop_r or mop_S".format(
                            format_mop_t(stack_mop)
                        )
                    )
                emulator_log.debug(
                    "  stack mop {0} value : {1}".format(
                        format_mop_t(stack_mop), stack_mop_value
                    )
                )
                return stack_mop_value & res_mask
            else:
                mem_seg = idaapi.getseg(load_address)
                seg_perm = mem_seg.perm
                if (seg_perm & idaapi.SEGPERM_WRITE) != 0:
                    raise WritableMemoryReadException(
                        "ldx {0:x} (writable -> return None)".format(load_address)
                    )
                else:
                    memory_value = idaapi.get_qword(load_address)
                    emulator_log.debug(
                        "ldx {0:x} (non writable -> return {1:x})".format(
                            load_address, memory_value & res_mask
                        )
                    )
                    return memory_value & res_mask

    def _eval_store(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        # TODO: implement
        emulator_log.warning(
            "Evaluation of %s not implemented: bypassing", format_minsn_t(ins)
        )
        return None

    def _eval_call(
        self, ins: ida_hexrays.minsn_t, environment: MicroCodeEnvironment
    ) -> int | None:
        # TODO: implement
        emulator_log.warning(
            "Evaluation of %s not implemented: bypassing", format_minsn_t(ins)
        )
        return None

    def eval(self, mop: ida_hexrays.mop_t, environment: MicroCodeEnvironment) -> int:
        if mop.t == ida_hexrays.mop_n:
            return mop.nnn.value
        elif mop.t in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
            if (value := environment.lookup(mop)) is not None:
                return value
            raise EmulationException(
                "Variable '{0}' is not defined for mop_r or mop_S".format(
                    format_mop_t(mop)
                )
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
                emulator_log.debug(
                    "Reading a mop_a '{0}' -> {1:x}".format(format_mop_t(mop), mop.a.g)
                )
                return mop.a.g
            elif mop.a.t == ida_hexrays.mop_S:
                emulator_log.debug(
                    "Reading a mop_a '{0}' -> {1:x}".format(
                        format_mop_t(mop), mop.a.s.off
                    )
                )
                return mop.a.s.off
            raise UnresolvedMopException(
                "Calling get_cst with unsupported mop type {0} - {1}: '{2}'".format(
                    mop.t, mop.a.t, format_mop_t(mop)
                )
            )
        elif mop.t == ida_hexrays.mop_v:
            mem_seg = idaapi.getseg(mop.g)
            seg_perm = mem_seg.perm
            if (seg_perm & idaapi.SEGPERM_WRITE) != 0:
                emulator_log.debug(
                    "Reading a (writable) mop_v {0}".format(format_mop_t(mop))
                )
                if (value := environment.lookup(mop)) is not None:
                    return value
                raise EmulationException(
                    "Variable '{0}' is not defined for mop_v".format(mop.dstr())
                )
            else:
                memory_value = idaapi.get_qword(mop.g)
                emulator_log.debug(
                    "Reading a mop_v {0:x} (non writable -> return {1:x})".format(
                        mop.g, memory_value
                    )
                )
                return mop.g
        raise EmulationException(
            "Unsupported mop type '{0}': '{1}'".format(
                mop_type_to_string(mop.t), format_mop_t(mop)
            )
        )

    def eval_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
        environment: MicroCodeEnvironment | None = None,
        raise_exception: bool = False,
    ) -> bool:
        try:
            if environment is None:
                environment = self.global_environment
            emulator_log.info(
                "Evaluating microcode instruction : '{0}'".format(format_minsn_t(ins))
            )
            if ins is None:
                return False
            self._eval_instruction_and_update_environment(blk, ins, environment)
            return True
        except EmulationException as e:
            emulator_log.warning(
                "Can't evaluate instruction: '{0}': {1}".format(format_minsn_t(ins), e)
            )
            if raise_exception:
                raise e
        except Exception as e:
            emulator_log.warning(
                "Error during evaluation of: '{0}': {1}".format(format_minsn_t(ins), e)
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
            emulator_log.warning(
                "Can't get constant mop value: '%s' for mop: '%s': %s",
                mop.dstr(),
                format_mop_t(mop),
                e,
            )
            if raise_exception:
                raise e
            else:
                return None
        except Exception as e:
            emulator_log.error(
                "Unexpected exception while computing constant mop value: '{0}': {1}".format(
                    format_mop_t(mop), e
                )
            )
            if raise_exception:
                raise e
            else:
                return None


class MopMapping(object):
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


class MicroCodeEnvironment(object):
    def __init__(self, parent: MicroCodeEnvironment | None = None):
        self.parent = parent
        self.mop_r_record = MopMapping()
        self.mop_S_record = MopMapping()

        self.cur_blk = None
        self.cur_ins = None
        self.next_blk = None
        self.next_ins = None

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
            self.next_blk = self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1)
            self.next_ins = self.next_blk.head
        else:
            self.next_ins = self.cur_ins.next
            if self.next_ins is None:
                self.next_blk = self.cur_blk.mba.get_mblock(self.cur_blk.serial + 1)
                self.next_ins = self.next_blk.head
        emulator_log.debug(
            "Setting next block {0} and next ins {1}".format(
                self.next_blk.serial, format_minsn_t(self.next_ins)
            )
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
            raise EmulationException(
                "Variable '{0}' is not defined".format(format_mop_t(searched_mop))
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
