"""Runtime: tainted values may not select control flow or an exact result.

Ticket ``d81-1t9x`` (review of ``d81-0xzp``).  An unmodeled call returns a
CONCRETE synthetic integer so the enclosing ``mov call(...), dst`` still
evaluates -- but ``_eval_conditional_jump`` used to compare those integers with
no taint consulted, so an unknown call result picked an arbitrary-but-stable
branch, and ``env.lookup`` / ``eval_mop`` handed the same invented integer to
the evidence backends as a PROVEN state value.

The repair makes exactness part of the RESULT:

* every operand read of a conditional jump / jump table / indirect jump goes
  through ``_require_exact``; on taint the emulator publishes UNKNOWN flow
  (``env.next_blk is None``) and ``eval_instruction`` reports failure;
* ``eval_mop`` and ``MicroCodeEnvironment.lookup`` are EXACT-or-``None`` by
  default -- the raw tainted integer needs an explicit ``require_exact=False``.

Asserted against LIVE microcode (no mocks).
"""

from __future__ import annotations

import os
import platform

import ida_hexrays
import pytest

from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.p_taint import Exactness

from tests.system.runtime.conftest import gen_microcode_at_maturity


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    system = platform.system()
    if system == "Windows":
        return "libobfuscated.dll"
    if system == "Darwin":
        return "libobfuscated.dylib"
    return "libobfuscated.so"


#: Cap the search so a miss costs seconds, not minutes.
_MAX_FUNCS = 200

_UNSUPPORTED_CALLEE = (ida_hexrays.mop_v, ida_hexrays.mop_b)

#: Scratch micro-registers, well above the ABI ones the sample code uses.
_SCRATCH_A = ida_hexrays.mr_first + 64
_SCRATCH_B = ida_hexrays.mr_first + 72
_SCRATCH_C = ida_hexrays.mr_first + 80


def _find_call(mba):
    """First ``(blk, call_insn)`` whose callee operand the emulator does not model."""
    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk is None or blk.nextb is None:
            continue
        insn = blk.head
        while insn is not None:
            if (
                insn.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall)
                and insn.l is not None
                and insn.l.t in _UNSUPPORTED_CALLEE
                and insn.d is not None
            ):
                return blk, insn
            insn = insn.next
    return None


@pytest.fixture(scope="class")
def live_call(libobfuscated_setup):
    """A live ``(mba, blk, call_insn)`` with an unmodeled callee operand."""
    import idautils

    for index, func_ea in enumerate(idautils.Functions()):
        if index >= _MAX_FUNCS:
            break
        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            continue
        found = _find_call(mba)
        if found is not None:
            return (mba,) + found
    pytest.skip("no unmodeled-callee call found in the sample binary")


def _other_serial(mba, blk) -> int:
    """A valid jump target that is NOT the fall-through of *blk*."""
    for serial in range(mba.qty):
        if serial in (blk.serial, blk.nextb.serial):
            continue
        if mba.get_mblock(serial) is not None:
            return serial
    pytest.skip("sample function has too few blocks for a two-way branch")
    raise AssertionError("unreachable")  # pragma: no cover


def _mov_call_into_reg(call_insn, mreg: int, size: int = 8):
    """The real consumer shape: ``mov call(...), reg``."""
    holder = ida_hexrays.minsn_t(call_insn.ea)
    holder.opcode = ida_hexrays.m_mov
    holder.l = ida_hexrays.mop_t()
    holder.l._make_insn(ida_hexrays.minsn_t(call_insn))
    holder.l.size = size
    holder.r = ida_hexrays.mop_t()
    holder.d = ida_hexrays.mop_t()
    holder.d._make_reg(mreg, size)
    return holder


def _binop(ea: int, opcode: int, left, right, dest_mreg: int, size: int):
    ins = ida_hexrays.minsn_t(ea)
    ins.opcode = opcode
    ins.l = ida_hexrays.mop_t(left)
    ins.r = ida_hexrays.mop_t(right)
    ins.d = ida_hexrays.mop_t()
    ins.d._make_reg(dest_mreg, size)
    return ins


def _number(value: int, size: int):
    mop = ida_hexrays.mop_t()
    mop.make_number(value, size)
    return mop


def _cond_jump(ea: int, opcode: int, left, right, target_serial: int):
    ins = ida_hexrays.minsn_t(ea)
    ins.opcode = opcode
    ins.l = ida_hexrays.mop_t(left)
    ins.r = ida_hexrays.mop_t(right)
    ins.d = ida_hexrays.mop_t()
    ins.d.make_blkref(int(target_serial))
    return ins


class TestTaintedConditionalJump:
    """A synthetic call return must not select a branch."""

    binary_name = _get_default_binary()

    def test_a_jump_on_a_synthetic_call_return_resolves_no_branch(self, live_call):
        mba, blk, call_insn = live_call
        target = _other_serial(mba, blk)
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        holder = _mov_call_into_reg(call_insn, _SCRATCH_A)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)
        assert interpreter.is_tainted_mop(holder.d, env)

        jump = _cond_jump(
            call_insn.ea, ida_hexrays.m_jz, holder.d, _number(0, 8), target
        )
        ok = interpreter.eval_instruction(blk, jump, env, raise_exception=False)
        assert not ok, "a jump on an unknown call result must not evaluate"
        assert env.next_blk is None, (
            "an unresolved conditional jump must publish UNKNOWN flow, never the "
            f"fall-through: got block {getattr(env.next_blk, 'serial', None)}"
        )

    def test_taint_reaches_the_jump_through_mov_and_add(self, live_call):
        mba, blk, call_insn = live_call
        target = _other_serial(mba, blk)
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        holder = _mov_call_into_reg(call_insn, _SCRATCH_A)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        # mov -> and -> add : the masked synthetic value carries no tag of its
        # own, so provenance has to travel with the LOCATION.
        copy = ida_hexrays.minsn_t(call_insn.ea)
        copy.opcode = ida_hexrays.m_mov
        copy.l = ida_hexrays.mop_t(holder.d)
        copy.r = ida_hexrays.mop_t()
        copy.d = ida_hexrays.mop_t()
        copy.d._make_reg(_SCRATCH_B, 8)
        interpreter._eval_instruction_and_update_environment(blk, copy, env)

        masked = _binop(
            call_insn.ea, ida_hexrays.m_and, copy.d, _number(0xFFFF, 8), _SCRATCH_C, 8
        )
        interpreter._eval_instruction_and_update_environment(blk, masked, env)

        summed = _binop(
            call_insn.ea, ida_hexrays.m_add, masked.d, _number(1, 8), _SCRATCH_C, 8
        )
        interpreter._eval_instruction_and_update_environment(blk, summed, env)
        assert interpreter.is_tainted_mop(summed.d, env)

        jump = _cond_jump(
            call_insn.ea, ida_hexrays.m_jnz, summed.d, _number(7, 8), target
        )
        ok = interpreter.eval_instruction(blk, jump, env, raise_exception=False)
        assert not ok
        assert env.next_blk is None

    def test_taint_survives_a_narrower_read_of_the_same_location(self, live_call):
        """``rax.8`` tainted must mean ``rax.4`` tainted.

        The value store matches locations with ``equal_mops_ignore_size``, so a
        size-SENSITIVE taint key silently laundered every widening/narrowing
        copy -- which is exactly what a 32-bit state variable does.
        """
        mba, blk, call_insn = live_call
        target = _other_serial(mba, blk)
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        holder = _mov_call_into_reg(call_insn, _SCRATCH_A, size=8)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        narrow = ida_hexrays.mop_t()
        narrow._make_reg(_SCRATCH_A, 4)
        assert interpreter.is_tainted_mop(narrow, env)

        jump = _cond_jump(call_insn.ea, ida_hexrays.m_jz, narrow, _number(0, 4), target)
        ok = interpreter.eval_instruction(blk, jump, env, raise_exception=False)
        assert not ok
        assert env.next_blk is None

    def test_a_bare_call_operand_in_the_condition_resolves_no_branch(self, live_call):
        """``jz call(...), #0`` has no operand KEY to taint -- the nested
        invented result is what makes it unprovable."""
        mba, blk, call_insn = live_call
        target = _other_serial(mba, blk)
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        call_mop = ida_hexrays.mop_t()
        call_mop._make_insn(ida_hexrays.minsn_t(call_insn))
        call_mop.size = 8

        jump = _cond_jump(
            call_insn.ea, ida_hexrays.m_jz, call_mop, _number(0, 8), target
        )
        ok = interpreter.eval_instruction(blk, jump, env, raise_exception=False)
        assert not ok
        assert env.next_blk is None

    def test_a_fully_concrete_jump_still_resolves_both_ways(self, live_call):
        """No regression: proven operands still pick a branch."""
        mba, blk, call_insn = live_call
        target = _other_serial(mba, blk)
        interpreter = MicroCodeInterpreter(symbolic_mode=False)

        env = MicroCodeEnvironment()
        taken = _cond_jump(
            call_insn.ea, ida_hexrays.m_jz, _number(1, 8), _number(1, 8), target
        )
        assert interpreter.eval_instruction(blk, taken, env, raise_exception=False)
        assert env.next_blk is not None
        assert int(env.next_blk.serial) == int(target)

        env = MicroCodeEnvironment()
        not_taken = _cond_jump(
            call_insn.ea, ida_hexrays.m_jz, _number(1, 8), _number(2, 8), target
        )
        assert interpreter.eval_instruction(blk, not_taken, env, raise_exception=False)
        assert env.next_blk is not None
        assert int(env.next_blk.serial) == int(blk.nextb.serial)

    def test_a_tainted_indirect_jump_resolves_no_target(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        holder = _mov_call_into_reg(call_insn, _SCRATCH_A)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        ijmp = ida_hexrays.minsn_t(call_insn.ea)
        ijmp.opcode = ida_hexrays.m_ijmp
        ijmp.l = ida_hexrays.mop_t()
        ijmp.r = ida_hexrays.mop_t()
        ijmp.d = ida_hexrays.mop_t(holder.d)
        ok = interpreter.eval_instruction(blk, ijmp, env, raise_exception=False)
        assert not ok
        assert env.next_blk is None


class TestTaintedExactResult:
    """``eval_mop`` / ``lookup`` are EXACT-or-``None``."""

    binary_name = _get_default_binary()

    def test_a_tainted_location_is_not_published_as_a_value(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = _mov_call_into_reg(call_insn, _SCRATCH_A)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        assert env.lookup(holder.d, raise_exception=False) is None
        assert interpreter.eval_mop(holder.d, environment=env) is None

    def test_the_raw_value_still_flows_when_asked_for_explicitly(self, live_call):
        """Propagation must not regress to the pre-d81-0xzp ``None``."""
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = _mov_call_into_reg(call_insn, _SCRATCH_A)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        assert (
            env.lookup(holder.d, raise_exception=False, require_exact=False) is not None
        )
        result = interpreter.eval_mop_result(holder.d, environment=env)
        assert result.exactness is Exactness.TAINTED
        assert result.value is not None
        assert result.exact_value is None

    def test_a_proven_location_is_published(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()

        clean = ida_hexrays.minsn_t(call_insn.ea)
        clean.opcode = ida_hexrays.m_mov
        clean.l = _number(0x2A, 8)
        clean.r = ida_hexrays.mop_t()
        clean.d = ida_hexrays.mop_t()
        clean.d._make_reg(_SCRATCH_A, 8)
        interpreter._eval_instruction_and_update_environment(blk, clean, env)

        assert env.lookup(clean.d, raise_exception=False) == 0x2A
        assert interpreter.eval_mop(clean.d, environment=env) == 0x2A
        result = interpreter.eval_mop_result(clean.d, environment=env)
        assert result.exactness is Exactness.EXACT
        assert result.exact_value == 0x2A

    def test_a_clean_overwrite_republishes_the_location(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = _mov_call_into_reg(call_insn, _SCRATCH_A)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)
        assert env.lookup(holder.d, raise_exception=False) is None

        clean = ida_hexrays.minsn_t(call_insn.ea + 1)
        clean.opcode = ida_hexrays.m_mov
        clean.l = _number(9, holder.d.size)
        clean.r = ida_hexrays.mop_t()
        clean.d = ida_hexrays.mop_t(holder.d)
        interpreter._eval_instruction_and_update_environment(blk, clean, env)
        assert env.lookup(holder.d, raise_exception=False) == 9
