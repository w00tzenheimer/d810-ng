"""Runtime: unmodeled calls return a TAINTED synthetic value, not ``None``.

Ticket ``d81-0xzp``.  A call whose ``l`` operand is ``mop_v``/``mop_b`` (and an
unimplemented helper) used to evaluate to ``None``; the enclosing
``mov call(...), dst`` then raised "Can't evaluate load with null value", which
discarded the whole emulated path -- even when the call result was dead.

Both directions are asserted against LIVE microcode (no mocks):

* a call now yields a stable synthetic value and the enclosing ``mov``
  evaluates, so a path carrying a DEAD call result can resolve;
* the destination is marked tainted and stays tainted through arithmetic, so a
  value DERIVED from the synthetic return is rejected by
  :meth:`MicroCodeInterpreter.is_tainted_mop` -- the guard both the state-write
  emulator and the fake-jump path evaluator consult.
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


def _find_call(mba):
    """First ``(blk, call_insn)`` whose callee operand the emulator does not model."""
    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk is None:
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


class TestSyntheticCallTaint:
    binary_name = _get_default_binary()

    def test_unmodeled_call_returns_a_value_instead_of_none(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        env.set_cur_flow(blk, call_insn)
        value = interpreter._eval_call(call_insn, env)
        assert value is not None
        assert isinstance(value, int)

    def test_the_synthetic_value_is_stable(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        env.set_cur_flow(blk, call_insn)
        first = interpreter._eval_call(call_insn, env)
        second = interpreter._eval_call(call_insn, env)
        assert first == second

    @staticmethod
    def _mov_call_into_reg(call_insn, mreg: int, size: int = 8):
        """Build the real consumer shape: ``mov call(...), reg``."""
        holder = ida_hexrays.minsn_t(call_insn.ea)
        holder.opcode = ida_hexrays.m_mov
        holder.l = ida_hexrays.mop_t()
        holder.l._make_insn(ida_hexrays.minsn_t(call_insn))
        holder.l.size = size
        holder.r = ida_hexrays.mop_t()
        holder.d = ida_hexrays.mop_t()
        holder.d._make_reg(mreg, size)
        return holder

    def test_the_enclosing_mov_evaluates_and_taints_its_destination(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = self._mov_call_into_reg(call_insn, ida_hexrays.mr_first + 64)
        value = interpreter._eval_instruction_and_update_environment(blk, holder, env)
        assert value is not None, "mov call(...), reg must no longer evaluate to None"
        assert interpreter.is_tainted_mop(holder.d, env), (
            "an unmodeled call result must be tainted; "
            f"tainted_keys={env.tainted_keys}"
        )

    def test_taint_survives_arithmetic(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = self._mov_call_into_reg(call_insn, ida_hexrays.mr_first + 64)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        # add dest, #1 -> other : the masked synthetic value carries no usable tag
        # of its own, so provenance must travel independently of the bits.
        derived = ida_hexrays.minsn_t(call_insn.ea)
        derived.opcode = ida_hexrays.m_add
        derived.l = ida_hexrays.mop_t(holder.d)
        derived.r = ida_hexrays.mop_t()
        derived.r.make_number(1, holder.d.size)
        derived.d = ida_hexrays.mop_t()
        derived.d._make_reg(ida_hexrays.mr_first + 72, holder.d.size)
        interpreter._eval_instruction_and_update_environment(blk, derived, env)
        assert interpreter.is_tainted_mop(derived.d, env)

    def test_a_clean_write_clears_the_taint(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = self._mov_call_into_reg(call_insn, ida_hexrays.mr_first + 64)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)
        assert interpreter.is_tainted_mop(holder.d, env)

        # mov #7, dest : the location now holds a proven value.
        clean = ida_hexrays.minsn_t(call_insn.ea + 1)
        clean.opcode = ida_hexrays.m_mov
        clean.l = ida_hexrays.mop_t()
        clean.l.make_number(7, holder.d.size)
        clean.r = ida_hexrays.mop_t()
        clean.d = ida_hexrays.mop_t(holder.d)
        interpreter._eval_instruction_and_update_environment(blk, clean, env)
        assert not interpreter.is_tainted_mop(holder.d, env)

    def test_an_unrelated_location_stays_clean(self, live_call):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        holder = self._mov_call_into_reg(call_insn, ida_hexrays.mr_first + 64)
        interpreter._eval_instruction_and_update_environment(blk, holder, env)

        other = ida_hexrays.mop_t()
        other._make_reg(ida_hexrays.mr_first + 96, 4)
        assert not interpreter.is_tainted_mop(other, env)

    def test_the_unsupported_call_warns_once_per_site(self, live_call, caplog):
        mba, blk, call_insn = live_call
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        env.set_cur_flow(blk, call_insn)
        with caplog.at_level("WARNING", logger="d810.evaluator.hexrays_microcode.emulator"):
            interpreter._eval_call(call_insn, env)
            interpreter._eval_call(call_insn, env)
            interpreter._eval_call(call_insn, env)
        warnings = [r for r in caplog.records if "synthetic return" in r.getMessage()]
        assert len(warnings) == 1, [r.getMessage() for r in warnings]
