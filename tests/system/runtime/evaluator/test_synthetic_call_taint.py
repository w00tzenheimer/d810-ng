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

from d810.core import observability
from d810.core.observability_emulator import (
    CAUSE_UNSUPPORTED_CALL_OPERAND,
    EmulatorGapScope,
    begin_emulator_gap_attempt,
    emulator_gap_counts,
    flush_emulator_gaps,
)
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

    @pytest.fixture(autouse=True)
    def _fake_emulator_gap_session_store(self, monkeypatch):
        """Stand in for a lifecycle-owned session store (ticket d81-e0uy).

        No DecompilationLifecycleCoordinator runs in this test module; a
        plain per-test dict keyed by func_ea gives ``record_emulator_gap`` /
        ``begin_emulator_gap_attempt`` somewhere to persist dedupe state
        across calls, exactly like production's session-owned scope.
        """
        store: dict[int, EmulatorGapScope] = {}

        def _scope_provider(func_ea):
            return store.setdefault(
                int(func_ea), EmulatorGapScope(func_ea=int(func_ea))
            )

        monkeypatch.setattr(
            observability, "_active_emulator_gap_scope_provider", _scope_provider
        )
        monkeypatch.setattr(
            observability,
            "_pending_emulator_gap_scopes_provider",
            lambda: tuple(store.values()),
        )
        yield store

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
        """Dedupe must survive a FRESH interpreter: the pipeline builds one per
        tracked path and per block consult, so an instance-scoped set still
        emitted ~1100 warnings for 3 call sites (ticket d81-0xzp).  Slice 5
        (d81-c6n7) moved the key to ``(function, attempt, cause, site)``."""
        mba, blk, call_insn = live_call
        with caplog.at_level(
            "WARNING", logger="d810.evaluator.hexrays_microcode.emulator"
        ):
            for _ in range(3):
                interpreter = MicroCodeInterpreter(symbolic_mode=False)
                env = MicroCodeEnvironment()
                env.set_cur_flow(blk, call_insn)
                interpreter._eval_call(call_insn, env)
        warnings = [
            r
            for r in caplog.records
            if f"cause={CAUSE_UNSUPPORTED_CALL_OPERAND}" in r.getMessage()
        ]
        assert len(warnings) == 1, [r.getMessage() for r in warnings]

    def test_a_new_attempt_warns_about_the_same_site_again(self, live_call, caplog):
        """A retry must not go silent: the module-scoped set it replaces never
        reset, so the second and third attempts lost their warnings."""
        mba, blk, call_insn = live_call
        func_ea = int(mba.entry_ea)
        with caplog.at_level(
            "WARNING", logger="d810.evaluator.hexrays_microcode.emulator"
        ):
            for _ in range(3):
                begin_emulator_gap_attempt(func_ea, maturity="MMAT_CALLS")
                interpreter = MicroCodeInterpreter(symbolic_mode=False)
                env = MicroCodeEnvironment()
                env.set_cur_flow(blk, call_insn)
                interpreter._eval_call(call_insn, env)
        warnings = [
            r
            for r in caplog.records
            if f"cause={CAUSE_UNSUPPORTED_CALL_OPERAND}" in r.getMessage()
        ]
        assert len(warnings) == 3, [r.getMessage() for r in warnings]

    def test_the_gap_line_is_anchored_and_actionable(self, live_call, caplog):
        mba, blk, call_insn = live_call
        with caplog.at_level(
            "WARNING", logger="d810.evaluator.hexrays_microcode.emulator"
        ):
            interpreter = MicroCodeInterpreter(symbolic_mode=False)
            env = MicroCodeEnvironment()
            env.set_cur_flow(blk, call_insn)
            interpreter._eval_call(call_insn, env)
        line = next(
            r.getMessage()
            for r in caplog.records
            if f"cause={CAUSE_UNSUPPORTED_CALL_OPERAND}" in r.getMessage()
        )
        assert line.startswith("EMULATOR_GAP ")
        assert f"func=0x{int(mba.entry_ea):x}" in line
        assert f"blk={int(blk.serial)}" in line
        assert f"site=0x{int(call_insn.ea):x}" in line
        assert "maturity=CALLS" in line
        assert "python -m d810.diagnostics unflat-why" in line

    def test_a_repeat_still_counts_toward_the_aggregate(self, live_call):
        mba, blk, call_insn = live_call
        func_ea = int(mba.entry_ea)
        begin_emulator_gap_attempt(func_ea, maturity="MMAT_CALLS")
        for _ in range(4):
            interpreter = MicroCodeInterpreter(symbolic_mode=False)
            env = MicroCodeEnvironment()
            env.set_cur_flow(blk, call_insn)
            interpreter._eval_call(call_insn, env)
        counts = emulator_gap_counts(func_ea)
        assert counts.get(CAUSE_UNSUPPORTED_CALL_OPERAND) == 4

    def test_the_attempt_publishes_one_fact_per_site(self, live_call):
        mba, blk, call_insn = live_call
        func_ea = int(mba.entry_ea)
        begin_emulator_gap_attempt(func_ea, maturity="MMAT_CALLS")
        for _ in range(3):
            interpreter = MicroCodeInterpreter(symbolic_mode=False)
            env = MicroCodeEnvironment()
            env.set_cur_flow(blk, call_insn)
            interpreter._eval_call(call_insn, env)
        published: list[object] = []
        line = flush_emulator_gaps(func_ea, emit_fn=published.append)
        assert line and line.startswith("EMULATOR_GAPS ")
        assert f"{CAUSE_UNSUPPORTED_CALL_OPERAND}=3" in line
        gaps = [
            event
            for event in published
            if getattr(event, "cause", "") == CAUSE_UNSUPPORTED_CALL_OPERAND
        ]
        assert len(gaps) == 1
        assert gaps[0].occurrences == 3
        assert gaps[0].site_ea == int(call_insn.ea)
        assert gaps[0].func_ea == func_ea
