"""Runtime: every emulator gap WARNING names a cause, a site and a next step.

Ticket ``d81-c6n7`` (slice 5).  The emulator's WARNINGs stay at WARNING -- they
are a worklist of real, individually fixable evaluator gaps -- but each line
now carries a stable cause token, the def sites / call site EA, the block, the
maturity and the command to run next, deduped per
``(function, attempt, cause, site)``.

One cause is new: ``stack_slot_in_aliased_memory``.  Hex-Rays builds
``get_stk_chain`` entries for RESTRICTED memory only, so a slot at or above
``mba.minstkref`` has no chain at all and ``ndefs=0`` there is a chain-coverage
gap, not a missing definition (plan section 6.5, ticket d81-cor5).

Run against LIVE microcode; no mocks.
"""

from __future__ import annotations

import os
import platform

import ida_hexrays
import pytest

from d810.core import observability
from d810.core.observability_emulator import (
    EMULATOR_GAP_CAUSES,
    EmulatorGapScope,
    begin_emulator_gap_attempt,
    emulator_gap_counts,
    flush_emulator_gaps,
    is_stack_slot_in_aliased_memory,
)
from d810.core.observability_state_write import (
    CAUSE_NO_REACHING_DEFS,
    CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
)
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)


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


def _stkvar_mop(mba, off: int):
    mop = ida_hexrays.mop_t()
    mop.erase()
    mop._make_stkvar(mba, off)
    return mop


class TestEmulatorGapFacts:
    binary_name = _get_default_binary()

    @pytest.fixture(autouse=True)
    def _fake_emulator_gap_session_store(self, monkeypatch):
        """Stand in for a lifecycle-owned session store (ticket d81-e0uy).

        No DecompilationLifecycleCoordinator runs in this test module (it
        drives the emulator directly against live microcode); a plain
        per-test dict keyed by func_ea stands in for "a session exists and
        owns this scope" so ``record_emulator_gap`` / ``begin_emulator_gap_attempt``
        have somewhere to persist dedupe state across calls, exactly like
        production's session-owned scope.
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

    def test_an_aliased_stack_slot_is_named_as_a_coverage_gap(self, merge_read):
        """``ndefs=0`` at/above ``minstkref`` is NOT "no reaching defs"."""
        mba = merge_read[0]
        minstkref = int(getattr(mba, "minstkref", 0) or 0)
        if minstkref <= 0 or minstkref >= 0x10000000:
            pytest.skip(f"no usable minstkref on this function ({minstkref:#x})")
        aliased = _stkvar_mop(mba, minstkref)
        if aliased.t != ida_hexrays.mop_S or aliased.s is None:
            pytest.skip("could not build a live stkvar mop")
        if int(aliased.s.off) != minstkref:
            pytest.skip("stkvar offsets are rebased on this function")
        assert (
            MicroCodeInterpreter._no_reaching_defs_cause(mba, aliased)
            == CAUSE_STACK_SLOT_IN_ALIASED_MEMORY
        )

    def test_a_restricted_stack_slot_stays_no_reaching_defs(self, merge_read):
        mba = merge_read[0]
        minstkref = int(getattr(mba, "minstkref", 0) or 0)
        if minstkref <= 8 or minstkref >= 0x10000000:
            pytest.skip(f"no usable minstkref on this function ({minstkref:#x})")
        restricted = _stkvar_mop(mba, minstkref - 8)
        if restricted.t != ida_hexrays.mop_S or restricted.s is None:
            pytest.skip("could not build a live stkvar mop")
        if int(restricted.s.off) != minstkref - 8:
            pytest.skip("stkvar offsets are rebased on this function")
        assert (
            MicroCodeInterpreter._no_reaching_defs_cause(mba, restricted)
            == CAUSE_NO_REACHING_DEFS
        )
        assert not is_stack_slot_in_aliased_memory(minstkref - 8, minstkref)

    def test_a_register_read_is_never_the_aliased_slot_gap(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        assert mop.t == ida_hexrays.mop_r
        assert (
            MicroCodeInterpreter._no_reaching_defs_cause(mba, mop)
            == CAUSE_NO_REACHING_DEFS
        )

    def test_an_unresolvable_instruction_warns_with_a_known_cause(
        self, merge_read, caplog
    ):
        """The gap WARNING is deduped, anchored and classified."""
        mba, blk, insn, mop, defs = merge_read
        func_ea = int(mba.entry_ea)
        begin_emulator_gap_attempt(func_ea, maturity="MMAT_GLBOPT1")
        with caplog.at_level(
            "WARNING", logger="d810.evaluator.hexrays_microcode.emulator"
        ):
            for _ in range(3):
                interpreter = MicroCodeInterpreter(symbolic_mode=False)
                env = MicroCodeEnvironment()
                interpreter.eval_instruction(blk, insn, environment=env)
        lines = [
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith("EMULATOR_GAP ")
        ]
        if not lines:
            pytest.skip("this instruction evaluated cleanly")
        # Deduped: one line per (cause, site) despite three evaluations.
        assert len(lines) == len(set(lines))
        for line in lines:
            cause = line.split("cause=", 1)[1].split(" ", 1)[0]
            assert cause in EMULATOR_GAP_CAUSES, line
            assert f"func=0x{func_ea:x}" in line
            assert f"site=0x{int(insn.ea):x}" in line
            assert "python -m d810.diagnostics unflat-why" in line

    def test_the_attempt_aggregate_sums_the_causes(self, merge_read, caplog):
        mba, blk, insn, mop, defs = merge_read
        func_ea = int(mba.entry_ea)
        begin_emulator_gap_attempt(func_ea, maturity="MMAT_GLBOPT1")
        for _ in range(3):
            interpreter = MicroCodeInterpreter(symbolic_mode=False)
            env = MicroCodeEnvironment()
            interpreter.eval_instruction(blk, insn, environment=env)
        counts = emulator_gap_counts(func_ea)
        if not counts:
            pytest.skip("this instruction evaluated cleanly")
        published: list[object] = []
        line = flush_emulator_gaps(func_ea, emit_fn=published.append)
        assert line and line.startswith("EMULATOR_GAPS ")
        assert f"func=0x{func_ea:x}" in line
        assert "maturity=GLBOPT1" in line
        assert "attempt=1" in line
        for cause, count in counts.items():
            assert f"{cause}={count}" in line
        assert len(published) == len(counts) or len(published) >= 1
        # Flushing resets the attempt's dedupe state.
        assert emulator_gap_counts(func_ea) == {}

    def test_the_gap_channel_never_changes_an_evaluation(
        self, merge_read, _fake_emulator_gap_session_store
    ):
        mba, blk, insn, mop, defs = merge_read
        env_a = MicroCodeEnvironment()
        env_a.set_cur_flow(blk, insn)
        first = MicroCodeInterpreter(symbolic_mode=False)._resolve_mop_via_def_use(
            mop, env_a
        )
        # Clear this function's dedupe state between the two evaluations so
        # the second one is not silently suppressed by the first.
        scope = _fake_emulator_gap_session_store.get(int(mba.entry_ea))
        if scope is not None:
            scope.clear()
        env_b = MicroCodeEnvironment()
        env_b.set_cur_flow(blk, insn)
        second = MicroCodeInterpreter(symbolic_mode=False)._resolve_mop_via_def_use(
            mop, env_b
        )
        assert first == second
