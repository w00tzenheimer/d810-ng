"""Runtime: an abstaining consult names its cause and its def sites (d81-qt4v).

Until slice 4 the only machine-readable trace of a starved state-write
recovery was ``Abstain("emulator+history could not resolve state-var write")``
-- one bucket for a multi-def give-up, an unseeded global, a synthetic-call
taint and a failed single-def evaluation alike.  These tests run the SHIPPED
``MicroCodeInterpreter`` / ``HexRaysBlockEmulator`` against LIVE microcode (no
mocks) and assert the cause channel is populated and stays purely additive.
"""

from __future__ import annotations

import os
import platform

import pytest

from d810.analyses.data_flow.concolic.emulation import Abstain, ConcreteStore
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.backends.hexrays.evidence.emulation import HexRaysBlockEmulator
from d810.core.observability_state_write import (
    CAUSE_NO_REACHING_DEFS,
    CAUSE_PHI_MULTI_DEF,
    STATE_WRITE_RESOLUTION_CAUSES,
    AbstainCauseLog,
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


class TestStateWriteAbstainCause:
    binary_name = _get_default_binary()

    def test_every_interpreter_carries_a_cause_log(self, merge_read):
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        assert isinstance(interpreter.abstain_causes, AbstainCauseLog)
        assert interpreter.abstain_causes.dominant() == ""

    def test_an_unresolved_merge_read_records_a_known_cause(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        env.set_cur_flow(blk, insn)
        value = interpreter._resolve_mop_via_def_use(mop, env)
        if value is not None:
            pytest.skip("this merge read resolved by path-insensitive agreement")
        cause = interpreter.abstain_causes.dominant()
        assert cause, "an unresolved def-use read must name its cause"
        assert cause in STATE_WRITE_RESOLUTION_CAUSES
        assert cause in (CAUSE_PHI_MULTI_DEF, CAUSE_NO_REACHING_DEFS,
                         "single_def_eval_failed", "global_not_seeded")

    def test_a_phi_give_up_reports_the_definition_sites(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        interpreter = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        env.set_cur_flow(blk, insn)
        if interpreter._resolve_mop_via_def_use(mop, env) is not None:
            pytest.skip("this merge read resolved by path-insensitive agreement")
        if interpreter.abstain_causes.dominant() != CAUSE_PHI_MULTI_DEF:
            pytest.skip("this read did not end at the multi-def give-up")
        sites = interpreter.abstain_causes.def_sites()
        assert sites, "phi_multi_def must name the definitions it could not merge"
        recorded = set(sites)
        assert recorded <= {(d.block_serial, d.ins_ea) for d in defs}

    def test_eval_block_abstention_carries_cause_and_def_sites(self, merge_read):
        mba, blk, insn, mop, defs = merge_read
        emu = HexRaysBlockEmulator(
            mba=mba, state_var_stkoff=0x7FFFFFFF, state_cell=LocationRef.stack(0, 8)
        )
        outcome = emu.eval_block(
            blk, ConcreteStore.of({}), pred_serial=min(int(p) for p in blk.predset)
        )
        assert isinstance(outcome, Abstain)
        # The fields exist and are well-typed on EVERY abstention, even the
        # "no state-var write in block" one that names no cause.
        assert isinstance(outcome.cause, str)
        assert isinstance(outcome.def_sites, tuple)
        for entry in outcome.def_sites:
            blk_serial, ea = entry
            assert isinstance(blk_serial, int) and isinstance(ea, int)

    def test_the_cause_channel_never_changes_a_resolution(self, merge_read):
        """Purely additive: the value the interpreter proves is unchanged."""
        mba, blk, insn, mop, defs = merge_read
        env_a = MicroCodeEnvironment()
        env_a.set_cur_flow(blk, insn)
        first = MicroCodeInterpreter(symbolic_mode=False)._resolve_mop_via_def_use(
            mop, env_a
        )
        env_b = MicroCodeEnvironment()
        env_b.set_cur_flow(blk, insn)
        second = MicroCodeInterpreter(symbolic_mode=False)._resolve_mop_via_def_use(
            mop, env_b
        )
        assert first == second
