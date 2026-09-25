"""Emu-consult decisions leave one StateWriteResolutionFact each (d81-qt4v).

Exercises the real ``_emulate_partition_states`` / ``_resolve_incoming_corridor``
seam with fakes for the emulator and the live graph, so the per-corridor facts
and the ``contributed_to_unresolved_transition`` flag are asserted on the
shipped code path rather than on a re-implementation.

The shape under test is ``blk330`` from the Wow_loader reference capture: three
incoming corridors, two of which resolve and one of which walks the glue hop
bound out without ever reaching a defining block.
"""

from __future__ import annotations

import pytest

from d810.analyses.control_flow import minimal_state_recovery as msr
from d810.analyses.data_flow.concolic.emulation import Abstain, ExactResult
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.core.observability import reset_diagnostic_bus, subscribe
from d810.core.observability_events import StateWriteResolutionObserved
from d810.core.observability_state_write import (
    CAUSE_NO_DEF_WITHIN_HOP_BOUND,
    CAUSE_PHI_MULTI_DEF,
    CAUSE_RESOLVED,
    decompose_by_cause,
)

STATE_CELL = LocationRef.stack(0x3C, 8)


class _Block:
    def __init__(self, serial, preds=()):
        self.serial = int(serial)
        self.predset = tuple(int(p) for p in preds)
        self.preds = self.predset
        self.start_ea = 0x7FFB0EB15239
        self.native_start_ea = 0x7FFB0EB15239


class _Fixpoint:
    def __init__(self, stores):
        self.out_stk_maps = dict(stores)
        self.out_reg_maps = {}


class _Emu:
    """Answers a consult by exact corridor path, else abstains."""

    def __init__(self, answers, abstain=None):
        self.answers = dict(answers)
        self.abstain = abstain or Abstain("emulator+history could not resolve state-var write")
        self.paths = []

    def eval_block(self, block, store, *, pred_serial=None):
        path = tuple(pred_serial or ())
        self.paths.append(path)
        value = self.answers.get(path)
        if value is None:
            return self.abstain
        return ExactResult({STATE_CELL: int(value)})


@pytest.fixture
def captured():
    reset_diagnostic_bus()
    events: list[StateWriteResolutionObserved] = []
    subscribe(StateWriteResolutionObserved, events.append)
    yield events
    reset_diagnostic_bus()


def _graph(preds_of):
    blocks = {serial: _Block(serial, preds) for serial, preds in preds_of.items()}

    def live_block_for(serial):
        return blocks.get(int(serial))

    return live_block_for


class TestBlk330Corridors:
    """329 resolves; 355>398 resolves; 355>397>178 exhausts the bound."""

    def _run(self, emu):
        live_block_for = _graph(
            {330: (329, 355), 329: (), 355: (398, 397), 398: (), 397: (178,), 178: ()}
        )
        # blk355 is store-less glue, so its corridor is split and walked.
        fp = _Fixpoint({329: {0x3C: 1}, 355: {}})
        return msr._emulate_partition_states(
            emu,
            live_block_for,
            STATE_CELL,
            fp,
            _Block(330, preds=(329, 355)),
            330,
            func_ea=0x7FFB0EB06E50,
            block_ea=0x7FFB0EB15239,
        )

    def test_partition_abstains_and_facts_decompose_by_cause(self, captured):
        emu = _Emu({(329,): 0x4BCC8BEE, (355, 398): 0x1B3EE0EF})
        assert self._run(emu) is None

        by_corridor = {event.corridor: event for event in captured}
        assert by_corridor[(329,)].cause == CAUSE_RESOLVED
        assert by_corridor[(329,)].folded_value == 0x4BCC8BEE
        assert by_corridor[(355, 398)].cause == CAUSE_RESOLVED
        assert by_corridor[(355, 398)].folded_value == 0x1B3EE0EF
        assert by_corridor[(355, 397, 178)].cause == CAUSE_NO_DEF_WITHIN_HOP_BOUND
        assert set(by_corridor) == {(329,), (355, 398), (355, 397, 178)}

        assert decompose_by_cause(captured) == {
            CAUSE_RESOLVED: 2,
            CAUSE_NO_DEF_WITHIN_HOP_BOUND: 1,
        }

    def test_only_the_abstaining_corridor_is_flagged(self, captured):
        emu = _Emu({(329,): 0x4BCC8BEE, (355, 398): 0x1B3EE0EF})
        self._run(emu)
        flagged = {
            event.corridor
            for event in captured
            if event.contributed_to_unresolved_transition
        }
        assert flagged == {(355, 397, 178)}

    def test_every_fact_names_the_state_write_block(self, captured):
        self._run(_Emu({(329,): 1, (355, 398): 2}))
        assert captured
        assert {event.block_serial for event in captured} == {330}
        assert {event.func_ea for event in captured} == {0x7FFB0EB06E50}
        assert {event.block_ea for event in captured} == {0x7FFB0EB15239}


class TestResolvedPartition:
    def test_a_fully_resolved_partition_flags_nothing(self, captured):
        live_block_for = _graph({330: (329,), 329: ()})
        fp = _Fixpoint({329: {0x3C: 1}})
        result = msr._emulate_partition_states(
            _Emu({(329,): 0x2A}),
            live_block_for,
            STATE_CELL,
            fp,
            _Block(330, preds=(329,)),
            330,
            func_ea=0x1000,
            block_ea=0x2000,
        )
        assert result is not None
        assert [event.cause for event in captured] == [CAUSE_RESOLVED]
        assert not any(
            event.contributed_to_unresolved_transition for event in captured
        )


class TestSharedGlueCompleteness:
    """A glue predecessor must account for every incoming physical path."""

    @staticmethod
    def _run(answers):
        live_block_for = _graph(
            {330: (355,), 355: (398,), 398: (321, 322), 321: (), 322: ()}
        )
        fp = _Fixpoint({355: {}})
        emu = _Emu(answers)
        result = msr._emulate_partition_states(
            emu,
            live_block_for,
            STATE_CELL,
            fp,
            _Block(330, preds=(355,)),
            330,
            func_ea=0x1000,
            block_ea=0x2000,
        )
        return result, emu.paths

    def test_distinct_grandparents_are_both_resolved(self):
        result, paths = self._run(
            {(355, 398, 321): 0x1111, (355, 398, 322): 0x2222}
        )
        assert result == (
            {321: 0x1111, 322: 0x2222},
            {321: 398, 322: 398},
        )
        assert (355, 398, 321) in paths
        assert (355, 398, 322) in paths

    def test_one_unresolved_grandparent_abstains_whole_partition(self, captured):
        result, paths = self._run({(355, 398, 321): 0x1111})
        assert result is None
        assert (355, 398, 321) in paths
        assert (355, 398, 322) in paths
        by_corridor = {event.corridor: event for event in captured}
        assert by_corridor[(355, 398, 322)].contributed_to_unresolved_transition

    def test_cycle_does_not_become_exact_because_an_acyclic_sibling_resolves(self, captured):
        live_block_for = _graph({330: (355,), 355: (355, 398), 398: ()})
        emu = _Emu({(355, 355): 0x1111, (355, 398): 0x1111})
        result = msr._emulate_partition_states(
            emu,
            live_block_for,
            STATE_CELL,
            _Fixpoint({355: {}}),
            _Block(330, preds=(355,)),
            330,
            func_ea=0x1000,
            block_ea=0x2000,
        )
        assert result is None
        assert (355, 398) in emu.paths
        cycle = next(event for event in captured if event.corridor == (355, 355))
        assert cycle.outcome == "abstain"
        assert cycle.cause == "unresolved"
        assert cycle.reason == "cyclic corridor"
        assert cycle.contributed_to_unresolved_transition

    def test_same_source_reached_through_two_hops_abstains(self, captured):
        live_block_for = _graph(
            {330: (355,), 355: (398, 399), 398: (321,), 399: (321, 322),
             321: (), 322: ()}
        )
        emu = _Emu(
            {(355, 398, 321): 0x1111,
             (355, 399, 321): 0x1111,
             (355, 399, 322): 0x2222}
        )
        result = msr._emulate_partition_states(
            emu,
            live_block_for,
            STATE_CELL,
            _Fixpoint({355: {}}),
            _Block(330, preds=(355,)),
            330,
            func_ea=0x1000,
            block_ea=0x2000,
        )
        assert result is None
        assert (355, 398, 321) in emu.paths
        assert (355, 399, 321) in emu.paths
        collision = next(
            event for event in captured if event.corridor == (355, 399, 321)
        )
        assert collision.outcome == "exact_result"
        assert collision.folded_value == 0x1111
        assert collision.reason == "source has multiple next hops"
        assert collision.contributed_to_unresolved_transition

    def test_same_source_with_conflicting_states_has_causal_fact(self, captured):
        live_block_for = _graph(
            {330: (355,), 355: (398, 399), 398: (321,), 399: (321,), 321: ()}
        )
        emu = _Emu(
            {(355, 398, 321): 0x1111, (355, 399, 321): 0x2222}
        )
        result = msr._emulate_partition_states(
            emu, live_block_for, STATE_CELL, _Fixpoint({355: {}}),
            _Block(330, preds=(355,)), 330, func_ea=0x1000, block_ea=0x2000,
        )
        assert result is None
        collision = next(
            event for event in captured if event.corridor == (355, 399, 321)
        )
        assert collision.outcome == "exact_result"
        assert collision.folded_value == 0x2222
        assert collision.reason == "source has conflicting next states"
        assert collision.contributed_to_unresolved_transition

    def test_consult_budget_abstains_before_omitting_a_sibling(
        self, monkeypatch, captured
    ):
        monkeypatch.setattr(msr, "_GLUE_CONSULT_BOUND", 3, raising=False)
        result, paths = self._run(
            {(355, 398, 321): 0x1111, (355, 398, 322): 0x2222}
        )
        assert result is None
        assert len(paths) == 3
        assert any(
            event.reason == "corridor consult budget exhausted"
            and event.contributed_to_unresolved_transition
            for event in captured
        )

    @pytest.mark.parametrize("case", ["cycle", "budget"])
    def test_diagnostic_failure_does_not_change_abstention(self, monkeypatch, case):
        def broken_note(*args, **kwargs):
            raise RuntimeError("diagnostic sink failed")

        monkeypatch.setattr(msr.StateWriteResolutionRecorder, "note", broken_note)
        if case == "budget":
            monkeypatch.setattr(msr, "_GLUE_CONSULT_BOUND", 0)
            result, _ = self._run({})
        else:
            live_block_for = _graph({330: (355,), 355: (355,)})
            result = msr._emulate_partition_states(
                _Emu({}), live_block_for, STATE_CELL, _Fixpoint({355: {}}),
                _Block(330, preds=(355,)), 330, func_ea=0x1000, block_ea=0x2000,
            )
        assert result is None


class TestEmulatorCauseIsCarried:
    def test_phi_multi_def_reaches_the_fact(self, captured):
        live_block_for = _graph({330: (329,), 329: ()})
        fp = _Fixpoint({329: {0x3C: 1}})
        emu = _Emu(
            {},
            abstain=Abstain(
                "emulator+history could not resolve state-var write",
                cause=CAUSE_PHI_MULTI_DEF,
                def_sites=((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7)),
            ),
        )
        assert (
            msr._emulate_partition_states(
                emu,
                live_block_for,
                STATE_CELL,
                fp,
                _Block(330, preds=(329,)),
                330,
                func_ea=0x1000,
                block_ea=0x2000,
            )
            is None
        )
        (event,) = captured
        assert event.cause == CAUSE_PHI_MULTI_DEF
        assert event.def_sites == ((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7))
        assert event.contributed_to_unresolved_transition is True
        assert event.outcome == "abstain"


class TestDiagnosticsAreNeverADecisionInput:
    def test_partition_result_is_identical_without_a_bus_subscriber(self):
        reset_diagnostic_bus()
        live_block_for = _graph({330: (329,), 329: ()})
        fp = _Fixpoint({329: {0x3C: 1}})
        result = msr._emulate_partition_states(
            _Emu({(329,): 0x2A}),
            live_block_for,
            STATE_CELL,
            fp,
            _Block(330, preds=(329,)),
            330,
            func_ea=0x1000,
            block_ea=0x2000,
        )
        assert result == ({329: 0x2A}, {329: 330})
