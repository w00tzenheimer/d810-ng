"""Orchestrator compose tests with FAKE engines (no IDA) (P4, llr-1d8u; §3/§6).

Verifies the pipeline order anchor->spine->refine(gate)->cross-val->rank and that:
* a ⊤ cell with a sound floor + a COMPLETE concolic V is refined to V;
* a ⊤ cell with an INCOMPLETE concolic V stays ⊤;
* refinement only touches ⊤ cells (resolved rows/transitions are untouched);
* a ⊤ floor never refines (the §0.1 defect guard, end-to-end).
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import (
    MachineRow,
    MachineTransition,
    RecoveredMachine,
    Soundness,
    ExitPathEffectSummary,
    ExitPathEffect,
)
from d810.analyses.data_flow.concolic import AbstractEvidence
from d810.analyses.machine.orchestrator import compose_reduced_product
from d810.analyses.machine.refinement_gate import ConcolicCellValue, GateMode

W = 4


def _floor_range(lo, hi, width=W):
    return AbstractEvidence(width, KnownBits.top(width), WrappedInterval(width, lo, hi, "range"))


@dataclass
class _FakeSpineResult:
    machine: RecoveredMachine
    top_density: float
    floors: dict

    def floor_for(self, src_state, context):
        return self.floors.get((int(src_state), tuple(context)))


@dataclass
class _FakeSpine:
    result: _FakeSpineResult
    name: str = "fake_spine"
    recovered_with_k: list = None

    def recover(self, graph, anchors, caps, *, k):
        if self.recovered_with_k is None:
            self.recovered_with_k = []
        self.recovered_with_k.append(k)
        return self.result


def _spine_machine(transitions, rows=()):
    return RecoveredMachine(
        rows=tuple(rows),
        transitions=tuple(transitions),
        soundness=Soundness.SOUND_OVERAPPROX,
        confidence=1.0,
        provenance=("fake_spine",),
    )


def _exit_path_effect_summary() -> ExitPathEffectSummary:
    return ExitPathEffectSummary(
        initial_state=7,
        terminal_state=9,
        path_blocks=(1, 2, 4, 8),
        effects=(
            ExitPathEffect(
                kind="store",
                target="result_slot",
                expression="R % 3u",
            ),
        ),
        terminal_block=8,
        symbolic_inputs=("R",),
        enumerated_inputs_complete=True,
        deterministic=True,
        terminal_reachable=True,
        provenance=("unit",),
    )


_ANCHORS = DispatcherAnchors(dispatcher_entry_block=1, state_var_stkoff=0x3C)


def test_complete_V_refines_top_cell():
    top = MachineTransition(src_state=7, context=(), next_states=())  # ⊤ cell
    machine = _spine_machine((top,), rows=(MachineRow(1, 101, 1),))
    floor = _floor_range(3, 4)  # γ = {3,4}
    spine = _FakeSpine(_FakeSpineResult(machine, top_density=0.0, floors={(7, ()): floor}))

    def resolver(src, ctx):
        if (src, ctx) == (7, ()):
            return ConcolicCellValue(next_states=frozenset({3, 4}))
        return None

    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=resolver,
    )
    assert out is not None
    fork = next(t for t in out.transitions if t.src_state == 7)
    assert fork.next_states == (3, 4)  # refined ⊤ -> V


def test_complete_exit_path_effect_summary_is_carried_into_machine():
    top = MachineTransition(src_state=7, context=(), next_states=())
    machine = _spine_machine((top,), rows=(MachineRow(1, 101, 1),))
    spine = _FakeSpine(_FakeSpineResult(machine, top_density=0.0, floors={}))
    exit_path = _exit_path_effect_summary()

    def resolver(src, ctx):
        if (src, ctx) == (7, ()):
            return ConcolicCellValue(
                next_states=frozenset({9}),
                enumerated_inputs_complete=True,
                deterministic=True,
                exit_path_effect_summary=exit_path,
            )
        return None

    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=resolver,
        gate_mode=GateMode.DETERMINISTIC_F,
    )

    assert out is not None
    assert out.exit_path_effect_summaries == (exit_path,)
    fork = next(t for t in out.transitions if t.src_state == 7)
    assert fork.next_states == (9,)


def test_incomplete_V_stays_top():
    top = MachineTransition(src_state=7, context=(), next_states=())
    machine = _spine_machine((top,))
    floor = _floor_range(3, 4)  # γ = {3,4}
    spine = _FakeSpine(_FakeSpineResult(machine, top_density=0.0, floors={(7, ()): floor}))

    def resolver(src, ctx):
        return ConcolicCellValue(next_states=frozenset({3}))  # missing 4 -> incomplete

    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=resolver,
    )
    fork = next(t for t in out.transitions if t.src_state == 7)
    assert fork.next_states == ()  # stayed ⊤


def test_top_floor_never_refines_end_to_end():
    top = MachineTransition(src_state=7, context=(), next_states=())
    machine = _spine_machine((top,))
    # ⊤ floor -> the gate must refuse, even with a "complete" V
    spine = _FakeSpine(
        _FakeSpineResult(machine, top_density=0.0, floors={(7, ()): AbstractEvidence.top(W)})
    )

    def resolver(src, ctx):
        return ConcolicCellValue(next_states=frozenset({3, 4}))

    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=resolver,
    )
    fork = next(t for t in out.transitions if t.src_state == 7)
    assert fork.next_states == ()  # ⊤ floor -> no refinement (§0.1 guard)


def test_resolved_cells_untouched():
    resolved = MachineTransition(src_state=5, context=(), next_states=(6,))  # already resolved
    top = MachineTransition(src_state=7, context=(), next_states=())
    machine = _spine_machine((resolved, top))
    floor = _floor_range(3, 4)
    spine = _FakeSpine(
        _FakeSpineResult(machine, top_density=0.0, floors={(7, ()): floor, (5, ()): floor})
    )

    calls = []

    def resolver(src, ctx):
        calls.append((src, ctx))
        return ConcolicCellValue(next_states=frozenset({3, 4}))

    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=resolver,
    )
    # resolver consulted ONLY for the ⊤ cell (5 is resolved, not consulted)
    assert calls == [(7, ())]
    res = next(t for t in out.transitions if t.src_state == 5)
    assert res.next_states == (6,)  # untouched


def test_no_concolic_resolver_leaves_top_cells():
    top = MachineTransition(src_state=7, context=(), next_states=())
    machine = _spine_machine((top,))
    spine = _FakeSpine(_FakeSpineResult(machine, top_density=0.0, floors={}))
    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=None,
    )
    fork = next(t for t in out.transitions if t.src_state == 7)
    assert fork.next_states == ()


def test_spine_none_returns_none():
    @dataclass
    class _NoneSpine:
        name: str = "none"

        def recover(self, graph, anchors, caps, *, k):
            return None

    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=_NoneSpine(), concolic_resolver=None,
    )
    assert out is None


def test_cross_validation_flags_conflict():
    resolved = MachineTransition(src_state=5, context=(), next_states=(6,))
    machine = _spine_machine((resolved,))
    spine = _FakeSpine(_FakeSpineResult(machine, top_density=0.0, floors={}))
    # concolic machine disagrees on the resolved cell -> keep AI, flag conflict
    conc_machine = RecoveredMachine(
        rows=(),
        transitions=(MachineTransition(5, (), (9,)),),
        soundness=Soundness.EXACT_BOUNDED,
    )
    out = compose_reduced_product(
        graph=object(), anchors=_ANCHORS, caps=None,
        spine_engine=spine, concolic_resolver=None,
        concolic_machine=conc_machine,
    )
    res = next(t for t in out.transitions if t.src_state == 5)
    assert res.next_states == (6,)  # AI result kept
    assert "cross_val_conflict" in out.provenance


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
