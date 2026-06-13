"""Cross-validation policy tests (P4, llr-1d8u; design §6.4)."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.recovered_machine import (
    MachineTransition,
    RecoveredMachine,
    Soundness,
)
from d810.analyses.machine.cross_validate import CONFLICT_FLAG, cross_validate


def _machine(transitions, *, confidence=0.5, provenance=()) -> RecoveredMachine:
    return RecoveredMachine(
        rows=(),
        transitions=tuple(transitions),
        soundness=Soundness.SOUND_OVERAPPROX,
        confidence=confidence,
        provenance=tuple(provenance),
    )


def test_no_concolic_keeps_spine_confidence():
    spine = _machine((MachineTransition(1, (), (2, 3)),), confidence=0.7)
    out = cross_validate(spine, None)
    assert out.machine is spine
    assert out.confidence == 0.7


def test_agreement_raises_confidence():
    spine = _machine((MachineTransition(1, (), (2, 3)),), confidence=0.1)
    conc = _machine((MachineTransition(1, (), (2, 3)),))
    out = cross_validate(spine, conc)
    # full agreement -> conf 1.0
    assert out.confidence == 1.0
    assert CONFLICT_FLAG not in out.machine.provenance


def test_disagreement_keeps_AI_next_states_and_flags():
    spine = _machine((MachineTransition(1, (), (2, 3)),))
    conc = _machine((MachineTransition(1, (), (9,)),))  # disagrees
    out = cross_validate(spine, conc)
    # next_states UNCHANGED (sound AI result kept)
    (t,) = out.machine.transitions
    assert t.next_states == (2, 3)
    assert CONFLICT_FLAG in out.machine.provenance
    # one conflict, no agreement -> conf 0.0
    assert out.confidence == 0.0


def test_mixed_agreement_and_conflict_confidence():
    spine = _machine(
        (
            MachineTransition(1, (), (2, 3)),   # agrees
            MachineTransition(4, (), (5,)),      # conflicts
        )
    )
    conc = _machine(
        (
            MachineTransition(1, (), (2, 3)),
            MachineTransition(4, (), (6,)),
        )
    )
    out = cross_validate(spine, conc)
    # (agree - conflict) / total = (1 - 1) / 2 = 0.0
    assert out.confidence == 0.0
    assert CONFLICT_FLAG in out.machine.provenance


def test_no_overlap_keeps_spine_confidence():
    spine = _machine((MachineTransition(1, (), (2,)),), confidence=0.42)
    conc = _machine((MachineTransition(99, (), (7,)),))  # different cell
    out = cross_validate(spine, conc)
    assert out.confidence == 0.42
    assert CONFLICT_FLAG not in out.machine.provenance


def test_top_cells_ignored_in_cross_val():
    # spine ⊤ cell (empty next_states) is not compared
    spine = _machine((MachineTransition(1, (), ()),))
    conc = _machine((MachineTransition(1, (), (5,)),))
    out = cross_validate(spine, conc)
    # no resolved overlap -> confidence unchanged, no flag
    assert CONFLICT_FLAG not in out.machine.provenance


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
