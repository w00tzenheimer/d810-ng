"""Engine ranking tests (P4, llr-1d8u; design §6 ranking / §7)."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.recovered_machine import (
    MachineRow,
    MachineTransition,
    RecoveredMachine,
    Soundness,
)
from d810.analyses.machine.engine_rank import rank_machines, specificity


def _row(s: int) -> MachineRow:
    return MachineRow(state_const=s, target_block=s + 100, dispatcher_block=1)


def _machine(soundness, *, rows=(), transitions=(), confidence=1.0) -> RecoveredMachine:
    return RecoveredMachine(
        rows=tuple(rows),
        transitions=tuple(transitions),
        soundness=soundness,
        confidence=confidence,
    )


def test_sound_overapprox_outranks_pattern():
    sound = _machine(Soundness.SOUND_OVERAPPROX, rows=(_row(1),))
    pattern = _machine(Soundness.PATTERN, rows=(_row(1), _row(2)))
    # SOUND_OVERAPPROX wins even though pattern is more specific (soundness first).
    assert rank_machines([pattern, sound]) is sound


def test_sound_overapprox_outranks_exact_bounded():
    sound = _machine(Soundness.SOUND_OVERAPPROX, rows=(_row(1),))
    exact = _machine(Soundness.EXACT_BOUNDED, rows=(_row(1),))
    assert rank_machines([exact, sound]) is sound


def test_specificity_breaks_tie_same_soundness():
    a = _machine(Soundness.PATTERN, rows=(_row(1),))
    b = _machine(Soundness.PATTERN, rows=(_row(1), _row(2)))
    assert rank_machines([a, b]) is b


def test_confidence_breaks_tie_same_specificity():
    a = _machine(Soundness.PATTERN, rows=(_row(1),), confidence=0.4)
    b = _machine(Soundness.PATTERN, rows=(_row(1),), confidence=0.9)
    assert rank_machines([a, b]) is b


def test_specificity_counts_resolved_forks_only():
    m = _machine(
        Soundness.SOUND_OVERAPPROX,
        rows=(_row(1),),
        transitions=(
            MachineTransition(1, (), (2, 3)),   # resolved fork -> counts
            MachineTransition(4, (), ()),        # ⊤ cell -> does NOT count
        ),
    )
    assert specificity(m) == 2  # 1 row + 1 resolved fork


def test_rank_machines_empty_is_none():
    assert rank_machines([]) is None


def test_single_candidate_returned():
    m = _machine(Soundness.SOUND_OVERAPPROX, rows=(_row(1),))
    assert rank_machines([m]) is m


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
