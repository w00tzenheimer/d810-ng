"""Gate unit tests -- the §7 (a)/(b) completeness gate + the Z3 CEX regression.

These are the P4 acceptance criteria A1/G-AC1 (ticket llr-1d8u). The gate must:
* NEVER refine on a ⊤ floor (the §0.1 vacuous-⊤ defect guard);
* reject the Z3 counterexample (``γ(floor)=0b1111``, ``V=∅``) -- incomplete;
* accept iff ``γ(floor) ⊆ V`` AND every value folds clean against the NON-⊤ floor;
* keep a fork when ``|V|>1`` and ``γ(floor) ⊆ V``;
* (a) refine only when ``enumerated_inputs_complete ∧ deterministic``.

Pure-Python (no IDA, no z3): the gate reuses the portable ``fold_exact`` primitive.
"""
from __future__ import annotations

import pytest

from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.control_flow.recovered_machine import (
    MachineTransition,
    Soundness,
    ExitPathEffectSummary,
    ExitPathEffect,
)
from d810.analyses.data_flow.concolic import AbstractEvidence
from d810.analyses.data_flow.concolic.emulation import ExactResult
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.machine.refinement_gate import (
    CompletenessGate,
    ConcolicCellValue,
    GateMode,
    TopCell,
    gamma_members,
)

W = 4  # small width so γ enumeration is exhaustive and the Z3 CEX is 0b1111


def _floor_range(lo: int, hi: int, width: int = W) -> AbstractEvidence:
    """A floor whose γ is the contiguous arc ``[lo, hi]`` (bits ⊤)."""
    return AbstractEvidence(width, KnownBits.top(width), WrappedInterval(width, lo, hi, "range"))


def _floor_singleton(v: int, width: int = W) -> AbstractEvidence:
    return AbstractEvidence.singleton(v, width)


def _cell(src_state: int = 7, context: tuple[int, ...] = ()) -> MachineTransition:
    # An unresolved (⊤) forking transition: empty next_states.
    return MachineTransition(src_state=src_state, context=context, next_states=())


def _top_cell(floor, src_state: int = 7) -> TopCell:
    return TopCell(transition=_cell(src_state), floor=floor, is_top=True)


def _state_loc() -> LocationRef:
    return LocationRef.stack(0x3C, 8)


def _symbolic_payload_exit_path_effect_summary(**overrides) -> ExitPathEffectSummary:
    values = {
        "initial_state": 0x1111,
        "terminal_state": 0x2222,
        "path_blocks": (1, 2, 4, 5, 6, 7, 8, 9),
        "terminal_block": 9,
        "symbolic_inputs": ("R",),
        "branch_dependency_symbols": (),
        "enumerated_inputs_complete": True,
        "deterministic": True,
        "terminal_reachable": True,
        "effects": (
            ExitPathEffect(
                kind="call_payload",
                target="rand",
                value="R",
            ),
            ExitPathEffect(
                kind="store",
                target="result_slot",
                expression="R % 3u",
            ),
            ExitPathEffect(
                kind="store",
                target="state_slot",
                value=0x2222,
            ),
        ),
        "provenance": ("unit",),
    }
    values.update(overrides)
    return ExitPathEffectSummary(**values)


# ── gamma_members soundness ────────────────────────────────────────────────


def test_gamma_members_is_sound_small_widths():
    """``gamma_members(floor)`` == the EXACT membership set (sound over-approx)."""
    for lo in range(1 << W):
        for hi in range(1 << W):
            floor = AbstractEvidence(W, KnownBits.top(W), WrappedInterval(W, lo, hi, "range"))
            members = gamma_members(floor)
            expected = {v for v in range(1 << W) if floor.contains(v)}
            assert members is not None
            assert set(members) == expected, (lo, hi)


def test_gamma_members_top_is_none():
    assert gamma_members(AbstractEvidence.top(W)) is None


def test_gamma_members_bottom_is_none():
    assert gamma_members(AbstractEvidence.bottom(W)) is None


# ── A1 / §0.1: the ⊤ floor never refines ───────────────────────────────────


def test_top_floor_never_refines():
    """A ⊤ floor returns the cell unchanged -- the §0.1 vacuous-⊤ defect guard."""
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    cell = _top_cell(AbstractEvidence.top(W))
    cv = ConcolicCellValue(next_states=frozenset({3, 4}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=AbstractEvidence.top(W))
    assert out.is_top is True
    assert out.transition.next_states == ()


def test_none_floor_never_refines():
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    cell = _top_cell(None)
    cv = ConcolicCellValue(next_states=frozenset({1}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=None)
    assert out.is_top is True


# ── A1 / the Z3 counterexample ─────────────────────────────────────────────


def test_gate_rejects_z3_counterexample():
    """γ(floor)=0b1111={0..15-feasible}, V=∅ -> stay ⊤ (the §7 CEX C⊄∅)."""
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    # floor whose γ is the full small space {0..15} == 0b1111 over 4 bits
    floor = _floor_range(0, (1 << W) - 1)
    assert set(gamma_members(floor)) == set(range(1 << W))
    cell = _top_cell(floor)
    cv = ConcolicCellValue(next_states=frozenset())  # V = ∅ (the Z3 CEX)
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is True
    assert out.transition.next_states == ()


# ── A1 / completeness ──────────────────────────────────────────────────────


def test_gate_b_accepts_when_floor_subset_V():
    """γ(floor)={3,4} ⊆ V={3,4} (no exact-outcome -> floor bounds it) -> refine."""
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    floor = _floor_range(3, 4)
    assert set(gamma_members(floor)) == {3, 4}
    cell = _top_cell(floor)
    cv = ConcolicCellValue(next_states=frozenset({3, 4}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is False
    assert out.transition.next_states == (3, 4)


def test_gate_b_rejects_when_V_misses_floor_member():
    """γ(floor)={3,4} ⊄ V={3} -> stay ⊤ (V is INCOMPLETE)."""
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    floor = _floor_range(3, 4)
    cell = _top_cell(floor)
    cv = ConcolicCellValue(next_states=frozenset({3}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is True


def test_gate_b_preserves_fork():
    """|V|>1 with γ(floor) ⊆ V -> the refined cell keeps BOTH next_states."""
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    floor = _floor_range(5, 6)
    cell = _top_cell(floor)
    cv = ConcolicCellValue(next_states=frozenset({5, 6}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is False
    assert set(out.transition.next_states) == {5, 6}


# ── A1 / per-value soundness via fold_exact (G-AC1) ────────────────────────


def test_fold_exact_establishes_V_supseteq_floor():
    """G-AC1: the accepted V satisfies γ(floor) ⊆ V AND folds clean vs the NON-⊤ floor.

    The per-arm exact value (3) is INSIDE γ(floor)={3} -> fold_exact returns CONCRETE
    against the non-⊤ floor (real work, not a ⊤-floor tautology) -> accept.
    """
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    floor = _floor_singleton(3)  # γ(floor) = {3}, a NON-⊤ floor
    loc = _state_loc()
    cell = _top_cell(floor)
    cv = ConcolicCellValue(
        next_states=frozenset({3}),
        per_state_value={3: 3},
        exact_outcome=ExactResult({loc: 3}),
        state_loc=loc,
    )
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is False
    assert out.transition.next_states == (3,)
    # Sanity: the floor is genuinely NON-⊤ (the check did real work).
    assert not floor.is_top()
    assert set(gamma_members(floor)) <= set(out.transition.next_states)


def test_gate_b_drops_unsound_backend_value():
    """Emulator asserts a value OUTSIDE γ(floor) -> fold_exact drops it -> stay ⊤.

    floor γ={4} (singleton), but the backend's ExactResult claims 9 (∉ γ(floor)).
    fold_exact returns the floor unchanged (ABSTRACT, not CONCRETE) -> reject.
    """
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    floor = _floor_singleton(4)
    loc = _state_loc()
    cell = _top_cell(floor)
    cv = ConcolicCellValue(
        next_states=frozenset({4}),
        per_state_value={4: 9},  # backend lies: claims 9 for the arm whose state is 4
        exact_outcome=ExactResult({loc: 9}),
        state_loc=loc,
    )
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is True  # unsound backend value caught and dropped


# ── singleton-only gate when γ(floor) un-enumerable ────────────────────────


def test_gate_b_singleton_accepts_when_floor_collapses():
    """Un-enumerable floor (wide ⊤-interval but singleton bits) -> accept singleton.

    A 64-bit floor whose bits prove a single value but whose interval is ⊤ is not
    arc-enumerable; the singleton gate accepts V={x} iff floor.to_const()==x.
    """
    width = 64
    floor = AbstractEvidence(width, KnownBits.of(0x2A, width), WrappedInterval.top(width))
    assert floor.to_const() == 0x2A
    assert gamma_members(floor) is None  # not finitely enumerable
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    cell = TopCell(transition=MachineTransition(7, (), ()), floor=floor, is_top=True)
    cv = ConcolicCellValue(next_states=frozenset({0x2A}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is False
    assert out.transition.next_states == (0x2A,)


def test_gate_b_singleton_refuses_fork_on_unenumerable_floor():
    """Un-enumerable floor + |V|>1 -> cannot prove complete -> stay ⊤ (risk-1 guard)."""
    width = 64
    floor = AbstractEvidence.top(width)  # ⊤ -> but test via a non-⊤-but-unenumerable
    # use a wide interval that is not a const and not arc-enumerable
    floor = AbstractEvidence(width, KnownBits.top(width), WrappedInterval(width, 0, (1 << 40), "range"))
    assert gamma_members(floor) is None
    gate = CompletenessGate(GateMode.FOLD_EXACT_FLOOR)
    cell = TopCell(transition=MachineTransition(7, (), ()), floor=floor, is_top=True)
    cv = ConcolicCellValue(next_states=frozenset({1, 2}))
    out = gate.refine_top_cell(cell=cell, concolic_value=cv, spine_floor=floor)
    assert out.is_top is True


# ── gate (a) ────────────────────────────────────────────────────────────────


def test_gate_a_requires_complete_enumeration():
    """(a) refuses unless enumerated_inputs_complete ∧ deterministic."""
    gate = CompletenessGate(GateMode.DETERMINISTIC_F)
    cell = _top_cell(None)
    # incomplete enumeration -> stay ⊤
    cv = ConcolicCellValue(
        next_states=frozenset({3, 4}),
        enumerated_inputs_complete=False,
        deterministic=True,
    )
    assert gate.refine_top_cell(cell=cell, concolic_value=cv).is_top is True
    # not deterministic -> stay ⊤
    cv2 = ConcolicCellValue(
        next_states=frozenset({3, 4}),
        enumerated_inputs_complete=True,
        deterministic=False,
    )
    assert gate.refine_top_cell(cell=cell, concolic_value=cv2).is_top is True


def test_gate_a_accepts_complete_deterministic():
    """(a) refines V=image(f) when the walk proves complete + deterministic."""
    gate = CompletenessGate(GateMode.DETERMINISTIC_F)
    cell = _top_cell(None)
    cv = ConcolicCellValue(
        next_states=frozenset({3, 4}),
        enumerated_inputs_complete=True,
        deterministic=True,
    )
    out = gate.refine_top_cell(cell=cell, concolic_value=cv)
    assert out.is_top is False
    assert set(out.transition.next_states) == {3, 4}
    assert out.floor is None  # gate (a) carries no floor


def test_gate_a_accepts_complete_exit_path_effect_summary():
    """A deterministic exit path can carry symbolic payload effects."""
    gate = CompletenessGate(GateMode.DETERMINISTIC_F)
    cell = _top_cell(None)
    exit_path = _symbolic_payload_exit_path_effect_summary()
    cv = ConcolicCellValue(
        next_states=frozenset({0x2222}),
        enumerated_inputs_complete=True,
        deterministic=True,
        exit_path_effect_summary=exit_path,
    )
    out = gate.refine_top_cell(cell=cell, concolic_value=cv)

    assert out.is_top is False
    assert out.transition.next_states == (0x2222,)
    assert out.exit_path_effect_summary == exit_path


def test_gate_a_rejects_exit_path_effect_summary_when_symbol_controls_branch():
    gate = CompletenessGate(GateMode.DETERMINISTIC_F)
    cell = _top_cell(None)
    cv = ConcolicCellValue(
        next_states=frozenset({0x2222}),
        enumerated_inputs_complete=True,
        deterministic=True,
        exit_path_effect_summary=_symbolic_payload_exit_path_effect_summary(branch_dependency_symbols=("R",)),
    )

    out = gate.refine_top_cell(cell=cell, concolic_value=cv)

    assert out.is_top is True
    assert out.exit_path_effect_summary is None


def test_gate_a_rejects_incomplete_exit_path_effect_summary():
    gate = CompletenessGate(GateMode.DETERMINISTIC_F)
    cell = _top_cell(None)
    cv = ConcolicCellValue(
        next_states=frozenset({0x2222}),
        enumerated_inputs_complete=True,
        deterministic=True,
        exit_path_effect_summary=_symbolic_payload_exit_path_effect_summary(enumerated_inputs_complete=False),
    )

    out = gate.refine_top_cell(cell=cell, concolic_value=cv)

    assert out.is_top is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
