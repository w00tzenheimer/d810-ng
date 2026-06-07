"""fold_exact (wrongness guard) + refine_concrete (ticket llr-iqm3, S3 gate).

Gate: abstain/unsupported leave the result == the abstract-only (S2) value; a valid
exact folds to CONCRETE (>=1 transition newly resolved); a wrong exact is dropped.
"""
from __future__ import annotations

from d810.analyses.data_flow.concolic.concrete_refiner import (
    fold_exact,
    refine_concrete,
)
from d810.analyses.data_flow.concolic.emulation import (
    Abstain,
    ConcreteStore,
    ExactResult,
    InsnRef,
    ReferenceEmulator,
    Unsupported,
)
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus

W = 8
DEST = LocationRef.reg(0, W)
LOC = LocationRef.stack(0x10, W)


def test_abstain_leaves_value_unchanged_equals_s2() -> None:
    top = ConcolicValue.top(W)
    assert fold_exact(top, Abstain(), DEST) == top
    assert fold_exact(top, Unsupported(), DEST) == top
    # and the status is exactly the abstract-only result (S2 behaviour)
    assert fold_exact(top, Abstain(), DEST).status is PrecisionStatus.TOP


def test_exact_in_floor_folds_to_concrete() -> None:
    # abstract-only left it TOP; the emulator proves the exact value -> resolved
    before = ConcolicValue.top(W)
    after = fold_exact(before, ExactResult({DEST: 42}), DEST)
    assert after.status is PrecisionStatus.CONCRETE
    assert after.concrete == 42
    assert after.abstract.to_const() == 42  # reduce tightened the floor too


def test_exact_omitting_dest_is_a_no_op() -> None:
    top = ConcolicValue.top(W)
    assert fold_exact(top, ExactResult({LOC: 7}), DEST) == top  # value_for(DEST) is None


def test_wrong_exact_is_dropped_and_reported() -> None:
    # the value is already proven {5}; a backend claiming 6 is WRONG, not imprecise
    five = ConcolicValue.of(5, W)
    seen: list[tuple] = []
    out = fold_exact(
        five, ExactResult({DEST: 6}), DEST, on_unsound=lambda d, e, a: seen.append((d, e))
    )
    assert out == five              # concrete claim dropped -> stay with the sound floor
    assert seen == [(DEST, 6)]      # the unsoundness was surfaced, not silent


def test_refine_concrete_resolves_via_emulator() -> None:
    # xor of two equal constants -> 0; abstract-only could not pin it, emulation does
    before = ConcolicValue.top(W)
    insn = InsnRef("xor", DEST, (0x55, 0x55), W)
    after = refine_concrete(before, insn, ConcreteStore.of({}), ReferenceEmulator())
    assert after.status is PrecisionStatus.CONCRETE and after.concrete == 0


def test_refine_concrete_no_emulator_is_identity() -> None:
    top = ConcolicValue.top(W)
    insn = InsnRef("xor", DEST, (0x55, 0x55), W)
    assert refine_concrete(top, insn, ConcreteStore.of({}), None) == top


def test_refine_concrete_abstain_path_equals_abstract_only() -> None:
    # operand unresolved -> emulator abstains -> result identical to abstract-only (S2)
    top = ConcolicValue.top(W)
    insn = InsnRef("add", DEST, (LOC, 1), W)  # LOC not in the store
    after = refine_concrete(top, insn, ConcreteStore.of({}), ReferenceEmulator())
    assert after == top and after.status is PrecisionStatus.TOP
