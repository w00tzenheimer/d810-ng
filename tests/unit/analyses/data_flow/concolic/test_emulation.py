"""ReferenceEmulator + EmulationCapability outcome ADTs (ticket llr-iqm3, S3)."""
from __future__ import annotations

from d810.analyses.data_flow.concolic.emulation import (
    Abstain,
    ConcreteStore,
    ExactResult,
    InsnRef,
    ReferenceEmulator,
    Unsupported,
)
from d810.analyses.data_flow.concolic.refs import LocationRef

W = 8
DEST = LocationRef.reg(0, W)
LOC = LocationRef.stack(0x10, W)
EMU = ReferenceEmulator()


def test_xor_of_immediates_is_exact() -> None:
    out = EMU.eval_insn(InsnRef("xor", DEST, (0x55, 0x55), W), ConcreteStore.of({}))
    assert isinstance(out, ExactResult)
    assert out.value_for(DEST) == 0


def test_add_wraps_at_width() -> None:
    out = EMU.eval_insn(InsnRef("add", DEST, (0xFF, 0x02), W), ConcreteStore.of({}))
    assert out.value_for(DEST) == 1  # 0x101 & 0xFF


def test_operand_read_from_store() -> None:
    out = EMU.eval_insn(InsnRef("sub", DEST, (LOC, 1), W), ConcreteStore.of({LOC: 10}))
    assert out.value_for(DEST) == 9


def test_unary_not_and_neg() -> None:
    assert EMU.eval_insn(InsnRef("not", DEST, (0x0F,), W), ConcreteStore.of({})).value_for(DEST) == 0xF0
    assert EMU.eval_insn(InsnRef("neg", DEST, (1,), W), ConcreteStore.of({})).value_for(DEST) == 0xFF


def test_unresolved_operand_abstains() -> None:
    out = EMU.eval_insn(InsnRef("add", DEST, (LOC, 1), W), ConcreteStore.of({}))
    assert isinstance(out, Abstain)  # could run, but the operand is unresolved


def test_unmodeled_op_is_unsupported() -> None:
    out = EMU.eval_insn(InsnRef("rotate", DEST, (1, 2), W), ConcreteStore.of({}))
    assert isinstance(out, Unsupported)


def test_arity_mismatch_is_unsupported() -> None:
    out = EMU.eval_insn(InsnRef("add", DEST, (1, 2, 3), W), ConcreteStore.of({}))
    assert isinstance(out, Unsupported)


def test_block_stepping_not_modeled_by_reference() -> None:
    assert isinstance(EMU.eval_block(object(), ConcreteStore.of({})), Unsupported)


def test_exact_result_value_for_missing_cell_is_none() -> None:
    assert ExactResult({LOC: 5}).value_for(DEST) is None
