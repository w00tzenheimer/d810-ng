"""Hosted block instruction transaction contract tests."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from d810.hexrays.mutation.block_instruction_commit import (
    AllocatedKreg,
    BlockInstructionAnchor,
    BlockInstructionBatchCandidate,
    BlockInstructionBatchReceipt,
    BlockInstructionEditIntent,
    BlockInstructionMaterializationContext,
    MaterializedBlockInstructionEdit,
    fingerprint_minsn,
)
from d810.hexrays.mutation.instruction_commit import NativeEpoch


class FakeMaterializer:
    def materialize(self, _context):
        return MaterializedBlockInstructionEdit(replacement=object())


def _epoch(*, generation: int = 4) -> NativeEpoch:
    return NativeEpoch(
        function_ea=0x401000,
        mba_identity=0x100,
        maturity=7,
        generation=generation,
    )


def _anchor(
    *,
    ordinal: int = 0,
    instruction_ea: int = 0x401010,
) -> BlockInstructionAnchor:
    return BlockInstructionAnchor(
        block_serial=3,
        block_start_ea=0x401000,
        ordinal=ordinal,
        instruction_ea=instruction_ea,
        opcode=42,
        before_fingerprint=99,
    )


def _anchor_with(**changes: int) -> BlockInstructionAnchor:
    fields = {
        "block_serial": 3,
        "block_start_ea": 0x401000,
        "ordinal": 0,
        "instruction_ea": 0x401010,
        "opcode": 42,
        "before_fingerprint": 99,
    }
    fields.update(changes)
    return BlockInstructionAnchor(**fields)


def _intent(anchor: BlockInstructionAnchor) -> BlockInstructionEditIntent:
    return BlockInstructionEditIntent(
        anchor=anchor,
        materializer=FakeMaterializer(),
        description="test edit",
    )


def _candidate(*intents: BlockInstructionEditIntent) -> BlockInstructionBatchCandidate:
    return BlockInstructionBatchCandidate(
        edits=tuple(intents),
        epoch_before=_epoch(),
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
    )


def _receipt(
    *,
    committed: bool = False,
    callback_result: int = 0,
    applied_edit_count: int = 0,
    inserted_instruction_count: int = 0,
    epoch_after: NativeEpoch | None = None,
) -> BlockInstructionBatchReceipt:
    epoch_before = _epoch()
    return BlockInstructionBatchReceipt(
        committed=committed,
        callback_result=callback_result,
        applied_edit_count=applied_edit_count,
        inserted_instruction_count=inserted_instruction_count,
        epoch_before=epoch_before,
        epoch_after=epoch_before if epoch_after is None else epoch_after,
        reason="rejected",
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
        mutation_batch_id=None,
    )


@pytest.mark.parametrize(
    "field",
    ("block_serial", "block_start_ea", "ordinal", "instruction_ea", "opcode"),
)
def test_anchor_rejects_negative_identity_fields(field: str) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        _anchor_with(**{field: -1})


@pytest.mark.parametrize("field", ("register", "size"))
def test_allocated_kreg_rejects_negative_fields(field: str) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        fields = {"register": 5, "size": 1}
        fields[field] = -1
        AllocatedKreg(**fields)


def test_candidate_rejects_empty_edits() -> None:
    with pytest.raises(ValueError, match="at least one edit"):
        _candidate()


def test_candidate_rejects_repeated_complete_anchors() -> None:
    intent = _intent(_anchor())

    with pytest.raises(ValueError, match="duplicate anchor"):
        _candidate(intent, intent)


def test_candidate_accepts_same_instruction_ea_with_distinct_ordinals() -> None:
    candidate = _candidate(_intent(_anchor(ordinal=0)), _intent(_anchor(ordinal=1)))

    assert len(candidate.edits) == 2
    assert (
        candidate.edits[0].anchor.instruction_ea
        == candidate.edits[1].anchor.instruction_ea
    )
    assert candidate.edits[0].anchor.ordinal != candidate.edits[1].anchor.ordinal


def test_contracts_are_frozen() -> None:
    anchor = _anchor()

    with pytest.raises(FrozenInstanceError):
        anchor.ordinal = 1


def test_materialization_context_uses_backend_allocation_port_and_ledger() -> None:
    allocations: list[int] = []
    ledger: list[AllocatedKreg] = []
    context = BlockInstructionMaterializationContext(
        block=object(),
        instruction=object(),
        allocate_kreg=lambda size: allocations.append(size) or 7,
        allocated_kregs=ledger,
    )

    assert context.alloc_kreg(4) == 7
    assert allocations == [4]
    assert ledger == [AllocatedKreg(register=7, size=4)]
    assert not hasattr(context, "mba")


def test_fingerprint_minsn_is_exported_as_the_common_helper() -> None:
    class Instruction:
        opcode = 42

        def _print(self) -> str:
            return "op42"

    instruction = Instruction()

    assert fingerprint_minsn(instruction, 0x401000) == hash(
        (instruction.opcode, instruction._print(), 0x401000)
    )


@pytest.mark.parametrize(
    "kwargs",
    (
        {"committed": True, "callback_result": 0, "applied_edit_count": 1},
        {"committed": True, "callback_result": 1, "applied_edit_count": 0},
        {"committed": False, "callback_result": 1},
        {"committed": False, "applied_edit_count": 1},
        {"committed": False, "inserted_instruction_count": 1},
    ),
)
def test_receipt_rejects_mismatched_callback_and_counts(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="receipt counts"):
        _receipt(**kwargs)


def test_receipt_rejects_non_retained_epoch() -> None:
    with pytest.raises(ValueError, match="retain"):
        _receipt(
            epoch_after=replace(_epoch(), generation=_epoch().generation + 1),
        )


def test_committed_receipt_requires_a_positive_edit_count() -> None:
    with pytest.raises(ValueError, match="receipt counts"):
        _receipt(committed=True, callback_result=1, applied_edit_count=0)


def test_receipt_primitive_fields_are_json_safe_and_omit_native_objects() -> None:
    receipt = BlockInstructionBatchReceipt(
        committed=True,
        callback_result=1,
        applied_edit_count=2,
        inserted_instruction_count=1,
        epoch_before=_epoch(),
        epoch_after=_epoch(),
        reason="committed",
        pass_id="test-pass",
        stage_id="test-stage",
        rule_id="test-rule",
        mutation_batch_id="batch-1",
    )

    fields = receipt.primitive_fields()

    json.dumps(fields, allow_nan=False)
    assert all(
        value is None or type(value) in (bool, int, str) for value in fields.values()
    )
    assert fields["callback_result"] == 1
    assert fields["applied_edit_count"] == 2
    assert fields["inserted_instruction_count"] == 1
    assert fields["generation_before"] == fields["generation_after"]
    assert "epoch_before" not in fields
    assert "epoch_after" not in fields
