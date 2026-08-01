from __future__ import annotations

import pytest

from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedConstantMaterializationFact,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnKind
from d810.transforms.fragment_plan import FragmentConstantPublicationEnvelope
from d810.transforms.prepared_native_body import PreparedNativeInstructionFact


def _envelope(length: int) -> tuple[PreparedNativeInstructionFact, ...]:
    return tuple(
        PreparedNativeInstructionFact(
            instruction_id=f"constant:test:{index}",
            native_ea=0x401000,
            opcode=index,
            kind=InsnKind.LOAD if index == 2 else InsnKind.MOV,
            operand_shape=(),
            writes_condition_codes=False,
        )
        for index in range(length)
    )


@pytest.mark.parametrize(
    ("consumer_operation", "publication_envelope", "length", "load_offset"),
    (
        (
            ValueOpKind.ADD,
            FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD,
            10,
            2,
        ),
        (
            ValueOpKind.MOVE,
            FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD,
            4,
            2,
        ),
        (
            ValueOpKind.MOVE,
            FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_MOVE,
            1,
            0,
        ),
        (
            ValueOpKind.MOVE,
            FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_MOVE,
            1,
            0,
        ),
        (
            ValueOpKind.MOVE,
            FragmentConstantPublicationEnvelope.IMPORTED_GLOBAL_BYTE_ZERO_EXTEND,
            1,
            0,
        ),
    ),
)
def test_constant_preparation_envelope_is_bound_to_typed_consumer(
    consumer_operation: ValueOpKind,
    publication_envelope: FragmentConstantPublicationEnvelope,
    length: int,
    load_offset: int,
) -> None:
    fact = PreparedConstantMaterializationFact(
        materialization_id="constant:test",
        source_block_id="native@0x401000",
        instruction_ea=0x401000,
        envelope_start_instruction_index=7,
        load_instruction_index=7 + load_offset,
        consumer_operation=consumer_operation,
        publication_envelope=publication_envelope,
        envelope=_envelope(length),
    )

    assert fact.consumer_operation is consumer_operation
    assert len(fact.envelope) == length


def test_mov_constant_preparation_rejects_add_envelope_length() -> None:
    with pytest.raises(
        ValueError,
        match="typed consumer envelope",
    ):
        PreparedConstantMaterializationFact(
            materialization_id="constant:test",
            source_block_id="native@0x401000",
            instruction_ea=0x401000,
            envelope_start_instruction_index=7,
            load_instruction_index=9,
            consumer_operation=ValueOpKind.MOVE,
            publication_envelope=(
                FragmentConstantPublicationEnvelope.GENERATED_ABSOLUTE_LOAD
            ),
            envelope=_envelope(10),
        )
