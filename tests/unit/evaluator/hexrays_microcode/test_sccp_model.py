from __future__ import annotations

from dataclasses import FrozenInstanceError
import sys
import types
from pathlib import Path

import pytest

# The legacy package initializer imports live IDA modules.  These model tests
# deliberately exercise the pure-Python subpackage without requiring IDA.
_package_name = "d810.evaluator.hexrays_microcode"
if _package_name not in sys.modules:
    _package = types.ModuleType(_package_name)
    _package.__path__ = [
        str(Path(__file__).resolve().parents[4] / "src" / "d810" / "evaluator" / "hexrays_microcode")
    ]
    sys.modules[_package_name] = _package

from d810.evaluator.hexrays_microcode.sccp_model import (  # noqa: E402
    OperandKind,
    SccpBlock,
    SccpInstruction,
    SccpOperand,
    SccpProgram,
)


def _constant(value: int, *, size: int = 4) -> SccpOperand:
    return SccpOperand(
        kind=OperandKind.CONSTANT,
        size=size,
        constant=value,
    )


def _value(value_id: int, *, size: int = 4) -> SccpOperand:
    return SccpOperand(
        kind=OperandKind.VALUE,
        size=size,
        value_id=value_id,
    )


def test_operand_rejects_fields_that_do_not_match_kind() -> None:
    with pytest.raises(ValueError):
        SccpOperand(
            kind=OperandKind.VALUE,
            size=4,
            constant=7,
            value_id=1,
        )

    with pytest.raises(ValueError):
        SccpOperand(
            kind=OperandKind.CONSTANT,
            size=4,
            value_id=1,
        )

    with pytest.raises(ValueError):
        SccpOperand(
            kind=OperandKind.UNSUPPORTED,
            size=4,
            constant=7,
        )

    with pytest.raises(ValueError):
        SccpOperand(
            kind=OperandKind.VALUE,
            size=-1,
            value_id=1,
        )


def test_model_records_are_frozen_and_slotted() -> None:
    operand = _constant(7)

    with pytest.raises(FrozenInstanceError):
        operand.size = 8  # type: ignore[misc]

    assert not hasattr(operand, "__dict__")


def test_program_indexes_each_value_use_once_per_instruction() -> None:
    instructions = (
        SccpInstruction(
            index=0,
            block_index=0,
            opcode="mov",
            ea=0x1000,
            size=4,
            left=_constant(7),
            destination_value_id=1,
        ),
        SccpInstruction(
            index=1,
            block_index=0,
            opcode="add",
            ea=0x1004,
            size=4,
            left=_value(1),
            right=_value(1),
            destination_value_id=2,
        ),
    )
    program = SccpProgram.from_parts(
        blocks=(SccpBlock(index=0, successors=(), instruction_indices=(0, 1)),),
        instructions=instructions,
        mop_keys_by_value={1: ("s", 1), 2: ("s", 2)},
    )

    assert program.uses_for(1) == (1,)
    assert program.uses_for(2) == ()
    assert program.mop_key_for(1) == ("s", 1)
    assert program.mop_key_for(999) is None


def test_equal_programs_have_equal_fingerprints_and_ea_changes_it() -> None:
    block = SccpBlock(index=0, successors=(), instruction_indices=(0,))
    instruction = SccpInstruction(
        index=0,
        block_index=0,
        opcode="mov",
        ea=0x1000,
        size=4,
        left=_constant(7),
        destination_value_id=1,
    )
    same = SccpProgram.from_parts(
        blocks=(block,),
        instructions=(instruction,),
        mop_keys_by_value={1: ("s", 1)},
        fingerprint_seed="fixture",
    )
    equal = SccpProgram.from_parts(
        blocks=(block,),
        instructions=(instruction,),
        mop_keys_by_value={1: ("s", 1)},
        fingerprint_seed="fixture",
    )
    changed = SccpProgram.from_parts(
        blocks=(block,),
        instructions=(
            SccpInstruction(
                index=0,
                block_index=0,
                opcode="mov",
                ea=0x1001,
                size=4,
                left=_constant(7),
                destination_value_id=1,
            ),
        ),
        mop_keys_by_value={1: ("s", 1)},
        fingerprint_seed="fixture",
    )

    assert same.fingerprint == equal.fingerprint
    assert same.fingerprint != changed.fingerprint
    assert len(same.fingerprint) == 64


def test_program_freezes_nested_mop_key_containers() -> None:
    mutable_key = ["s", {"offset": 8}, [4], {"stack", "read"}]
    program = SccpProgram.from_parts(
        blocks=(SccpBlock(index=0, successors=(), instruction_indices=()),),
        instructions=(),
        mop_keys_by_value={1: mutable_key},
        fingerprint_seed="mutable-key",
    )
    fingerprint_before = program.fingerprint
    key_before = repr(program.mop_key_for(1))

    mutable_key[0] = "r"
    mutable_key[1]["offset"] = 16
    mutable_key[2].append(8)
    mutable_key[3].add("write")

    assert program.fingerprint == fingerprint_before
    assert repr(program.mop_key_for(1)) == key_before

    returned_key = program.mop_key_for(1)
    assert returned_key is not None
    with pytest.raises(TypeError):
        returned_key[0] = "r"  # type: ignore[index]
    with pytest.raises(TypeError):
        returned_key[1]["offset"] = 16  # type: ignore[index]
