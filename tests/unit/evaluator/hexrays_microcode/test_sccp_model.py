from __future__ import annotations

from dataclasses import FrozenInstanceError
import gc
import sys
import types
import weakref
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
    SccpResult,
    SccpStatus,
)
from d810.evaluator.hexrays_microcode import sccp_model  # noqa: E402


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


@pytest.mark.parametrize(
    "status",
    (SccpStatus.WORK_LIMIT, SccpStatus.BLOCK_LIMIT, SccpStatus.ERROR),
)
@pytest.mark.parametrize(
    "field, value",
    (
        ("constants", {("s", 1): 7}),
        ("executable_edges", frozenset({(0, 1)})),
        ("reachable_blocks", frozenset({0})),
    ),
)
def test_nonconverged_result_rejects_populated_proof_fields(
    status: SccpStatus,
    field: str,
    value: object,
) -> None:
    fields: dict[str, object] = {
        "constants": {},
        "executable_edges": frozenset(),
        "reachable_blocks": frozenset(),
    }
    fields[field] = value

    with pytest.raises(ValueError, match="proof-empty"):
        SccpResult(status=status, **fields)  # type: ignore[arg-type]


def test_converged_result_accepts_proof_fields() -> None:
    result = SccpResult(
        status=SccpStatus.CONVERGED,
        constants={("s", 1): 7},
        executable_edges=frozenset({(0, 1)}),
        reachable_blocks=frozenset({0, 1}),
    )

    assert result.constants == {("s", 1): 7}
    assert result.executable_edges == frozenset({(0, 1)})
    assert result.reachable_blocks == frozenset({0, 1})


class _FakeLiveObject:
    """Weak-referenceable stand-in for a live IDA/SWIG object."""


def test_program_rejects_live_block_before_retaining_it() -> None:
    live = _FakeLiveObject()
    live_ref = weakref.ref(live)

    with pytest.raises(TypeError, match="SccpBlock"):
        SccpProgram(
            blocks=(live,),  # type: ignore[arg-type]
            instructions=(),
            uses_by_value={},
            mop_keys_by_value={},
            fingerprint="live-block",
        )

    del live
    gc.collect()
    assert live_ref() is None


def test_program_rejects_live_instruction_before_retaining_it() -> None:
    live = _FakeLiveObject()
    live_ref = weakref.ref(live)

    with pytest.raises(TypeError, match="SccpInstruction"):
        SccpProgram(
            blocks=(),
            instructions=(live,),  # type: ignore[arg-type]
            uses_by_value={},
            mop_keys_by_value={},
            fingerprint="live-instruction",
        )

    del live
    gc.collect()
    assert live_ref() is None


def test_from_parts_rejects_nonprimitive_mop_value_id_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sccp_model.hashlib,
        "sha256",
        lambda *_args, **_kwargs: pytest.fail("invalid model was hashed"),
    )
    with pytest.raises(TypeError, match="MOP key value id must be an integer"):
        SccpProgram.from_parts(
            blocks=(SccpBlock(0, (), ()),),
            instructions=(),
            mop_keys_by_value={"live": ("s", 1)},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize(
    "blocks, instructions, message",
    (
        (
            (SccpBlock(0, (), ()), SccpBlock(0, (), ())),
            (),
            "duplicate block index",
        ),
        (
            (SccpBlock(0, (), (0, 0)),),
            (SccpInstruction(0, 0, "nop", 0x1000, 4),),
            "duplicate instruction index",
        ),
        (
            (SccpBlock(0, (), (1,)),),
            (SccpInstruction(0, 0, "nop", 0x1000, 4),),
            "unknown instruction index",
        ),
        (
            (SccpBlock(0, (), ()),),
            (SccpInstruction(0, 0, "nop", 0x1000, 4),),
            "unreferenced instruction",
        ),
        (
            (SccpBlock(0, (1,), ()),),
            (),
            "unknown successor",
        ),
        (
            (SccpBlock(0, (1, 1), ()), SccpBlock(1, (), ())),
            (),
            "duplicate successor",
        ),
        (
            (SccpBlock(0, (), (0,)),),
            (SccpInstruction(0, 1, "nop", 0x1000, 4),),
            "belongs to another block",
        ),
    ),
)
def test_program_rejects_inconsistent_structure(
    blocks: tuple[SccpBlock, ...],
    instructions: tuple[SccpInstruction, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        SccpProgram(
            blocks=blocks,
            instructions=instructions,
            uses_by_value={},
            mop_keys_by_value={},
            fingerprint="invalid-structure",
        )
