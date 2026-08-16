from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

# The legacy package initializer imports live IDA modules.  These solver tests
# deliberately exercise the pure-Python subpackage without requiring IDA.
_package_name = "d810.evaluator.hexrays_microcode"
if _package_name not in sys.modules:
    _package = types.ModuleType(_package_name)
    _package.__path__ = [
        str(Path(__file__).resolve().parents[4] / "src" / "d810" / "evaluator" / "hexrays_microcode")
    ]
    sys.modules[_package_name] = _package

from d810.evaluator.hexrays_microcode.p_sccp import solve  # noqa: E402
from d810.evaluator.hexrays_microcode.sccp_model import (  # noqa: E402
    OperandKind,
    SccpBlock,
    SccpInstruction,
    SccpOperand,
    SccpProgram,
    SccpStatus,
)
from d810.evaluator.hexrays_microcode import p_sccp  # noqa: E402


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


def _instruction(
    index: int,
    block_index: int,
    opcode: str,
    *,
    left: SccpOperand | None = None,
    right: SccpOperand | None = None,
    destination_value_id: int | None = None,
) -> SccpInstruction:
    return SccpInstruction(
        index=index,
        block_index=block_index,
        opcode=opcode,
        ea=0x1000 + index * 4,
        size=4,
        left=left,
        right=right,
        destination_value_id=destination_value_id,
    )


def diamond_program() -> SccpProgram:
    instructions = (
        _instruction(
            0,
            0,
            "mov",
            left=_constant(7),
            destination_value_id=1,
        ),
        _instruction(
            1,
            0,
            "jnz",
            left=_value(1),
            right=_constant(0),
        ),
        _instruction(
            2,
            1,
            "add",
            left=_value(1),
            right=_constant(1),
            destination_value_id=2,
        ),
        _instruction(3, 1, "goto"),
        _instruction(
            4,
            2,
            "add",
            left=_value(1),
            right=_constant(2),
            destination_value_id=3,
        ),
        _instruction(5, 3, "add", left=_value(1), right=_constant(0), destination_value_id=4),
    )
    return SccpProgram.from_parts(
        blocks=(
            # The conditional branch's second successor is its taken edge;
            # ordering these as (dead, live) makes edge (0, 1) the true path.
            SccpBlock(index=0, successors=(2, 1), instruction_indices=(0, 1)),
            SccpBlock(index=1, successors=(3,), instruction_indices=(2, 3)),
            SccpBlock(index=2, successors=(3,), instruction_indices=(4,)),
            SccpBlock(index=3, successors=(), instruction_indices=(5,)),
        ),
        instructions=instructions,
        mop_keys_by_value={
            1: ("s", 1),
            2: ("s", 2),
            3: ("s", 3),
            4: ("s", 4),
        },
        fingerprint_seed="diamond",
    )


def program_with_two_reads_of_value_one() -> SccpProgram:
    instructions = (
        _instruction(
            0,
            0,
            "mov",
            left=_constant(7),
            destination_value_id=1,
        ),
        _instruction(
            1,
            0,
            "add",
            left=_value(1),
            right=_value(1),
            destination_value_id=2,
        ),
    )
    return SccpProgram.from_parts(
        blocks=(SccpBlock(index=0, successors=(), instruction_indices=(0, 1)),),
        instructions=instructions,
        mop_keys_by_value={1: ("s", 1), 2: ("s", 2)},
        fingerprint_seed="duplicate-uses",
    )


def test_work_limit_is_proof_empty() -> None:
    result = solve(diamond_program(), work_budget=1)

    assert result.status is SccpStatus.WORK_LIMIT
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()
    assert not result.is_edge_executable(0, 1)
    assert not result.is_edge_dead(0, 2)


def test_constant_condition_selects_one_edge() -> None:
    result = solve(diamond_program())

    assert result.status is SccpStatus.CONVERGED
    assert result.constants[("s", 1)] == 7
    assert (0, 1) in result.executable_edges
    assert (0, 2) not in result.executable_edges
    assert result.is_edge_dead(0, 2)


def test_duplicate_uses_are_indexed() -> None:
    result = solve(program_with_two_reads_of_value_one())

    assert result.status is SccpStatus.CONVERGED
    assert result.value_events <= 2 * len(result.constants)


def test_default_budget_does_not_charge_virtual_entry_seed() -> None:
    program = SccpProgram.from_parts(
        blocks=(
            SccpBlock(index=0, successors=(1,), instruction_indices=()),
            SccpBlock(index=1, successors=(), instruction_indices=()),
        ),
        instructions=(),
        mop_keys_by_value={},
        fingerprint_seed="two-block-empty",
    )

    result = solve(program)

    assert result.status is SccpStatus.CONVERGED
    assert result.executable_edges == frozenset({(0, 1)})
    assert result.reachable_blocks == frozenset({0, 1})
    assert result.cfg_events == 1


def test_block_limit_records_solver_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((3.0, 3.25))
    monkeypatch.setattr(p_sccp.time, "perf_counter", lambda: next(ticks))
    block_count = 501
    program = SccpProgram.from_parts(
        blocks=tuple(
            SccpBlock(
                index=index,
                successors=((index + 1,) if index + 1 < block_count else ()),
                instruction_indices=(),
            )
            for index in range(block_count)
        ),
        instructions=(),
        mop_keys_by_value={},
    )

    result = solve(program)

    assert result.status is SccpStatus.BLOCK_LIMIT
    assert result.solver_seconds == pytest.approx(0.25)
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()


def test_work_limit_records_solver_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((4.0, 4.125))
    monkeypatch.setattr(p_sccp.time, "perf_counter", lambda: next(ticks))

    result = solve(diamond_program(), work_budget=1)

    assert result.status is SccpStatus.WORK_LIMIT
    assert result.solver_seconds == pytest.approx(0.125)
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()


def test_error_records_solver_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((8.0, 8.5))
    monkeypatch.setattr(p_sccp.time, "perf_counter", lambda: next(ticks))
    program = SccpProgram.from_parts(
        blocks=(SccpBlock(index=0, successors=(9,), instruction_indices=()),),
        instructions=(),
        mop_keys_by_value={},
    )

    result = solve(program)

    assert result.status is SccpStatus.ERROR
    assert result.solver_seconds == pytest.approx(0.5)
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()


def test_unsupported_operand_converges_to_none_constant() -> None:
    unsupported = SccpOperand(kind=OperandKind.UNSUPPORTED, size=4)
    program = SccpProgram.from_parts(
        blocks=(SccpBlock(index=0, successors=(), instruction_indices=(0,)),),
        instructions=(
            _instruction(
                0,
                0,
                "mov",
                left=unsupported,
                destination_value_id=1,
            ),
        ),
        mop_keys_by_value={1: ("s", 1)},
    )

    result = solve(program)

    assert result.status is SccpStatus.CONVERGED
    assert result.constants == {("s", 1): None}


def test_loop_reaches_top_after_second_monotone_transition() -> None:
    instructions = (
        _instruction(
            0,
            0,
            "mov",
            left=_constant(1),
            destination_value_id=1,
        ),
        _instruction(
            1,
            0,
            "jnz",
            left=_value(1),
            right=_constant(0),
        ),
        _instruction(
            2,
            1,
            "mov",
            left=_constant(2),
            destination_value_id=1,
        ),
        _instruction(3, 1, "goto"),
        _instruction(4, 2, "add", left=_value(1), right=_constant(0), destination_value_id=2),
    )
    program = SccpProgram.from_parts(
        blocks=(
            SccpBlock(index=0, successors=(2, 1), instruction_indices=(0, 1)),
            SccpBlock(index=1, successors=(0,), instruction_indices=(2, 3)),
            SccpBlock(index=2, successors=(), instruction_indices=(4,)),
        ),
        instructions=instructions,
        mop_keys_by_value={1: ("s", 1), 2: ("s", 2)},
        fingerprint_seed="loop",
    )

    result = solve(program)

    assert result.status is SccpStatus.CONVERGED
    assert result.constants[("s", 1)] is None
    assert (0, 1) in result.executable_edges
    assert (0, 2) in result.executable_edges
    assert 1 in result.reachable_blocks
    assert 2 in result.reachable_blocks


def test_block_limit_is_proof_empty() -> None:
    block_count = 501
    blocks = tuple(
        SccpBlock(
            index=index,
            successors=((index + 1,) if index + 1 < block_count else ()),
            instruction_indices=(),
        )
        for index in range(block_count)
    )
    program = SccpProgram.from_parts(
        blocks=blocks,
        instructions=(),
        mop_keys_by_value={},
        fingerprint_seed="block-limit",
    )

    result = solve(program)

    assert result.status is SccpStatus.BLOCK_LIMIT
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()
