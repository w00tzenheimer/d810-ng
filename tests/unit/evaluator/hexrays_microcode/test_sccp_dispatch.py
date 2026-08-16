from __future__ import annotations

import gc
import importlib
import os
import sys
import types
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
import weakref

import pytest

from d810.core import CythonMode


# The legacy package initializer imports live IDA modules.  Keep this focused
# model/dispatcher suite detached from IDA, as the Task 1/2 unit suites do.
_package_name = "d810.evaluator.hexrays_microcode"
if _package_name not in sys.modules:
    _package = types.ModuleType(_package_name)
    _package.__path__ = [
        str(
            Path(__file__).resolve().parents[4]
            / "src"
            / "d810"
            / "evaluator"
            / "hexrays_microcode"
        )
    ]
    sys.modules[_package_name] = _package

from d810.evaluator.hexrays_microcode import p_sccp  # noqa: E402
from d810.evaluator.hexrays_microcode.sccp_model import (  # noqa: E402
    OperandKind,
    SccpBlock,
    SccpInstruction,
    SccpOperand,
    SccpProgram,
    SccpResult,
    SccpStatus,
)


def make_program() -> SccpProgram:
    return SccpProgram.from_parts((SccpBlock(0, (), ()),), (), {})


def make_constant_program(value: int) -> SccpProgram:
    constant = SccpOperand(OperandKind.CONSTANT, 1, constant=value)
    instruction = SccpInstruction(
        0,
        0,
        "mov",
        0x4000,
        1,
        constant,
        destination_value_id=1,
    )
    return SccpProgram.from_parts(
        (SccpBlock(0, (), (0,)),),
        (instruction,),
        {1: ("r", 1)},
    )


def make_diamond() -> SccpProgram:
    """A constant branch with one join and one dead arm."""

    constant = SccpOperand(OperandKind.CONSTANT, 1, constant=1)
    seven = SccpOperand(OperandKind.CONSTANT, 1, constant=7)
    zero = SccpOperand(OperandKind.CONSTANT, 1, constant=0)
    blocks = (
        SccpBlock(0, (1, 2), (0, 1)),
        SccpBlock(1, (3,), (2,)),
        SccpBlock(2, (3,), (3,)),
        SccpBlock(3, (), (4,)),
    )
    instructions = (
        SccpInstruction(0, 0, "mov", 0x1000, 1, seven, destination_value_id=1),
        SccpInstruction(1, 0, "jnz", 0x1004, 1, constant, zero),
        SccpInstruction(2, 1, "mov", 0x1010, 1, seven, destination_value_id=2),
        SccpInstruction(3, 2, "mov", 0x1020, 1, zero, destination_value_id=2),
        SccpInstruction(
            4,
            3,
            "add",
            0x1030,
            1,
            SccpOperand(OperandKind.VALUE, 1, value_id=2),
            seven,
            destination_value_id=3,
        ),
    )
    return SccpProgram.from_parts(
        blocks,
        instructions,
        {1: ("r", 1), 2: ("r", 2), 3: ("r", 3)},
    )


def make_loop() -> SccpProgram:
    """A loop whose second incoming value forces a monotone TOP transition."""

    one = SccpOperand(OperandKind.CONSTANT, 1, constant=1)
    blocks = (
        SccpBlock(0, (1,), (0,)),
        SccpBlock(1, (1, 2), (1, 2)),
        SccpBlock(2, (), (3,)),
    )
    instructions = (
        SccpInstruction(0, 0, "mov", 0x2000, 1, one, destination_value_id=1),
        SccpInstruction(
            1,
            1,
            "add",
            0x2010,
            1,
            SccpOperand(OperandKind.VALUE, 1, value_id=1),
            one,
            destination_value_id=1,
        ),
        SccpInstruction(
            2,
            1,
            "jnz",
            0x2014,
            1,
            SccpOperand(OperandKind.VALUE, 1, value_id=1),
            one,
        ),
        SccpInstruction(3, 2, "mov", 0x2020, 1, one, destination_value_id=2),
    )
    return SccpProgram.from_parts(
        blocks,
        instructions,
        {1: ("r", 1), 2: ("r", 2)},
    )


def make_unsupported() -> SccpProgram:
    unsupported = SccpOperand(OperandKind.UNSUPPORTED, 1)
    instruction = SccpInstruction(
        0,
        0,
        "mov",
        0x3000,
        1,
        unsupported,
        destination_value_id=1,
    )
    return SccpProgram.from_parts(
        (SccpBlock(0, (), (0,)),),
        (instruction,),
        {1: ("r", 1)},
    )


def make_error_program() -> SccpProgram:
    """A valid empty model whose virtual entry edge has no target block."""

    return SccpProgram.from_parts((), (), {})


def test_disabled_mode_is_python(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().disable()
    monkeypatch.setattr(
        _fast_sccp,
        "_load_cython_solver",
        lambda: pytest.fail("disabled mode attempted a Cython import"),
    )

    result = _fast_sccp.solve(make_program())

    assert result.backend == "python"
    assert result.status is SccpStatus.CONVERGED


def test_enabled_without_extension_falls_back_with_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()
    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: None)

    result = _fast_sccp.solve(make_program())

    assert result.backend == "python-fallback"
    assert result.fallback_reason
    assert result.parity_key() == p_sccp.solve(make_program()).parity_key()


def test_enabled_and_disabled_modes_have_equal_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    model = make_diamond()
    CythonMode().disable()
    python_result = _fast_sccp.solve(model)
    CythonMode().enable()
    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: None)
    fallback_result = _fast_sccp.solve(model)

    assert fallback_result.parity_key() == python_result.parity_key()
    assert fallback_result.backend == "python-fallback"


def test_import_failure_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()

    def fail() -> object:
        raise ImportError("extension missing")

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", fail)

    result = _fast_sccp.solve(make_program())

    assert result.backend == "python-fallback"
    assert "extension missing" in result.fallback_reason


def test_execution_failure_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()

    class Broken:
        @staticmethod
        def solve(_program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            raise RuntimeError("typed queue exploded")

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Broken)

    result = _fast_sccp.solve(make_program())

    assert result.backend == "python-fallback"
    assert "typed queue exploded" in result.fallback_reason


def test_available_cython_changes_backend_not_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()
    model = make_diamond()

    class Compiled:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            return p_sccp.solve(program, work_budget=work_budget)

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Compiled)

    result = _fast_sccp.solve(model)
    expected = p_sccp.solve(model)

    assert result.backend == "cython"
    assert result.parity_key() == expected.parity_key()
    assert result.solver_seconds >= 0.0


def test_parity_check_mismatch_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()
    monkeypatch.setenv("D810_SCCP_PARITY_CHECK", "1")

    class Wrong:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            result = p_sccp.solve(program, work_budget=work_budget)
            return SccpResult.empty(
                status=SccpStatus.WORK_LIMIT,
                program_fingerprint=result.program_fingerprint,
                backend="cython",
                fallback_reason="wrong fixture",
            )

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Wrong)

    result = _fast_sccp.solve(make_diamond())

    assert result.backend == "python-fallback"
    assert "parity" in result.fallback_reason
    assert result.parity_key() == p_sccp.solve(make_diamond()).parity_key()


@pytest.mark.parametrize("program_factory", [make_diamond, make_loop, make_unsupported])
def test_cython_dispatch_matches_python_for_control_and_lattice_cases(
    monkeypatch: pytest.MonkeyPatch,
    program_factory,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()
    model = program_factory()

    class Compiled:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            return p_sccp.solve(program, work_budget=work_budget)

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Compiled)

    assert _fast_sccp.solve(model).parity_key() == p_sccp.solve(model).parity_key()


def test_cython_dispatch_preserves_limit_and_error_proof_invariants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()

    class Compiled:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            return p_sccp.solve(program, work_budget=work_budget)

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Compiled)

    limited = _fast_sccp.solve(make_diamond(), work_budget=0)
    invalid = _fast_sccp.solve(make_error_program())

    for result in (limited, invalid):
        assert result.constants == {}
        assert result.executable_edges == frozenset()
        assert result.reachable_blocks == frozenset()
    assert limited.status is SccpStatus.WORK_LIMIT
    assert invalid.status is SccpStatus.ERROR


class _FakeLiveBlock:
    """Stand-in for a live IDA/SWIG block that must not cross the model boundary."""


def test_detached_cache_boundary_rejects_live_blocks_and_freezes_valid_inputs() -> None:
    live = _FakeLiveBlock()
    live_ref = weakref.ref(live)

    with pytest.raises(TypeError, match="SccpBlock"):
        SccpProgram.from_parts((live,), (), {})  # type: ignore[arg-type]

    del live
    gc.collect()
    assert live_ref() is None

    valid = make_constant_program(7)
    assert isinstance(valid.blocks, tuple)
    assert all(isinstance(block, SccpBlock) for block in valid.blocks)
    assert isinstance(valid.instructions, tuple)
    assert all(isinstance(instruction, SccpInstruction) for instruction in valid.instructions)
    assert isinstance(valid.uses_by_value, MappingProxyType)
    assert isinstance(valid.mop_keys_by_value, MappingProxyType)
    assert isinstance(valid.mop_keys_by_value[1], tuple)


def test_facade_default_uses_dispatcher_and_can_expose_cython_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp, sccp

    CythonMode().enable()
    model = make_diamond()

    class Compiled:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            return p_sccp.solve(program, work_budget=work_budget)

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Compiled)
    facade = sccp.SccpFacade(snapshot_fn=lambda _mba: model)
    result = facade.run(object())

    assert sccp.DEFAULT_SOLVER is _fast_sccp.solve
    assert result.backend == "cython"
    assert result.parity_key() == p_sccp.solve(model).parity_key()


def test_dispatcher_forwards_work_budget_to_compiled_solver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()
    seen: list[int | None] = []

    class Compiled:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            seen.append(work_budget)
            return p_sccp.solve(program, work_budget=work_budget)

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Compiled)

    result = _fast_sccp.solve(make_diamond(), work_budget=1)

    assert seen == [1]
    assert result.status is SccpStatus.WORK_LIMIT


def test_no_parity_check_in_normal_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.evaluator.hexrays_microcode import _fast_sccp

    CythonMode().enable()
    monkeypatch.delenv("D810_SCCP_PARITY_CHECK", raising=False)

    class Compiled:
        @staticmethod
        def solve(program: SccpProgram, work_budget: int | None = None) -> SccpResult:
            result = p_sccp.solve(program, work_budget=work_budget)
            return SccpResult(
                status=result.status,
                constants=result.constants,
                executable_edges=result.executable_edges,
                reachable_blocks=result.reachable_blocks,
                program_fingerprint=result.program_fingerprint,
                backend="cython",
                cfg_events=result.cfg_events,
                value_events=result.value_events,
                peak_cfg_queue=result.peak_cfg_queue,
                peak_value_queue=result.peak_value_queue,
                solver_seconds=result.solver_seconds,
                fallback_reason="native diagnostic metadata",
            )

    monkeypatch.setattr(_fast_sccp, "_load_cython_solver", lambda: Compiled)
    result = _fast_sccp.solve(make_program())

    assert result.backend == "cython"
    assert result.fallback_reason == "native diagnostic metadata"


def _load_compiled_solver_or_skip() -> object:
    try:
        return importlib.import_module("d810.speedups.evaluator.c_sccp")
    except Exception as exc:
        if os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1":
            pytest.fail(
                "D810_REQUIRE_COMPILED_SCCP=1 but the compiled SCCP extension "
                f"could not be imported: {exc}"
            )
        pytest.skip(f"compiled SCCP extension unavailable: {exc}")


def test_compiled_solver_gate_fails_when_extension_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_extension(_name: str) -> object:
        raise ImportError("extension intentionally unavailable")

    monkeypatch.setattr(importlib, "import_module", missing_extension)
    monkeypatch.setenv("D810_REQUIRE_COMPILED_SCCP", "1")

    with pytest.raises(pytest.fail.Exception, match="D810_REQUIRE_COMPILED_SCCP=1"):
        _load_compiled_solver_or_skip()


def test_compiled_view_cache_rejects_same_fingerprint_different_programs() -> None:
    c_sccp = _load_compiled_solver_or_skip()

    first = replace(make_constant_program(7), fingerprint="forced-cache-collision")
    second = replace(make_constant_program(9), fingerprint=first.fingerprint)

    assert first is not second
    assert first.fingerprint == second.fingerprint
    assert first != second

    actual_first = c_sccp.solve(first)
    actual_second = c_sccp.solve(second)

    assert actual_first.parity_key() == p_sccp.solve(first).parity_key()
    assert actual_second.parity_key() == p_sccp.solve(second).parity_key()
    assert actual_first.constants != actual_second.constants


def test_compiled_solver_matches_python_when_extension_is_built() -> None:
    c_sccp = _load_compiled_solver_or_skip()

    cases = (
        (make_diamond(), None),
        (make_loop(), None),
        (make_unsupported(), None),
        (make_diamond(), 0),
        (make_diamond(), 1),
        (make_error_program(), None),
    )
    for model, budget in cases:
        actual = c_sccp.solve(model, work_budget=budget)
        expected = p_sccp.solve(model, work_budget=budget)
        assert actual.backend == "cython"
        assert actual.parity_key() == expected.parity_key()
