"""Runtime parity and snapshot-fingerprint checks for the SCCP dispatcher."""

from __future__ import annotations

from dataclasses import replace
import importlib
import os
from pathlib import Path
import platform

import ida_hexrays
import idaapi
import idc
import pytest

from d810.core import CythonMode
from d810.evaluator.hexrays_microcode import p_sccp
from d810.evaluator.hexrays_microcode import _fast_sccp
from d810.evaluator.hexrays_microcode.sccp import SccpFacade
from d810.evaluator.hexrays_microcode.sccp_model import (
    OperandKind,
    SccpBlock,
    SccpInstruction,
    SccpOperand,
    SccpProgram,
)
from d810.evaluator.hexrays_microcode.sccp_snapshot import snapshot_from_mba


MATURITIES = (
    ("LOCOPT", ida_hexrays.MMAT_LOCOPT),
    ("CALLS", ida_hexrays.MMAT_CALLS),
    ("GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
    ("GLBOPT2", ida_hexrays.MMAT_GLBOPT2),
    ("GLBOPT3", ida_hexrays.MMAT_GLBOPT3),
)


def _default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _compiled_required() -> bool:
    return os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1"


def _fixture_available(binary_name: str) -> bool:
    current = idaapi.get_root_filename() or ""
    if current and (binary_name in current or current.endswith(binary_name)):
        return True
    root = Path(__file__).resolve().parents[4]
    return any(
        (root / relative / binary_name).is_file()
        for relative in ("samples/bins", "tests/_resources/bin", "tests/system/bins")
    )


@pytest.fixture
def compiled_sccp_runtime_prerequisite():
    """Make required-mode fixture/plugin absence a failure, never a skip."""

    if not _compiled_required():
        return
    binary_name = _default_binary()
    if not _fixture_available(binary_name):
        pytest.fail(
            "D810_REQUIRE_COMPILED_SCCP=1 but the configured fixture is missing: "
            f"{binary_name}"
        )
    if not idaapi.init_hexrays_plugin():
        pytest.fail(
            "D810_REQUIRE_COMPILED_SCCP=1 but the Hex-Rays runtime is unavailable"
        )


def _resolve_function_ea() -> int:
    requested = os.environ.get("D810_SCCP_PARITY_FUNCTION")
    candidates = (requested,) if requested else ("main", "test_chained_add")
    for name in candidates:
        if not name:
            continue
        ea = idc.get_name_ea_simple(name)
        if ea == idaapi.BADADDR:
            ea = idc.get_name_ea_simple("_" + name)
        if ea != idaapi.BADADDR:
            return int(ea)
    return int(idaapi.BADADDR)


def _gen_microcode(func_ea: int, maturity: int):
    func = idaapi.get_func(func_ea)
    if func is None:
        return None
    return ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(func),
        ida_hexrays.hexrays_failure_t(),
        None,
        ida_hexrays.DECOMP_NO_WAIT,
        maturity,
    )


def _compiled_extension_or_fail() -> object | None:
    try:
        return importlib.import_module("d810.speedups.evaluator.c_sccp")
    except Exception as exc:
        if _compiled_required():
            pytest.fail(
                "D810_REQUIRE_COMPILED_SCCP=1 but the compiled SCCP extension "
                f"could not be imported: {exc}"
            )
        return None


class TestSccpSnapshotParity:
    """Compare one detached snapshot per real disposable MBA maturity."""

    binary_name = _default_binary()

    @pytest.mark.ida_required
    def test_python_cython_parity(
        self,
        compiled_sccp_runtime_prerequisite,
        libobfuscated_setup,
    ) -> None:
        func_ea = _resolve_function_ea()
        if func_ea == idaapi.BADADDR:
            message = (
                "SCCP parity function is not present in the configured runtime binary"
            )
            if _compiled_required():
                pytest.fail(message)
            pytest.skip(message)

        _compiled_extension_or_fail()
        mode = CythonMode()
        was_enabled = mode.is_enabled()
        mode.enable()
        try:
            for label, maturity in MATURITIES:
                mba = _gen_microcode(func_ea, maturity)
                if mba is None:
                    message = f"could not generate disposable MBA at {label}"
                    if _compiled_required():
                        pytest.fail(message)
                    pytest.skip(message)

                # The live adapter is deliberately called once.  Both solvers
                # consume this same immutable program, so parity cannot hide
                # separate live-MBA traversals or mutation between runs.
                program = snapshot_from_mba(mba)
                reference = p_sccp.solve(program)
                selected = _fast_sccp.solve(program)

                if _compiled_required() and selected.backend != "cython":
                    pytest.fail(
                        "D810_REQUIRE_COMPILED_SCCP=1 but dispatcher selected "
                        f"{selected.backend!r} at {label}: "
                        f"{selected.fallback_reason or 'no fallback reason'}"
                    )
                assert selected.parity_key() == reference.parity_key(), label
                print(
                    f"[{label}] status={selected.status.value} "
                    f"backend={selected.backend} "
                    f"fingerprint={program.fingerprint}"
                )
        finally:
            if was_enabled:
                mode.enable()
            else:
                mode.disable()


def _model_program(
    *,
    ea: int = 0x401000,
    opcode: str = "mov",
    left: SccpOperand | None = None,
    right: SccpOperand | None = None,
    destination: int | None = 1,
    size: int = 4,
    successors: tuple[int, ...] = (),
) -> SccpProgram:
    if left is None:
        left = SccpOperand(OperandKind.CONSTANT, 4, constant=7)
    instruction = SccpInstruction(
        index=0,
        block_index=0,
        opcode=opcode,
        ea=ea,
        size=size,
        left=left,
        right=right,
        destination_value_id=destination,
    )
    blocks = (
        SccpBlock(index=0, successors=successors, instruction_indices=(0,)),
        SccpBlock(index=1, successors=(), instruction_indices=()),
    )
    return SccpProgram.from_parts(
        blocks,
        (instruction,),
        {1: ("r", 1), 2: ("r", 2)},
        fingerprint_seed="runtime-fingerprint-invalidation",
    )


def _rebuild_program(
    program: SccpProgram,
    *,
    blocks: tuple[SccpBlock, ...] | None = None,
    instructions: tuple[SccpInstruction, ...] | None = None,
) -> SccpProgram:
    """Recompute the immutable model fingerprint after a test mutation."""

    return SccpProgram.from_parts(
        blocks if blocks is not None else program.blocks,
        instructions if instructions is not None else program.instructions,
        program.mop_keys_by_value,
        fingerprint_seed="runtime-fingerprint-invalidation",
    )


@pytest.mark.parametrize(
    ("field", "changed"),
    (
        ("ea", lambda program: replace(program.instructions[0], ea=0x401004)),
        ("opcode", lambda program: replace(program.instructions[0], opcode="sub")),
        (
            "operand",
            lambda program: replace(
                program.instructions[0],
                left=SccpOperand(OperandKind.CONSTANT, 4, constant=8),
            ),
        ),
        (
            "destination",
            lambda program: replace(program.instructions[0], destination_value_id=2),
        ),
        ("size", lambda program: replace(program.instructions[0], size=8)),
        ("successor", lambda program: replace(program.blocks[0], successors=(1,))),
    ),
)
def test_snapshot_mutation_changes_fingerprint_and_reexecutes_facade(field, changed):
    """Every cache-relevant snapshot mutation invalidates the facade memo."""

    baseline = _model_program()
    if field == "successor":
        mutated_block = changed(baseline)
        mutated = _rebuild_program(
            baseline,
            blocks=(mutated_block, baseline.blocks[1]),
        )
    else:
        mutated_instruction = changed(baseline)
        mutated = _rebuild_program(
            baseline,
            instructions=(mutated_instruction,),
        )

    assert baseline != mutated
    assert baseline.fingerprint != mutated.fingerprint

    snapshots = iter((baseline, baseline, mutated))
    solver_fingerprints: list[str] = []

    def snapshot_fn(_mba: object) -> SccpProgram:
        return next(snapshots)

    def solve_fn(program: SccpProgram):
        solver_fingerprints.append(program.fingerprint)
        return p_sccp.solve(program)

    facade = SccpFacade(snapshot_fn=snapshot_fn, solve_fn=solve_fn)
    facade.run(object())
    facade.run(object())
    facade.run(object())

    assert solver_fingerprints == [baseline.fingerprint, mutated.fingerprint]
    assert facade.stats().executions == 2
    assert facade.stats().reuses == 1
