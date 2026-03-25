from __future__ import annotations

import pytest

pytest.importorskip("unicorn")
pytest.importorskip("triton")

from d810.backends.emulation.common import Architecture, BoundaryKind
from d810.backends.emulation.oracle import EmulationOracle
from d810.backends.emulation.triton import TritonEmulator


def test_oracle_classify_boundary_uses_unicorn_for_transient_corridor() -> None:
    oracle = EmulationOracle.create("x86_64")
    assert oracle.has_unicorn

    # mov dword ptr [rsp-4], 0x12345678 ; ret
    code = bytes.fromhex("C74424FC78563412C3")
    result = oracle.classify_boundary(
        code,
        state_var_offset=-4,
        initial_stack_values={-4: 0},
        max_instructions=8,
    )

    assert result == BoundaryKind.TRANSIENT_CORRIDOR


def test_oracle_classify_boundary_detects_unsafe_side_effect() -> None:
    oracle = EmulationOracle.create("x86_64")
    assert oracle.has_unicorn

    # mov dword ptr [rsp-4], 0x12345678 ; mov dword ptr [rsp-8], 0x87654321 ; ret
    code = bytes.fromhex("C74424FC78563412C74424F821436587C3")
    result = oracle.classify_boundary(
        code,
        state_var_offset=-4,
        initial_stack_values={-4: 0, -8: 0},
        watched_stack_offsets=(-8,),
        max_instructions=8,
    )

    assert result == BoundaryKind.UNSAFE_SIDE_EFFECT


def test_triton_backend_supports_string_arch_and_basic_queries() -> None:
    emu = TritonEmulator("x86_64")
    assert emu.available

    assert emu.arch == Architecture.X86_64
    assert emu._triton is not None

    ast = emu._triton.getAstContext()
    cond = ast.equal(ast.bv(1, 8), ast.bv(1, 8))
    proved, model = emu.prove_branch(cond)

    assert proved is True
    assert model == {}
    assert emu.enumerate_values(ast.bv(7, 8), max_values=4) == [7]
