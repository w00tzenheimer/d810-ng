from __future__ import annotations

from dataclasses import dataclass
import sys
import types
from pathlib import Path

import pytest

# The legacy package initializer imports live IDA modules.  These tests install
# a test-only namespace so the facade and immutable model can run without IDA.
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
    SccpProgram,
    SccpResult,
    SccpStatus,
)
from d810.evaluator.hexrays_microcode.sccp import SccpFacade  # noqa: E402
from d810.evaluator.hexrays_microcode.sccp_snapshot import (  # noqa: E402
    SccpSnapshotError,
    snapshot_from_mba,
)


def make_program(seed: object) -> SccpProgram:
    return SccpProgram.from_parts(
        (SccpBlock(0, (), ()),),
        (),
        {},
        fingerprint_seed=seed,
    )


def converged(program: SccpProgram) -> SccpResult:
    return SccpResult(
        status=SccpStatus.CONVERGED,
        constants={("s", 1): 7},
        executable_edges=frozenset(),
        reachable_blocks=frozenset({0}),
        program_fingerprint=program.fingerprint,
        backend="python",
        cfg_events=1,
        value_events=1,
        peak_cfg_queue=1,
        peak_value_queue=1,
        adapter_seconds=0.0,
        solver_seconds=0.0,
    )


def test_identical_snapshot_reuses_once() -> None:
    mba = object()
    calls: list[str] = []
    facade = SccpFacade(
        snapshot_fn=lambda _mba: make_program(0x1000),
        solve_fn=lambda program: calls.append(program.fingerprint) or converged(program),
    )

    assert facade.run(mba).constants[("s", 1)] == 7
    assert facade.run(mba).constants[("s", 1)] == 7
    assert len(calls) == 1
    assert facade.stats().requests == 2
    assert facade.stats().executions == 1
    assert facade.stats().reuses == 1
    assert facade.stats().adapter_seconds == 0.0
    assert facade.stats().solver_seconds == 0.0


def test_nonconverged_projection_is_empty() -> None:
    result = SccpResult.empty(status=SccpStatus.WORK_LIMIT)
    facade = SccpFacade(
        snapshot_fn=lambda _mba: make_program(0x2000),
        solve_fn=lambda _program: result,
    )

    assert facade._project_constants(result) == {}
    assert not result.is_edge_dead(0, 1)


@dataclass
class _FakeNumber:
    value: int


@dataclass
class _FakeStack:
    off: int


@dataclass
class _FakeMop:
    t: int
    size: int = 4
    nnn: _FakeNumber | None = None
    r: int | None = None
    s: _FakeStack | None = None
    d: object | None = None
    next: object | None = None


@dataclass
class _FakeInsn:
    opcode: int
    ea: int
    l: _FakeMop | None = None  # noqa: E741
    r: _FakeMop | None = None
    d: _FakeMop | None = None
    next: object | None = None


@dataclass
class _FakeBlock:
    succset: tuple[int, ...]
    head: _FakeInsn | None


class _FakeMba:
    qty = 2

    def __init__(self, blocks: tuple[_FakeBlock, ...]) -> None:
        self._blocks = blocks

    def get_mblock(self, index: int) -> _FakeBlock:
        return self._blocks[index]


def _install_fake_ida(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    ida_hexrays = types.ModuleType("ida_hexrays")
    ida_hexrays.mop_z = 0
    ida_hexrays.mop_r = 1
    ida_hexrays.mop_n = 2
    ida_hexrays.mop_d = 4
    ida_hexrays.mop_S = 5
    ida_hexrays.mop_v = 6
    ida_hexrays.mop_f = 8
    ida_hexrays.m_mov = 10
    ida_hexrays.m_add = 11
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    p_ast = types.ModuleType("d810.hexrays.expr.p_ast")

    def fake_get_mop_key(mop: _FakeMop) -> tuple[int, int, int]:
        if mop.t == ida_hexrays.mop_r:
            assert mop.r is not None
            return (mop.t, mop.size, mop.r)
        if mop.t == ida_hexrays.mop_S:
            assert mop.s is not None
            return (mop.t, mop.size, mop.s.off)
        raise AssertionError(f"unexpected key request for mop type {mop.t}")

    p_ast.get_mop_key = fake_get_mop_key  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "d810.hexrays", types.ModuleType("d810.hexrays"))
    monkeypatch.setitem(sys.modules, "d810.hexrays.expr", types.ModuleType("d810.hexrays.expr"))
    monkeypatch.setitem(sys.modules, "d810.hexrays.expr.p_ast", p_ast)
    return ida_hexrays


def test_snapshot_maps_constants_and_values_without_live_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ida_hexrays = _install_fake_ida(monkeypatch)
    register = _FakeMop(ida_hexrays.mop_r, r=1)
    stack = _FakeMop(ida_hexrays.mop_S, s=_FakeStack(8))
    first = _FakeInsn(
        ida_hexrays.m_mov,
        0x1000,
        l=_FakeMop(ida_hexrays.mop_n, nnn=_FakeNumber(7)),
        d=register,
    )
    second = _FakeInsn(
        ida_hexrays.m_add,
        0x1004,
        l=_FakeMop(ida_hexrays.mop_r, r=1),
        r=stack,
        d=_FakeMop(ida_hexrays.mop_S, s=_FakeStack(16)),
    )
    first.next = second
    mba = _FakeMba((_FakeBlock((1,), first), _FakeBlock((), None)))

    program = snapshot_from_mba(mba)

    assert program.blocks[0].successors == (1,)
    assert program.instructions[0].left is not None
    assert program.instructions[0].left.kind is OperandKind.CONSTANT
    assert program.instructions[0].left.constant == 7
    assert program.instructions[1].left is not None
    assert program.instructions[1].left.kind is OperandKind.VALUE
    assert program.instructions[1].right is not None
    assert program.instructions[1].right.kind is OperandKind.VALUE
    assert program.instructions[1].left.value_id != program.instructions[1].right.value_id
    assert all(not hasattr(value, "t") for value in program.mop_keys_by_value.values())


def test_snapshot_rejects_invalid_successor(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_ida(monkeypatch)
    mba = _FakeMba((_FakeBlock((99,), None), _FakeBlock((), None)))

    with pytest.raises(SccpSnapshotError, match="successor"):
        snapshot_from_mba(mba)


def test_snapshot_failure_is_error_and_proof_empty() -> None:
    def fail(_mba: object) -> SccpProgram:
        raise SccpSnapshotError("missing block")

    facade = SccpFacade(snapshot_fn=fail)

    result = facade.run(object())

    assert result.status is SccpStatus.ERROR
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()
    assert not result.is_edge_dead(0, 1)
    assert facade.stats().requests == 1
    assert facade.stats().executions == 0
    assert facade.stats().errors == 1


def test_snapshot_programming_error_is_not_hidden_as_ida_unavailable() -> None:
    def fail(_mba: object) -> SccpProgram:
        raise RuntimeError("adapter bug")

    facade = SccpFacade(snapshot_fn=fail)

    with pytest.raises(RuntimeError, match="adapter bug"):
        facade.run(object())
