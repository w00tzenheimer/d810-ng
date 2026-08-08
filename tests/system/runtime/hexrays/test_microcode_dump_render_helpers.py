"""Runtime tests for live-only microcode dump renderer helpers."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("idaapi")

from d810.backends.hexrays.evidence import microcode_dump


class _FakeMList:
    def __init__(self, text: str, *, empty: bool = False) -> None:
        self._text = text
        self._empty = empty

    def dstr(self) -> str:
        return self._text

    def empty(self) -> bool:
        return self._empty


def test_print_list_pair_delegates_may_only_live_formatting(monkeypatch) -> None:
    calls: list[tuple[object, object]] = []

    def fake_format_may_only(may: object, must: object) -> str:
        calls.append((may, must))
        return "may-only"

    monkeypatch.setattr(microcode_dump, "format_may_only_mlist", fake_format_may_only)
    must = _FakeMList("must-list")
    may = _FakeMList("may-list")

    assert (
        microcode_dump._print_list_pair("USE", must, may)
        == "; USE: must-list,(may-only)"
    )
    assert calls == [(may, must)]


def test_stack_frame_overview_delegates_saved_register_live_formatting(
    monkeypatch,
) -> None:
    saved_register = object()
    calls: list[tuple[object, int]] = []

    def fake_format_saved_register(sr: object, slot_size: int) -> str:
        calls.append((sr, slot_size))
        return "saved-rbx"

    monkeypatch.setattr(
        microcode_dump, "format_saved_register_slot", fake_format_saved_register
    )
    mba = SimpleNamespace(
        tmpstk_size=0x10,
        minstkref=0x20,
        stacksize=0x30,
        inargoff=0x40,
        minargref=0x50,
        fullsize=0x60,
        shadow_args=0x70,
        procinf=SimpleNamespace(sregs=[saved_register]),
        slotsize=lambda: 8,
    )
    header: list[str] = []

    microcode_dump._print_stack_frame_overview(header, mba)

    assert any(line == "; SAVEDREGS: saved-rbx" for line in header)
    assert calls == [(saved_register, 8)]


def _is_type_checking_guard(test: ast.expr) -> bool:
    """Whether an ``if`` test is ``TYPE_CHECKING`` / ``typing.TYPE_CHECKING``."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING"
    return False


def _ida_imports_outside_type_checking(source: str) -> list[str]:
    """IDA imports that actually execute, i.e. not under ``if TYPE_CHECKING``."""
    tree = ast.parse(source)

    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_type_checking_guard(node.test):
            for child in ast.walk(node):
                guarded.add(id(child))

    offenders: list[str] = []
    for node in ast.walk(tree):
        if id(node) in guarded:
            continue
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            continue
        for module in modules:
            root = module.split(".")[0]
            if root in {"idaapi", "idc", "idautils"} or root.startswith("ida_"):
                offenders.append(f"line {node.lineno}: {module}")
    return offenders


def _runtime_idaapi_name_uses(source: str) -> list[str]:
    """Places where the *name* ``idaapi`` is evaluated at runtime.

    String annotations (``mba: "idaapi.mbl_array_t"``) are ``Constant`` nodes,
    never ``Name`` nodes, so they cannot show up here -- which is the point:
    naming a Hex-Rays type for a reader is fine, touching it is not.
    """
    return [
        f"line {node.lineno}"
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Name)
        and node.id == "idaapi"
        and isinstance(node.ctx, ast.Load)
    ]


def test_microcode_dump_has_no_direct_idaapi_operations() -> None:
    """This module is idaapi-free: the half that needed it moved to
    ``d810.hexrays.diagnostics.microcode_capture``.

    Checked structurally rather than by substring. A substring check cannot
    tell a real import from one under ``if TYPE_CHECKING`` (which never
    executes), and it fires on any comment or docstring that merely mentions
    the text -- both of which produced false failures here.
    """
    source = Path(microcode_dump.__file__).read_text(encoding="utf-8")

    assert _ida_imports_outside_type_checking(source) == []
    assert _runtime_idaapi_name_uses(source) == []
