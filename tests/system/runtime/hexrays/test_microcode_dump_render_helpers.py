"""Runtime tests for live-only microcode dump renderer helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("idaapi")

from d810.recon import microcode_dump


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


def test_stack_frame_overview_delegates_saved_register_live_formatting(monkeypatch) -> None:
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


def test_microcode_dump_has_no_direct_idaapi_operations() -> None:
    source = Path(microcode_dump.__file__).read_text(encoding="utf-8")

    assert "import idaapi" not in source
    assert "idaapi.mlist_t" not in source
    assert "idaapi.rlist_t" not in source
