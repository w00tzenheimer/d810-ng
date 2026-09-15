from __future__ import annotations

from types import SimpleNamespace

from d810.ui import export_disasm_masm_emit as emit


def test_unnamed_native_block_start_receives_stable_ea_label(monkeypatch) -> None:
    emitter = emit._FunctionMasmEmitter.__new__(emit._FunctionMasmEmitter)
    emitter._names = {}
    emitter._block_starts = frozenset({0x180001234})
    monkeypatch.setattr(
        emit,
        "ida_name",
        SimpleNamespace(GN_LOCAL=1, get_ea_name=lambda _ea, _flags: ""),
        raising=False,
    )

    assert emitter.sym_name(0x180001234) == "loc_180001234"
    assert emitter.sym_name(0x180001235) is None


def test_clean_ida_mem_preserves_long_mode_fs_and_gs_overrides() -> None:
    assert emit._clean_ida_mem("gs:60h") == "gs:60h"
    assert emit._clean_ida_mem("qword ptr fs:0[rax*8]") == "qword ptr fs:[rax*8]"


def test_clean_ida_mem_drops_flat_long_mode_segment_overrides() -> None:
    assert emit._clean_ida_mem("ds:0[rax*8]") == "[rax*8]"
    assert emit._clean_ida_mem("qword ptr ss:[rsp+20h]") == "qword ptr [rsp+20h]"
