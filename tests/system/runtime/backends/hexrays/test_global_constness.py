from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace

import pytest

from d810.analyses.value_flow.global_constness import (
    GlobalConstPolicy,
    GlobalConstReason,
    GlobalItemKind,
)


class _XrefBlock:
    def __init__(self, writes: set[int]) -> None:
        self._writes = writes
        self.type = 0

    def first_to(self, ea: int, _flags: int) -> bool:
        if ea not in self._writes:
            return False
        self.type = 7
        return True

    def next_to(self) -> bool:
        return False


def _load_adapter(
    monkeypatch: pytest.MonkeyPatch,
    *,
    item_kind: str,
    permissions: int,
    item_head: int = 0x1000,
    item_size: int = 8,
    value: int = 0xAABBCCDD,
    writes: set[int] | None = None,
):
    writes = set() if writes is None else set(writes)
    kind_flag = {"data": 1, "code": 2, "unknown": 0}[item_kind]
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        SimpleNamespace(
            get_item_head=lambda _ea: item_head,
            get_item_size=lambda _ea: item_size,
            get_full_flags=lambda _ea: kind_flag,
            is_data=lambda flags: flags == 1,
            is_code=lambda flags: flags == 2,
            is_tail=lambda _flags: False,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_segment",
        SimpleNamespace(
            SEGPERM_READ=1,
            SEGPERM_WRITE=2,
            SEGPERM_EXEC=4,
            getseg=lambda _ea: SimpleNamespace(perm=permissions),
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_xref",
        SimpleNamespace(
            XREF_ALL=0,
            dr_W=7,
            xrefblk_t=lambda: _XrefBlock(writes),
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "idaapi",
        SimpleNamespace(
            BADADDR=(1 << 64) - 1,
            get_byte=lambda _ea: value & 0xFF,
            get_word=lambda _ea: value & 0xFFFF,
            get_dword=lambda _ea: value & 0xFFFFFFFF,
            get_qword=lambda _ea: value,
        ),
    )
    module_name = "d810.backends.hexrays.evidence.global_constness"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    return importlib.import_module(module_name)


def test_adapter_accepts_rx_data_without_platform_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _load_adapter(
        monkeypatch,
        item_kind="data",
        permissions=1 | 4,
    )

    evidence = adapter.capture_hexrays_global_const_evidence(0x1004, 4)
    decision = adapter.decide_hexrays_global_read(
        0x1004,
        4,
        policy=GlobalConstPolicy.STRICT,
    )

    assert evidence.item_head == 0x1000
    assert evidence.item_end == 0x1008
    assert evidence.item_kind is GlobalItemKind.DATA
    assert evidence.executable is True
    assert decision.can_inline_read is True
    assert decision.can_persist_const is True
    assert decision.value == 0xAABBCCDD


def test_adapter_requires_dangerous_override_for_rx_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _load_adapter(
        monkeypatch,
        item_kind="code",
        permissions=1 | 4,
    )

    strict = adapter.decide_hexrays_global_read(
        0x1000,
        4,
        policy=GlobalConstPolicy.STRICT,
    )
    forced = adapter.decide_hexrays_global_read(
        0x1000,
        4,
        policy=GlobalConstPolicy.STRICT,
        allow_executable_readonly=True,
    )

    assert strict.reason is GlobalConstReason.EXECUTABLE_ITEM_REJECTED
    assert forced.reason is GlobalConstReason.DANGEROUS_EXECUTABLE_READONLY_OVERRIDE
    assert forced.can_inline_read is True
    assert forced.can_persist_const is False


def test_adapter_detects_direct_write_to_any_byte_in_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _load_adapter(
        monkeypatch,
        item_kind="data",
        permissions=1 | 2,
        writes={0x1006},
    )

    evidence = adapter.capture_hexrays_global_const_evidence(0x1000, 4)
    decision = adapter.decide_hexrays_global_read(
        0x1000,
        4,
        policy=GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES,
    )

    assert evidence.has_direct_write is True
    assert decision.can_inline_read is False
    assert decision.reason is GlobalConstReason.DIRECT_WRITE_WITHOUT_STABLE_READ
