import sys
from types import SimpleNamespace

from d810.hexrays.preanalysis.indirect_jump_labels import (
    _add_user_cref_with_fallback,
    _add_resolved_state_write_crefs,
    plan_indirect_label_materialization,
)


def test_indirect_label_materialization_plan_uses_configured_bounds() -> None:
    plan = plan_indirect_label_materialization(
        function_ea=0x1800175C0,
        table_address=0x180019F10,
        target_eas=(0x1800178E3, 0x18001761A, 0x1800178E3),
        configured_label_start=0x180017600,
        configured_label_end=0x180017D2F,
        discovered_function_end=0x180017610,
    )

    assert plan is not None
    assert plan.label_start == 0x180017600
    assert plan.label_end == 0x180017D2F
    assert plan.target_eas == (0x18001761A, 0x1800178E3)


def test_indirect_label_materialization_plan_uses_next_function_boundary() -> None:
    plan = plan_indirect_label_materialization(
        function_ea=0x1800175C0,
        table_address=0x180019F10,
        target_eas=(0x18001761A, 0x180017CE5),
        discovered_function_end=0x180017610,
        discovered_next_function_start=0x180017D30,
    )

    assert plan is not None
    assert plan.label_start == 0x18001761A
    assert plan.label_end == 0x180017D30


def test_indirect_label_materialization_plan_rejects_unbounded_range() -> None:
    assert (
        plan_indirect_label_materialization(
            function_ea=0x1800175C0,
            table_address=0x180019F10,
            target_eas=(0x18001761A, 0x180017CE5),
            discovered_function_end=0x180017610,
        )
        is None
    )


def test_indirect_label_cref_uses_fallback_kind(monkeypatch) -> None:
    calls: list[int] = []

    def add_cref(_source: int, _target: int, flags: int) -> bool:
        calls.append(flags)
        return flags == (0x20 | 0x8000)

    fake_ida_xref = SimpleNamespace(
        fl_JN=0x10,
        fl_CF=0x20,
        fl_F=0x40,
        XREF_USER=0x8000,
        add_cref=add_cref,
    )
    monkeypatch.setitem(sys.modules, "ida_xref", fake_ida_xref)

    assert _add_user_cref_with_fallback(0x18001776D, 0x18001761A)
    assert calls == [0x10 | 0x8000, 0x20 | 0x8000]


def test_resolved_state_write_crefs_scan_raw_label_range(monkeypatch) -> None:
    data: dict[int, int] = {}
    for ea, state_value in ((0x100, 2), (0x120, 3)):
        encoded = (0xC7, 0x44, 0x24, 0x30) + tuple(
            (state_value >> shift) & 0xFF for shift in (0, 8, 16, 24)
        )
        for offset, byte in enumerate(encoded):
            data[ea + offset] = byte
    calls: list[tuple[int, int]] = []

    fake_idaapi = SimpleNamespace(BADADDR=-1)
    fake_idc = SimpleNamespace(print_insn_mnem=lambda _ea: "")
    fake_ida_bytes = SimpleNamespace(
        get_byte=lambda ea: data.get(ea, 0x90),
        get_dword=lambda ea: sum(data.get(ea + i, 0) << (i * 8) for i in range(4)),
        next_head=lambda _ea, _stop: -1,
    )

    def add_cref(source: int, target: int, _flags: int) -> bool:
        calls.append((source, target))
        return True

    fake_ida_xref = SimpleNamespace(
        fl_JN=0x10,
        fl_CF=0x20,
        fl_F=0x40,
        XREF_USER=0x8000,
        add_cref=add_cref,
    )
    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
    monkeypatch.setitem(sys.modules, "idc", fake_idc)
    monkeypatch.setitem(sys.modules, "ida_bytes", fake_ida_bytes)
    monkeypatch.setitem(sys.modules, "ida_xref", fake_ida_xref)

    count = _add_resolved_state_write_crefs(
        function_ea=0x80,
        label_end=0x140,
        targets=(0xAAA0, 0xBBB0, 0xCCC0),
        state_base=1,
        state_var_stkoff=0x30,
    )

    assert count == 2
    assert calls == [(0x100, 0xBBB0), (0x120, 0xCCC0)]
