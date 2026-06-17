from __future__ import annotations

from types import SimpleNamespace

from d810.backends.hexrays import condition_chain_runtime


def test_condition_chain_runtime_falls_back_when_idaapi_is_unavailable(monkeypatch) -> None:
    def missing_idaapi():
        raise ImportError("idaapi unavailable")

    monkeypatch.setattr(condition_chain_runtime, "_idaapi", missing_idaapi)

    assert condition_chain_runtime.build_opcode_map() == {}
    assert condition_chain_runtime.build_mop_type_map() == {}
    assert condition_chain_runtime.opcode_value("m_add", 28) == 28
    assert condition_chain_runtime.mop_type_value("mop_S", 5) == 5
    assert condition_chain_runtime.fetch_idb_value(0x1000, 4) is None
    assert condition_chain_runtime.segment_is_read_only(0x1000) is False
    assert condition_chain_runtime.is_never_written_var(0x1000) is False


def test_condition_chain_runtime_builds_maps_from_idaapi(monkeypatch) -> None:
    fake_idaapi = SimpleNamespace(
        m_add=28,
        m_sub=29,
        mop_S=5,
        mop_n=2,
        unrelated=99,
    )
    monkeypatch.setattr(condition_chain_runtime, "_idaapi", lambda: fake_idaapi)

    assert condition_chain_runtime.build_opcode_map() == {28: "m_add", 29: "m_sub"}
    assert condition_chain_runtime.build_mop_type_map() == {5: "mop_S", 2: "mop_n"}
    assert condition_chain_runtime.opcode_value("m_add") == 28
    assert condition_chain_runtime.mop_type_value("mop_S") == 5
