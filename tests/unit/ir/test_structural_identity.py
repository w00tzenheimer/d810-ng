"""Explicit structural adapter closure, independent of canonical serialization."""

from dataclasses import fields

import pytest

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.core.structural_identity import compare_values
from d810.ir.structural_identity import (
    capture_native_key,
    capture_graph_record,
    NATIVE_KEY_FIELDS,
)
from d810.ir.graph_fingerprint import GraphRecord, BlockRecord, InsnRecord
from d810.ir.flowgraph import BlockKind, InsnKind


def table():
    return RuntimeAuthorityArena(RuntimeAuthorityScope("capture")).structural


def key():
    return NativePreanalysisKey("input", "metapc", 64, 16, "function", "profile", "sdk")


def test_native_key_schema_all_seven_components_and_no_json(monkeypatch):
    assert tuple(f.name for f in fields(NativePreanalysisKey)) == NATIVE_KEY_FIELDS
    monkeypatch.setattr(
        NativePreanalysisKey, "to_json", lambda self: pytest.fail("codec")
    )
    a, b = table(), table()
    assert compare_values(
        a, capture_native_key(a, key()), b, capture_native_key(b, key())
    )
    for name in NATIVE_KEY_FIELDS:
        values = {f: getattr(key(), f) for f in NATIVE_KEY_FIELDS}
        values[name] = (
            32 if name == "bitness" else 17 if name == "function_rva" else "different"
        )
        changed = NativePreanalysisKey(**values)
        assert not compare_values(
            a, capture_native_key(a, key()), b, capture_native_key(b, changed)
        )


def graph(attrs):
    insn = InsnRecord(
        1,
        1,
        InsnKind.UNKNOWN,
        16,
        16,
        None,
        None,
        None,
        None,
        None,
        None,
        False,
        False,
        False,
        None,
        None,
        None,
        attrs,
        "text",
    )
    block = BlockRecord(
        0, 0, 0, BlockKind.ZERO_WAY, 0, 16, 16, (), (), None, None, None, (insn,)
    )
    return GraphRecord(16, 0, (block,))


def test_graph_capture_detaches_nested_alias_and_fresh_capture_sees_mutation():
    aliases = [1, {"value": 2}]
    value = graph({"custom": aliases})
    left, right = table(), table()
    before = capture_graph_record(left, value)
    expected = capture_graph_record(right, graph({"custom": [1, {"value": 2}]}))
    aliases[1]["value"] = 3
    assert compare_values(left, before, right, expected)
    assert not compare_values(left, before, right, capture_graph_record(right, value))


def test_graph_capture_rejects_cycles_and_unsupported_descendants():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cycle"):
        capture_graph_record(table(), graph({"bad": cycle}))
    with pytest.raises(TypeError):
        capture_graph_record(table(), graph({"bad": object()}))
