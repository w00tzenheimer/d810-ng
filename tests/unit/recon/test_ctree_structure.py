"""Tests for CtreeStructureCollector.

Uses a stub cfunc-like object — no real IDA dependency for the logic layer.
The collector only walks the cfunc using duck-typed access.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import pytest
from d810.recon.collectors.ctree_structure import CtreeStructureCollector


# ---------------------------------------------------------------------------
# Minimal stub cfunc tree  (no IDA imports needed)
# ---------------------------------------------------------------------------

@dataclass
class StubCItem:
    """Stub citem_t-like node."""
    op: int                          # e.g. cot_asg=51, cif=1, cswitch=14, cgoto=17
    children: list["StubCItem"] = field(default_factory=list)

    def __iter__(self):
        return iter(self.children)


# cinsn_t op constants (IDA values — duplicated here for test clarity)
_CIT_IF = 1
_CIT_SWITCH = 14
_CIT_GOTO = 17
_CIT_BLOCK = 20
_COT_CALL = 50


def _make_flat_stub() -> StubCItem:
    """Stub of a flattened function's ctree:
    outer block -> switch(10 arms) -> each arm has 1 statement
    """
    arms = [StubCItem(op=_CIT_BLOCK) for _ in range(10)]
    switch = StubCItem(op=_CIT_SWITCH, children=arms)
    return StubCItem(op=_CIT_BLOCK, children=[switch])


def _make_nested_if_stub() -> StubCItem:
    """Stub with 3-deep if nesting."""
    inner = StubCItem(op=_CIT_IF, children=[])
    mid = StubCItem(op=_CIT_IF, children=[inner])
    outer = StubCItem(op=_CIT_IF, children=[mid])
    return StubCItem(op=_CIT_BLOCK, children=[outer])


def _make_goto_stub() -> StubCItem:
    """Two goto statements in a flat block."""
    return StubCItem(op=_CIT_BLOCK, children=[
        StubCItem(op=_CIT_GOTO),
        StubCItem(op=_CIT_GOTO),
        StubCItem(op=_CIT_BLOCK),
    ])


class StubCfunc:
    def __init__(self, body: StubCItem):
        self.body = body


class TestCtreeStructureCollector:
    def test_name_and_level(self):
        c = CtreeStructureCollector()
        assert c.name == "CtreeStructureCollector"
        assert c.level == "ctree"

    def test_maturities_include_cmat_final(self):
        c = CtreeStructureCollector()
        # CMAT_FINAL = 60 in IDA SDK
        assert 60 in c.maturities

    def test_flat_switch_detected(self):
        cfunc = StubCfunc(_make_flat_stub())
        result = CtreeStructureCollector().collect(cfunc, func_ea=0x401000, maturity=60)
        assert result.metrics["switch_count"] == 1
        assert result.metrics["switch_max_arms"] == 10

    def test_nested_if_depth(self):
        cfunc = StubCfunc(_make_nested_if_stub())
        result = CtreeStructureCollector().collect(cfunc, func_ea=0x401000, maturity=60)
        assert result.metrics["if_count"] == 3
        assert result.metrics["max_nesting_depth"] >= 3

    def test_goto_density(self):
        cfunc = StubCfunc(_make_goto_stub())
        result = CtreeStructureCollector().collect(cfunc, func_ea=0x401000, maturity=60)
        assert result.metrics["goto_count"] == 2

    def test_flat_switch_flags_candidate(self):
        cfunc = StubCfunc(_make_flat_stub())
        result = CtreeStructureCollector().collect(cfunc, func_ea=0x401000, maturity=60)
        # Switch with >= 5 arms should be flagged
        assert len(result.candidates) >= 1
        kinds = {c.kind for c in result.candidates}
        assert "large_switch" in kinds

    def test_empty_body_no_crash(self):
        cfunc = StubCfunc(StubCItem(op=_CIT_BLOCK))
        result = CtreeStructureCollector().collect(cfunc, func_ea=0x401000, maturity=60)
        assert result.metrics["switch_count"] == 0
        assert result.metrics["goto_count"] == 0
