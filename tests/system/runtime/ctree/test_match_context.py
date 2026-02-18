"""Unit tests for d810.ctree.match_context.MatchContext.

Tests variable binding storage and equivalence checking without IDA.
"""
from __future__ import annotations

import pytest

from d810.ctree.match_context import MatchContext


class MockItem:
    """Minimal mock for a ctree item with an op attribute."""

    def __init__(self, op: int = 0, idx: int = 0):
        self.op = op

    def equal_effect(self, other: "MockItem") -> bool:
        return self.op == other.op


class MockPat:
    """Minimal mock for a pattern (used as MatchContext.pattern)."""
    pass


class TestMatchContext:
    def test_init(self):
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        assert ctx.binded_items == {}

    def test_get_item_returns_none_for_unbound(self):
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        assert ctx.get_item("x") is None

    def test_bind_and_get_item(self):
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        item = MockItem(op=42)
        assert ctx.bind_item("x", item) is True
        assert ctx.get_item("x") is item

    def test_has_item(self):
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        assert ctx.has_item("x") is False
        ctx.bind_item("x", MockItem(op=1))
        assert ctx.has_item("x") is True

    def test_rebind_same_item_uses_equal_effect(self):
        """When rebinding, should use equal_effect to compare."""
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        item1 = MockItem(op=10)
        item2 = MockItem(op=10)  # same op -> equal_effect returns True
        item3 = MockItem(op=99)  # different op -> equal_effect returns False

        assert ctx.bind_item("x", item1) is True
        assert ctx.bind_item("x", item2) is True  # equivalent
        assert ctx.bind_item("x", item3) is False  # not equivalent

    def test_multiple_bindings(self):
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        a = MockItem(op=1)
        b = MockItem(op=2)
        ctx.bind_item("a", a)
        ctx.bind_item("b", b)
        assert ctx.get_item("a") is a
        assert ctx.get_item("b") is b


# -------------------------------------------------------------------------
# cot_var rebinding tests (Issue D8)
#
# Without IDA, the cot_var branch (idaapi.cot_var) is not taken because
# idaapi is None. These tests verify the fallback behavior: when IDA
# is not available, rebinding uses equal_effect exclusively.
#
# When IDA IS available, rebinding cot_var checks v.idx rather than
# equal_effect. We mock this path by temporarily setting idaapi.
# -------------------------------------------------------------------------

class MockVarRef:
    """Mock for the v attribute on cot_var items, holding an idx."""

    def __init__(self, idx: int):
        self.idx = idx


class MockCotVarItem:
    """Mock for a cot_var item with v.idx for variable comparison."""

    COT_VAR_OP = 77  # arbitrary op code for our mock cot_var

    def __init__(self, idx: int):
        self.op = self.COT_VAR_OP
        self.v = MockVarRef(idx)

    def equal_effect(self, other):
        return self.op == other.op


class TestMatchContextCotVar:
    def test_rebind_cot_var_uses_vidx_when_ida_available(self):
        """When idaapi is present, rebinding cot_var should compare v.idx."""
        import d810.ctree.match_context as mc_mod

        # Save original
        orig_idaapi = mc_mod.idaapi

        # Create a minimal mock idaapi module with cot_var
        class FakeIdaApi:
            cot_var = MockCotVarItem.COT_VAR_OP

        try:
            mc_mod.idaapi = FakeIdaApi()

            ctx = MatchContext(ast_ctx=None, pattern=MockPat())
            item1 = MockCotVarItem(idx=3)
            item2 = MockCotVarItem(idx=3)  # same idx
            item3 = MockCotVarItem(idx=7)  # different idx

            assert ctx.bind_item("v", item1) is True
            assert ctx.bind_item("v", item2) is True   # same v.idx
            assert ctx.bind_item("v", item3) is False   # different v.idx
        finally:
            mc_mod.idaapi = orig_idaapi

    def test_rebind_cot_var_rejects_non_var_when_bound_is_var(self):
        """When bound item is cot_var and new item is not, should return False."""
        import d810.ctree.match_context as mc_mod

        orig_idaapi = mc_mod.idaapi

        class FakeIdaApi:
            cot_var = MockCotVarItem.COT_VAR_OP

        try:
            mc_mod.idaapi = FakeIdaApi()

            ctx = MatchContext(ast_ctx=None, pattern=MockPat())
            var_item = MockCotVarItem(idx=3)
            non_var_item = MockItem(op=999)

            assert ctx.bind_item("v", var_item) is True
            assert ctx.bind_item("v", non_var_item) is False
        finally:
            mc_mod.idaapi = orig_idaapi

    def test_rebind_without_ida_uses_equal_effect(self):
        """Without IDA, rebinding always uses equal_effect regardless of op."""
        ctx = MatchContext(ast_ctx=None, pattern=MockPat())
        item1 = MockCotVarItem(idx=3)
        item2 = MockCotVarItem(idx=7)  # different idx but same op

        assert ctx.bind_item("v", item1) is True
        # Without IDA, equal_effect is used: same op -> True
        assert ctx.bind_item("v", item2) is True
