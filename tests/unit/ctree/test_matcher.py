"""Unit tests for d810.ctree.matcher and d810.ctree.scheme (no IDA needed).

Tests Matcher walking AST and collecting matches, Scheme pairing
pattern with handler, exception handling in scheme handlers, and
lifecycle hooks (on_tree_iteration_start/end).
"""
from __future__ import annotations

import pytest

from d810.ctree.match_context import MatchContext
from d810.ctree.ast_patch import ASTPatch
from d810.ctree.matcher import Matcher
from d810.ctree.scheme import Scheme
from d810.ctree.patterns.base_pattern import BasePat
from d810.ctree.patterns.abstracts import AnyPat


# ---------------------------------------------------------------------------
# Register mock ops for iteration (same technique as test_ast_processor.py)
# ---------------------------------------------------------------------------
_MOCK_LEAF_OP = 9990
_MOCK_BLOCK_OP = 9993


class MockNode:
    """Mock AST node."""

    def __init__(self, name: str, op: int, children: list["MockNode"] | None = None):
        self.name = name
        self.op = op
        self._children = children or []
        self.opname = name
        self.ea = 0x1000
        self.label_num = -1

    def is_expr(self) -> bool:
        return False

    def equal_effect(self, other):
        return self.op == other.op

    def __repr__(self):
        return f"MockNode({self.name})"


def _register_mock_ops():
    from d810.ctree import ast_iteration
    if _MOCK_BLOCK_OP not in ast_iteration.op2func:
        ast_iteration.op2func[_MOCK_BLOCK_OP] = lambda x: tuple(x._children)


_register_mock_ops()


def _make_leaf(name: str) -> MockNode:
    return MockNode(name, _MOCK_LEAF_OP)


def _make_block(name: str, *children: MockNode) -> MockNode:
    return MockNode(name, _MOCK_BLOCK_OP, list(children))


# ---------------------------------------------------------------------------
# Mock ASTContext for Matcher (lightweight, no cfunc)
# ---------------------------------------------------------------------------

class MockASTContext:
    """Lightweight mock for ASTContext. The Matcher needs it for check_schemes."""

    def __init__(self):
        self.label2gotos: dict = {}
        self.label2instr: dict = {}
        self.is_modified: bool = False
        self.cfunc = None

    def rebuild(self):
        pass


# ---------------------------------------------------------------------------
# Concrete pattern that matches specific nodes
# ---------------------------------------------------------------------------

class NamePat(BasePat):
    """Pattern that matches MockNodes by name."""

    def __init__(self, target_name: str, **kwargs):
        super().__init__(**kwargs)
        self.target_name = target_name

    @BasePat.base_check
    def check(self, item, ctx):
        return getattr(item, "name", None) == self.target_name

    @property
    def children(self):
        return ()


# ---------------------------------------------------------------------------
# Test Scheme
# ---------------------------------------------------------------------------

class TestScheme:
    def test_default_handler_returns_none(self):
        """Default on_matched_item returns None (no patch)."""
        pat = AnyPat()
        scheme = Scheme(pat)
        item = MockNode("test", _MOCK_LEAF_OP)
        ctx = MatchContext(ast_ctx=None, pattern=pat)
        result = scheme.on_matched_item(item, ctx)
        assert result is None

    def test_scheme_types(self):
        scheme = Scheme(AnyPat(), scheme_type=Scheme.SchemeType.GENERIC)
        assert scheme.stype == Scheme.SchemeType.GENERIC

        scheme2 = Scheme(AnyPat(), scheme_type=Scheme.SchemeType.READONLY)
        assert scheme2.stype == Scheme.SchemeType.READONLY

        scheme3 = Scheme(AnyPat(), scheme_type=Scheme.SchemeType.SINGULAR)
        assert scheme3.stype == Scheme.SchemeType.SINGULAR

    def test_scheme_stores_patterns(self):
        p1 = AnyPat()
        p2 = AnyPat()
        scheme = Scheme(p1, p2)
        assert scheme.patterns == (p1, p2)

    def test_lifecycle_hooks_are_no_ops(self):
        """Default lifecycle hooks should not raise."""
        scheme = Scheme()
        scheme.on_tree_iteration_start()
        scheme.on_tree_iteration_end()


# ---------------------------------------------------------------------------
# Custom scheme subclass for testing
# ---------------------------------------------------------------------------

class CollectorScheme(Scheme):
    """Records matched items for testing."""

    def __init__(self, *patterns: BasePat, **kwargs):
        super().__init__(*patterns, **kwargs)
        self.matched_items: list = []
        self.start_count = 0
        self.end_count = 0

    def on_matched_item(self, item, ctx):
        self.matched_items.append(item)
        return None  # no patch

    def on_tree_iteration_start(self):
        self.start_count += 1

    def on_tree_iteration_end(self):
        self.end_count += 1


class ErrorScheme(Scheme):
    """Scheme whose handler raises an exception."""

    def __init__(self, *patterns: BasePat, **kwargs):
        super().__init__(*patterns, **kwargs)

    def on_matched_item(self, item, ctx):
        raise RuntimeError("handler error")


# ---------------------------------------------------------------------------
# Test Matcher
# ---------------------------------------------------------------------------

class TestMatcher:
    def test_matcher_stores_schemes(self):
        s1 = Scheme(AnyPat())
        s2 = Scheme(AnyPat())
        matcher = Matcher(s1, s2)
        assert len(matcher.schemes) == 2
        assert matcher.get_scheme("scheme0") is s1
        assert matcher.get_scheme("scheme1") is s2

    def test_add_and_remove_scheme(self):
        matcher = Matcher()
        s = Scheme(AnyPat())
        matcher.add_scheme("test", s)
        assert matcher.get_scheme("test") is s
        matcher.remove_scheme("test")
        assert matcher.get_scheme("test") is None

    def test_remove_nonexistent_scheme(self):
        matcher = Matcher()
        # Should not raise
        matcher.remove_scheme("nonexistent")

    def test_get_scheme_returns_none_for_missing(self):
        matcher = Matcher()
        assert matcher.get_scheme("no_such") is None

    def test_check_schemes_returns_none_when_no_match(self):
        """When no scheme patterns match, check_schemes returns None."""
        pat = NamePat("doesnotexist")
        scheme = CollectorScheme(pat)
        matcher = Matcher(scheme)
        item = MockNode("something", _MOCK_LEAF_OP)
        ctx = MockASTContext()
        result = matcher.check_schemes(item, ctx, [scheme])
        assert result is None

    def test_check_scheme_with_matching_pattern(self):
        """When pattern matches but handler returns None, check_scheme returns None."""
        pat = AnyPat()
        scheme = CollectorScheme(pat)
        matcher = Matcher(scheme)
        item = MockNode("test", _MOCK_LEAF_OP)
        ctx = MockASTContext()
        # CollectorScheme.on_matched_item returns None
        result = matcher.check_scheme(scheme, item, ctx)
        assert result is None
        assert len(scheme.matched_items) == 1
        assert scheme.matched_items[0] is item

    def test_exception_handling_in_scheme_handler(self):
        """Exceptions in scheme handlers should be caught, returning None."""
        pat = AnyPat()
        scheme = ErrorScheme(pat)
        matcher = Matcher(scheme)
        item = MockNode("test", _MOCK_LEAF_OP)
        ctx = MockASTContext()
        # Should not raise, should return None
        result = matcher.check_scheme(scheme, item, ctx)
        assert result is None

    def test_match_ast_tree_calls_lifecycle_hooks(self):
        """match_ast_tree should call on_tree_iteration_start and _end."""
        pat = AnyPat()
        scheme = CollectorScheme(pat)
        matcher = Matcher(scheme)
        tree = _make_leaf("root")
        ctx = MockASTContext()
        matcher.match_ast_tree(tree, ctx, [scheme])
        assert scheme.start_count == 1
        assert scheme.end_count == 1

    def test_match_ast_tree_visits_all_nodes(self):
        """Matcher should visit all nodes in the tree."""
        pat = AnyPat()
        scheme = CollectorScheme(pat)
        matcher = Matcher(scheme)
        a = _make_leaf("A")
        b = _make_leaf("B")
        root = _make_block("Root", a, b)
        ctx = MockASTContext()
        matcher.match_ast_tree(root, ctx, [scheme])
        # Should have matched A, B, Root
        names = [item.name for item in scheme.matched_items]
        assert "A" in names
        assert "B" in names
        assert "Root" in names

    def test_check_scheme_invalid_return_type_raises(self):
        """If handler returns non-ASTPatch/non-None, should raise TypeError."""

        class BadReturnScheme(Scheme):
            def on_matched_item(self, item, ctx):
                return "not_a_patch"

        pat = AnyPat()
        scheme = BadReturnScheme(pat)
        matcher = Matcher(scheme)
        item = MockNode("test", _MOCK_LEAF_OP)
        ctx = MockASTContext()
        # The check_scheme wrapper catches exceptions, so we call _check_scheme directly
        with pytest.raises(TypeError, match="should be ASTPatch"):
            matcher._check_scheme(scheme, item, ctx)

    def test_check_scheme_catches_bad_return_type(self):
        """The public check_scheme catches TypeError from bad return type."""

        class BadReturnScheme(Scheme):
            def on_matched_item(self, item, ctx):
                return "not_a_patch"

        pat = AnyPat()
        scheme = BadReturnScheme(pat)
        matcher = Matcher(scheme)
        item = MockNode("test", _MOCK_LEAF_OP)
        ctx = MockASTContext()
        result = matcher.check_scheme(scheme, item, ctx)
        assert result is None
