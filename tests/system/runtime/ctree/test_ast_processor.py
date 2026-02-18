"""Unit tests for d810.ctree.ast_processor (no IDA needed).

Tests ASTProcessor tree walking, restart-on-modification, path tracking,
and build_path using mock AST nodes.
"""
from __future__ import annotations

import pytest

from d810.ctree.ast_processor import ASTProcessor, build_path, RelativePosition
from d810.ctree.ast_iteration import get_children


# ---------------------------------------------------------------------------
# Mock AST node that mimics ctree items for iteration.
#
# We need to register our mock ops in the op2func mapping so that
# get_children() works on our mocks.
# ---------------------------------------------------------------------------

# We use op values in a range that won't conflict with real IDA ops.
_MOCK_LEAF_OP = 9990
_MOCK_UNARY_OP = 9991
_MOCK_BINARY_OP = 9992
_MOCK_BLOCK_OP = 9993


class MockNode:
    """Mock AST node with configurable children."""

    def __init__(self, name: str, op: int, children: list["MockNode"] | None = None):
        self.name = name
        self.op = op
        self._children = children or []
        self.opname = name
        self.ea = 0x1000
        self.label_num = -1

    def __repr__(self):
        return f"MockNode({self.name})"


def _register_mock_ops():
    """Register our mock ops in ast_iteration.op2func."""
    from d810.ctree import ast_iteration
    ast_iteration.op2func[_MOCK_UNARY_OP] = lambda x: tuple(x._children)
    ast_iteration.op2func[_MOCK_BINARY_OP] = lambda x: tuple(x._children)
    ast_iteration.op2func[_MOCK_BLOCK_OP] = lambda x: tuple(x._children)


_register_mock_ops()


def _make_leaf(name: str) -> MockNode:
    return MockNode(name, _MOCK_LEAF_OP)


def _make_unary(name: str, child: MockNode) -> MockNode:
    return MockNode(name, _MOCK_UNARY_OP, [child])


def _make_binary(name: str, left: MockNode, right: MockNode) -> MockNode:
    return MockNode(name, _MOCK_BINARY_OP, [left, right])


def _make_block(name: str, *children: MockNode) -> MockNode:
    return MockNode(name, _MOCK_BLOCK_OP, list(children))


# ---------------------------------------------------------------------------
# build_path tests
# ---------------------------------------------------------------------------

class TestBuildPath:
    def test_single_leaf(self):
        leaf = _make_leaf("A")
        path = build_path(leaf)
        assert len(path) == 1
        assert path[0] == (leaf, -1)

    def test_linear_chain(self):
        """A -> B -> C: path should be [(A, 0), (B, 0), (C, -1)]."""
        c = _make_leaf("C")
        b = _make_unary("B", c)
        a = _make_unary("A", b)
        path = build_path(a)
        assert len(path) == 3
        assert path[0] == (a, 0)
        assert path[1] == (b, 0)
        assert path[2] == (c, -1)

    def test_binary_takes_leftmost(self):
        """Binary A(B, C): path should descend to leftmost child B."""
        b = _make_leaf("B")
        c = _make_leaf("C")
        a = _make_binary("A", b, c)
        path = build_path(a)
        assert len(path) == 2
        assert path[0] == (a, 0)
        assert path[1] == (b, -1)


# ---------------------------------------------------------------------------
# ASTProcessor iteration order tests
# ---------------------------------------------------------------------------

class TestASTProcessorIteration:
    def test_single_leaf_iteration(self):
        """Iterating a single leaf should yield that leaf then end."""
        leaf = _make_leaf("A")
        proc = ASTProcessor(leaf)
        assert proc.get_current() is leaf
        result = proc.pop_current()
        assert result is leaf
        assert proc.is_iteration_ended()

    def test_linear_chain_order(self):
        """A -> B -> C: iteration should yield C, B, A (children first)."""
        c = _make_leaf("C")
        b = _make_unary("B", c)
        a = _make_unary("A", b)

        proc = ASTProcessor(a)
        items = []
        while (item := proc.get_current()) is not None:
            items.append(item.name)
            proc.pop_current()

        assert items == ["C", "B", "A"]

    def test_binary_tree_order(self):
        """Binary tree A(B, C): get_current() visits B, A, C, A.

        The parent is visited between children (after first child is
        popped, parent becomes current; then pop advances to next child).
        After all children are done, parent is visited one final time.
        """
        b = _make_leaf("B")
        c = _make_leaf("C")
        a = _make_binary("A", b, c)

        proc = ASTProcessor(a)
        items = []
        while (item := proc.get_current()) is not None:
            items.append(item.name)
            proc.pop_current()

        assert items == ["B", "A", "C", "A"]

    def test_deeper_tree_order(self):
        """
        Tree: root(left(ll, lr), right)
        Expected iteration via get_current():
        ll, left, lr, left, root, right, root
        """
        ll = _make_leaf("ll")
        lr = _make_leaf("lr")
        left = _make_binary("left", ll, lr)
        right = _make_leaf("right")
        root = _make_binary("root", left, right)

        proc = ASTProcessor(root)
        items = []
        while (item := proc.get_current()) is not None:
            items.append(item.name)
            proc.pop_current()

        assert items == ["ll", "left", "lr", "left", "root", "right", "root"]

    def test_block_iteration(self):
        """Block(A, B, C): get_current() visits A, Block, B, Block, C, Block.

        After each child is popped, the parent block becomes current,
        then popping it advances to the next child.
        """
        a = _make_leaf("A")
        b = _make_leaf("B")
        c = _make_leaf("C")
        block = _make_block("Block", a, b, c)

        proc = ASTProcessor(block)
        items = []
        while (item := proc.get_current()) is not None:
            items.append(item.name)
            proc.pop_current()

        assert items == ["A", "Block", "B", "Block", "C", "Block"]

    def test_all_nodes_visited(self):
        """Verify all distinct nodes are visited at least once."""
        b = _make_leaf("B")
        c = _make_leaf("C")
        a = _make_binary("A", b, c)

        proc = ASTProcessor(a)
        visited = set()
        while (item := proc.get_current()) is not None:
            visited.add(item.name)
            proc.pop_current()

        assert visited == {"A", "B", "C"}


# ---------------------------------------------------------------------------
# Restart-on-modification
# ---------------------------------------------------------------------------

class TestASTProcessorRestart:
    def test_restart_resets_to_beginning(self):
        """After restart_iteration, processor starts from leftmost leaf again."""
        b = _make_leaf("B")
        c = _make_leaf("C")
        a = _make_binary("A", b, c)

        proc = ASTProcessor(a)
        # Initially at B (leftmost leaf)
        assert proc.get_current().name == "B"
        # Advance: pop B, parent A becomes current
        proc.pop_current()
        assert proc.get_current().name == "A"

        # Restart
        proc.restart_iteration()
        # Should be back at leftmost leaf B
        assert proc.get_current().name == "B"

    def test_is_iteration_started(self):
        """is_iteration_started() should return True only at the very beginning."""
        b = _make_leaf("B")
        c = _make_leaf("C")
        a = _make_binary("A", b, c)

        proc = ASTProcessor(a)
        assert proc.is_iteration_started() is True

        proc.pop_current()
        assert proc.is_iteration_started() is False


# ---------------------------------------------------------------------------
# Path tracking
# ---------------------------------------------------------------------------

class TestASTProcessorPath:
    def test_path_not_empty_during_iteration(self):
        leaf = _make_leaf("A")
        proc = ASTProcessor(leaf)
        assert len(proc.path) > 0
        proc.pop_current()
        assert len(proc.path) == 0

    def test_path_depth_matches_tree_depth(self):
        """For a linear chain of depth 3, initial path should have 3 entries."""
        c = _make_leaf("C")
        b = _make_unary("B", c)
        a = _make_unary("A", b)

        proc = ASTProcessor(a)
        assert len(proc.path) == 3

    def test_is_iteration_ended(self):
        leaf = _make_leaf("A")
        proc = ASTProcessor(leaf)
        assert proc.is_iteration_ended() is False
        proc.pop_current()
        assert proc.is_iteration_ended() is True

    def test_get_current_returns_none_after_end(self):
        leaf = _make_leaf("A")
        proc = ASTProcessor(leaf)
        proc.pop_current()
        assert proc.get_current() is None

    def test_pop_current_returns_none_after_end(self):
        leaf = _make_leaf("A")
        proc = ASTProcessor(leaf)
        proc.pop_current()
        assert proc.pop_current() is None
