from __future__ import annotations

import unittest

from d810.expr import p_ast


class _MappedLeaf:
    def __init__(self, mop):
        self.mop = mop


class _Source:
    def __init__(self):
        self.leafs_by_name = {
            "x_0": _MappedLeaf(mop="mop_x"),
            "c_1": _MappedLeaf(mop="mop_c"),
        }


class _Leaf:
    def __init__(self, name: str, should_succeed: bool):
        self.name = name
        self.mop = None
        self._should_succeed = should_succeed
        self.calls = 0

    def update_leafs_mop(self, other, other2=None):
        self.calls += 1
        if self.name in other.leafs_by_name:
            self.mop = other.leafs_by_name[self.name].mop
        return self._should_succeed


class _NodeLike:
    def __init__(self, leaves):
        self._leaves = leaves
        self.leafs = []

    def get_leaf_list(self):
        return self._leaves


def test_update_leafs_mop_delegates_to_leaf_specific_update():
    ok_leaf = _Leaf("x_0", should_succeed=True)
    failing_leaf = _Leaf("c_1", should_succeed=False)
    node_like = _NodeLike([ok_leaf, failing_leaf])
    source = _Source()

    result = p_ast.AstNode.update_leafs_mop(node_like, source)

    assert result is False
    assert ok_leaf.calls == 1
    assert failing_leaf.calls == 1
    assert ok_leaf.mop == "mop_x"
    assert failing_leaf.mop == "mop_c"


class _EmptyCandidate:
    """Stand-in for an AstNode candidate whose leafs_by_name has nothing for
    the constant being queried. Mirrors what happens for REPLACEMENT-side
    literal constants (e.g. NEGATIVE_TWO from d810.mba.dsl) that have no
    binding in the matched pattern."""

    def __init__(self):
        self.leafs_by_name = {}


class TestAstConstantUpdateLeafsMop(unittest.TestCase):
    """Regression tests for AstConstant.update_leafs_mop literal-value handling.

    Guards against the bug where a REPLACEMENT referencing a numeric constant
    not bound in PATTERN (e.g. Mul_FactorRule_2's ``NEG_TWO * (x & y)``)
    silently fails to fire because update_leafs_mop returned False whenever
    the constant's name was missing from the candidate's leafs_by_name —
    even when expected_value was already set at construction time. This
    aborted get_replacement before _materialize_replacement_constants could
    synthesise the constant mop_t from expected_value.
    """

    def test_with_expected_value_short_circuits(self):
        """Literal constant with expected_value succeeds without binding."""
        const = p_ast.AstConstant("NEG_TWO", expected_value=-2)
        self.assertTrue(const.update_leafs_mop(_EmptyCandidate()))

    def test_zero_value_short_circuits(self):
        """expected_value=0 is a real value, not a missing binding."""
        const = p_ast.AstConstant("ZERO", expected_value=0)
        self.assertTrue(const.update_leafs_mop(_EmptyCandidate()))

    def test_without_expected_value_returns_false(self):
        """Pattern-bound constants with no expected_value still return False."""
        const = p_ast.AstConstant("c_1")
        self.assertFalse(const.update_leafs_mop(_EmptyCandidate()))

    def test_short_circuit_via_other2_fallback(self):
        """Short-circuit fires regardless of which candidate is provided."""
        const = p_ast.AstConstant("ONE", expected_value=1)
        self.assertTrue(
            const.update_leafs_mop(_EmptyCandidate(), _EmptyCandidate())
        )
