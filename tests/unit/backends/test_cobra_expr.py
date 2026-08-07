"""Unit tests for the CoBRA expression layer (no IDA, no hexrays).

These cover the three pieces of the CoBRA backend that are pure data:
parsing cobra-cli output, evaluating a tree, and choosing whether to accept a
rewrite.  Everything that needs ``ida_hexrays`` lives in
``tests/system/runtime`` instead -- unit tests are barred from importing
``d810.hexrays`` by the import-linter contract.

Measured facts these tests pin down (see
``docs/plans/2026-08-06-cobra-mba-solve-integration.md``):

* cobra-cli and CPython agree on operator precedence, which is what makes
  parsing with ``ast.parse`` sound rather than a lucky coincidence.
* 26 of 55 CoBRA rewrites are LARGER than their input, so accepting
  unconditionally regresses the output.  Acceptance must compare sizes.
"""

from __future__ import annotations

import unittest

from d810.backends.cobra.expr import (
    ExprParseError,
    accept_rewrite,
    evaluate,
    node_count,
    parse_cobra_output,
)


class TestParseCobraOutput(unittest.TestCase):
    def test_parses_a_simple_binary_expression(self):
        tree = parse_cobra_output("x0 ^ x1", ["a", "b"])
        self.assertEqual(tree["kind"], "bin")
        self.assertEqual(tree["op"], "^")
        self.assertEqual(tree["a"], {"kind": "var", "name": "a"})
        self.assertEqual(tree["b"], {"kind": "var", "name": "b"})

    def test_maps_x_indices_back_to_real_leaf_names(self):
        tree = parse_cobra_output("x1", ["first", "second"])
        self.assertEqual(tree, {"kind": "var", "name": "second"})

    def test_folds_negative_literals_into_constants(self):
        # cobra prints negative coefficients; a rebuilt instruction wants a
        # constant, not a negation node.
        tree = parse_cobra_output("-2", [])
        self.assertEqual(tree, {"kind": "const", "value": -2})

    def test_precedence_matches_cobra_not_left_to_right(self):
        # cobra ExprParser.cpp: * = 2, + = 3, & = 5 (lower binds tighter).
        # So "1 + x0 * 2 & 3" is ((1 + (x0 * 2)) & 3).
        tree = parse_cobra_output("1 + x0 * 2 & 3", ["v"])
        self.assertEqual(tree["op"], "&")
        self.assertEqual(tree["a"]["op"], "+")
        self.assertEqual(tree["a"]["b"]["op"], "*")

    def test_unary_operators(self):
        self.assertEqual(
            parse_cobra_output("~x0", ["v"]),
            {"kind": "un", "op": "~", "a": {"kind": "var", "name": "v"}},
        )

    def test_rejects_unknown_variable(self):
        with self.assertRaises(ExprParseError):
            parse_cobra_output("x9", ["only_one"])

    def test_rejects_unsupported_operator(self):
        # cobra-cli has no shift token; anything that parses to one is not
        # something we can have produced, so it must be refused loudly.
        with self.assertRaises(ExprParseError):
            parse_cobra_output("x0 >> 2", ["v"])

    def test_rejects_garbage(self):
        with self.assertRaises(ExprParseError):
            parse_cobra_output("this is not (an expression", ["v"])


class TestEvaluate(unittest.TestCase):
    def test_masks_to_bit_width(self):
        tree = parse_cobra_output("x0 + 1", ["v"])
        self.assertEqual(evaluate(tree, {"v": 0xFF}, mask=0xFF), 0)

    def test_negation_is_twos_complement(self):
        tree = parse_cobra_output("-x0", ["v"])
        self.assertEqual(evaluate(tree, {"v": 1}, mask=0xFFFFFFFF), 0xFFFFFFFF)

    def test_known_identity_holds(self):
        # (x|y) - (x&y) == x ^ y
        lhs = parse_cobra_output("(x0 | x1) - (x0 & x1)", ["a", "b"])
        rhs = parse_cobra_output("x0 ^ x1", ["a", "b"])
        for a in (0, 1, 0x5A5A, 0xFFFF):
            for b in (0, 1, 0xA5A5, 0xFFFF):
                vals = {"a": a, "b": b}
                self.assertEqual(
                    evaluate(lhs, vals, 0xFFFF), evaluate(rhs, vals, 0xFFFF)
                )


class TestNodeCount(unittest.TestCase):
    def test_counts_every_node(self):
        self.assertEqual(node_count(parse_cobra_output("x0", ["v"])), 1)
        self.assertEqual(node_count(parse_cobra_output("x0 + 1", ["v"])), 3)
        self.assertEqual(node_count(parse_cobra_output("~(x0 + 1)", ["v"])), 4)


class TestAcceptRewrite(unittest.TestCase):
    """26/55 real rewrites were LARGER; accepting blindly regresses output."""

    def test_accepts_a_strictly_smaller_rewrite(self):
        original = parse_cobra_output("(x0 | x1) - (x0 & x1)", ["a", "b"])
        rewrite = parse_cobra_output("x0 ^ x1", ["a", "b"])
        self.assertTrue(accept_rewrite(original, rewrite))

    def test_rejects_a_larger_rewrite(self):
        original = parse_cobra_output("x0 ^ x1", ["a", "b"])
        rewrite = parse_cobra_output("(x0 | x1) - (x0 & x1)", ["a", "b"])
        self.assertFalse(accept_rewrite(original, rewrite))

    def test_rejects_an_equal_sized_rewrite(self):
        # No benefit, so no churn: same size is not an improvement.
        original = parse_cobra_output("x0 + x1", ["a", "b"])
        rewrite = parse_cobra_output("x0 | x1", ["a", "b"])
        self.assertFalse(accept_rewrite(original, rewrite))


if __name__ == "__main__":
    unittest.main()
