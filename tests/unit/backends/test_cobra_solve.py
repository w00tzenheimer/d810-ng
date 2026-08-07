"""Solver-layer tests, including binding-vs-CLI parity.

The binding is the production path; cobra-cli is kept as an independent oracle.
Both are optional, so every test that needs one skips cleanly when it is
absent -- a machine without CoBRA must behave exactly like one where the
feature is off.
"""

from __future__ import annotations

import unittest

from d810.backends.cobra.expr import (
    evaluate,
    node_count,
    parse_cobra_output,
    signature_of,
)
from d810.backends.cobra.probe import find_cobra_cli
from d810.backends.cobra.solve import (
    SolveStatus,
    binding_available,
    solve_expression,
    solve_signature,
)

_MASK32 = 0xFFFFFFFF


def _tree(text: str, names: list[str]) -> dict:
    return parse_cobra_output(text, names)


class TestSignatureOf(unittest.TestCase):
    """The solver's actual input: no text, no AST marshalling."""

    def test_length_is_two_to_the_leaf_count(self):
        tree = _tree("x0 ^ x1", ["a", "b"])
        self.assertEqual(len(signature_of(tree, ["a", "b"], 32)), 4)

    def test_entries_are_the_expression_at_each_assignment(self):
        # x0 ^ x1 over (0,0) (1,0) (0,1) (1,1) -- bit i of the index is leaf i.
        self.assertEqual(signature_of(_tree("x0 ^ x1", ["a", "b"]), ["a", "b"], 32),
                         [0, 1, 1, 0])

    def test_entries_are_masked_to_bitwidth(self):
        tree = _tree("-x0", ["a"])
        self.assertEqual(signature_of(tree, ["a"], 8), [0, 0xFF])


@unittest.skipUnless(binding_available(), "CoBRA binding not built")
class TestSolveSignature(unittest.TestCase):
    def test_solves_a_known_identity(self):
        tree = _tree("(x0 | x1) - (x0 & x1)", ["a", "b"])
        result = solve_signature(tree, ["a", "b"], 32)

        self.assertIs(result.status, SolveStatus.SOLVED)
        self.assertIsNotNone(result.tree)
        for a in (0, 1, 0x5A5A5A5A, _MASK32):
            for b in (0, 1, 0xA5A5A5A5, _MASK32):
                self.assertEqual(
                    evaluate(result.tree, {"a": a, "b": b}, _MASK32), a ^ b
                )

    def test_result_is_smaller_than_the_input(self):
        tree = _tree("(x0 | x1) - (x0 & x1)", ["a", "b"])
        result = solve_signature(tree, ["a", "b"], 32)
        self.assertLess(node_count(result.tree), node_count(tree))

    def test_identity_input_reports_unchanged_not_solved(self):
        # The solver only sees a signature, so it cannot judge "unchanged" --
        # it has no input to compare against, and returns Variable(0) here.
        # solve_signature compares for it; without that this looked SOLVED.
        tree = _tree("x0", ["a"])
        result = solve_signature(tree, ["a"], 32)
        self.assertIs(result.status, SolveStatus.UNCHANGED)
        self.assertIsNone(result.tree)

    def test_signature_length_cannot_mismatch(self):
        # solve_signature derives the signature from leaf_names itself, so the
        # binding's length check is unreachable through it. Naming more leaves
        # than the tree uses is legal: the extra ones are simply free.
        result = solve_signature(_tree("x0", ["a"]), ["a", "b"], 32)
        self.assertIn(result.status, (SolveStatus.SOLVED, SolveStatus.UNCHANGED))

    def test_unevaluable_tree_is_a_result_not_an_exception(self):
        # A leaf the caller did not declare: evaluation raises, and the layer
        # must turn that into a skip rather than let it reach the pipeline.
        orphan = {"kind": "var", "name": "never_declared"}
        result = solve_signature(orphan, ["a"], 32)
        self.assertIs(result.status, SolveStatus.FAILED)
        self.assertIn("could not evaluate", result.reason)

    def test_bad_bitwidth_is_a_result_not_an_exception(self):
        result = solve_signature(_tree("x0 ^ x1", ["a", "b"]), ["a", "b"], 7)
        self.assertIs(result.status, SolveStatus.FAILED)
        self.assertTrue(result.reason)


@unittest.skipUnless(
    binding_available() and find_cobra_cli().available,
    "needs both the binding and cobra-cli",
)
class TestBindingCliParity(unittest.TestCase):
    """cobra-cli is the independent oracle for the native path."""

    CASES = (
        ("(x0 | x1) - (x0 & x1)", ["a", "b"], 32),
        ("(x0 + x1) - (x0 & x1)", ["a", "b"], 32),
        ("(x0 ^ x1) + 2 * (x0 & x1)", ["a", "b"], 32),
        ("~(x0 | x1) + x0 + x1", ["a", "b"], 32),
    )

    def test_both_paths_agree_semantically(self):
        probe = find_cobra_cli()
        for text, names, bits in self.CASES:
            with self.subTest(expression=text):
                tree = _tree(text, names)

                native = solve_signature(tree, names, bits)
                cli = solve_expression(probe, text, bits, names)

                # They may print differently; they must not disagree on value.
                mask = (1 << bits) - 1
                for i in range(64):
                    values = {n: (i * 0x9E3779B9 + j) & mask
                              for j, n in enumerate(names)}
                    expected = evaluate(tree, values, mask)
                    if native.tree is not None:
                        self.assertEqual(
                            evaluate(native.tree, values, mask), expected
                        )
                    if cli.tree is not None:
                        self.assertEqual(evaluate(cli.tree, values, mask), expected)


if __name__ == "__main__":
    unittest.main()
