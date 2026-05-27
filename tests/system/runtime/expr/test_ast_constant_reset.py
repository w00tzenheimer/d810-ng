"""Regression tests for AstConstant.reset_mops restoring initial state.

Before the fix, a free placeholder ``Const("c")`` (no initial expected_value)
that was bound to a concrete value by ``_copy_mops_from_ast`` during a
successful match retained that value forever. ``reset_mops()`` only cleared
``self.mop``; ``expected_value`` was left mutated. The next match attempt
with a different constant in the same slot was silently rejected at the
equality check in ``_copy_mops_from_ast``.

These tests exercise the contract: after ``reset_mops()``, every
``AstConstant`` must look exactly like it did right after ``__init__``.
"""

from __future__ import annotations

import unittest

from d810.expr import p_ast


class TestAstConstantResetMops(unittest.TestCase):
    """reset_mops() must restore constructor-provided state."""

    def test_free_const_reverts_to_none(self):
        """Const("c_1") with no initial: simulated match sets expected_value,
        reset_mops() must clear it back to None."""
        c = p_ast.AstConstant("c_1")
        self.assertIsNone(c.expected_value)
        self.assertIsNone(c.expected_size)

        # Simulate _copy_mops_from_ast binding the placeholder
        c.expected_value = 8
        c.expected_size = 4
        self.assertEqual(c.expected_value, 8)

        c.reset_mops()
        self.assertIsNone(
            c.expected_value,
            "reset_mops should restore expected_value to its constructor value",
        )
        self.assertIsNone(c.expected_size)

    def test_initial_const_is_preserved_across_reset(self):
        """Const("TWO", 2) was given an initial value; reset_mops() must NOT
        clobber it -- only restore it after any mutation."""
        t = p_ast.AstConstant("TWO", 2, 8)
        self.assertEqual(t.expected_value, 2)
        self.assertEqual(t.expected_size, 8)

        # Even a no-op reset should leave the initial intact
        t.reset_mops()
        self.assertEqual(t.expected_value, 2)
        self.assertEqual(t.expected_size, 8)

        # Mutate then reset — initial must come back
        t.expected_value = 99
        t.expected_size = 1
        t.reset_mops()
        self.assertEqual(t.expected_value, 2)
        self.assertEqual(t.expected_size, 8)

    def test_match_unbind_match_cycle(self):
        """The core scenario: bind to one literal, reset, bind to a different
        literal. Without the fix, the second binding's equality check would
        return False because expected_value still held the first literal."""
        c = p_ast.AstConstant("c_1")

        # First match site: input constant = 8
        c.expected_value = 8
        self.assertEqual(c.expected_value, 8)

        # Pattern is reset before the next match attempt
        c.reset_mops()

        # Second match site: input constant = 1. Without the fix, expected_value
        # is still 8 here and the new binding's equality check rejects it.
        # With the fix, expected_value is back to None and binding proceeds.
        self.assertIsNone(c.expected_value)
        c.expected_value = 1
        self.assertEqual(c.expected_value, 1)

    def test_clone_carries_initial(self):
        """clone() must propagate _initial_* so the clone's reset_mops() also
        restores correctly. Without this, candidates produced by ast_generator
        (which clones) would be permanent: reset would set expected_value to
        None even if the original was created with an initial like TWO."""
        original = p_ast.AstConstant("TWO", 2)
        clone = original.clone()
        self.assertEqual(clone.expected_value, 2)

        # Mutate the clone (simulate a match binding it)
        clone.expected_value = 99
        clone.reset_mops()
        self.assertEqual(
            clone.expected_value,
            2,
            "clone() must propagate _initial_expected_value for reset to work",
        )

    def test_clone_of_free_const_resets_to_none(self):
        """A free clone (Const without initial) must reset to None, not to
        whatever value it carried at clone time."""
        original = p_ast.AstConstant("c_2")
        clone = original.clone()
        clone.expected_value = 16  # bound during a match
        clone.reset_mops()
        self.assertIsNone(clone.expected_value)


if __name__ == "__main__":
    unittest.main()
