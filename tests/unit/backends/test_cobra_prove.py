"""Proof-layer tests: the inline budget and the meaning of a timeout.

The critical property here is that a *short* budget degrades to UNKNOWN and
never to REFUTED.  The rule treats UNKNOWN as "skip this rewrite", so a tight
inline timeout costs coverage only.  If a timeout could ever surface as
REFUTED, shortening the budget would start discarding valid rewrites and --
worse -- would log them as if CoBRA had produced bad math.
"""

from __future__ import annotations

import unittest

from d810.backends.cobra.prove import (
    DEFAULT_TIMEOUT_MS,
    INLINE_TIMEOUT_MS,
    ProofResult,
    prove_equivalent,
    z3_available,
)

V = lambda n: {"kind": "var", "name": n}  # noqa: E731
C = lambda v: {"kind": "const", "value": v}  # noqa: E731
B = lambda o, a, b: {"kind": "bin", "op": o, "a": a, "b": b}  # noqa: E731


class TestInlineBudget(unittest.TestCase):
    def test_inline_budget_is_far_below_the_escalation_budget(self):
        """The two budgets serve different masters and must not converge.

        INLINE_TIMEOUT_MS bounds the critical path; DEFAULT_TIMEOUT_MS is what
        the off-path prover may spend.  Measured on VM_DecryptPacket, 98% of
        total proof time sat in 4 of 14 proofs, so the split is the whole
        point of the design.
        """
        self.assertLess(INLINE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS)

    def test_inline_budget_matches_the_measured_knee(self):
        """500ms was chosen from data, not taste.

        Sorted proof times (ms) over the 14 accepted candidates:
        0 1 3 8 115 197 284 440 701 1611 6213 18554 68113 93610.
        500ms keeps 8/14 for 4.05s; 1000ms buys one more proof for +2.7s.
        """
        self.assertEqual(INLINE_TIMEOUT_MS, 500)


class TestTimeoutSemantics(unittest.TestCase):
    def setUp(self):
        if not z3_available():
            self.skipTest("z3 not installed")

    def test_equivalent_pair_proves(self):
        # (a & b) + (a | b) == a + b, for all 32-bit a, b.
        a, b = V("a"), V("b")
        original = B("+", B("&", a, b), B("|", a, b))
        rewrite = B("+", a, b)
        self.assertIs(
            prove_equivalent(original, rewrite, ["a", "b"], 32),
            ProofResult.PROVED,
        )

    def test_inequivalent_pair_refutes(self):
        a, b = V("a"), V("b")
        self.assertIs(
            prove_equivalent(B("+", a, b), B("^", a, b), ["a", "b"], 32),
            ProofResult.REFUTED,
        )

    def test_starved_budget_never_reports_refuted(self):
        """A 1ms budget on a genuinely-equal pair must not say REFUTED.

        This is the safety property the whole inline-budget design rests on.
        z3 may still finish in under a millisecond, so PROVED is an acceptable
        outcome too -- what must never happen is REFUTED.
        """
        a, b = V("a"), V("b")
        original = B("*", B("+", a, b), B("+", a, b))
        rewrite = B(
            "+",
            B("+", B("*", a, a), B("*", C(2), B("*", a, b))),
            B("*", b, b),
        )
        verdict = prove_equivalent(original, rewrite, ["a", "b"], 32, timeout_ms=1)
        self.assertIn(verdict, (ProofResult.PROVED, ProofResult.UNKNOWN))
        self.assertIsNot(verdict, ProofResult.REFUTED)

    def test_default_timeout_is_used_when_unspecified(self):
        a = V("a")
        self.assertIs(
            prove_equivalent(a, a, ["a"], 32),
            ProofResult.PROVED,
        )


if __name__ == "__main__":
    unittest.main()
