"""Escalation-prover tests.

The escalation prover re-proves candidates that the inline 500ms budget could
not settle, using the generous off-path budget, and writes results into the
table so the next decompile gets them for free.

It runs on a worker thread.  That is only safe because of a structural fact:
``expr``, ``prove`` and ``table`` have no IDA dependency, and candidate trees
are plain dicts built from ``MopSnapshot`` rather than borrowed ``mop_t``.  The
worker therefore never touches the Hex-Rays API.  These tests use a fake
prover so they exercise the queue, the threading and the table contract
without needing z3 or IDA.
"""

from __future__ import annotations

import threading
import unittest

from d810.backends.cobra.escalate import EscalationProver
from d810.backends.cobra.prove import ProofResult
from d810.backends.cobra.table import Outcome, RewriteTable

V = lambda n: {"kind": "var", "name": n}  # noqa: E731
B = lambda o, a, b: {"kind": "bin", "op": o, "a": a, "b": b}  # noqa: E731

TREE = B("+", B("&", V("a"), V("b")), B("|", V("a"), V("b")))
REWRITE = B("+", V("a"), V("b"))


class TestEscalationProver(unittest.TestCase):
    def setUp(self):
        self.table = RewriteTable()

    def test_proved_result_lands_in_the_table(self):
        prover = EscalationProver(
            self.table, prover=lambda *a, **k: ProofResult.PROVED
        )
        prover.start()
        prover.submit(TREE, 32, REWRITE, ["a", "b"])
        prover.drain()
        prover.stop()

        entry = self.table.lookup(TREE, 32)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outcome, Outcome.PROVED)
        self.assertEqual(entry.rewrite, REWRITE)

    def test_refuted_result_is_recorded_as_no_rewrite(self):
        """A refuted rewrite must be remembered, not merely dropped.

        Forgetting it means re-solving and re-proving the same bad candidate
        on every future pass.
        """
        prover = EscalationProver(
            self.table, prover=lambda *a, **k: ProofResult.REFUTED
        )
        prover.start()
        prover.submit(TREE, 32, REWRITE, ["a", "b"])
        prover.drain()
        prover.stop()
        self.assertEqual(self.table.lookup(TREE, 32).outcome, Outcome.NO_REWRITE)

    def test_unknown_after_the_long_budget_is_recorded_as_no_rewrite(self):
        """If the generous budget also times out, stop asking.

        Leaving it PENDING forever would re-queue the same candidate on every
        decompile and never converge.
        """
        prover = EscalationProver(
            self.table, prover=lambda *a, **k: ProofResult.UNKNOWN
        )
        prover.start()
        prover.submit(TREE, 32, REWRITE, ["a", "b"])
        prover.drain()
        prover.stop()
        self.assertEqual(self.table.lookup(TREE, 32).outcome, Outcome.NO_REWRITE)

    def test_submit_marks_pending_immediately(self):
        """Between submit and completion the entry must read PENDING.

        Otherwise the live rule re-submits the same candidate on every visit
        and the queue grows without bound.
        """
        gate = threading.Event()
        prover = EscalationProver(
            self.table, prover=lambda *a, **k: (gate.wait(5), ProofResult.PROVED)[1]
        )
        prover.start()
        prover.submit(TREE, 32, REWRITE, ["a", "b"])
        self.assertEqual(self.table.lookup(TREE, 32).outcome, Outcome.PENDING)
        gate.set()
        prover.drain()
        prover.stop()
        self.assertEqual(self.table.lookup(TREE, 32).outcome, Outcome.PROVED)

    def test_duplicate_submissions_are_not_requeued(self):
        calls = []
        prover = EscalationProver(
            self.table,
            prover=lambda *a, **k: (calls.append(1), ProofResult.PROVED)[1],
        )
        prover.start()
        for _ in range(5):
            prover.submit(TREE, 32, REWRITE, ["a", "b"])
        prover.drain()
        prover.stop()
        self.assertEqual(len(calls), 1)

    def test_a_prover_that_raises_does_not_kill_the_worker(self):
        """One bad candidate must not silently stop all future escalation."""
        seen = []

        def flaky(original, rewrite, leaves, bitwidth, **kw):
            seen.append(leaves)
            if len(seen) == 1:
                raise ValueError("boom")
            return ProofResult.PROVED

        prover = EscalationProver(self.table, prover=flaky)
        prover.start()
        prover.submit(TREE, 32, REWRITE, ["a", "b"])
        prover.drain()
        other = B("^", V("x"), V("y"))
        prover.submit(other, 32, B("+", V("x"), V("y")), ["x", "y"])
        prover.drain()
        prover.stop()

        self.assertEqual(len(seen), 2)
        self.assertEqual(self.table.lookup(other, 32).outcome, Outcome.PROVED)

    def test_stop_is_idempotent(self):
        prover = EscalationProver(
            self.table, prover=lambda *a, **k: ProofResult.PROVED
        )
        prover.start()
        prover.stop()
        prover.stop()

    def test_submit_before_start_is_a_no_op_not_a_crash(self):
        """The feature can be off; nothing here may raise into a decompile."""
        prover = EscalationProver(
            self.table, prover=lambda *a, **k: ProofResult.PROVED
        )
        prover.submit(TREE, 32, REWRITE, ["a", "b"])
        self.assertIsNone(self.table.lookup(TREE, 32))


if __name__ == "__main__":
    unittest.main()
