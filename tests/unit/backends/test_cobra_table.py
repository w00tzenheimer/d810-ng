"""Rewrite-table tests.

The table exists to keep solving and proving off the critical path.  Two
properties carry that weight:

* a **negative** result is cached as aggressively as a positive one.  Only 14
  of 60 measured candidates yield a usable rewrite (25 already-minimal, 21
  not-smaller) while solving costs 11.52s across all 60, so a table that only
  remembers successes re-solves 46 dead candidates on every pass.
* the key is the **tree**, not the signature.  Signature-keying would only be
  sound under the linear-MBA class assumption (it needs bitwidth >= 2**n, so
  n <= 5 at 32-bit, while max_leaves is 8).  Two expressions sharing a
  signature are not interchangeable in general, and reusing one's rewrite for
  the other would be unsound.
"""

from __future__ import annotations

import unittest

from d810.backends.cobra.table import (
    Outcome,
    RewriteTable,
    canonical_key,
)

V = lambda n: {"kind": "var", "name": n}  # noqa: E731
C = lambda v: {"kind": "const", "value": v}  # noqa: E731
B = lambda o, a, b: {"kind": "bin", "op": o, "a": a, "b": b}  # noqa: E731
U = lambda o, a: {"kind": "un", "op": o, "a": a}  # noqa: E731


class TestCanonicalKey(unittest.TestCase):
    def test_leaf_names_are_abstracted_positionally(self):
        """Renaming leaves must not change the key.

        The proof is universally quantified over the leaves (prove.py builds
        free BitVecs), so leaf identity is not part of what was proved.
        """
        left = B("+", V("a"), V("b"))
        right = B("+", V("x"), V("y"))
        self.assertEqual(canonical_key(left, 32), canonical_key(right, 32))

    def test_leaf_aliasing_is_preserved(self):
        """a+a and a+b are different functions and must key differently."""
        self.assertNotEqual(
            canonical_key(B("+", V("a"), V("a")), 32),
            canonical_key(B("+", V("a"), V("b")), 32),
        )

    def test_constants_are_part_of_the_key(self):
        self.assertNotEqual(
            canonical_key(B("+", V("a"), C(1)), 32),
            canonical_key(B("+", V("a"), C(2)), 32),
        )

    def test_bitwidth_is_part_of_the_key(self):
        """A proof holds at one width and says nothing about another."""
        tree = B("+", V("a"), V("b"))
        self.assertNotEqual(canonical_key(tree, 32), canonical_key(tree, 64))

    def test_alpha_equivalent_operand_order_shares_a_key(self):
        """``a - b`` and ``b - a`` are the same pattern, not different ones.

        The proof is over free variables, so a proof of ``x - y`` covers both
        by substitution.  What must then be true is that a hit hands back a
        rewrite instantiated with the *querying* expression's leaves -- see
        TestRewriteInstantiation.
        """
        self.assertEqual(
            canonical_key(B("-", V("a"), V("b")), 32),
            canonical_key(B("-", V("b"), V("a")), 32),
        )

    def test_operator_identity_is_significant(self):
        self.assertNotEqual(
            canonical_key(B("-", V("a"), V("b")), 32),
            canonical_key(B("+", V("a"), V("b")), 32),
        )

    def test_unary_ops_distinguish(self):
        self.assertNotEqual(
            canonical_key(U("~", V("a")), 32),
            canonical_key(U("-", V("a")), 32),
        )


class TestRewriteTable(unittest.TestCase):
    def setUp(self):
        self.table = RewriteTable()
        self.tree = B("+", B("&", V("a"), V("b")), B("|", V("a"), V("b")))
        self.rewrite = B("+", V("a"), V("b"))

    def test_miss_on_empty_table(self):
        entry = self.table.lookup(self.tree, 32)
        self.assertIsNone(entry)
        self.assertEqual(self.table.stats.misses, 1)

    def test_proved_rewrite_round_trips(self):
        self.table.record_proved(self.tree, 32, self.rewrite)
        entry = self.table.lookup(self.tree, 32)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outcome, Outcome.PROVED)
        self.assertEqual(entry.rewrite, self.rewrite)
        self.assertEqual(self.table.stats.hits, 1)

    def test_negative_result_is_cached(self):
        """The whole point: a dead candidate must never be re-solved."""
        self.table.record_no_rewrite(self.tree, 32)
        entry = self.table.lookup(self.tree, 32)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outcome, Outcome.NO_REWRITE)
        self.assertIsNone(entry.rewrite)
        self.assertEqual(self.table.stats.negative_hits, 1)

    def test_pending_is_distinct_from_negative(self):
        """PENDING means 'escalated, ask again later'; NO_REWRITE means 'never'.

        Collapsing them would either re-solve escalated work every pass or
        permanently suppress a rewrite the off-path prover is about to find.
        """
        self.table.record_pending(self.tree, 32)
        entry = self.table.lookup(self.tree, 32)
        self.assertEqual(entry.outcome, Outcome.PENDING)
        self.assertEqual(self.table.stats.pending_hits, 1)

    def test_pending_is_upgraded_by_a_later_proof(self):
        self.table.record_pending(self.tree, 32)
        self.table.record_proved(self.tree, 32, self.rewrite)
        entry = self.table.lookup(self.tree, 32)
        self.assertEqual(entry.outcome, Outcome.PROVED)
        self.assertEqual(entry.rewrite, self.rewrite)

    def test_a_proved_entry_is_not_downgraded_to_pending(self):
        """Escalation racing a cached proof must not lose the proof."""
        self.table.record_proved(self.tree, 32, self.rewrite)
        self.table.record_pending(self.tree, 32)
        self.assertEqual(self.table.lookup(self.tree, 32).outcome, Outcome.PROVED)

    def test_stats_account_for_every_outcome(self):
        """An invariant that counts needs a term for every legitimate result.

        hits + negative_hits + pending_hits + misses must equal lookups, or
        the telemetry silently under-reports one category.
        """
        self.table.record_proved(self.tree, 32, self.rewrite)
        other = B("^", V("a"), V("b"))
        self.table.record_no_rewrite(other, 32)
        third = B("*", V("a"), V("b"))
        self.table.record_pending(third, 32)

        self.table.lookup(self.tree, 32)
        self.table.lookup(other, 32)
        self.table.lookup(third, 32)
        self.table.lookup(B("-", V("a"), V("b")), 32)

        s = self.table.stats
        self.assertEqual(s.lookups, 4)
        self.assertEqual(s.hits + s.negative_hits + s.pending_hits + s.misses, 4)

    def test_different_bitwidths_do_not_share_an_entry(self):
        self.table.record_proved(self.tree, 32, self.rewrite)
        self.assertIsNone(self.table.lookup(self.tree, 64))

    def test_leaf_renaming_hits_the_same_entry(self):
        self.table.record_proved(self.tree, 32, self.rewrite)
        renamed = B("+", B("&", V("p"), V("q")), B("|", V("p"), V("q")))
        entry = self.table.lookup(renamed, 32)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outcome, Outcome.PROVED)


class TestRewriteInstantiation(unittest.TestCase):
    """A cached rewrite must come back bound to the caller's own leaves.

    This is the sharp edge of alpha-equivalence: keying ``a-b`` and ``b-a`` to
    the same entry is correct, but returning the stored rewrite verbatim would
    hand the caller an expression over the wrong variables.  Silently wrong
    output is worse than a miss.
    """

    def test_rewrite_is_renamed_to_the_querying_expression(self):
        table = RewriteTable()
        # proved over leaves a, b
        table.record_proved(
            B("+", B("&", V("a"), V("b")), B("|", V("a"), V("b"))),
            32,
            B("+", V("a"), V("b")),
        )
        # queried with leaves p, q
        entry = table.lookup(
            B("+", B("&", V("p"), V("q")), B("|", V("p"), V("q"))), 32
        )
        self.assertEqual(entry.rewrite, B("+", V("p"), V("q")))

    def test_swapped_operands_instantiate_in_the_right_order(self):
        table = RewriteTable()
        # x - y  ->  x + (-y), proved over x, y
        table.record_proved(
            B("-", V("x"), V("y")),
            32,
            B("+", V("x"), U("-", V("y"))),
        )
        # query b - a: position 0 is b, position 1 is a
        entry = table.lookup(B("-", V("b"), V("a")), 32)
        self.assertEqual(entry.rewrite, B("+", V("b"), U("-", V("a"))))

    def test_constants_in_the_rewrite_are_untouched(self):
        table = RewriteTable()
        table.record_proved(B("*", V("a"), C(2)), 32, B("+", V("a"), V("a")))
        entry = table.lookup(B("*", V("z"), C(2)), 32)
        self.assertEqual(entry.rewrite, B("+", V("z"), V("z")))


class TestPersistence(unittest.TestCase):
    def test_round_trips_through_serialisation(self):
        table = RewriteTable()
        tree = B("+", B("&", V("a"), V("b")), B("|", V("a"), V("b")))
        table.record_proved(tree, 32, B("+", V("a"), V("b")))
        table.record_no_rewrite(B("^", V("a"), V("b")), 32)

        restored = RewriteTable.from_dict(table.to_dict())
        self.assertEqual(restored.lookup(tree, 32).outcome, Outcome.PROVED)
        self.assertEqual(
            restored.lookup(B("^", V("a"), V("b")), 32).outcome,
            Outcome.NO_REWRITE,
        )

    def test_pending_entries_are_not_persisted(self):
        """PENDING is in-flight state, not a result.

        Persisting it would make a killed session look like it had escalated
        work outstanding forever, permanently suppressing those candidates.
        """
        table = RewriteTable()
        tree = B("*", V("a"), V("b"))
        table.record_pending(tree, 32)
        restored = RewriteTable.from_dict(table.to_dict())
        self.assertIsNone(restored.lookup(tree, 32))


if __name__ == "__main__":
    unittest.main()


class TestConcurrency(unittest.TestCase):
    """The escalation prover shares this table with the decompiling thread.

    HONEST SCOPE: these are regression guards, not demonstrations.  Neither
    test could be made to fail against the unlocked implementation, even at a
    1us switch interval with 40,000 lookups across 8 threads -- CPython checks
    the eval-breaker mainly at backward jumps and calls, so an inline ``+=``
    is practically atomic.  Do not read a pass here as proof of safety.

    The lock is justified by a specific reachable interleaving in
    ``record_pending`` rather than by these tests:

        B: existing = self._entries.get(key)   -> None
        A: self._entries[key] = Entry(PROVED)
        B: self._entries[key] = Entry(PENDING) -> the proof is destroyed

    ``Entry(Outcome.PENDING)`` is a call, and calls *are* eval-breaker
    checkpoints, so the switch is reachable; the window is simply narrow.
    """

    def test_stats_stay_balanced_under_concurrent_lookups(self):
        import threading

        table = RewriteTable()
        tree = B("+", V("a"), V("b"))
        table.record_proved(tree, 32, V("a"))

        def hammer():
            for _ in range(2000):
                table.lookup(tree, 32)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(table.stats.lookups, 8000)
        self.assertTrue(
            table.stats.balanced,
            f"stats lost updates: {table.stats}",
        )

    def test_pending_never_downgrades_a_proof_under_contention(self):
        import threading

        table = RewriteTable()
        trees = [B("+", V("a"), C(i)) for i in range(500)]

        def prove_all():
            for t in trees:
                table.record_proved(t, 32, V("a"))

        def pend_all():
            for t in trees:
                table.record_pending(t, 32)

        threads = [
            threading.Thread(target=prove_all),
            threading.Thread(target=pend_all),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Whatever the interleaving, a proof must survive a concurrent pending.
        for t in trees:
            table.record_pending(t, 32)
            self.assertEqual(table.lookup(t, 32).outcome, Outcome.PROVED)


class TestBoundedAndEvicting(unittest.TestCase):
    """The table must not grow without limit, and eviction must not lose data.

    The original implementation was an unbounded dict: on a large binary that
    is unbounded memory. A single function banked 207 entries, so the cap has
    to be sized against real traffic, not CacheImpl's 256 default.

    FLUSH-BEFORE-EVICT, not load-on-miss. A miss is the thing the table exists
    to avoid: an evicted NO_REWRITE would return None, the rule would re-solve
    it (~84ms measured), and only then discover the disk already knew. Writing
    on the way out keeps the durable store authoritative without ever paying a
    solve to find out.
    """

    def test_respects_max_size(self):
        table = RewriteTable(max_size=8)
        for i in range(40):
            table.record_no_rewrite(B("+", V("a"), C(i)), 32)
        self.assertLessEqual(table.size, 8)

    def test_evicted_entries_are_handed_to_the_sink(self):
        evicted = []
        table = RewriteTable(max_size=4, on_evict=lambda k, e: evicted.append((k, e)))
        for i in range(20):
            table.record_no_rewrite(B("+", V("a"), C(i)), 32)
        self.assertTrue(evicted, "eviction must notify, or entries are lost")
        key, entry = evicted[0]
        self.assertEqual(entry.outcome, Outcome.NO_REWRITE)

    def test_a_proved_rewrite_survives_eviction_via_the_sink(self):
        evicted = []
        table = RewriteTable(max_size=2, on_evict=lambda k, e: evicted.append((k, e)))
        tree = B("+", B("&", V("a"), V("b")), B("|", V("a"), V("b")))
        table.record_proved(tree, 32, B("+", V("a"), V("b")))
        for i in range(10):
            table.record_no_rewrite(B("^", V("a"), C(i)), 32)
        proved = [e for _, e in evicted if e.outcome == Outcome.PROVED]
        self.assertTrue(proved, "a proved rewrite was dropped without notice")
        self.assertIsNotNone(proved[0].rewrite)

    def test_stats_still_account_for_every_outcome(self):
        """CacheImpl.Stats has only hits/misses; the three-way outcome
        accounting must stay in RewriteTable or negatives get folded away."""
        table = RewriteTable(max_size=64)
        t = B("+", V("a"), V("b"))
        table.record_proved(t, 32, V("a"))
        table.record_no_rewrite(B("^", V("a"), V("b")), 32)
        table.record_pending(B("*", V("a"), V("b")), 32)
        table.lookup(t, 32)
        table.lookup(B("^", V("a"), V("b")), 32)
        table.lookup(B("*", V("a"), V("b")), 32)
        table.lookup(B("-", V("a"), V("b")), 32)
        s = table.stats
        self.assertEqual(s.lookups, 4)
        self.assertEqual(s.hits + s.negative_hits + s.pending_hits + s.misses, 4)

    def test_default_cap_is_sized_for_real_traffic(self):
        """A single function banked 207 entries; CacheImpl's 256 default would
        evict constantly across a whole binary."""
        from d810.backends.cobra.table import DEFAULT_MAX_ENTRIES

        self.assertGreaterEqual(DEFAULT_MAX_ENTRIES, 4096)
