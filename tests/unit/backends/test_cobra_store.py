"""Durable proof-cache tests.

The rewrite table's whole justification is that a proof paid for once is never
paid for again.  Without durable storage that reduces to intra-run reuse only,
so this is the layer that makes tasks 2-4 worth their complexity.

Deliberately GLOBAL, not per-binary.  Table entries are positional-leaf and
universally quantified -- ``(a&b)+(a|b) == a+b`` is a fact about arithmetic,
not about any particular database.  Sharing across databases is the point.

Follows the conventions in ``d810/passes/store.py``: sqlite, INSERT OR REPLACE
upserts, a JSON column for the variable-length rewrite, and no IDA imports.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from d810.backends.cobra.store import ProofCacheStore, proof_cache_db_path
from d810.backends.cobra.table import Outcome, RewriteTable

V = lambda n: {"kind": "var", "name": n}  # noqa: E731
C = lambda v: {"kind": "const", "value": v}  # noqa: E731
B = lambda o, a, b: {"kind": "bin", "op": o, "a": a, "b": b}  # noqa: E731

TREE = B("+", B("&", V("a"), V("b")), B("|", V("a"), V("b")))
REWRITE = B("+", V("a"), V("b"))
DEAD = B("^", V("a"), V("b"))


class TestPathResolution(unittest.TestCase):
    def test_path_lives_beside_the_analysis_db(self):
        """Mirrors passes/artifacts.py:analysis_db_path so both land together."""
        self.assertEqual(
            proof_cache_db_path("/some/logs"),
            Path("/some/logs/d810_mba_proofs.db"),
        )

    def test_falls_back_to_tempdir_without_a_log_dir(self):
        self.assertEqual(
            proof_cache_db_path(None).name, "d810_mba_proofs.db"
        )


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "proofs.db"

    def tearDown(self):
        self._tmp.cleanup()

    def test_proved_entry_survives_a_new_process_equivalent(self):
        table = RewriteTable()
        table.record_proved(TREE, 32, REWRITE)

        store = ProofCacheStore(self.db)
        store.flush(table)
        store.close()

        restored = ProofCacheStore(self.db).load()
        entry = restored.lookup(TREE, 32)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outcome, Outcome.PROVED)
        self.assertEqual(entry.rewrite, REWRITE)

    def test_negative_entries_survive_too(self):
        """46 of 60 candidates are dead; forgetting that re-solves them all."""
        table = RewriteTable()
        table.record_no_rewrite(DEAD, 32)
        store = ProofCacheStore(self.db)
        store.flush(table)
        store.close()

        restored = ProofCacheStore(self.db).load()
        self.assertEqual(restored.lookup(DEAD, 32).outcome, Outcome.NO_REWRITE)

    def test_pending_entries_are_never_persisted(self):
        """PENDING is in-flight state. A killed session must not resurrect it
        as permanently-suppressed work."""
        table = RewriteTable()
        table.record_pending(B("*", V("a"), V("b")), 32)
        store = ProofCacheStore(self.db)
        store.flush(table)
        store.close()

        restored = ProofCacheStore(self.db).load()
        self.assertIsNone(restored.lookup(B("*", V("a"), V("b")), 32))

    def test_reloaded_rewrite_is_bound_to_the_querying_leaves(self):
        """Persistence must not lose the positional-instantiation contract."""
        table = RewriteTable()
        table.record_proved(TREE, 32, REWRITE)
        store = ProofCacheStore(self.db)
        store.flush(table)
        store.close()

        restored = ProofCacheStore(self.db).load()
        renamed = B("+", B("&", V("p"), V("q")), B("|", V("p"), V("q")))
        entry = restored.lookup(renamed, 32)
        self.assertEqual(entry.rewrite, B("+", V("p"), V("q")))

    def test_flush_is_idempotent(self):
        table = RewriteTable()
        table.record_proved(TREE, 32, REWRITE)
        store = ProofCacheStore(self.db)
        store.flush(table)
        store.flush(table)
        store.close()
        self.assertEqual(len(ProofCacheStore(self.db).load().to_dict()["entries"]), 1)

    def test_second_session_accumulates_rather_than_replaces(self):
        """Two databases analysed in sequence must both contribute."""
        first = RewriteTable()
        first.record_proved(TREE, 32, REWRITE)
        s = ProofCacheStore(self.db)
        s.flush(first)
        s.close()

        second = RewriteTable()
        second.record_no_rewrite(DEAD, 32)
        s = ProofCacheStore(self.db)
        s.flush(second)
        s.close()

        restored = ProofCacheStore(self.db).load()
        self.assertEqual(restored.lookup(TREE, 32).outcome, Outcome.PROVED)
        self.assertEqual(restored.lookup(DEAD, 32).outcome, Outcome.NO_REWRITE)

    def test_missing_database_loads_empty_rather_than_raising(self):
        """A cold cache is normal, not an error."""
        store = ProofCacheStore(Path(self._tmp.name) / "absent.db")
        self.assertIsNone(store.load().lookup(TREE, 32))

    def test_corrupt_database_degrades_to_empty(self):
        """A bad cache must never take a decompilation down with it."""
        self.db.write_bytes(b"this is not a sqlite database")
        store = ProofCacheStore(self.db)
        self.assertIsNone(store.load().lookup(TREE, 32))

    def test_schema_version_mismatch_is_ignored_not_misread(self):
        store = ProofCacheStore(self.db)
        table = RewriteTable()
        table.record_proved(TREE, 32, REWRITE)
        store.flush(table)
        store.close()

        import sqlite3

        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE cobra_proofs SET schema_version = 999")
        conn.commit()
        conn.close()

        self.assertIsNone(ProofCacheStore(self.db).load().lookup(TREE, 32))


if __name__ == "__main__":
    unittest.main()
