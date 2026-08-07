"""Durable proof cache for the MBA rewrite table.

Without this, the table is per-process and its headline justification -- a
proof paid for once is never paid for again -- reduces to whatever intra-run
reuse happens to exist.  Measured cost of *not* having it: 11.52s of solving
across 60 candidates plus 189.9s of proving across the 14 that yield a
rewrite, repeated on every session.

Deliberately GLOBAL, not per-binary
-----------------------------------
Table entries are positional-leaf and universally quantified: ``prove_equivalent``
builds free bitvectors, so ``(a&b)+(a|b) == a+b`` is a fact about 32-bit
arithmetic, not about any database.  Sharing across databases is the point --
per-binary keying would discard most of the value.  The default location
follows from that: ``log_dir`` is ``<ida_user_dir>/logs``, already global.

Conventions follow ``d810/passes/store.py``: sqlite, ``INSERT OR REPLACE``
upserts, a JSON column for variable-length data, and no IDA imports so the
whole thing is unit-testable headless.

Nothing here may raise into a decompilation.  A missing cache is normal, and a
corrupt one degrades to empty rather than taking the session down.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from d810.backends.cobra.table import Outcome, RewriteTable
from d810.core import getLogger

logger = getLogger(__name__)

#: Bump when the on-disk row shape changes. Rows carrying a different version
#: are ignored rather than misread -- a stale schema silently reinterpreted is
#: how a cache turns into a correctness bug.
SCHEMA_VERSION = 1

_CREATE = """
CREATE TABLE IF NOT EXISTS cobra_proofs (
    key            TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    outcome        TEXT NOT NULL,
    rewrite_json   TEXT
)
"""


def proof_cache_db_path(log_dir: Path | str | None) -> Path:
    """Resolve the proof-cache DB path.

    Mirrors ``d810.passes.artifacts.analysis_db_path`` so the two databases sit
    together and inherit the same lifecycle.
    """
    if log_dir:
        return Path(log_dir) / "d810_mba_proofs.db"
    return Path(tempfile.gettempdir()) / "d810_mba_proofs.db"


class ProofCacheStore:
    """SQLite-backed durable store for settled rewrite-table entries."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    # -- connection --------------------------------------------------------

    def _connect(self) -> sqlite3.Connection | None:
        if self._conn is not None:
            return self._conn
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            conn.execute(_CREATE)
            conn.commit()
        except (sqlite3.Error, OSError) as exc:
            logger.debug("cobra proof cache unavailable at %s: %s", self.db_path, exc)
            return None
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # -- io ----------------------------------------------------------------

    def load(self) -> RewriteTable:
        """Return a table populated from disk, or an empty one.

        A cold or corrupt cache is not an error: it costs a re-solve, which is
        exactly what the caller would have done anyway.
        """
        table = RewriteTable()
        conn = self._connect()
        if conn is None:
            return table
        try:
            rows = conn.execute(
                "SELECT key, outcome, rewrite_json FROM cobra_proofs "
                "WHERE schema_version = ?",
                (SCHEMA_VERSION,),
            ).fetchall()
        except sqlite3.Error as exc:
            logger.debug("cobra proof cache unreadable: %s", exc)
            return table

        entries = []
        for key_json, outcome, rewrite_json in rows:
            try:
                entries.append(
                    {
                        "key": json.loads(key_json),
                        "outcome": outcome,
                        "rewrite": (
                            json.loads(rewrite_json) if rewrite_json else None
                        ),
                    }
                )
            except (json.JSONDecodeError, TypeError):
                continue
        return RewriteTable.from_dict(
            {"version": SCHEMA_VERSION, "entries": entries}
        )

    def flush(self, table: RewriteTable) -> int:
        """Upsert every settled entry. Returns the number written.

        ``to_dict`` already drops PENDING, so in-flight escalations never reach
        disk -- otherwise a killed session would look like it had work
        outstanding forever and permanently suppress those candidates.
        """
        conn = self._connect()
        if conn is None:
            return 0
        payload = table.to_dict()
        rows = [
            (
                json.dumps(entry["key"]),
                SCHEMA_VERSION,
                entry["outcome"],
                json.dumps(entry["rewrite"]) if entry["rewrite"] else None,
            )
            for entry in payload["entries"]
            if entry["outcome"] != Outcome.PENDING.value
        ]
        if not rows:
            return 0
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO cobra_proofs "
                "(key, schema_version, outcome, rewrite_json) VALUES (?, ?, ?, ?)",
                rows,
            )
            conn.commit()
        except sqlite3.Error as exc:
            logger.debug("cobra proof cache not writable: %s", exc)
            return 0
        return len(rows)


__all__ = ["SCHEMA_VERSION", "ProofCacheStore", "proof_cache_db_path"]
