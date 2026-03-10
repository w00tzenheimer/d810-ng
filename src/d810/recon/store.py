"""SQLite persistence layer for ReconResults and DeobfuscationHints.

Schema follows the existing pattern in ``core/persistence.py``:
- ``INSERT OR REPLACE`` for upsert semantics
- JSON columns for variable-length data (metrics, candidates, inferences)
- Composite primary key ``(func_ea, maturity, collector_name)`` for results
- Single primary key ``func_ea`` for hints

No IDA imports - fully unit-testable.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from types import MappingProxyType

from d810.recon.models import CandidateFlag, DeobfuscationHints, ReconResult


_SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_results (
    func_ea         INTEGER NOT NULL,
    maturity        INTEGER NOT NULL,
    collector_name  TEXT    NOT NULL,
    timestamp       REAL    NOT NULL,
    metrics_json    TEXT    NOT NULL,
    candidates_json TEXT    NOT NULL,
    PRIMARY KEY (func_ea, maturity, collector_name)
);

CREATE TABLE IF NOT EXISTS deobfuscation_hints (
    func_ea                  INTEGER PRIMARY KEY,
    obfuscation_type         TEXT,
    confidence               REAL    NOT NULL,
    recommended_inferences_json TEXT    NOT NULL,
    candidates_json          TEXT    NOT NULL,
    suppress_rules_json      TEXT    NOT NULL,
    updated_at               REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recon_func_ea
    ON recon_results(func_ea);

CREATE TABLE IF NOT EXISTS recon_session_summary (
    func_ea INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    collectors_fired INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    inferences_json TEXT NOT NULL DEFAULT '[]',
    suppress_rules_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (func_ea)
);

CREATE TABLE IF NOT EXISTS consumer_outcomes (
    func_ea INTEGER NOT NULL,
    consumer_name TEXT NOT NULL,
    timestamp REAL NOT NULL,
    artifacts_available INTEGER NOT NULL DEFAULT 0,
    summary_available INTEGER NOT NULL DEFAULT 0,
    verdict_applied INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    provenance_json TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (func_ea, consumer_name)
);

CREATE TABLE IF NOT EXISTS user_overrides (
    func_ea INTEGER NOT NULL,
    override_type TEXT NOT NULL,
    override_value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    created_at REAL NOT NULL,
    PRIMARY KEY (func_ea, override_type)
);
"""


def _candidate_to_dict(c: CandidateFlag) -> dict:
    return {
        "kind": c.kind,
        "block_serial": c.block_serial,
        "confidence": c.confidence,
        "detail": c.detail,
    }


def _candidate_from_dict(d: dict) -> CandidateFlag:
    return CandidateFlag(
        kind=str(d["kind"]),
        block_serial=int(d["block_serial"]),
        confidence=float(d["confidence"]),
        detail=str(d["detail"]),
    )


class ReconStore:
    """SQLite-backed store for recon results and deobfuscation hints.

    Example:
        >>> store = ReconStore("/tmp/recon.db")
        >>> store.save_recon_result(result)
        >>> rows = store.load_recon_results(func_ea=0x401000, maturity=5)
        >>> store.close()
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # ReconResult persistence
    # ------------------------------------------------------------------

    def save_recon_result(self, result: ReconResult) -> None:
        """Upsert a ReconResult (primary key: func_ea, maturity, collector_name)."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO recon_results
                (func_ea, maturity, collector_name, timestamp, metrics_json, candidates_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                int(result.func_ea),
                int(result.maturity),
                str(result.collector_name),
                float(result.timestamp),
                json.dumps(dict(result.metrics)),
                json.dumps([_candidate_to_dict(c) for c in result.candidates]),
            ),
        )
        self._conn.commit()

    def load_recon_results(
        self, *, func_ea: int, maturity: int
    ) -> list[ReconResult]:
        """Load all collector results for a specific func/maturity pair."""
        cursor = self._conn.execute(
            """
            SELECT collector_name, timestamp, metrics_json, candidates_json
            FROM recon_results
            WHERE func_ea = ? AND maturity = ?
            """,
            (int(func_ea), int(maturity)),
        )
        return [self._row_to_result(row, func_ea=func_ea, maturity=maturity)
                for row in cursor.fetchall()]

    def load_all_recon_results(self, *, func_ea: int) -> list[ReconResult]:
        """Load all collector results for a function across all maturities."""
        cursor = self._conn.execute(
            """
            SELECT collector_name, maturity, timestamp, metrics_json, candidates_json
            FROM recon_results
            WHERE func_ea = ?
            """,
            (int(func_ea),),
        )
        rows = cursor.fetchall()
        return [
            self._row_to_result(row, func_ea=func_ea, maturity=int(row["maturity"]))
            for row in rows
        ]

    def load_latest_recon_result(
        self,
        *,
        func_ea: int,
        collector_name: str,
        maturity: int | None = None,
    ) -> ReconResult | None:
        """Load the latest result for one collector.

        When *maturity* is provided, constrain the query to that maturity.
        Otherwise return the latest row across all maturities, ordered by
        maturity descending then timestamp descending.
        """
        if maturity is None:
            cursor = self._conn.execute(
                """
                SELECT maturity, collector_name, timestamp, metrics_json, candidates_json
                FROM recon_results
                WHERE func_ea = ? AND collector_name = ?
                ORDER BY maturity DESC, timestamp DESC
                LIMIT 1
                """,
                (int(func_ea), str(collector_name)),
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT maturity, collector_name, timestamp, metrics_json, candidates_json
                FROM recon_results
                WHERE func_ea = ? AND collector_name = ? AND maturity = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (int(func_ea), str(collector_name), int(maturity)),
            )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_result(row, func_ea=func_ea, maturity=int(row["maturity"]))

    @staticmethod
    def _row_to_result(
        row: sqlite3.Row, *, func_ea: int, maturity: int
    ) -> ReconResult:
        candidates = tuple(
            _candidate_from_dict(d)
            for d in json.loads(row["candidates_json"] or "[]")
        )
        return ReconResult(
            collector_name=str(row["collector_name"]),
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=float(row["timestamp"]),
            metrics=MappingProxyType(json.loads(row["metrics_json"] or "{}")),
            candidates=candidates,
        )

    # ------------------------------------------------------------------
    # DeobfuscationHints persistence
    # ------------------------------------------------------------------

    def save_hints(self, hints: DeobfuscationHints) -> None:
        """Upsert DeobfuscationHints for a function (primary key: func_ea)."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO deobfuscation_hints
                (func_ea, obfuscation_type, confidence,
                 recommended_inferences_json, candidates_json,
                 suppress_rules_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(hints.func_ea),
                hints.obfuscation_type,
                float(hints.confidence),
                json.dumps(list(hints.recommended_inferences)),
                json.dumps([_candidate_to_dict(c) for c in hints.candidates]),
                json.dumps(list(hints.suppress_rules)),
                time.time(),
            ),
        )
        self._conn.commit()

    def load_hints(self, *, func_ea: int) -> DeobfuscationHints | None:
        """Load DeobfuscationHints for a function, or None if not present."""
        cursor = self._conn.execute(
            """
            SELECT obfuscation_type, confidence, recommended_inferences_json,
                   candidates_json, suppress_rules_json
            FROM deobfuscation_hints
            WHERE func_ea = ?
            """,
            (int(func_ea),),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        candidates = tuple(
            _candidate_from_dict(d)
            for d in json.loads(row["candidates_json"] or "[]")
        )
        return DeobfuscationHints(
            func_ea=int(func_ea),
            obfuscation_type=row["obfuscation_type"],
            confidence=float(row["confidence"]),
            recommended_inferences=tuple(json.loads(row["recommended_inferences_json"] or "[]")),
            candidates=candidates,
            suppress_rules=tuple(json.loads(row["suppress_rules_json"] or "[]")),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Session summary persistence
    # ------------------------------------------------------------------

    def save_session_summary(
        self,
        func_ea: int,
        collectors_fired: int,
        classification: str,
        confidence: float,
        inferences: list[str],
        suppress_rules: list[str],
    ) -> None:
        """Persist per-function session summary (upsert)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO recon_session_summary "
            "(func_ea, timestamp, collectors_fired, classification, confidence, "
            "inferences_json, suppress_rules_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (func_ea, time.time(), collectors_fired, classification, confidence,
             json.dumps(inferences), json.dumps(suppress_rules)),
        )
        self._conn.commit()

    def load_session_summary(self, func_ea: int) -> dict | None:
        """Load persisted session summary for a function."""
        row = self._conn.execute(
            "SELECT * FROM recon_session_summary WHERE func_ea = ?",
            (func_ea,),
        ).fetchone()
        if row is None:
            return None
        return {
            "func_ea": row["func_ea"],
            "collectors_fired": row["collectors_fired"],
            "classification": row["classification"],
            "confidence": row["confidence"],
            "inferences": json.loads(row["inferences_json"]),
            "suppress_rules": json.loads(row["suppress_rules_json"]),
        }

    # ------------------------------------------------------------------
    # Consumer outcome persistence
    # ------------------------------------------------------------------

    def save_consumer_outcome(
        self,
        func_ea: int,
        consumer_name: str,
        artifacts_available: bool,
        summary_available: bool,
        verdict_applied: bool,
        detail: str = "",
        provenance_json: str = "",
    ) -> None:
        """Persist a consumer outcome record (upsert by func_ea + consumer_name)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO consumer_outcomes "
            "(func_ea, consumer_name, timestamp, artifacts_available, summary_available, "
            "verdict_applied, detail, provenance_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (func_ea, consumer_name, time.time(),
             int(artifacts_available), int(summary_available), int(verdict_applied),
             detail, provenance_json),
        )
        self._conn.commit()

    def load_consumer_outcomes(self, func_ea: int) -> list[dict]:
        """Load all consumer outcomes for a function."""
        rows = self._conn.execute(
            "SELECT * FROM consumer_outcomes WHERE func_ea = ? ORDER BY consumer_name",
            (func_ea,),
        ).fetchall()
        return [
            {
                "consumer_name": r["consumer_name"],
                "artifacts_available": bool(r["artifacts_available"]),
                "summary_available": bool(r["summary_available"]),
                "verdict_applied": bool(r["verdict_applied"]),
                "detail": r["detail"],
                "provenance_json": r["provenance_json"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Aggregate queries (for E2E pipeline assertions)
    # ------------------------------------------------------------------

    def count_functions_with_hints(self) -> int:
        """Count distinct functions that have deobfuscation hints."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT func_ea) AS cnt FROM deobfuscation_hints"
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def count_functions_with_session_summaries(self) -> int:
        """Count distinct functions that have session summaries."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT func_ea) AS cnt FROM recon_session_summary"
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def count_functions_with_consumer_outcomes(self) -> int:
        """Count distinct functions that have at least one consumer outcome."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT func_ea) AS cnt FROM consumer_outcomes"
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def list_functions_with_hints(self) -> list[int]:
        """Return sorted list of func_ea values that have hints."""
        rows = self._conn.execute(
            "SELECT DISTINCT func_ea FROM deobfuscation_hints ORDER BY func_ea"
        ).fetchall()
        return [int(r["func_ea"]) for r in rows]

    def list_functions_missing_session_summary(self) -> list[int]:
        """Return func_eas that have hints but no session summary."""
        rows = self._conn.execute(
            """
            SELECT DISTINCT h.func_ea
            FROM deobfuscation_hints h
            LEFT JOIN recon_session_summary s ON h.func_ea = s.func_ea
            WHERE s.func_ea IS NULL
            ORDER BY h.func_ea
            """
        ).fetchall()
        return [int(r["func_ea"]) for r in rows]

    def load_all_session_summaries(self) -> list[dict]:
        """Load all session summaries across all functions."""
        rows = self._conn.execute(
            "SELECT * FROM recon_session_summary ORDER BY func_ea"
        ).fetchall()
        return [
            {
                "func_ea": int(r["func_ea"]),
                "collectors_fired": int(r["collectors_fired"]),
                "classification": r["classification"],
                "confidence": float(r["confidence"]),
                "inferences": json.loads(r["inferences_json"]),
                "suppress_rules": json.loads(r["suppress_rules_json"]),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # User override persistence
    # ------------------------------------------------------------------

    def save_user_override(
        self,
        func_ea: int,
        override_type: str,
        override_value: str,
        confidence: float = 1.0,
    ) -> None:
        """Persist a user classification override (upsert)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO user_overrides "
            "(func_ea, override_type, override_value, confidence, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (func_ea, override_type, override_value, confidence, time.time()),
        )
        self._conn.commit()

    def load_user_override(
        self, func_ea: int, override_type: str = "classification"
    ) -> dict | None:
        """Load a user override for a function, or None."""
        row = self._conn.execute(
            "SELECT override_value, confidence FROM user_overrides "
            "WHERE func_ea = ? AND override_type = ?",
            (func_ea, override_type),
        ).fetchone()
        if row is None:
            return None
        return {"override_value": row["override_value"], "confidence": row["confidence"]}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def clear_func(self, *, func_ea: int) -> None:
        """Delete all stored data for a function except user overrides.

        User overrides persist across decompilation resets so that manual
        classifications survive re-analysis.
        """
        self._conn.execute(
            "DELETE FROM recon_results WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM deobfuscation_hints WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM recon_session_summary WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM consumer_outcomes WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> "ReconStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
