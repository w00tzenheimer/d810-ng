"""SQLite persistence layer for ReconResults and DeobfuscationHints.

Schema follows the existing pattern in ``core/persistence.py``:
- ``INSERT OR REPLACE`` for upsert semantics
- JSON columns for variable-length data (metrics, candidates, recipes)
- Composite primary key ``(func_ea, maturity, collector_name)`` for results
- Single primary key ``func_ea`` for hints

No IDA imports — fully unit-testable.
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
    recommended_recipes_json TEXT    NOT NULL,
    candidates_json          TEXT    NOT NULL,
    suppress_rules_json      TEXT    NOT NULL,
    updated_at               REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recon_func_ea
    ON recon_results(func_ea);
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
                 recommended_recipes_json, candidates_json,
                 suppress_rules_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(hints.func_ea),
                hints.obfuscation_type,
                float(hints.confidence),
                json.dumps(list(hints.recommended_recipes)),
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
            SELECT obfuscation_type, confidence, recommended_recipes_json,
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
            recommended_recipes=tuple(json.loads(row["recommended_recipes_json"] or "[]")),
            candidates=candidates,
            suppress_rules=tuple(json.loads(row["suppress_rules_json"] or "[]")),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def clear_func(self, *, func_ea: int) -> None:
        """Delete all stored data for a function (recon results + hints)."""
        self._conn.execute(
            "DELETE FROM recon_results WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM deobfuscation_hints WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> "ReconStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
