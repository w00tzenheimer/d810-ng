from __future__ import annotations

import sqlite3
from pathlib import Path

from d810.core.deobfuscation_case import CaseEvidenceLevel, CaseFindingKind
from d810.diagnostics.deobfuscation_case_repository import (
    CaseDiagnosticRow,
    DeobfuscationCaseRepository,
    SqliteCaseDiagnosticReader,
)


class _Reader:
    def __init__(self, rows: tuple[CaseDiagnosticRow, ...]) -> None:
        self._rows = rows

    def case_records(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> tuple[CaseDiagnosticRow, ...]:
        assert function_ea == 0x1800020F0
        assert function_fingerprint == "native-key:fixture"
        return self._rows


def _row(
    finding_id: str,
    sequence: int,
    *,
    kind: CaseFindingKind,
    native_ea: int | None,
    level: CaseEvidenceLevel,
    blocked_obligation: str | None = None,
) -> CaseDiagnosticRow:
    return CaseDiagnosticRow(
        finding_id=finding_id,
        sequence=sequence,
        kind=kind,
        summary=f"{kind.value} evidence",
        detail="typed diagnostic row",
        native_ea=native_ea,
        confidence=1.0,
        provenance=(f"lifecycle-event:{sequence}",),
        evidence_level=level,
        blocked_obligation=blocked_obligation,
    )


def test_repository_builds_a_chronological_case_trace_from_typed_rows() -> None:
    repository = DeobfuscationCaseRepository(
        _Reader(
            (
                _row(
                    "observation:10",
                    10,
                    kind=CaseFindingKind.OBSERVATION,
                    native_ea=None,
                    level=CaseEvidenceLevel.C0_ENVIRONMENT,
                ),
                _row(
                    "identity:20",
                    20,
                    kind=CaseFindingKind.PORTABLE_EVIDENCE,
                    native_ea=0x1800020F0,
                    level=CaseEvidenceLevel.C1_DISCOVERY,
                ),
                _row(
                    "plan:30",
                    30,
                    kind=CaseFindingKind.FRAGMENT_PLAN,
                    native_ea=0x1800020F0,
                    level=CaseEvidenceLevel.C1_DISCOVERY,
                ),
                _row(
                    "rejection:40",
                    40,
                    kind=CaseFindingKind.REJECTION,
                    native_ea=0x1800020F0,
                    level=CaseEvidenceLevel.C1_DISCOVERY,
                    blocked_obligation="unique realization failed",
                ),
            )
        )
    )

    evidence = repository.load(0x1800020F0, "native-key:fixture")

    assert evidence is not None
    assert [finding.finding_id for finding in evidence.findings] == [
        "observation:10",
        "identity:20",
        "plan:30",
        "rejection:40",
    ]
    assert evidence.verdict.level is CaseEvidenceLevel.C1_DISCOVERY
    assert evidence.verdict.first_blocked_obligation == "unique realization failed"
    assert evidence.verdict.semantic_verified is False


def test_repository_returns_none_when_no_typed_rows_match() -> None:
    repository = DeobfuscationCaseRepository(_Reader(()))

    assert repository.load(0x1800020F0, "native-key:fixture") is None


def _lifecycle_database(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE diagnostic_schema (singleton INTEGER PRIMARY KEY, version INTEGER);
        CREATE TABLE diagnostic_sessions (
            session_id TEXT PRIMARY KEY, func_ea_i64 INTEGER,
            native_key_json TEXT, started_at REAL
        );
        CREATE TABLE lifecycle_events (
            event_id INTEGER PRIMARY KEY, session_id TEXT, event_seq INTEGER,
            timestamp REAL, event_kind TEXT, func_ea_i64 INTEGER, summary TEXT
        );
        CREATE TABLE evidence_generation_events (
            event_id INTEGER PRIMARY KEY, outcome TEXT, reason TEXT
        );
        CREATE TABLE identity_decisions (
            event_id INTEGER PRIMARY KEY, outcome TEXT, reason TEXT,
            primary_anchor_ea_i64 INTEGER
        );
        CREATE TABLE mutation_plan_items (
            event_id INTEGER, item_index INTEGER, source_anchor_ea_i64 INTEGER,
            target_anchor_ea_i64 INTEGER, reason TEXT
        );
        CREATE TABLE mutation_receipts (
            event_id INTEGER PRIMARY KEY, mutation_batch_id TEXT,
            outcome TEXT, reason TEXT
        );
        CREATE TABLE mutation_receipt_identities (
            event_id INTEGER, identity_index INTEGER,
            primary_anchor_ea_i64 INTEGER
        );
        INSERT INTO diagnostic_schema VALUES (1, 7);
        INSERT INTO diagnostic_sessions VALUES ('run-1', 6442459376, '{"ea":6442459376}', 10.0);
        INSERT INTO lifecycle_events VALUES
            (1, 'run-1', 1, 11.0, 'evidence_generation', 6442459376, 'native evidence accepted'),
            (2, 'run-1', 2, 12.0, 'identity_decision', 6442459376, 'identity accepted'),
            (3, 'run-1', 3, 13.0, 'mutation_plan', 6442459376, 'fragment planned'),
            (4, 'run-1', 4, 14.0, 'mutation_receipt', 6442459376, 'fragment aborted');
        INSERT INTO evidence_generation_events VALUES (1, 'accepted', 'native facts ready');
        INSERT INTO identity_decisions VALUES (2, 'accepted', 'unique native block', 6442459376);
        INSERT INTO mutation_plan_items VALUES (3, 0, 6442459376, NULL, 'plan item');
        INSERT INTO mutation_receipts VALUES (4, 'batch-1', 'aborted', 'unique realization failed');
        INSERT INTO mutation_receipt_identities VALUES (4, 0, 6442459376);
        """
    )
    connection.commit()
    connection.close()
    return path


def test_sqlite_reader_projects_typed_lifecycle_rows_without_log_parsing(
    tmp_path: Path,
) -> None:
    path = _lifecycle_database(tmp_path / "case.diag.sqlite3")

    rows = SqliteCaseDiagnosticReader((path,)).case_records(
        function_ea=0x1800020F0,
        function_fingerprint=None,
    )

    assert [row.kind for row in rows] == [
        CaseFindingKind.OBSERVATION,
        CaseFindingKind.PORTABLE_EVIDENCE,
        CaseFindingKind.FRAGMENT_PLAN,
        CaseFindingKind.REJECTION,
    ]
    assert [row.sequence for row in rows] == [1, 2, 3, 4]
    assert rows[-1].blocked_obligation == "unique realization failed"
    assert rows[-1].native_ea == 0x1800020F0
