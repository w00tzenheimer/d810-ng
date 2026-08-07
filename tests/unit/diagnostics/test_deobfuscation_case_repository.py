from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from d810.core.deobfuscation_case import CaseEvidenceLevel, CaseFindingKind
from d810.diagnostics.deobfuscation_case_repository import (
    CaseDiagnosticRow,
    DeobfuscationCaseEvidenceError,
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


def _closed_case_database(
    path: Path,
    *,
    function_fingerprint: str = "native:fixture",
    malformed_provenance: bool = False,
    include_witness: bool = False,
) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE diagnostic_schema (singleton INTEGER PRIMARY KEY, version INTEGER);
        CREATE TABLE diagnostic_sessions (
            session_id TEXT PRIMARY KEY, func_ea_i64 INTEGER
        );
        CREATE TABLE deobfuscation_cases (
            case_id TEXT PRIMARY KEY, session_id TEXT, case_schema_version INTEGER,
            function_fingerprint TEXT, runtime_identity TEXT, run_identity TEXT,
            closed_status TEXT, closed_at REAL, verdict_level TEXT,
            verdict_summary TEXT, first_blocked_obligation TEXT, semantic_witness TEXT
        );
        CREATE TABLE deobfuscation_case_findings (
            case_id TEXT, finding_index INTEGER, finding_id TEXT,
            finding_kind TEXT, evidence_level TEXT, summary TEXT, detail TEXT,
            native_anchor_ea_i64 INTEGER, confidence REAL, provenance_json TEXT,
            blocked_obligation TEXT
        );
        CREATE TABLE deobfuscation_case_semantic_witnesses (
            case_id TEXT, witness_id TEXT, source_event_id INTEGER,
            verifier_id TEXT, native_anchor_ea_i64 INTEGER, summary TEXT
        );
        """
    )
    connection.execute("INSERT INTO diagnostic_schema VALUES (1, 11)")
    connection.execute("INSERT INTO diagnostic_sessions VALUES ('run-1', ?)", (0x1800020F0,))
    connection.execute(
        "INSERT INTO deobfuscation_cases VALUES "
        "('run-1:case-v1','run-1',1,?,'runtime:v1','run-1','finished',20.0,"
        "'c1_discovery','Discovery evidence was recorded.',NULL,NULL)",
        (function_fingerprint,),
    )
    provenance = "not-json" if malformed_provenance else '["lifecycle:1"]'
    connection.executemany(
        "INSERT INTO deobfuscation_case_findings VALUES "
        "('run-1:case-v1',?,?,?,?,?,?,?,?,?,?)",
        (
            (
                0,
                "environment:1",
                "observation",
                "c0_environment",
                "Environment evidence recorded.",
                "closed",
                0x1800020F0,
                1.0,
                provenance,
                None,
            ),
            (
                1,
                "identity-decision:2",
                "portable_evidence",
                "c1_discovery",
                "Identity evidence recorded.",
                "unique native block",
                0x1800020F0,
                1.0,
                '["lifecycle:2"]',
                None,
            ),
        ),
    )
    if include_witness:
        connection.execute(
            "UPDATE deobfuscation_cases SET verdict_level='c6_semantic_output',"
            "semantic_witness='witness-1' WHERE case_id='run-1:case-v1'"
        )
        connection.execute(
            "INSERT INTO deobfuscation_case_semantic_witnesses VALUES "
            "('run-1:case-v1','witness-1',2,'verifier',?,'semantic output verified')",
            (0x1800020F0,),
        )
    connection.commit()
    connection.close()
    return path


def test_sqlite_reader_projects_normalized_case_rows_without_log_parsing(
    tmp_path: Path,
) -> None:
    path = _closed_case_database(tmp_path / "case.diag.sqlite3")

    rows = SqliteCaseDiagnosticReader((path,)).case_records(
        function_ea=0x1800020F0,
        function_fingerprint=None,
    )

    assert [row.kind for row in rows] == [
        CaseFindingKind.OBSERVATION,
        CaseFindingKind.PORTABLE_EVIDENCE,
    ]
    assert [row.sequence for row in rows] == [0, 1]
    assert rows[-1].blocked_obligation is None
    assert rows[-1].native_ea == 0x1800020F0

    evidence = DeobfuscationCaseRepository(
        SqliteCaseDiagnosticReader((path,))
    ).load(0x1800020F0, "native:fixture")
    assert evidence is not None
    assert evidence.schema_version == 1
    assert evidence.runtime_identity == "runtime:v1"
    assert evidence.verdict.level is CaseEvidenceLevel.C1_DISCOVERY


def test_sqlite_reader_rejects_a_stale_native_preanalysis_fingerprint(
    tmp_path: Path,
) -> None:
    path = _closed_case_database(tmp_path / "case.diag.sqlite3")

    rows = SqliteCaseDiagnosticReader((path,)).case_records(
        function_ea=0x1800020F0,
        function_fingerprint="native:changed",
    )

    assert rows == ()


def test_sqlite_reader_rejects_malformed_normalized_provenance(
    tmp_path: Path,
) -> None:
    path = _closed_case_database(
        tmp_path / "case.diag.sqlite3",
        malformed_provenance=True,
    )

    with pytest.raises(DeobfuscationCaseEvidenceError, match="malformed provenance"):
        SqliteCaseDiagnosticReader((path,)).case_records(
            function_ea=0x1800020F0,
            function_fingerprint="native:fixture",
        )


def test_sqlite_reader_requires_a_semantic_witness_for_c6(
    tmp_path: Path,
) -> None:
    path = _closed_case_database(tmp_path / "case.diag.sqlite3", include_witness=False)
    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE deobfuscation_cases SET verdict_level='c6_semantic_output',"
        "semantic_witness='witness-1'"
    )
    connection.commit()
    connection.close()

    with pytest.raises(DeobfuscationCaseEvidenceError, match="without a semantic witness"):
        SqliteCaseDiagnosticReader((path,)).case_records(
            function_ea=0x1800020F0,
            function_fingerprint=None,
        )


def test_repository_accepts_a_closed_c6_case_with_a_witness(tmp_path: Path) -> None:
    path = _closed_case_database(
        tmp_path / "case.diag.sqlite3",
        include_witness=True,
    )

    evidence = DeobfuscationCaseRepository(
        SqliteCaseDiagnosticReader((path,))
    ).load(0x1800020F0, "native:fixture")

    assert evidence is not None
    assert evidence.verdict.level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
    assert evidence.verdict.semantic_witness == "witness-1"
    assert evidence.verdict.semantic_verified is True
