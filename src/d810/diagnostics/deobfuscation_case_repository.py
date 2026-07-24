"""Read-only projection of typed diagnostic rows into case evidence."""
from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path
from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
)
from d810.core.typing import Protocol

__all__ = [
    "CaseDiagnosticReader",
    "CaseDiagnosticRow",
    "DeobfuscationCaseEvidenceError",
    "DeobfuscationCaseRepository",
    "SqliteCaseDiagnosticReader",
]


class DeobfuscationCaseEvidenceError(ValueError):
    """Raised when a matching typed diagnostic trace is incomplete or invalid."""


@dataclasses.dataclass(frozen=True, slots=True)
class CaseDiagnosticRow:
    """One already-typed, chronologically ordered diagnostic fact."""

    finding_id: str
    sequence: int
    kind: CaseFindingKind
    summary: str
    detail: str
    native_ea: int | None
    confidence: float | None
    provenance: tuple[str, ...]
    evidence_level: CaseEvidenceLevel
    blocked_obligation: str | None = None

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise DeobfuscationCaseEvidenceError("finding_id must be non-empty")
        if self.sequence < 0:
            raise DeobfuscationCaseEvidenceError("sequence must be non-negative")
        if not isinstance(self.kind, CaseFindingKind):
            raise DeobfuscationCaseEvidenceError("kind must be a CaseFindingKind")
        if not isinstance(self.evidence_level, CaseEvidenceLevel):
            raise DeobfuscationCaseEvidenceError(
                "evidence_level must be a CaseEvidenceLevel"
            )
        if not self.summary.strip():
            raise DeobfuscationCaseEvidenceError("summary must be non-empty")
        if not self.provenance:
            raise DeobfuscationCaseEvidenceError("provenance must not be empty")
        if self.blocked_obligation is not None and not self.blocked_obligation.strip():
            raise DeobfuscationCaseEvidenceError(
                "blocked_obligation must be non-empty when present"
            )


class CaseDiagnosticReader(Protocol):
    """The narrow read-only port used by the case-evidence projection."""

    def case_records(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> tuple[CaseDiagnosticRow, ...]: ...


class SqliteCaseDiagnosticReader:
    """Read the supported v7 lifecycle schema without opening it for writing."""

    _SUPPORTED_SCHEMA_VERSION = 7
    _REQUIRED_TABLES = frozenset(
        {
            "diagnostic_schema",
            "diagnostic_sessions",
            "lifecycle_events",
            "evidence_generation_events",
            "identity_decisions",
            "mutation_plan_items",
            "mutation_receipts",
            "mutation_receipt_identities",
        }
    )

    def __init__(self, paths: tuple[Path, ...]) -> None:
        self._paths = tuple(Path(path).expanduser().resolve() for path in paths)

    def case_records(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> tuple[CaseDiagnosticRow, ...]:
        candidates: list[tuple[float, tuple[CaseDiagnosticRow, ...]]] = []
        for path in self._paths:
            rows, started_at = self._records_for_path(path, int(function_ea))
            if rows:
                candidates.append((started_at, rows))
        if not candidates:
            return ()
        _, rows = max(candidates, key=lambda item: item[0])
        return rows

    def _records_for_path(
        self,
        path: Path,
        function_ea: int,
    ) -> tuple[tuple[CaseDiagnosticRow, ...], float]:
        if not path.is_file():
            return (), float("-inf")
        wal_path = Path(str(path) + "-wal")
        if wal_path.exists() and wal_path.stat().st_size:
            raise DeobfuscationCaseEvidenceError(
                f"uncheckpointed WAL is not readable: {path}"
            )
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            self._require_schema(connection, path)
            session = connection.execute(
                "SELECT session_id,started_at FROM diagnostic_sessions "
                "WHERE func_ea_i64=? ORDER BY started_at DESC,session_id DESC LIMIT 1",
                (function_ea,),
            ).fetchone()
            if session is None:
                return (), float("-inf")
            session_id = str(session["session_id"])
            rows = tuple(
                row
                for event in connection.execute(
                    "SELECT event_id,event_seq,event_kind,summary FROM lifecycle_events "
                    "WHERE session_id=? AND func_ea_i64=? ORDER BY event_seq,event_id",
                    (session_id, function_ea),
                )
                if (row := self._project_event(connection, session_id, event)) is not None
            )
            return rows, float(session["started_at"])
        finally:
            connection.close()

    def _require_schema(self, connection: sqlite3.Connection, path: Path) -> None:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = sorted(self._REQUIRED_TABLES.difference(tables))
        if missing:
            raise DeobfuscationCaseEvidenceError(
                f"unsupported diagnostic schema missing tables: {', '.join(missing)}"
            )
        row = connection.execute(
            "SELECT version FROM diagnostic_schema WHERE singleton=1"
        ).fetchone()
        observed = None if row is None else int(row[0])
        if observed != self._SUPPORTED_SCHEMA_VERSION:
            raise DeobfuscationCaseEvidenceError(
                "unsupported diagnostic schema version: "
                f"expected {self._SUPPORTED_SCHEMA_VERSION}, observed {observed!r} at {path}"
            )

    @staticmethod
    def _project_event(
        connection: sqlite3.Connection,
        session_id: str,
        event: sqlite3.Row,
    ) -> CaseDiagnosticRow | None:
        event_id = int(event["event_id"])
        sequence = int(event["event_seq"])
        event_kind = str(event["event_kind"])
        summary = str(event["summary"])
        provenance = (f"diagnostic-session:{session_id}", f"lifecycle-event:{event_id}")
        if event_kind == "evidence_generation":
            record = connection.execute(
                "SELECT outcome,reason FROM evidence_generation_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if record is None:
                raise DeobfuscationCaseEvidenceError(
                    f"evidence event {event_id} has no typed detail row"
                )
            accepted = str(record["outcome"]) == "accepted"
            return CaseDiagnosticRow(
                finding_id=f"evidence:{event_id}",
                sequence=sequence,
                kind=(
                    CaseFindingKind.OBSERVATION
                    if accepted
                    else CaseFindingKind.REJECTION
                ),
                summary=summary,
                detail=str(record["reason"]),
                native_ea=None,
                confidence=1.0 if accepted else 0.0,
                provenance=provenance,
                evidence_level=(
                    CaseEvidenceLevel.C1_DISCOVERY
                    if accepted
                    else CaseEvidenceLevel.C0_ENVIRONMENT
                ),
                blocked_obligation=None if accepted else str(record["reason"]),
            )
        if event_kind == "identity_decision":
            record = connection.execute(
                "SELECT outcome,reason,primary_anchor_ea_i64 FROM identity_decisions "
                "WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if record is None or record["primary_anchor_ea_i64"] is None:
                raise DeobfuscationCaseEvidenceError(
                    f"identity event {event_id} lacks its native EA anchor"
                )
            accepted = str(record["outcome"]) == "accepted"
            return CaseDiagnosticRow(
                finding_id=f"identity:{event_id}",
                sequence=sequence,
                kind=(
                    CaseFindingKind.PORTABLE_EVIDENCE
                    if accepted
                    else CaseFindingKind.REJECTION
                ),
                summary=summary,
                detail=str(record["reason"]),
                native_ea=int(record["primary_anchor_ea_i64"]),
                confidence=1.0 if accepted else 0.0,
                provenance=provenance,
                evidence_level=CaseEvidenceLevel.C1_DISCOVERY,
                blocked_obligation=None if accepted else str(record["reason"]),
            )
        if event_kind == "mutation_plan":
            record = connection.execute(
                "SELECT source_anchor_ea_i64,target_anchor_ea_i64,reason "
                "FROM mutation_plan_items WHERE event_id=? ORDER BY item_index LIMIT 1",
                (event_id,),
            ).fetchone()
            if record is None:
                raise DeobfuscationCaseEvidenceError(
                    f"plan event {event_id} has no typed plan item"
                )
            anchor = record["source_anchor_ea_i64"] or record["target_anchor_ea_i64"]
            if anchor is None:
                raise DeobfuscationCaseEvidenceError(
                    f"plan event {event_id} lacks its native EA anchor"
                )
            return CaseDiagnosticRow(
                finding_id=f"plan:{event_id}",
                sequence=sequence,
                kind=CaseFindingKind.FRAGMENT_PLAN,
                summary=summary,
                detail=str(record["reason"]),
                native_ea=int(anchor),
                confidence=1.0,
                provenance=provenance,
                evidence_level=CaseEvidenceLevel.C1_DISCOVERY,
            )
        if event_kind == "mutation_receipt":
            record = connection.execute(
                "SELECT outcome,reason FROM mutation_receipts WHERE event_id=?",
                (event_id,),
            ).fetchone()
            anchor_row = connection.execute(
                "SELECT primary_anchor_ea_i64 FROM mutation_receipt_identities "
                "WHERE event_id=? ORDER BY identity_index LIMIT 1",
                (event_id,),
            ).fetchone()
            if record is None or anchor_row is None:
                raise DeobfuscationCaseEvidenceError(
                    f"receipt event {event_id} lacks typed receipt identity"
                )
            committed = str(record["outcome"]) == "committed"
            return CaseDiagnosticRow(
                finding_id=f"receipt:{event_id}",
                sequence=sequence,
                kind=CaseFindingKind.RECEIPT if committed else CaseFindingKind.REJECTION,
                summary=summary,
                detail=str(record["reason"]),
                native_ea=int(anchor_row["primary_anchor_ea_i64"]),
                confidence=1.0 if committed else 0.0,
                provenance=provenance,
                evidence_level=(
                    CaseEvidenceLevel.C5_PUBLICATION
                    if committed
                    else CaseEvidenceLevel.C1_DISCOVERY
                ),
                blocked_obligation=None if committed else str(record["reason"]),
            )
        return None


_LEVEL_ORDER = {
    level: index for index, level in enumerate(CaseEvidenceLevel)
}

_LEVEL_SUMMARIES = {
    CaseEvidenceLevel.C0_ENVIRONMENT: "Environment evidence recorded.",
    CaseEvidenceLevel.C1_DISCOVERY: "Discovery evidence recorded.",
    CaseEvidenceLevel.C2_NORMALIZATION: "Normalization evidence recorded.",
    CaseEvidenceLevel.C3_CANONICAL_PLAN: "Canonical plan recorded.",
    CaseEvidenceLevel.C4_STAGED_PROOF: "Staged proof recorded.",
    CaseEvidenceLevel.C5_PUBLICATION: "Publication receipt committed.",
    CaseEvidenceLevel.C6_SEMANTIC_OUTPUT: "Semantic result verified.",
}


class DeobfuscationCaseRepository:
    """Build immutable case evidence without inferring facts from log text."""

    def __init__(self, reader: CaseDiagnosticReader) -> None:
        self._reader = reader

    def load(
        self,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> DeobfuscationCaseEvidence | None:
        rows = self._reader.case_records(
            function_ea=int(function_ea),
            function_fingerprint=function_fingerprint,
        )
        if not rows:
            return None
        ordered = tuple(sorted(rows, key=lambda row: row.sequence))
        self._validate(ordered)
        findings = tuple(
            CaseFinding(
                finding_id=row.finding_id,
                kind=row.kind,
                summary=row.summary,
                detail=row.detail,
                native_ea=row.native_ea,
                confidence=row.confidence,
                provenance=row.provenance,
            )
            for row in ordered
        )
        level = max(ordered, key=lambda row: _LEVEL_ORDER[row.evidence_level]).evidence_level
        blocked_obligation = next(
            (row.blocked_obligation for row in ordered if row.blocked_obligation),
            None,
        )
        if level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT:
            raise DeobfuscationCaseEvidenceError(
                "C6 requires an explicit semantic witness row"
            )
        return DeobfuscationCaseEvidence(
            schema_version=1,
            function_fingerprint=function_fingerprint or f"ea:{int(function_ea):x}",
            runtime_identity="diagnostic-runtime",
            run_identity=ordered[0].provenance[0],
            findings=findings,
            verdict=CaseVerdict(
                level=level,
                summary=_LEVEL_SUMMARIES[level],
                first_blocked_obligation=blocked_obligation,
            ),
        )

    @staticmethod
    def _validate(rows: tuple[CaseDiagnosticRow, ...]) -> None:
        sequences = tuple(row.sequence for row in rows)
        if len(set(sequences)) != len(sequences):
            raise DeobfuscationCaseEvidenceError("duplicate diagnostic sequences")
        finding_ids = tuple(row.finding_id for row in rows)
        if len(set(finding_ids)) != len(finding_ids):
            raise DeobfuscationCaseEvidenceError("duplicate diagnostic finding ids")
