"""Read-only projection of normalized producer-owned deobfuscation cases.

The producer materializes one closed, versioned case in schema 10.  The UI
must consume those rows directly; it must not infer a case by replaying raw
lifecycle events or parsing diagnostic log text.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from pathlib import Path

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
)
from d810.core.diag.schema import DIAGNOSTIC_SCHEMA_VERSION
from d810.core.typing import Protocol

__all__ = [
    "CaseDiagnosticReader",
    "CaseDiagnosticRow",
    "DeobfuscationCaseEvidenceError",
    "DeobfuscationCaseRepository",
    "SqliteCaseDiagnosticReader",
]


class DeobfuscationCaseEvidenceError(ValueError):
    """Raised when a matching normalized case is incomplete or invalid."""


@dataclasses.dataclass(frozen=True, slots=True)
class CaseDiagnosticRow:
    """One normalized case finding, retaining the closed-case metadata."""

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
    semantic_witness: str | None = None
    case_schema_version: int = 1
    function_fingerprint: str | None = None
    runtime_identity: str | None = None
    run_identity: str | None = None
    verdict_summary: str | None = None
    verdict_level: CaseEvidenceLevel | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.finding_id, str) or not self.finding_id.strip():
            raise DeobfuscationCaseEvidenceError("finding_id must be non-empty")
        if self.sequence < 0:
            raise DeobfuscationCaseEvidenceError("sequence must be non-negative")
        if not isinstance(self.kind, CaseFindingKind):
            raise DeobfuscationCaseEvidenceError("kind must be a CaseFindingKind")
        if not isinstance(self.evidence_level, CaseEvidenceLevel):
            raise DeobfuscationCaseEvidenceError(
                "evidence_level must be a CaseEvidenceLevel"
            )
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise DeobfuscationCaseEvidenceError("summary must be non-empty")
        if not self.provenance:
            raise DeobfuscationCaseEvidenceError("provenance must not be empty")
        if any(not isinstance(value, str) or not value.strip() for value in self.provenance):
            raise DeobfuscationCaseEvidenceError("provenance must contain text")
        if self.blocked_obligation is not None and not self.blocked_obligation.strip():
            raise DeobfuscationCaseEvidenceError(
                "blocked_obligation must be non-empty when present"
            )
        if self.semantic_witness is not None and not self.semantic_witness.strip():
            raise DeobfuscationCaseEvidenceError(
                "semantic_witness must be non-empty when present"
            )
        if self.case_schema_version < 1:
            raise DeobfuscationCaseEvidenceError("case_schema_version must be positive")


class CaseDiagnosticReader(Protocol):
    """The narrow read-only port used by the case-evidence projection."""

    def case_records(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> tuple[CaseDiagnosticRow, ...]: ...


class SqliteCaseDiagnosticReader:
    """Read closed producer cases without opening a diagnostic DB for writing."""

    _SUPPORTED_SCHEMA_VERSION = DIAGNOSTIC_SCHEMA_VERSION
    _REQUIRED_COLUMNS = {
        "diagnostic_schema": frozenset({"singleton", "version"}),
        "diagnostic_sessions": frozenset({"session_id", "func_ea_i64"}),
        "deobfuscation_cases": frozenset(
            {
                "case_id",
                "session_id",
                "case_schema_version",
                "function_fingerprint",
                "runtime_identity",
                "run_identity",
                "closed_status",
                "closed_at",
                "verdict_level",
                "verdict_summary",
                "first_blocked_obligation",
                "semantic_witness",
            }
        ),
        "deobfuscation_case_findings": frozenset(
            {
                "case_id",
                "finding_index",
                "finding_id",
                "finding_kind",
                "evidence_level",
                "summary",
                "detail",
                "native_anchor_ea_i64",
                "confidence",
                "provenance_json",
                "blocked_obligation",
            }
        ),
        "deobfuscation_case_semantic_witnesses": frozenset(
            {
                "case_id",
                "witness_id",
                "verifier_id",
                "native_anchor_ea_i64",
                "summary",
            }
        ),
    }

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
            rows, closed_at = self._records_for_path(
                path,
                int(function_ea),
                function_fingerprint,
            )
            if rows:
                candidates.append((closed_at, rows))
        if not candidates:
            return ()
        _, rows = max(candidates, key=lambda item: item[0])
        return rows

    def _records_for_path(
        self,
        path: Path,
        function_ea: int,
        function_fingerprint: str | None,
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
            case = connection.execute(
                "SELECT c.case_id,c.session_id,c.case_schema_version,"
                "c.function_fingerprint,c.runtime_identity,c.run_identity,"
                "c.closed_status,c.closed_at,c.verdict_level,c.verdict_summary,"
                "c.first_blocked_obligation,c.semantic_witness "
                "FROM deobfuscation_cases c "
                "JOIN diagnostic_sessions s ON s.session_id=c.session_id "
                "WHERE s.func_ea_i64=? AND c.closed_status IN ('finished','failed') "
                "ORDER BY c.closed_at DESC,c.case_id DESC LIMIT 1",
                (function_ea,),
            ).fetchone()
            if case is None:
                return (), float("-inf")
            if (
                function_fingerprint is not None
                and str(case["function_fingerprint"]) != function_fingerprint
            ):
                return (), float("-inf")
            case_id = str(case["case_id"])
            rows = tuple(
                self._project_finding(connection, case, row)
                for row in connection.execute(
                    "SELECT finding_index,finding_id,finding_kind,evidence_level,"
                    "summary,detail,native_anchor_ea_i64,confidence,"
                    "provenance_json,blocked_obligation "
                    "FROM deobfuscation_case_findings "
                    "WHERE case_id=? ORDER BY finding_index,finding_id",
                    (case_id,),
                )
            )
            if not rows:
                raise DeobfuscationCaseEvidenceError(
                    f"closed case {case_id} has no normalized findings"
                )
            if str(case["verdict_level"]) == CaseEvidenceLevel.C6_SEMANTIC_OUTPUT.value:
                witness = connection.execute(
                    "SELECT 1 FROM deobfuscation_case_semantic_witnesses "
                    "WHERE case_id=? LIMIT 1",
                    (case_id,),
                ).fetchone()
                if witness is None or case["semantic_witness"] is None:
                    raise DeobfuscationCaseEvidenceError(
                        f"closed case {case_id} claims C6 without a semantic witness"
                    )
            return rows, float(case["closed_at"])
        finally:
            connection.close()

    def _require_schema(self, connection: sqlite3.Connection, path: Path) -> None:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing_tables = sorted(set(self._REQUIRED_COLUMNS).difference(tables))
        if missing_tables:
            raise DeobfuscationCaseEvidenceError(
                "unsupported diagnostic schema missing tables: "
                + ", ".join(missing_tables)
            )
        for table, required in self._REQUIRED_COLUMNS.items():
            available = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            missing_columns = sorted(required.difference(available))
            if missing_columns:
                raise DeobfuscationCaseEvidenceError(
                    "unsupported diagnostic schema missing columns for "
                    f"{table}: {', '.join(missing_columns)}"
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
    def _project_finding(
        _connection: sqlite3.Connection,
        case: sqlite3.Row,
        row: sqlite3.Row,
    ) -> CaseDiagnosticRow:
        try:
            kind = CaseFindingKind(str(row["finding_kind"]))
            level = CaseEvidenceLevel(str(row["evidence_level"]))
            verdict_level = CaseEvidenceLevel(str(case["verdict_level"]))
        except ValueError as exc:
            raise DeobfuscationCaseEvidenceError(
                f"unsupported normalized case finding enum for {row['finding_id']}"
            ) from exc
        try:
            provenance_value = json.loads(str(row["provenance_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DeobfuscationCaseEvidenceError(
                f"malformed provenance for case finding {row['finding_id']}"
            ) from exc
        if not isinstance(provenance_value, list) or any(
            not isinstance(value, str) or not value.strip() for value in provenance_value
        ):
            raise DeobfuscationCaseEvidenceError(
                f"malformed provenance for case finding {row['finding_id']}"
            )
        witness = case["semantic_witness"]
        return CaseDiagnosticRow(
            finding_id=str(row["finding_id"]),
            sequence=int(row["finding_index"]),
            kind=kind,
            summary=str(row["summary"]),
            detail=str(row["detail"]),
            native_ea=(
                None
                if row["native_anchor_ea_i64"] is None
                else int(row["native_anchor_ea_i64"])
            ),
            confidence=(
                None if row["confidence"] is None else float(row["confidence"])
            ),
            provenance=tuple(provenance_value),
            evidence_level=level,
            blocked_obligation=(
                None
                if row["blocked_obligation"] is None
                else str(row["blocked_obligation"])
            ),
            semantic_witness=None if witness is None else str(witness),
            case_schema_version=int(case["case_schema_version"]),
            function_fingerprint=str(case["function_fingerprint"]),
            runtime_identity=str(case["runtime_identity"]),
            run_identity=str(case["run_identity"]),
            verdict_summary=str(case["verdict_summary"]),
            verdict_level=verdict_level,
        )


_LEVEL_ORDER = {level: index for index, level in enumerate(CaseEvidenceLevel)}


class DeobfuscationCaseRepository:
    """Build immutable case evidence from normalized producer rows."""

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
        first = ordered[0]
        level = first.verdict_level or first.evidence_level
        if first.verdict_level is None:
            for row in ordered[1:]:
                if _LEVEL_ORDER[row.evidence_level] > _LEVEL_ORDER[level]:
                    level = row.evidence_level
        semantic_witness = next(
            (row.semantic_witness for row in ordered if row.semantic_witness),
            None,
        )
        if level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT and semantic_witness is None:
            raise DeobfuscationCaseEvidenceError(
                "C6 requires an explicit semantic witness row"
            )
        blocked_obligation = next(
            (row.blocked_obligation for row in ordered if row.blocked_obligation),
            None,
        )
        evidence = DeobfuscationCaseEvidence(
            schema_version=first.case_schema_version,
            function_fingerprint=first.function_fingerprint
            or function_fingerprint
            or f"ea:{int(function_ea):x}",
            runtime_identity=first.runtime_identity or "diagnostic-runtime",
            run_identity=first.run_identity or first.provenance[0],
            findings=tuple(
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
            ),
            verdict=CaseVerdict(
                level=level,
                summary=first.verdict_summary
                or f"{level.value} evidence recorded.",
                first_blocked_obligation=blocked_obligation,
                semantic_witness=semantic_witness,
            ),
        )
        return evidence

    @staticmethod
    def _validate(rows: tuple[CaseDiagnosticRow, ...]) -> None:
        sequences = tuple(row.sequence for row in rows)
        if len(set(sequences)) != len(sequences):
            raise DeobfuscationCaseEvidenceError("duplicate diagnostic sequences")
        finding_ids = tuple(row.finding_id for row in rows)
        if len(set(finding_ids)) != len(finding_ids):
            raise DeobfuscationCaseEvidenceError("duplicate diagnostic finding ids")
