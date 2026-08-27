"""Transactional SQLite persistence for portable MBA residual discovery."""

from __future__ import annotations

import json
import math
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from d810.mba.differential_report import outcome_from_dict
from d810.mba.discovery_models import (
    ClaimReceipt,
    DiscoveryAttempt,
    DiscoveryReceipt,
    DiscoveryStatus,
    HeartbeatReceipt,
    LifecycleReceipt,
    MiningClaim,
    MiningRun,
    MiningRunState,
    Proposal,
    ProposalState,
    ReceiptStatus,
    ResidualGroup,
    ResidualGroupState,
    valid_group_transition,
    valid_proposal_transition,
)
from d810.mba.provider_outcome import MbaProviderOutcome
from d810.mba.term_codec import (
    TERM_WIRE_SCHEMA_VERSION,
    typed_term_from_dict,
    typed_term_to_dict,
)
from d810.mba.typed_term import TypedBvTerm, term_fingerprint
from d810.core.typing import Iterator


SCHEMA_VERSION = 1

_TABLES: dict[str, tuple[str, ...]] = {
    "schema_migrations": ("version", "applied_at"),
    "inputs": (
        "input_id",
        "input_identity",
        "identity_provenance",
        "external_evidence_allowed",
    ),
    "databases": ("database_id", "database_uuid", "database_identity", "input_id"),
    "functions": (
        "function_id",
        "database_id",
        "function_ea",
        "function_rva",
        "function_fingerprint",
    ),
    "terms": (
        "term_id",
        "canonical_fingerprint",
        "width",
        "canonical_term",
        "canonical_codec_version",
    ),
    "raw_terms": (
        "raw_term_id",
        "term_id",
        "raw_fingerprint",
        "raw_term",
        "raw_codec_version",
    ),
    "provider_attempts": (
        "attempt_id",
        "attempt_uuid",
        "function_id",
        "term_id",
        "raw_term_id",
        "session_id",
        "top_level_epoch",
        "evidence_generation",
        "maturity",
        "instruction_ea",
        "block_serial",
        "block_ea",
        "provider",
        "plugin_name",
        "plugin_version",
        "status",
        "input_cost_ops",
        "input_cost_nodes",
        "output_cost_ops",
        "output_cost_nodes",
        "proof_verdict",
        "elapsed_ms",
        "refusal_reason",
        "outcome_payload",
        "created_at",
    ),
    "residual_groups": (
        "group_id",
        "term_id",
        "state",
        "eligible_observation_count",
        "last_observed_at",
        "last_mined_at",
        "materialized_at",
        "admitted_at",
        "revision",
    ),
    "mining_runs": (
        "run_id",
        "group_id",
        "claimed_revision",
        "miner_version",
        "budget_fingerprint",
        "state",
        "started_at",
        "heartbeat_at",
        "finished_at",
        "failure_reason",
    ),
    "proposals": (
        "proposal_id",
        "group_id",
        "run_id",
        "proposal_fingerprint",
        "replacement_term",
        "proposal_payload",
        "proof_receipt_payload",
        "state",
        "created_at",
        "materialized_path",
        "materialized_digest",
        "materialized_at",
        "admitted_rule_id",
        "admitted_at",
        "rejection_reason",
    ),
}

_INDEXES = {
    "idx_residual_groups_claim",
    "idx_mining_runs_lease",
    "idx_provider_attempts_term",
    "idx_provider_attempts_function",
    "idx_provider_attempts_provider",
    "idx_proposals_group_state",
}


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant: {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite JSON number: {value}")
    return number


def _strict_loads(payload: bytes) -> object:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid deterministic JSON payload") from exc


def _same_json(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _same_json(left[key], right[key])
            for key in left  # type: ignore[index]
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json(a, b)
            for a, b in zip(left, right)  # type: ignore[arg-type]
        )
    return left == right


def _json_bytes(value: object, *, name: str) -> bytes:
    if type(value) is bytes:
        payload = value
        decoded = _strict_loads(payload)
    else:
        try:
            payload = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"{name} must be finite JSON") from exc
        decoded = _strict_loads(payload)
    try:
        canonical = json.dumps(
            decoded,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be canonical JSON") from exc
    if payload != canonical or not _same_json(decoded, _strict_loads(canonical)):
        raise ValueError(f"{name} must use deterministic compact JSON")
    return payload


def _term_bytes(term: TypedBvTerm, *, name: str) -> bytes:
    try:
        payload = json.dumps(
            typed_term_to_dict(term),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        decoded = typed_term_from_dict(_strict_loads(payload))  # type: ignore[arg-type]
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError(f"{name} is not canonically representable") from exc
    if decoded != term:
        raise ValueError(f"{name} is not canonically representable")
    return payload


def _decode_term(payload: bytes, *, name: str) -> TypedBvTerm:
    decoded = _strict_loads(payload)
    try:
        term = typed_term_from_dict(decoded)  # type: ignore[arg-type]
        if _term_bytes(term, name=name) != payload:
            raise ValueError(f"{name} bytes are not canonical")
        return term
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError(f"invalid {name} bytes") from exc


def _outcome_bytes(outcome: MbaProviderOutcome) -> bytes:
    payload = outcome.to_json().encode("utf-8")
    decoded = _strict_loads(payload)
    try:
        restored = outcome_from_dict(decoded)  # type: ignore[arg-type]
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise ValueError("outcome is not canonically representable") from exc
    if restored.to_json().encode("utf-8") != payload:
        raise ValueError("outcome is not canonically representable")
    return payload


def _timestamp(value: object) -> str:
    if isinstance(value, datetime):
        current = value
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
        return current.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if type(value) is str and value:
        return value
    raise TypeError("clock must return a datetime or timestamp string")


def _seconds(value: object) -> float:
    if isinstance(value, timedelta):
        result = value.total_seconds()
    elif type(value) in (int, float):
        result = float(value)
    else:
        raise TypeError("lease_timeout must be seconds or timedelta")
    if not math.isfinite(result) or result <= 0:
        raise ValueError("lease_timeout must be positive and finite")
    return result


class MbaDiscoveryStore:
    """The sole owner of schema and lifecycle mutations for MBA discovery."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: object = datetime.now,
        uuid_factory: object = uuid4,
    ) -> None:
        self.path = str(path)
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._lock = threading.RLock()
        self._closed = False
        self._last_lease_timeout = 300.0
        self._connection = sqlite3.connect(
            self.path, timeout=5.0, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure_and_migrate()
        except Exception:
            self._connection.close()
            self._closed = True
            raise

    def _now(self) -> str:
        return _timestamp(self._clock())  # type: ignore[operator]

    def _new_uuid(self) -> str:
        value = self._uuid_factory()  # type: ignore[operator]
        if isinstance(value, UUID):
            return str(value)
        if type(value) is str:
            try:
                return str(UUID(value))
            except ValueError as exc:
                raise ValueError("uuid factory returned an invalid UUID") from exc
        raise TypeError("uuid factory must return a UUID or string")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("discovery store is closed")

    @contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        self._ensure_open()
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                yield self._connection
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _configure_and_migrate(self) -> None:
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys=ON")
            if self._connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise ValueError("foreign key enforcement is unavailable")
            self._connection.execute("PRAGMA busy_timeout=5000")
            journal = self._connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if self.path != ":memory:" and str(journal).lower() != "wal":
                raise ValueError("WAL journal mode could not be enabled")
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                migration_exists = self._connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
                ).fetchone()
                any_expected = self._connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name IN (%s) LIMIT 1"
                    % ",".join("?" for _ in _TABLES),
                    tuple(_TABLES),
                ).fetchone()
                if not migration_exists:
                    if any_expected:
                        raise ValueError("partial schema")
                    self._create_schema()
                    self._connection.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (SCHEMA_VERSION, self._now()),
                    )
                else:
                    versions = self._connection.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()
                    if any(row[0] > SCHEMA_VERSION for row in versions):
                        raise ValueError("unsupported schema version")
                    if [tuple(row) for row in versions] != [(SCHEMA_VERSION,)]:
                        raise ValueError("partial schema")
                    self._validate_schema()
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
            self._validate_pragmas()

    def _validate_pragmas(self) -> None:
        if self._connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ValueError("foreign keys are not enabled")
        if self._connection.execute("PRAGMA busy_timeout").fetchone()[0] != 5000:
            raise ValueError("busy timeout is not 5000ms")

    def _create_schema(self) -> None:
        schema_sql = """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            CREATE TABLE inputs (
                input_id INTEGER PRIMARY KEY,
                input_identity TEXT NOT NULL UNIQUE,
                identity_provenance TEXT,
                external_evidence_allowed INTEGER NOT NULL
            );
            CREATE TABLE databases (
                database_id INTEGER PRIMARY KEY,
                database_uuid TEXT NOT NULL,
                database_identity TEXT NOT NULL,
                input_id INTEGER NOT NULL REFERENCES inputs,
                UNIQUE(database_uuid, database_identity, input_id)
            );
            CREATE TABLE functions (
                function_id INTEGER PRIMARY KEY,
                database_id INTEGER NOT NULL REFERENCES databases,
                function_ea INTEGER NOT NULL,
                function_rva INTEGER,
                function_fingerprint TEXT NOT NULL,
                UNIQUE(database_id, function_ea, function_fingerprint)
            );
            CREATE TABLE terms (
                term_id INTEGER PRIMARY KEY,
                canonical_fingerprint TEXT NOT NULL UNIQUE,
                width INTEGER NOT NULL,
                canonical_term BLOB NOT NULL,
                canonical_codec_version INTEGER NOT NULL
            );
            CREATE TABLE raw_terms (
                raw_term_id INTEGER PRIMARY KEY,
                term_id INTEGER NOT NULL REFERENCES terms,
                raw_fingerprint TEXT NOT NULL,
                raw_term BLOB NOT NULL,
                raw_codec_version INTEGER NOT NULL,
                UNIQUE(term_id, raw_fingerprint)
            );
            CREATE TABLE provider_attempts (
                attempt_id INTEGER PRIMARY KEY,
                attempt_uuid TEXT NOT NULL UNIQUE,
                function_id INTEGER NOT NULL REFERENCES functions,
                term_id INTEGER NOT NULL REFERENCES terms,
                raw_term_id INTEGER NOT NULL REFERENCES raw_terms,
                session_id TEXT NOT NULL,
                top_level_epoch INTEGER NOT NULL,
                evidence_generation INTEGER NOT NULL,
                maturity TEXT NOT NULL,
                instruction_ea INTEGER NOT NULL,
                block_serial INTEGER,
                block_ea INTEGER,
                provider TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                plugin_version TEXT,
                status TEXT NOT NULL,
                input_cost_ops INTEGER,
                input_cost_nodes INTEGER,
                output_cost_ops INTEGER,
                output_cost_nodes INTEGER,
                proof_verdict INTEGER,
                elapsed_ms REAL NOT NULL,
                refusal_reason TEXT,
                outcome_payload BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE residual_groups (
                group_id INTEGER PRIMARY KEY,
                term_id INTEGER NOT NULL UNIQUE REFERENCES terms,
                state TEXT NOT NULL,
                eligible_observation_count INTEGER NOT NULL,
                last_observed_at TEXT NOT NULL,
                last_mined_at TEXT,
                materialized_at TEXT,
                admitted_at TEXT,
                revision INTEGER NOT NULL
            );
            CREATE TABLE mining_runs (
                run_id TEXT PRIMARY KEY,
                group_id INTEGER NOT NULL REFERENCES residual_groups,
                claimed_revision INTEGER NOT NULL,
                miner_version TEXT NOT NULL,
                budget_fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                started_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                finished_at TEXT,
                failure_reason TEXT
            );
            CREATE TABLE proposals (
                proposal_id TEXT PRIMARY KEY,
                group_id INTEGER NOT NULL REFERENCES residual_groups,
                run_id TEXT NOT NULL REFERENCES mining_runs,
                proposal_fingerprint TEXT NOT NULL UNIQUE,
                replacement_term BLOB NOT NULL,
                proposal_payload BLOB NOT NULL,
                proof_receipt_payload BLOB NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                materialized_path TEXT,
                materialized_digest TEXT,
                materialized_at TEXT,
                admitted_rule_id TEXT,
                admitted_at TEXT,
                rejection_reason TEXT
            );
            CREATE INDEX idx_residual_groups_claim
                ON residual_groups(state, last_observed_at, group_id);
            CREATE INDEX idx_mining_runs_lease
                ON mining_runs(state, heartbeat_at, group_id);
            CREATE INDEX idx_provider_attempts_term
                ON provider_attempts(term_id, created_at, attempt_id);
            CREATE INDEX idx_provider_attempts_function
                ON provider_attempts(function_id, created_at, attempt_id);
            CREATE INDEX idx_provider_attempts_provider
                ON provider_attempts(provider, created_at, attempt_id);
            CREATE INDEX idx_proposals_group_state
                ON proposals(group_id, state, created_at, proposal_id);
            """
        for statement in schema_sql.split(";"):
            statement = statement.strip()
            if statement:
                self._connection.execute(statement)

    def _validate_schema(self) -> None:
        for table, expected in _TABLES.items():
            row = self._connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if row is None:
                raise ValueError("partial schema")
            columns = tuple(
                item[1]
                for item in self._connection.execute(f'PRAGMA table_info("{table}")')
            )
            if columns != expected:
                raise ValueError(f"partial schema: {table} columns")
        indexes = {
            row[1]
            for row in self._connection.execute("PRAGMA index_list('residual_groups')")
        }
        indexes |= {
            row[1]
            for table in ("mining_runs", "provider_attempts", "proposals")
            for row in self._connection.execute(f"PRAGMA index_list('{table}')")
        }
        if not _INDEXES <= indexes:
            raise ValueError("partial schema: indexes")
        for table, columns in {
            "inputs": ("input_identity",),
            "databases": ("database_uuid", "database_identity", "input_id"),
            "functions": ("database_id", "function_ea", "function_fingerprint"),
            "terms": ("canonical_fingerprint",),
            "raw_terms": ("term_id", "raw_fingerprint"),
        }.items():
            found = False
            for index in self._connection.execute(f"PRAGMA index_list('{table}')"):
                if index[2] != 1:
                    continue
                actual = tuple(
                    row[2]
                    for row in self._connection.execute(
                        f"PRAGMA index_info('{index[1]}')"
                    )
                )
                if actual == columns:
                    found = True
                    break
            if not found:
                raise ValueError(f"partial schema: unique constraint on {table}")
        for table in _TABLES:
            if table == "schema_migrations":
                continue
            if not self._connection.execute(
                f"PRAGMA foreign_key_list('{table}')"
            ).fetchall() and table not in {"inputs", "terms"}:
                raise ValueError(f"partial schema: foreign keys on {table}")

    def schema_version(self) -> int:
        self._ensure_open()
        row = self._connection.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()
        return int(row[0])

    def table_columns(self) -> dict[str, tuple[str, ...]]:
        self._ensure_open()
        return {
            table: tuple(
                row[1]
                for row in self._connection.execute(f'PRAGMA table_info("{table}")')
            )
            for table in _TABLES
        }

    def connection_pragmas(self) -> dict[str, int]:
        self._ensure_open()
        return {
            "foreign_keys": int(
                self._connection.execute("PRAGMA foreign_keys").fetchone()[0]
            ),
            "busy_timeout": int(
                self._connection.execute("PRAGMA busy_timeout").fetchone()[0]
            ),
        }

    def journal_mode(self) -> str:
        self._ensure_open()
        return str(
            self._connection.execute("PRAGMA journal_mode").fetchone()[0]
        ).lower()

    def count_rows(self, table: str) -> int:
        self._ensure_open()
        if table not in _TABLES:
            raise ValueError("unknown discovery table")
        return int(
            self._connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        )

    def _input(self, conn: sqlite3.Connection, attempt: DiscoveryAttempt) -> int:
        identity = attempt.context.function_identity
        row = conn.execute(
            "SELECT * FROM inputs WHERE input_identity=?", (identity.input_identity,)
        ).fetchone()
        values = (
            identity.input_identity,
            identity.input_identity_provenance,
            int(identity.external_evidence_allowed),
        )
        if row is not None:
            if tuple(row[1:]) != values:
                raise ValueError("input identity disagreement")
            return int(row[0])
        return int(
            conn.execute(
                "INSERT INTO inputs(input_identity, identity_provenance, external_evidence_allowed) VALUES (?, ?, ?)",
                values,
            ).lastrowid
        )

    def _database(
        self, conn: sqlite3.Connection, attempt: DiscoveryAttempt, input_id: int
    ) -> int:
        identity = attempt.context.function_identity
        row = conn.execute(
            "SELECT * FROM databases WHERE database_uuid=? AND database_identity=? AND input_id=?",
            (identity.database_uuid, identity.database_identity, input_id),
        ).fetchone()
        if row is not None:
            return int(row[0])
        return int(
            conn.execute(
                "INSERT INTO databases(database_uuid, database_identity, input_id) VALUES (?, ?, ?)",
                (identity.database_uuid, identity.database_identity, input_id),
            ).lastrowid
        )

    def _function(
        self, conn: sqlite3.Connection, attempt: DiscoveryAttempt, database_id: int
    ) -> int:
        identity = attempt.context.function_identity
        row = conn.execute(
            "SELECT * FROM functions WHERE database_id=? AND function_ea=? AND function_fingerprint=?",
            (database_id, identity.function_ea, identity.function_fingerprint),
        ).fetchone()
        if row is not None:
            if row[3] != identity.function_rva:
                raise ValueError("function identity disagreement")
            return int(row[0])
        return int(
            conn.execute(
                "INSERT INTO functions(database_id, function_ea, function_rva, function_fingerprint) VALUES (?, ?, ?, ?)",
                (
                    database_id,
                    identity.function_ea,
                    identity.function_rva,
                    identity.function_fingerprint,
                ),
            ).lastrowid
        )

    def _term(
        self, conn: sqlite3.Connection, attempt: DiscoveryAttempt
    ) -> tuple[int, int, bytes, bytes]:
        canonical = _term_bytes(attempt.canonical_term, name="canonical term")
        raw = _term_bytes(attempt.raw_term, name="raw term")
        fingerprint = term_fingerprint(attempt.canonical_term)
        row = conn.execute(
            "SELECT * FROM terms WHERE canonical_fingerprint=?", (fingerprint,)
        ).fetchone()
        if row is not None:
            if (
                row[2] != attempt.canonical_term.width
                or bytes(row[3]) != canonical
                or row[4] != TERM_WIRE_SCHEMA_VERSION
            ):
                raise ValueError("canonical term fingerprint collision")
            term_id = int(row[0])
        else:
            term_id = int(
                conn.execute(
                    "INSERT INTO terms(canonical_fingerprint, width, canonical_term, canonical_codec_version) VALUES (?, ?, ?, ?)",
                    (
                        fingerprint,
                        attempt.canonical_term.width,
                        canonical,
                        TERM_WIRE_SCHEMA_VERSION,
                    ),
                ).lastrowid
            )
        raw_fp = term_fingerprint(attempt.raw_term)
        raw_row = conn.execute(
            "SELECT * FROM raw_terms WHERE term_id=? AND raw_fingerprint=?",
            (term_id, raw_fp),
        ).fetchone()
        if raw_row is not None:
            if bytes(raw_row[3]) != raw or raw_row[4] != TERM_WIRE_SCHEMA_VERSION:
                raise ValueError("raw term fingerprint collision")
            raw_id = int(raw_row[0])
        else:
            raw_id = int(
                conn.execute(
                    "INSERT INTO raw_terms(term_id, raw_fingerprint, raw_term, raw_codec_version) VALUES (?, ?, ?, ?)",
                    (term_id, raw_fp, raw, TERM_WIRE_SCHEMA_VERSION),
                ).lastrowid
            )
        return term_id, raw_id, canonical, raw

    def _group(
        self, conn: sqlite3.Connection, term_id: int, *, eligible: bool, now: str
    ) -> tuple[int, ResidualGroupState, int]:
        row = conn.execute(
            "SELECT * FROM residual_groups WHERE term_id=?", (term_id,)
        ).fetchone()
        if row is None:
            state = (
                ResidualGroupState.ELIGIBLE if eligible else ResidualGroupState.OBSERVED
            )
            group_id = int(
                conn.execute(
                    "INSERT INTO residual_groups(term_id,state,eligible_observation_count,last_observed_at,revision) VALUES (?, ?, ?, ?, 1)",
                    (term_id, state.value, int(eligible), now),
                ).lastrowid
            )
            return group_id, state, 1
        current = ResidualGroupState(row[2])
        next_state = current
        if eligible and current is ResidualGroupState.OBSERVED:
            next_state = ResidualGroupState.ELIGIBLE
        elif eligible and current is ResidualGroupState.NO_PROPOSAL:
            next_state = ResidualGroupState.ELIGIBLE
        revision = int(row[8]) + 1
        if next_state is not current and not valid_group_transition(
            current, next_state
        ):
            raise ValueError("invalid residual group transition")
        conn.execute(
            "UPDATE residual_groups SET state=?, eligible_observation_count=eligible_observation_count+?, last_observed_at=?, revision=? WHERE group_id=?",
            (next_state.value, int(eligible), now, revision, row[0]),
        )
        return int(row[0]), next_state, revision

    def record_attempt(self, attempt: DiscoveryAttempt) -> DiscoveryReceipt:
        if not isinstance(attempt, DiscoveryAttempt):
            raise TypeError("attempt must be a DiscoveryAttempt")
        canonical = _term_bytes(attempt.canonical_term, name="canonical term")
        raw = _term_bytes(attempt.raw_term, name="raw term")
        outcome_payload = _outcome_bytes(attempt.outcome)
        try:
            with self._transaction() as conn:
                # Check UUID identity before any upsert so both an exact
                # retry and a conflicting collision are mutation-free.
                existing = conn.execute(
                    """
                    SELECT pa.*, f.function_ea, f.function_rva, f.function_fingerprint,
                           d.database_uuid, d.database_identity, i.input_identity,
                           i.identity_provenance, i.external_evidence_allowed,
                           t.canonical_fingerprint, rt.raw_fingerprint
                    FROM provider_attempts pa
                    JOIN functions f ON f.function_id = pa.function_id
                    JOIN databases d ON d.database_id = f.database_id
                    JOIN inputs i ON i.input_id = d.input_id
                    JOIN terms t ON t.term_id = pa.term_id
                    JOIN raw_terms rt ON rt.raw_term_id = pa.raw_term_id
                    WHERE pa.attempt_uuid=?
                    """,
                    (attempt.attempt_uuid,),
                ).fetchone()
                if existing is not None:
                    identity = attempt.context.function_identity
                    context = attempt.context
                    outcome = attempt.outcome
                    input_cost = outcome.input_cost or (None, None)
                    output_cost = outcome.output_cost or (None, None)
                    exact = (
                        existing[25] == identity.function_ea
                        and existing[26] == identity.function_rva
                        and existing[27] == identity.function_fingerprint
                        and existing[28] == identity.database_uuid
                        and existing[29] == identity.database_identity
                        and existing[30] == identity.input_identity
                        and existing[31] == identity.input_identity_provenance
                        and existing[32] == int(identity.external_evidence_allowed)
                        and existing[33] == term_fingerprint(attempt.canonical_term)
                        and existing[34] == term_fingerprint(attempt.raw_term)
                        and existing[5] == identity.decompilation_session_id
                        and existing[6] == identity.top_level_epoch
                        and existing[7] == identity.evidence_generation
                        and existing[8] == identity.maturity
                        and existing[9] == context.instruction_ea
                        and existing[10] == context.block_serial
                        and existing[11] == context.block_ea
                        and existing[12] == outcome.provider.value
                        and existing[13] == context.plugin_identity.name
                        and existing[14] == context.plugin_identity.version
                        and existing[15] == outcome.status.value
                        and existing[16] == input_cost[0]
                        and existing[17] == input_cost[1]
                        and existing[18] == output_cost[0]
                        and existing[19] == output_cost[1]
                        and existing[20]
                        == (
                            None
                            if outcome.proof_verdict is None
                            else int(outcome.proof_verdict)
                        )
                        and existing[21] == outcome.elapsed_ms
                        and existing[22] == outcome.refusal_reason
                        and bytes(existing[23]) == outcome_payload
                    )
                    group = conn.execute(
                        "SELECT * FROM residual_groups WHERE term_id=?", (existing[3],)
                    ).fetchone()
                    if exact and group is not None:
                        return DiscoveryReceipt(
                            ReceiptStatus.DUPLICATE,
                            attempt_id=int(existing[0]),
                            group_id=int(group[0]),
                            term_id=int(existing[3]),
                            raw_term_id=int(existing[4]),
                            revision=int(group[8]),
                            state=ResidualGroupState(group[2]),
                        )
                    return DiscoveryReceipt(
                        ReceiptStatus.REFUSED, reason="attempt_uuid_conflict"
                    )
                input_id = self._input(conn, attempt)
                database_id = self._database(conn, attempt, input_id)
                function_id = self._function(conn, attempt, database_id)
                term_id, raw_id, canonical, raw = self._term(conn, attempt)
                identity = attempt.context.function_identity
                context = attempt.context
                outcome = attempt.outcome
                input_cost = outcome.input_cost or (None, None)
                output_cost = outcome.output_cost or (None, None)
                attempt_id = int(
                    conn.execute(
                        "INSERT INTO provider_attempts(attempt_uuid,function_id,term_id,raw_term_id,session_id,top_level_epoch,evidence_generation,maturity,instruction_ea,block_serial,block_ea,provider,plugin_name,plugin_version,status,input_cost_ops,input_cost_nodes,output_cost_ops,output_cost_nodes,proof_verdict,elapsed_ms,refusal_reason,outcome_payload,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            attempt.attempt_uuid,
                            function_id,
                            term_id,
                            raw_id,
                            identity.decompilation_session_id,
                            identity.top_level_epoch,
                            identity.evidence_generation,
                            identity.maturity,
                            context.instruction_ea,
                            context.block_serial,
                            context.block_ea,
                            outcome.provider.value,
                            context.plugin_identity.name,
                            context.plugin_identity.version,
                            outcome.status.value,
                            input_cost[0],
                            input_cost[1],
                            output_cost[0],
                            output_cost[1],
                            None
                            if outcome.proof_verdict is None
                            else int(outcome.proof_verdict),
                            outcome.elapsed_ms,
                            outcome.refusal_reason,
                            outcome_payload,
                            self._now(),
                        ),
                    ).lastrowid
                )
                group_id, state, revision = self._group(
                    conn, term_id, eligible=attempt.eligible_for_mining, now=self._now()
                )
                return DiscoveryReceipt(
                    ReceiptStatus.STORED,
                    attempt_id=attempt_id,
                    group_id=group_id,
                    term_id=term_id,
                    raw_term_id=raw_id,
                    revision=revision,
                    state=state,
                )
        except (sqlite3.IntegrityError, ValueError) as exc:
            return DiscoveryReceipt(ReceiptStatus.REFUSED, reason=str(exc))

    def _project_group(self, conn: sqlite3.Connection, group_id: int) -> ResidualGroup:
        row = conn.execute(
            "SELECT * FROM residual_groups WHERE group_id=?", (group_id,)
        ).fetchone()
        if row is None:
            raise ValueError("unknown group")
        term = conn.execute("SELECT * FROM terms WHERE term_id=?", (row[1],)).fetchone()
        if term is None:
            raise ValueError("group term is missing")
        canonical = _decode_term(bytes(term[3]), name="canonical term")
        if (
            term[1] != term_fingerprint(canonical)
            or term[2] != canonical.width
            or term[4] != TERM_WIRE_SCHEMA_VERSION
        ):
            raise ValueError("canonical term identity is corrupt")
        raws = tuple(
            self._decode_raw_term(raw)
            for raw in conn.execute(
                "SELECT * FROM raw_terms WHERE term_id=? ORDER BY raw_term_id",
                (row[1],),
            )
        )
        return ResidualGroup(
            int(row[0]),
            int(row[1]),
            ResidualGroupState(row[2]),
            int(row[3]),
            row[4],
            row[5],
            row[6],
            row[7],
            int(row[8]),
            canonical,
            raws,
        )

    def _decode_raw_term(self, row: sqlite3.Row) -> TypedBvTerm:
        term = _decode_term(bytes(row[3]), name="raw term")
        if row[2] != term_fingerprint(term) or row[4] != TERM_WIRE_SCHEMA_VERSION:
            raise ValueError("raw term identity is corrupt")
        return term

    def _project_run(self, row: sqlite3.Row) -> MiningRun:
        return MiningRun(
            row[0],
            int(row[1]),
            int(row[2]),
            row[3],
            row[4],
            MiningRunState(row[5]),
            row[6],
            row[7],
            row[8],
            row[9],
        )

    def _project_proposal(self, row: sqlite3.Row) -> Proposal:
        replacement = _decode_term(bytes(row[4]), name="replacement term")
        for payload, name in (
            (bytes(row[5]), "proposal payload"),
            (bytes(row[6]), "proof receipt payload"),
        ):
            _json_bytes(payload, name=name)
        return Proposal(
            row[0],
            int(row[1]),
            row[2],
            row[3],
            replacement,
            bytes(row[5]),
            bytes(row[6]),
            ProposalState(row[7]),
            row[8],
            row[9],
            row[10],
            row[11],
            row[12],
            row[13],
            row[14],
        )

    def claim_next_group(
        self, miner_version: str, budget_fingerprint: str, lease_timeout: object
    ) -> ClaimReceipt:
        if (
            type(miner_version) is not str
            or not miner_version
            or miner_version.strip() != miner_version
        ):
            raise ValueError("miner_version must be canonical")
        if (
            type(budget_fingerprint) is not str
            or not budget_fingerprint
            or budget_fingerprint.strip() != budget_fingerprint
        ):
            raise ValueError("budget_fingerprint must be canonical")
        timeout = _seconds(lease_timeout)
        self._last_lease_timeout = timeout
        try:
            with self._transaction(immediate=True) as conn:
                now = self._now()
                cutoff = datetime.fromisoformat(now.replace("Z", "+00:00")) - timedelta(
                    seconds=timeout
                )
                cutoff_text = _timestamp(cutoff)
                expired = conn.execute(
                    "SELECT run_id FROM mining_runs WHERE state=? AND heartbeat_at<=? ORDER BY heartbeat_at, run_id",
                    (MiningRunState.CLAIMED.value, cutoff_text),
                ).fetchall()
                for old in expired:
                    conn.execute(
                        "UPDATE mining_runs SET state=?, finished_at=?, failure_reason=? WHERE run_id=? AND state=?",
                        (
                            MiningRunState.EXPIRED.value,
                            now,
                            "lease_expired",
                            old[0],
                            MiningRunState.CLAIMED.value,
                        ),
                    )
                    conn.execute(
                        "UPDATE residual_groups SET state=? WHERE group_id=(SELECT group_id FROM mining_runs WHERE run_id=?) AND state=?",
                        (
                            ResidualGroupState.ELIGIBLE.value,
                            old[0],
                            ResidualGroupState.MINING.value,
                        ),
                    )
                candidate = conn.execute(
                    "SELECT group_id, revision FROM residual_groups WHERE state=? ORDER BY last_observed_at, group_id LIMIT 1",
                    (ResidualGroupState.ELIGIBLE.value,),
                ).fetchone()
                if candidate is None:
                    return ClaimReceipt(
                        ReceiptStatus.REFUSED, reason="no_eligible_group"
                    )
                claimed_revision = int(candidate[1]) + 1
                updated = conn.execute(
                    "UPDATE residual_groups SET state=?, revision=? WHERE group_id=? AND state=? AND revision=?",
                    (
                        ResidualGroupState.MINING.value,
                        claimed_revision,
                        candidate[0],
                        ResidualGroupState.ELIGIBLE.value,
                        candidate[1],
                    ),
                ).rowcount
                if updated != 1:
                    return ClaimReceipt(ReceiptStatus.REFUSED, reason="claim_conflict")
                run_id = self._new_uuid()
                conn.execute(
                    "INSERT INTO mining_runs(run_id,group_id,claimed_revision,miner_version,budget_fingerprint,state,started_at,heartbeat_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        run_id,
                        candidate[0],
                        claimed_revision,
                        miner_version,
                        budget_fingerprint,
                        MiningRunState.CLAIMED.value,
                        now,
                        now,
                    ),
                )
                group = self._project_group(conn, int(candidate[0]))
                run = self._project_run(
                    conn.execute(
                        "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
                    ).fetchone()
                )
                return ClaimReceipt(ReceiptStatus.CLAIMED, MiningClaim(group, run))
        except (sqlite3.IntegrityError, ValueError) as exc:
            return ClaimReceipt(ReceiptStatus.REFUSED, reason=str(exc))

    def heartbeat(self, run_id: str, claimed_revision: int) -> HeartbeatReceipt:
        try:
            run_id = str(UUID(run_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("run_id must be a UUID") from exc
        if type(claimed_revision) is not int or claimed_revision < 0:
            raise ValueError("claimed_revision must be non-negative")
        with self._transaction(immediate=True) as conn:
            now = self._now()
            updated = conn.execute(
                "UPDATE mining_runs SET heartbeat_at=? WHERE run_id=? AND claimed_revision=? AND state=? AND group_id IN (SELECT group_id FROM residual_groups WHERE state=? AND revision=?)",
                (
                    now,
                    run_id,
                    claimed_revision,
                    MiningRunState.CLAIMED.value,
                    ResidualGroupState.MINING.value,
                    claimed_revision,
                ),
            ).rowcount
            if updated != 1:
                return HeartbeatReceipt(
                    ReceiptStatus.REFUSED, reason="stale_or_not_owner"
                )
            return HeartbeatReceipt(
                ReceiptStatus.HEARTBEATED,
                self._project_run(
                    conn.execute(
                        "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
                    ).fetchone()
                ),
            )

    def finish_no_proposal(
        self, run_id: str, claimed_revision: int, reason: str = "no_proposal"
    ) -> LifecycleReceipt:
        return self._finish_run(
            run_id,
            claimed_revision,
            MiningRunState.NO_PROPOSAL,
            ResidualGroupState.NO_PROPOSAL,
            reason,
        )

    def _finish_run(
        self,
        run_id: str,
        claimed_revision: int,
        run_state: MiningRunState,
        group_state: ResidualGroupState,
        reason: str,
    ) -> LifecycleReceipt:
        try:
            run_id = str(UUID(run_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("run_id must be a UUID") from exc
        if type(claimed_revision) is not int or claimed_revision < 0:
            raise ValueError("claimed_revision must be non-negative")
        if type(reason) is not str or not reason or reason.strip() != reason:
            raise ValueError("reason must be canonical and non-empty")
        with self._transaction(immediate=True) as conn:
            now = self._now()
            run = conn.execute(
                "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="unknown_run")
            if run[5] != MiningRunState.CLAIMED.value or run[2] != claimed_revision:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="not_active")
            group = conn.execute(
                "SELECT state, revision FROM residual_groups WHERE group_id=?",
                (run[1],),
            ).fetchone()
            if (
                group is None
                or group[0] != ResidualGroupState.MINING.value
                or group[1] != claimed_revision
            ):
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            updated = conn.execute(
                "UPDATE mining_runs SET state=?, finished_at=?, failure_reason=? WHERE run_id=? AND state=? AND claimed_revision=?",
                (
                    run_state.value,
                    now,
                    reason,
                    run_id,
                    MiningRunState.CLAIMED.value,
                    claimed_revision,
                ),
            ).rowcount
            group_updated = conn.execute(
                "UPDATE residual_groups SET state=?, last_mined_at=? WHERE group_id=? AND state=? AND revision=?",
                (
                    group_state.value,
                    now,
                    run[1],
                    ResidualGroupState.MINING.value,
                    claimed_revision,
                ),
            ).rowcount
            if updated != 1 or group_updated != 1:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            return LifecycleReceipt(
                ReceiptStatus.FINISHED,
                run=self._project_run(
                    conn.execute(
                        "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
                    ).fetchone()
                ),
                group=self._project_group(conn, int(run[1])),
            )

    def publish_proposal(
        self,
        run_id: str,
        claimed_revision: int,
        proposal_fingerprint: str,
        replacement_term: TypedBvTerm,
        proposal_payload: object,
        proof_receipt_payload: object,
    ) -> LifecycleReceipt:
        try:
            run_id = str(UUID(run_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("run_id must be a UUID") from exc
        if type(claimed_revision) is not int or claimed_revision < 0:
            raise ValueError("claimed_revision must be non-negative")
        if (
            type(proposal_fingerprint) is not str
            or not proposal_fingerprint
            or proposal_fingerprint.strip() != proposal_fingerprint
        ):
            raise ValueError("proposal_fingerprint must be canonical")
        replacement = _term_bytes(replacement_term, name="replacement term")
        proposal_bytes = _json_bytes(proposal_payload, name="proposal payload")
        proof_bytes = _json_bytes(proof_receipt_payload, name="proof receipt payload")
        with self._transaction(immediate=True) as conn:
            existing = conn.execute(
                "SELECT * FROM proposals WHERE proposal_fingerprint=?",
                (proposal_fingerprint,),
            ).fetchone()
            if existing is not None:
                exact = (
                    existing[2] == run_id
                    and bytes(existing[4]) == replacement
                    and bytes(existing[5]) == proposal_bytes
                    and bytes(existing[6]) == proof_bytes
                )
                return LifecycleReceipt(
                    ReceiptStatus.DUPLICATE if exact else ReceiptStatus.REFUSED,
                    proposal=self._project_proposal(existing),
                    reason=None if exact else "proposal_fingerprint_conflict",
                )
            run = conn.execute(
                "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="unknown_run")
            group = conn.execute(
                "SELECT * FROM residual_groups WHERE group_id=?", (run[1],)
            ).fetchone()
            if (
                run[5] != MiningRunState.CLAIMED.value
                or run[2] != claimed_revision
                or group is None
                or group[2] != ResidualGroupState.MINING.value
                or group[8] != claimed_revision
            ):
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            proposal_id = self._new_uuid()
            now = self._now()
            conn.execute(
                "INSERT INTO proposals(proposal_id,group_id,run_id,proposal_fingerprint,replacement_term,proposal_payload,proof_receipt_payload,state,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    proposal_id,
                    group[0],
                    run_id,
                    proposal_fingerprint,
                    replacement,
                    proposal_bytes,
                    proof_bytes,
                    ProposalState.PROPOSED.value,
                    now,
                ),
            )
            if (
                conn.execute(
                    "UPDATE mining_runs SET state=?, finished_at=? WHERE run_id=? AND state=? AND claimed_revision=?",
                    (
                        MiningRunState.PROPOSED.value,
                        now,
                        run_id,
                        MiningRunState.CLAIMED.value,
                        claimed_revision,
                    ),
                ).rowcount
                != 1
            ):
                conn.rollback()
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="publication_conflict"
                )
            if (
                conn.execute(
                    "UPDATE residual_groups SET state=? WHERE group_id=? AND state=? AND revision=?",
                    (
                        ResidualGroupState.PROPOSED.value,
                        group[0],
                        ResidualGroupState.MINING.value,
                        claimed_revision,
                    ),
                ).rowcount
                != 1
            ):
                conn.rollback()
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="publication_conflict"
                )
            proposal = self._project_proposal(
                conn.execute(
                    "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                ).fetchone()
            )
            return LifecycleReceipt(
                ReceiptStatus.PUBLISHED,
                proposal=proposal,
                run=self._project_run(
                    conn.execute(
                        "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
                    ).fetchone()
                ),
                group=self._project_group(conn, int(group[0])),
            )

    def mark_materialized(
        self,
        proposal_id: str,
        path: str,
        digest: str,
        *,
        expected_state: ProposalState | str | None = None,
        expected_revision: int | None = None,
    ) -> LifecycleReceipt:
        try:
            proposal_id = str(UUID(proposal_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("proposal_id must be a UUID") from exc
        if type(path) is not str or not path or path.strip() != path:
            raise ValueError("materialized path must be canonical")
        if type(digest) is not str or not digest or digest.strip() != digest:
            raise ValueError("materialized digest must be canonical")
        with self._transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="unknown_proposal"
                )
            if (
                expected_state is not None
                and ProposalState(expected_state).value != row[7]
            ):
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            if expected_revision is not None:
                if type(expected_revision) is not int or expected_revision < 0:
                    raise ValueError("expected_revision must be non-negative")
                group_revision = conn.execute(
                    "SELECT revision FROM residual_groups WHERE group_id=?", (row[1],)
                ).fetchone()
                if group_revision is None or group_revision[0] != expected_revision:
                    return LifecycleReceipt(
                        ReceiptStatus.REFUSED, reason="stale_revision"
                    )
            if row[7] == ProposalState.MATERIALIZED.value:
                if row[9] == path and row[10] == digest:
                    return LifecycleReceipt(
                        ReceiptStatus.DUPLICATE, proposal=self._project_proposal(row)
                    )
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="materialization_conflict"
                )
            if row[7] != ProposalState.PROPOSED.value:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            group = conn.execute(
                "SELECT * FROM residual_groups WHERE group_id=?", (row[1],)
            ).fetchone()
            if (
                group is None
                or group[2] != ResidualGroupState.PROPOSED.value
                or not valid_proposal_transition(
                    ProposalState.PROPOSED, ProposalState.MATERIALIZED
                )
            ):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            now = self._now()
            if (
                conn.execute(
                    "UPDATE proposals SET state=?, materialized_path=?, materialized_digest=?, materialized_at=? WHERE proposal_id=? AND state=?",
                    (
                        ProposalState.MATERIALIZED.value,
                        path,
                        digest,
                        now,
                        proposal_id,
                        ProposalState.PROPOSED.value,
                    ),
                ).rowcount
                != 1
            ):
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            if (
                conn.execute(
                    "UPDATE residual_groups SET state=?, materialized_at=? WHERE group_id=? AND state=? AND revision=?",
                    (
                        ResidualGroupState.MATERIALIZED.value,
                        now,
                        row[1],
                        ResidualGroupState.PROPOSED.value,
                        group[8],
                    ),
                ).rowcount
                != 1
            ):
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            return LifecycleReceipt(
                ReceiptStatus.MATERIALIZED,
                proposal=self._project_proposal(
                    conn.execute(
                        "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                    ).fetchone()
                ),
                group=self._project_group(conn, int(row[1])),
            )

    def mark_admitted(
        self,
        proposal_id: str,
        rule_id: str,
        *,
        expected_state: ProposalState | str | None = None,
        expected_revision: int | None = None,
    ) -> LifecycleReceipt:
        return self._mark_terminal_proposal(
            proposal_id,
            ProposalState.ADMITTED,
            ResidualGroupState.ADMITTED,
            rule_id=rule_id,
            expected_state=expected_state,
            expected_revision=expected_revision,
        )

    def mark_rejected(
        self,
        proposal_id: str,
        reason: str,
        *,
        expected_state: ProposalState | str | None = None,
        expected_revision: int | None = None,
    ) -> LifecycleReceipt:
        return self._mark_terminal_proposal(
            proposal_id,
            ProposalState.REJECTED,
            ResidualGroupState.REJECTED,
            reason=reason,
            expected_state=expected_state,
            expected_revision=expected_revision,
        )

    def _mark_terminal_proposal(
        self,
        proposal_id: str,
        target: ProposalState,
        group_target: ResidualGroupState,
        *,
        rule_id: str | None = None,
        reason: str | None = None,
        expected_state: ProposalState | str | None = None,
        expected_revision: int | None = None,
    ) -> LifecycleReceipt:
        try:
            proposal_id = str(UUID(proposal_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("proposal_id must be a UUID") from exc
        value = rule_id if target is ProposalState.ADMITTED else reason
        if type(value) is not str or not value or value.strip() != value:
            raise ValueError("lifecycle value must be canonical and non-empty")
        with self._transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="unknown_proposal"
                )
            if (
                expected_state is not None
                and ProposalState(expected_state).value != row[7]
            ):
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            if expected_revision is not None:
                if type(expected_revision) is not int or expected_revision < 0:
                    raise ValueError("expected_revision must be non-negative")
                group_revision = conn.execute(
                    "SELECT revision FROM residual_groups WHERE group_id=?", (row[1],)
                ).fetchone()
                if group_revision is None or group_revision[0] != expected_revision:
                    return LifecycleReceipt(
                        ReceiptStatus.REFUSED, reason="stale_revision"
                    )
            current = ProposalState(row[7])
            if current is target:
                if (
                    target is ProposalState.ADMITTED
                    and row[12] == rule_id
                    or target is ProposalState.REJECTED
                    and row[14] == reason
                ):
                    return LifecycleReceipt(
                        ReceiptStatus.DUPLICATE, proposal=self._project_proposal(row)
                    )
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="lifecycle_conflict"
                )
            if not valid_proposal_transition(current, target):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            group = conn.execute(
                "SELECT * FROM residual_groups WHERE group_id=?", (row[1],)
            ).fetchone()
            expected_group = (
                ResidualGroupState.MATERIALIZED
                if current is ProposalState.MATERIALIZED
                else ResidualGroupState.PROPOSED
            )
            if (
                group is None
                or ResidualGroupState(group[2]) is not expected_group
                or not valid_group_transition(expected_group, group_target)
            ):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            now = self._now()
            if target is ProposalState.ADMITTED:
                updated = conn.execute(
                    "UPDATE proposals SET state=?, admitted_rule_id=?, admitted_at=? WHERE proposal_id=? AND state=?",
                    (target.value, rule_id, now, proposal_id, current.value),
                ).rowcount
            else:
                updated = conn.execute(
                    "UPDATE proposals SET state=?, rejection_reason=? WHERE proposal_id=? AND state=?",
                    (target.value, reason, proposal_id, current.value),
                ).rowcount
            if updated != 1:
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            group_updated = conn.execute(
                "UPDATE residual_groups SET state=?, admitted_at=? WHERE group_id=? AND state=? AND revision=?",
                (
                    group_target.value,
                    now if target is ProposalState.ADMITTED else group[7],
                    row[1],
                    expected_group.value,
                    group[8],
                ),
            ).rowcount
            if group_updated != 1:
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            return LifecycleReceipt(
                ReceiptStatus.ADMITTED
                if target is ProposalState.ADMITTED
                else ReceiptStatus.REJECTED,
                proposal=self._project_proposal(
                    conn.execute(
                        "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                    ).fetchone()
                ),
                group=self._project_group(conn, int(row[1])),
            )

    def status_counts(self) -> DiscoveryStatus:
        self._ensure_open()
        groups = tuple(
            (
                state,
                int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM residual_groups WHERE state=?",
                        (state.value,),
                    ).fetchone()[0]
                ),
            )
            for state in ResidualGroupState
        )
        runs = tuple(
            (
                state,
                int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM mining_runs WHERE state=?", (state.value,)
                    ).fetchone()[0]
                ),
            )
            for state in MiningRunState
            if state.name != "ACTIVE"
        )
        proposals = tuple(
            (
                state,
                int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM proposals WHERE state=?", (state.value,)
                    ).fetchone()[0]
                ),
            )
            for state in ProposalState
        )
        cutoff = _timestamp(
            datetime.fromisoformat(self._now().replace("Z", "+00:00"))
            - timedelta(seconds=self._last_lease_timeout)
        )
        expired = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM mining_runs WHERE state=? AND heartbeat_at<=?",
                (MiningRunState.CLAIMED.value, cutoff),
            ).fetchone()[0]
        )
        outstanding = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM mining_runs WHERE state=? AND heartbeat_at>?",
                (MiningRunState.CLAIMED.value, cutoff),
            ).fetchone()[0]
        )
        return DiscoveryStatus(groups, runs, proposals, outstanding, expired)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True


__all__ = ["MbaDiscoveryStore", "SCHEMA_VERSION"]
