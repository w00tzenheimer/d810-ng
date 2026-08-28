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

from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PluginIdentity
from d810.mba.differential_report import outcome_from_dict
from d810.mba.bounded_synthesis import (
    CERTIFICATION_WIDTHS,
    GrammarAllOnesOrigin,
    MbaCertification,
    MbaSynthesisResult,
    ProofReceipt,
)
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
from d810.mba.rule_proposal import MbaRuleProposal
from d810.mba.subterm_atomization import MbaAtomBinding
from d810.mba.term_codec import (
    TERM_WIRE_SCHEMA_VERSION,
    typed_term_from_dict,
    typed_term_to_dict,
)
from d810.mba.typed_term import TypedBvTerm, term_fingerprint
from d810.core.typing import Iterator


SCHEMA_VERSION = 1
DISCOVERY_LEASE_TIMEOUT = timedelta(minutes=5)
DISCOVERY_LEASE_TIMEOUT_SECONDS = DISCOVERY_LEASE_TIMEOUT.total_seconds()

_SCHEMA_SQL = """
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
        materialized_source_revision INTEGER,
        admitted_rule_id TEXT,
        admitted_at TEXT,
        terminal_source_state TEXT,
        terminal_source_revision INTEGER,
        rejection_reason TEXT
    );
    CREATE TABLE residual_group_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL REFERENCES residual_groups,
        event_kind TEXT NOT NULL CHECK (event_kind IN (
            'observed',
            'claimed',
            'run_no_proposal',
            'run_failed',
            'run_expired',
            'run_superseded',
            'proposal_published',
            'materialized',
            'admitted',
            'rejected'
        )),
        group_revision INTEGER NOT NULL,
        source_proposal_state TEXT,
        provider_attempt_id INTEGER REFERENCES provider_attempts,
        run_id TEXT REFERENCES mining_runs,
        proposal_id TEXT REFERENCES proposals,
        occurred_at TEXT NOT NULL,
        CHECK (group_revision >= 1),
        CHECK (
            (event_kind = 'observed'
                AND provider_attempt_id IS NOT NULL
                AND run_id IS NULL
                AND proposal_id IS NULL
                AND source_proposal_state IS NULL)
            OR
            (event_kind IN (
                    'claimed', 'run_no_proposal', 'run_failed',
                    'run_expired', 'run_superseded'
                )
                AND provider_attempt_id IS NULL
                AND run_id IS NOT NULL
                AND proposal_id IS NULL
                AND source_proposal_state IS NULL)
            OR
            (event_kind = 'proposal_published'
                AND provider_attempt_id IS NULL
                AND run_id IS NOT NULL
                AND proposal_id IS NOT NULL
                AND source_proposal_state IS NULL)
            OR
            (event_kind = 'materialized'
                AND provider_attempt_id IS NULL
                AND run_id IS NOT NULL
                AND proposal_id IS NOT NULL
                AND source_proposal_state IS NOT NULL
                AND source_proposal_state = 'proposed')
            OR
            (event_kind = 'admitted'
                AND provider_attempt_id IS NULL
                AND run_id IS NOT NULL
                AND proposal_id IS NOT NULL
                AND source_proposal_state IS NOT NULL
                AND source_proposal_state = 'materialized')
            OR
            (event_kind = 'rejected'
                AND provider_attempt_id IS NULL
                AND run_id IS NOT NULL
                AND proposal_id IS NOT NULL
                AND source_proposal_state IS NOT NULL
                AND source_proposal_state IN ('proposed', 'materialized'))
        )
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
    CREATE UNIQUE INDEX idx_residual_group_events_revision
        ON residual_group_events(group_id, group_revision)
        WHERE event_kind IN ('observed', 'claimed');
    CREATE UNIQUE INDEX idx_residual_group_events_attempt_owner
        ON residual_group_events(provider_attempt_id)
        WHERE provider_attempt_id IS NOT NULL;
    CREATE UNIQUE INDEX idx_residual_group_events_run_kind
        ON residual_group_events(run_id, event_kind)
        WHERE run_id IS NOT NULL;
    CREATE UNIQUE INDEX idx_residual_group_events_proposal_kind
        ON residual_group_events(proposal_id, event_kind)
        WHERE proposal_id IS NOT NULL;
    CREATE UNIQUE INDEX idx_residual_group_events_run_terminal
        ON residual_group_events(run_id)
        WHERE event_kind IN (
            'run_no_proposal', 'run_failed', 'run_expired',
            'run_superseded', 'proposal_published'
        );
    CREATE UNIQUE INDEX idx_residual_group_events_proposal_terminal
        ON residual_group_events(proposal_id)
        WHERE event_kind IN ('admitted', 'rejected');
    CREATE INDEX idx_residual_group_events_group_order
        ON residual_group_events(group_id, event_id);
"""

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
        "materialized_source_revision",
        "admitted_rule_id",
        "admitted_at",
        "terminal_source_state",
        "terminal_source_revision",
        "rejection_reason",
    ),
    "residual_group_events": (
        "event_id",
        "group_id",
        "event_kind",
        "group_revision",
        "source_proposal_state",
        "provider_attempt_id",
        "run_id",
        "proposal_id",
        "occurred_at",
    ),
}

_INDEXES = {
    "idx_residual_groups_claim",
    "idx_mining_runs_lease",
    "idx_provider_attempts_term",
    "idx_provider_attempts_function",
    "idx_provider_attempts_provider",
    "idx_proposals_group_state",
    "idx_residual_group_events_revision",
    "idx_residual_group_events_attempt_owner",
    "idx_residual_group_events_run_kind",
    "idx_residual_group_events_proposal_kind",
    "idx_residual_group_events_run_terminal",
    "idx_residual_group_events_proposal_terminal",
    "idx_residual_group_events_group_order",
}

_TYPE_BY_NAME = {
    "version": "INTEGER",
    "input_id": "INTEGER",
    "database_id": "INTEGER",
    "function_id": "INTEGER",
    "function_ea": "INTEGER",
    "function_rva": "INTEGER",
    "term_id": "INTEGER",
    "raw_term_id": "INTEGER",
    "group_id": "INTEGER",
    "claimed_revision": "INTEGER",
    "width": "INTEGER",
    "canonical_codec_version": "INTEGER",
    "raw_codec_version": "INTEGER",
    "attempt_id": "INTEGER",
    "top_level_epoch": "INTEGER",
    "evidence_generation": "INTEGER",
    "instruction_ea": "INTEGER",
    "block_serial": "INTEGER",
    "block_ea": "INTEGER",
    "input_cost_ops": "INTEGER",
    "input_cost_nodes": "INTEGER",
    "output_cost_ops": "INTEGER",
    "output_cost_nodes": "INTEGER",
    "proof_verdict": "INTEGER",
    "eligible_observation_count": "INTEGER",
    "revision": "INTEGER",
    "materialized_source_revision": "INTEGER",
    "terminal_source_revision": "INTEGER",
    "external_evidence_allowed": "INTEGER",
    "elapsed_ms": "REAL",
    "event_id": "INTEGER",
    "event_kind": "TEXT",
    "group_revision": "INTEGER",
    "source_proposal_state": "TEXT",
    "provider_attempt_id": "INTEGER",
    "run_id": "TEXT",
    "proposal_id": "TEXT",
    "occurred_at": "TEXT",
}
_BLOB_COLUMNS = {
    "canonical_term",
    "raw_term",
    "outcome_payload",
    "replacement_term",
    "proposal_payload",
    "proof_receipt_payload",
}
_COLUMN_TYPES = {
    table: tuple(
        "BLOB" if name in _BLOB_COLUMNS else _TYPE_BY_NAME.get(name, "TEXT")
        for name in columns
    )
    for table, columns in _TABLES.items()
}
_NOT_NULL = {
    table: tuple(
        name
        not in {
            "identity_provenance",
            "function_rva",
            "plugin_version",
            "block_serial",
            "block_ea",
            "input_cost_ops",
            "input_cost_nodes",
            "output_cost_ops",
            "output_cost_nodes",
            "proof_verdict",
            "refusal_reason",
            "last_mined_at",
            "materialized_at",
            "admitted_at",
            "finished_at",
            "failure_reason",
            "materialized_path",
            "materialized_digest",
            "materialized_source_revision",
            "admitted_rule_id",
            "terminal_source_state",
            "terminal_source_revision",
            "rejection_reason",
        }
        for name in columns
    )
    for table, columns in _TABLES.items()
}
_NOT_NULL["schema_migrations"] = (False, True)
for _table, _values in tuple(_NOT_NULL.items()):
    if _table != "schema_migrations":
        _NOT_NULL[_table] = (False,) + _values[1:]
_NOT_NULL["residual_group_events"] = (
    False,
    True,
    True,
    True,
    False,
    False,
    False,
    False,
    True,
)
_PRIMARY_KEYS = {
    table: tuple(name == columns[0] for name in columns)
    for table, columns in _TABLES.items()
}
_UNIQUE_COLUMNS = {
    "inputs": {("input_identity",)},
    "databases": {("database_uuid", "database_identity", "input_id")},
    "functions": {("database_id", "function_ea", "function_fingerprint")},
    "terms": {("canonical_fingerprint",)},
    "raw_terms": {("term_id", "raw_fingerprint")},
    "provider_attempts": {("attempt_uuid",)},
    "residual_groups": {("term_id",)},
    "mining_runs": {("run_id",)},
    "proposals": {("proposal_id",), ("proposal_fingerprint",)},
}
_FOREIGN_KEYS = {
    "schema_migrations": set(),
    "inputs": set(),
    "terms": set(),
    "databases": {("input_id", "inputs", None, "NO ACTION", "NO ACTION")},
    "functions": {("database_id", "databases", None, "NO ACTION", "NO ACTION")},
    "raw_terms": {("term_id", "terms", None, "NO ACTION", "NO ACTION")},
    "provider_attempts": {
        ("function_id", "functions", None, "NO ACTION", "NO ACTION"),
        ("term_id", "terms", None, "NO ACTION", "NO ACTION"),
        ("raw_term_id", "raw_terms", None, "NO ACTION", "NO ACTION"),
    },
    "residual_groups": {("term_id", "terms", None, "NO ACTION", "NO ACTION")},
    "mining_runs": {("group_id", "residual_groups", None, "NO ACTION", "NO ACTION")},
    "proposals": {
        ("group_id", "residual_groups", None, "NO ACTION", "NO ACTION"),
        ("run_id", "mining_runs", None, "NO ACTION", "NO ACTION"),
    },
    "residual_group_events": {
        ("group_id", "residual_groups", None, "NO ACTION", "NO ACTION"),
        ("provider_attempt_id", "provider_attempts", None, "NO ACTION", "NO ACTION"),
        ("run_id", "mining_runs", None, "NO ACTION", "NO ACTION"),
        ("proposal_id", "proposals", None, "NO ACTION", "NO ACTION"),
    },
}

_NAMED_INDEX_COLUMNS = {
    "idx_residual_groups_claim": (
        "residual_groups",
        ("state", "last_observed_at", "group_id"),
    ),
    "idx_mining_runs_lease": (
        "mining_runs",
        ("state", "heartbeat_at", "group_id"),
    ),
    "idx_provider_attempts_term": (
        "provider_attempts",
        ("term_id", "created_at", "attempt_id"),
    ),
    "idx_provider_attempts_function": (
        "provider_attempts",
        ("function_id", "created_at", "attempt_id"),
    ),
    "idx_provider_attempts_provider": (
        "provider_attempts",
        ("provider", "created_at", "attempt_id"),
    ),
    "idx_proposals_group_state": (
        "proposals",
        ("group_id", "state", "created_at", "proposal_id"),
    ),
    "idx_residual_group_events_revision": (
        "residual_group_events",
        ("group_id", "group_revision"),
    ),
    "idx_residual_group_events_attempt_owner": (
        "residual_group_events",
        ("provider_attempt_id",),
    ),
    "idx_residual_group_events_run_kind": (
        "residual_group_events",
        ("run_id", "event_kind"),
    ),
    "idx_residual_group_events_proposal_kind": (
        "residual_group_events",
        ("proposal_id", "event_kind"),
    ),
    "idx_residual_group_events_run_terminal": (
        "residual_group_events",
        ("run_id",),
    ),
    "idx_residual_group_events_proposal_terminal": (
        "residual_group_events",
        ("proposal_id",),
    ),
    "idx_residual_group_events_group_order": (
        "residual_group_events",
        ("group_id", "event_id"),
    ),
}
_INDEX_DDL = {
    "idx_residual_groups_claim": "create index idx_residual_groups_claim on residual_groups(state, last_observed_at, group_id)",
    "idx_mining_runs_lease": "create index idx_mining_runs_lease on mining_runs(state, heartbeat_at, group_id)",
    "idx_provider_attempts_term": "create index idx_provider_attempts_term on provider_attempts(term_id, created_at, attempt_id)",
    "idx_provider_attempts_function": "create index idx_provider_attempts_function on provider_attempts(function_id, created_at, attempt_id)",
    "idx_provider_attempts_provider": "create index idx_provider_attempts_provider on provider_attempts(provider, created_at, attempt_id)",
    "idx_proposals_group_state": "create index idx_proposals_group_state on proposals(group_id, state, created_at, proposal_id)",
    "idx_residual_group_events_revision": "create unique index idx_residual_group_events_revision on residual_group_events(group_id, group_revision) where event_kind in ('observed', 'claimed')",
    "idx_residual_group_events_attempt_owner": "create unique index idx_residual_group_events_attempt_owner on residual_group_events(provider_attempt_id) where provider_attempt_id is not null",
    "idx_residual_group_events_run_kind": "create unique index idx_residual_group_events_run_kind on residual_group_events(run_id, event_kind) where run_id is not null",
    "idx_residual_group_events_proposal_kind": "create unique index idx_residual_group_events_proposal_kind on residual_group_events(proposal_id, event_kind) where proposal_id is not null",
    "idx_residual_group_events_run_terminal": "create unique index idx_residual_group_events_run_terminal on residual_group_events(run_id) where event_kind in ( 'run_no_proposal', 'run_failed', 'run_expired', 'run_superseded', 'proposal_published' )",
    "idx_residual_group_events_proposal_terminal": "create unique index idx_residual_group_events_proposal_terminal on residual_group_events(proposal_id) where event_kind in ('admitted', 'rejected')",
    "idx_residual_group_events_group_order": "create index idx_residual_group_events_group_order on residual_group_events(group_id, event_id)",
}

_NAMED_INDEX_PARTIAL = {
    name: name.startswith("idx_residual_group_events_")
    and name != "idx_residual_group_events_group_order"
    for name in _NAMED_INDEX_COLUMNS
}
_NAMED_INDEX_UNIQUE = {
    name: name.startswith("idx_residual_group_events_")
    and name != "idx_residual_group_events_group_order"
    for name in _NAMED_INDEX_COLUMNS
}

_ATTEMPT_AUTHORITY_SELECT = """
    SELECT pa.*,
           f.function_ea AS authority_function_ea,
           f.function_rva AS authority_function_rva,
           f.function_fingerprint AS authority_function_fingerprint,
           d.database_uuid AS authority_database_uuid,
           d.database_identity AS authority_database_identity,
           i.input_identity AS authority_input_identity,
           i.identity_provenance AS authority_identity_provenance,
           i.external_evidence_allowed AS authority_external_evidence_allowed,
           t.canonical_fingerprint AS authority_canonical_fingerprint,
           rt.raw_fingerprint AS authority_raw_fingerprint,
           rt.term_id AS raw_owner_term_id,
           t.width AS authority_width,
           t.canonical_term AS authority_canonical_term,
           t.canonical_codec_version AS authority_canonical_codec_version,
           rt.raw_term AS authority_raw_term,
           rt.raw_codec_version AS authority_raw_codec_version
    FROM provider_attempts pa
    JOIN functions f ON f.function_id = pa.function_id
    JOIN databases d ON d.database_id = f.database_id
    JOIN inputs i ON i.input_id = d.input_id
    JOIN terms t ON t.term_id = pa.term_id
    JOIN raw_terms rt ON rt.raw_term_id = pa.raw_term_id
"""

_EVENT_KINDS = frozenset(
    {
        "observed",
        "claimed",
        "run_no_proposal",
        "run_failed",
        "run_expired",
        "run_superseded",
        "proposal_published",
        "materialized",
        "admitted",
        "rejected",
    }
)
_REVISION_EVENT_KINDS = frozenset({"observed", "claimed"})
_RUN_TERMINAL_EVENT_KINDS = frozenset(
    {
        "run_no_proposal",
        "run_failed",
        "run_expired",
        "run_superseded",
        "proposal_published",
    }
)
_RUN_STATE_FOR_EVENT = {
    "run_no_proposal": MiningRunState.NO_PROPOSAL.value,
    "run_failed": MiningRunState.FAILED.value,
    "run_expired": MiningRunState.EXPIRED.value,
    "run_superseded": MiningRunState.SUPERSEDED.value,
}


def _normalized_ddl(value: str) -> str:
    return " ".join(value.lower().split())


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


_PROPOSAL_FIELDS = frozenset(
    {
        "schema_version",
        "proposal_fingerprint",
        "source_fingerprints",
        "occurrence_count",
        "pattern",
        "replacement",
        "source_cost",
        "replacement_cost",
        "atomization_bindings",
        "proof_receipts",
        "class_name",
        "family",
        "description",
        "provenance",
        "fixture",
        "width_relative_all_ones",
        "fixed_operation_descriptors",
    }
)
_PROOF_FIELDS = frozenset({"width", "verdict", "elapsed_ms", "counterexample", "error"})


def _tupleize(value: object) -> object:
    if isinstance(value, list):
        return tuple(_tupleize(item) for item in value)
    if isinstance(value, dict):
        return {key: _tupleize(item) for key, item in value.items()}
    return value


def _proof_payload(proofs: tuple[ProofReceipt, ...]) -> bytes:
    return json.dumps(
        [
            {
                "width": proof.width,
                "verdict": proof.verdict,
                "elapsed_ms": proof.elapsed_ms,
                "counterexample": dict(proof.counterexample)
                if proof.counterexample is not None
                else None,
                "error": proof.error,
            }
            for proof in proofs
        ],
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _proofs_from_payload(payload: bytes) -> tuple[ProofReceipt, ...]:
    decoded = _strict_loads(payload)
    if type(decoded) is not list:
        raise ValueError("proof receipt payload must be a list")
    proofs: list[ProofReceipt] = []
    for row in decoded:
        if type(row) is not dict or set(row) != _PROOF_FIELDS:
            raise ValueError("proof receipt has invalid fields")
        proofs.append(
            ProofReceipt(
                width=row["width"],
                verdict=row["verdict"],
                elapsed_ms=row["elapsed_ms"],
                counterexample=row["counterexample"],
                error=row["error"],
            )
        )
    result = tuple(proofs)
    if result != tuple(
        sorted(result, key=lambda item: CERTIFICATION_WIDTHS.index(item.width))
    ):
        raise ValueError("proof receipts must be ordered by width")
    if tuple(item.width for item in result) != CERTIFICATION_WIDTHS:
        raise ValueError("proof receipts must cover exactly 8, 16, 32, and 64 bits")
    if any(not item.certified for item in result):
        raise ValueError("proof receipts must all be certified")
    if _proof_payload(result) != payload:
        raise ValueError("proof receipt payload is not canonical")
    return result


def _proposal_from_bytes(payload: bytes) -> MbaRuleProposal:
    decoded = _strict_loads(payload)
    if type(decoded) is not dict or set(decoded) != _PROPOSAL_FIELDS:
        raise ValueError("proposal payload has invalid fields")
    if decoded["schema_version"] != 1:
        raise ValueError("unsupported proposal schema version")
    proofs_raw = decoded["proof_receipts"]
    if type(proofs_raw) is not list:
        raise ValueError("proposal proof receipts must be a list")
    proofs: list[ProofReceipt] = []
    for row in proofs_raw:
        if type(row) is not dict or set(row) != _PROOF_FIELDS:
            raise ValueError("proof receipt has invalid fields")
        proofs.append(
            ProofReceipt(
                width=row["width"],
                verdict=row["verdict"],
                elapsed_ms=row["elapsed_ms"],
                counterexample=row["counterexample"],
                error=row["error"],
            )
        )
    bindings_raw = decoded["atomization_bindings"]
    if type(bindings_raw) is not list:
        raise ValueError("atomization bindings must be a list")
    bindings: list[MbaAtomBinding] = []
    for row in bindings_raw:
        if type(row) is not dict or set(row) != {
            "leaf_key",
            "original_subterm",
            "occurrence_count",
            "saved_operator_nodes",
        }:
            raise ValueError("atomization binding has invalid fields")
        bindings.append(
            MbaAtomBinding(
                leaf_key=_tupleize(row["leaf_key"]),  # type: ignore[arg-type]
                original_subterm=typed_term_from_dict(row["original_subterm"]),  # type: ignore[arg-type]
                occurrence_count=row["occurrence_count"],
                saved_operator_nodes=row["saved_operator_nodes"],
            )
        )
    pattern = typed_term_from_dict(decoded["pattern"])  # type: ignore[arg-type]
    replacement = typed_term_from_dict(decoded["replacement"])  # type: ignore[arg-type]
    origins_raw = decoded["width_relative_all_ones"]
    if type(origins_raw) is not list:
        raise ValueError("width-relative origins must be a list")
    origins = tuple(
        GrammarAllOnesOrigin(
            occurrence_path=tuple(item["occurrence_path"]),
            terminal_fingerprint=item["terminal_fingerprint"],
            source_width=item["source_width"],
            origin=item["origin"],
        )
        for item in origins_raw
    )
    fixed = tuple(tuple(item) for item in decoded["fixed_operation_descriptors"])
    synthesis = MbaSynthesisResult(
        source=pattern,
        replacement=replacement,
        source_cost=tuple(decoded["source_cost"]),
        replacement_cost=tuple(decoded["replacement_cost"]),
        certification=MbaCertification(tuple(proofs)),
        exhaustion=None,
        width_relative_all_ones=origins,
        fixed_operation_descriptors=fixed,
    )
    proposal = MbaRuleProposal(
        proposal_fingerprint=decoded["proposal_fingerprint"],
        source_fingerprints=tuple(decoded["source_fingerprints"]),
        occurrence_count=decoded["occurrence_count"],
        pattern=pattern,
        replacement=replacement,
        source_cost=tuple(decoded["source_cost"]),
        replacement_cost=tuple(decoded["replacement_cost"]),
        atomization_bindings=tuple(bindings),
        proof_receipts=tuple(proofs),
        class_name=decoded["class_name"],
        family=decoded["family"],
        description=decoded["description"],
        provenance=tuple(decoded["provenance"]),
        fixture=decoded["fixture"],
        fixed_operation_descriptors=fixed,
        synthesis_result=synthesis,
    )
    if (
        json.dumps(
            proposal.to_dict(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        != payload
    ):
        raise ValueError("proposal payload is not canonical")
    return proposal


def _proposal_payload_bytes(proposal: MbaRuleProposal) -> bytes:
    return json.dumps(
        proposal.to_dict(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _coerce_proposal_payload(value: object) -> tuple[MbaRuleProposal, bytes]:
    if isinstance(value, MbaRuleProposal):
        payload = _proposal_payload_bytes(value)
        return value, payload
    if type(value) is dict:
        payload = _proposal_payload_bytes(
            _proposal_from_bytes(_json_bytes(value, name="proposal payload"))
        )
        return _proposal_from_bytes(payload), payload
    if type(value) is bytes:
        proposal = _proposal_from_bytes(value)
        return proposal, value
    raise TypeError("proposal payload must be an MbaRuleProposal or canonical bytes")


def _coerce_proof_payload(value: object, proposal: MbaRuleProposal) -> bytes:
    if value is None:
        return _proof_payload(proposal.proof_receipts)
    if type(value) is bytes:
        proofs = _proofs_from_payload(value)
    elif type(value) in (tuple, list) and all(
        isinstance(item, ProofReceipt) for item in value
    ):
        proofs = tuple(value)
    else:
        raise TypeError(
            "proof receipt payload must be canonical bytes or ProofReceipt values"
        )
    if proofs != proposal.proof_receipts:
        raise ValueError("proof receipts do not match proposal")
    return _proof_payload(proofs)


def _decode_term(payload: bytes, *, name: str) -> TypedBvTerm:
    decoded = _strict_loads(payload)
    try:
        term = typed_term_from_dict(decoded)  # type: ignore[arg-type]
        if _term_bytes(term, name=name) != payload:
            raise ValueError(f"{name} bytes are not canonical")
        return term
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError(f"invalid {name} bytes") from exc


def _attempt_payload_bytes(attempt: DiscoveryAttempt) -> bytes:
    outcome = attempt.outcome
    eligible_for_mining = attempt.eligible_for_mining
    if type(eligible_for_mining) is not bool:
        raise TypeError("eligible_for_mining must be a bool")
    payload = json.dumps(
        {
            "schema_version": 1,
            "attempt_uuid": attempt.attempt_uuid,
            "canonical_fingerprint": term_fingerprint(attempt.canonical_term),
            "raw_fingerprint": term_fingerprint(attempt.raw_term),
            "eligible_for_mining": eligible_for_mining,
            "context": attempt.context.to_dict(),
            "outcome": outcome.to_dict(),
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    decoded = _strict_loads(payload)
    try:
        if type(decoded) is not dict or set(decoded) != {
            "schema_version",
            "attempt_uuid",
            "canonical_fingerprint",
            "raw_fingerprint",
            "eligible_for_mining",
            "context",
            "outcome",
        }:
            raise ValueError("attempt payload has invalid fields")
        if decoded["schema_version"] != 1:
            raise ValueError("unsupported attempt payload schema")
        if (
            decoded["attempt_uuid"] != attempt.attempt_uuid
            or decoded["canonical_fingerprint"]
            != term_fingerprint(attempt.canonical_term)
            or decoded["raw_fingerprint"] != term_fingerprint(attempt.raw_term)
        ):
            raise ValueError("attempt payload identity is invalid")
        if type(decoded["eligible_for_mining"]) is not bool:
            raise ValueError("attempt eligibility must be a boolean")
        restored = outcome_from_dict(decoded["outcome"])  # type: ignore[arg-type]
        restored_context = _context_from_dict(decoded["context"])
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise ValueError("attempt payload is not canonically representable") from exc
    if (
        decoded["eligible_for_mining"] is not eligible_for_mining
        or restored.to_dict() != decoded["outcome"]
        or restored_context != attempt.context
        or json.dumps(
            decoded,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        != payload
    ):
        raise ValueError("attempt payload is not canonically representable")
    return payload


def _context_from_dict(value: object) -> MbaObservationContext:
    if type(value) is not dict or set(value) != {
        "function_identity",
        "plugin_identity",
        "plugin_name",
        "plugin_version",
        "instruction_ea",
        "block_serial",
        "block_ea",
        "block_identity",
    }:
        raise ValueError("attempt context has invalid fields")
    identity_raw = value["function_identity"]
    plugin_raw = value["plugin_identity"]
    if type(identity_raw) is not dict or type(plugin_raw) is not dict:
        raise ValueError("attempt context identity is invalid")
    try:
        identity = FunctionExecutionIdentity(**identity_raw)
        plugin = PluginIdentity(**plugin_raw)
        context = MbaObservationContext(
            function_identity=identity,
            plugin_identity=plugin,
            instruction_ea=value["instruction_ea"],
            block_serial=value["block_serial"],
            block_ea=value["block_ea"],
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("attempt context is invalid") from exc
    if context.to_dict() != value:
        raise ValueError("attempt context is not canonical")
    return context


def _validate_attempt_payload(
    payload: bytes,
) -> tuple[bool, MbaProviderOutcome, MbaObservationContext]:
    decoded = _strict_loads(payload)
    if type(decoded) is not dict or set(decoded) != {
        "schema_version",
        "attempt_uuid",
        "canonical_fingerprint",
        "raw_fingerprint",
        "eligible_for_mining",
        "context",
        "outcome",
    }:
        raise ValueError("attempt payload has invalid fields")
    if decoded["schema_version"] != 1:
        raise ValueError("unsupported attempt payload schema")
    try:
        if str(UUID(decoded["attempt_uuid"])) != decoded["attempt_uuid"]:
            raise ValueError("attempt UUID is not canonical")
    except (TypeError, ValueError) as exc:
        raise ValueError("attempt payload UUID is invalid") from exc
    if (
        type(decoded["canonical_fingerprint"]) is not str
        or not decoded["canonical_fingerprint"]
        or type(decoded["raw_fingerprint"]) is not str
        or not decoded["raw_fingerprint"]
    ):
        raise ValueError("attempt payload fingerprints are invalid")
    if type(decoded["eligible_for_mining"]) is not bool:
        raise ValueError("attempt eligibility must be a boolean")
    try:
        outcome = outcome_from_dict(decoded["outcome"])  # type: ignore[arg-type]
        context = _context_from_dict(decoded["context"])
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise ValueError("attempt payload has invalid outcome") from exc
    canonical = _json_bytes(decoded, name="attempt payload")
    if canonical != payload:
        raise ValueError("attempt payload is not canonical")
    return decoded["eligible_for_mining"], outcome, context


def _timestamp(value: object) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("clock must return an aware datetime")
        current = value
        current = current.astimezone(timezone.utc)
        return current.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if type(value) is str and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an aware ISO-8601 value") from exc
        if parsed.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return (
            parsed.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    raise TypeError("clock must return a datetime or timestamp string")


def _parse_timestamp(
    value: object, *, name: str, required: bool = True
) -> datetime | None:
    if value is None:
        if required:
            raise ValueError(f"{name} is required")
        return None
    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be a canonical timestamp") from exc
    if parsed.tzinfo is None or _timestamp(parsed) != value:
        raise ValueError(f"{name} must be a canonical UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _canonical_text(value: object, *, name: str, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if type(value) is not str or not value or value.strip() != value:
        raise ValueError(f"{name} must be canonical non-empty text")
    return value


def _canonical_uuid(value: object, *, name: str) -> str:
    if isinstance(value, UUID):
        return str(value)
    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical UUID")
    try:
        result = str(UUID(value))
    except ValueError as exc:
        raise ValueError(f"{name} must be a canonical UUID") from exc
    if result != value:
        raise ValueError(f"{name} must be a canonical UUID")
    return result


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
        clock: object = lambda: datetime.now(timezone.utc),
        uuid_factory: object = uuid4,
    ) -> None:
        self.path = str(path)
        self._clock = clock
        self._uuid_factory = uuid_factory
        self._lock = threading.RLock()
        self._closed = False
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
        return _canonical_uuid(value, name="uuid factory result")

    def _append_event(
        self,
        conn: sqlite3.Connection,
        *,
        group_id: int,
        event_kind: str,
        group_revision: int,
        occurred_at: str,
        provider_attempt_id: int | None = None,
        run_id: str | None = None,
        proposal_id: str | None = None,
        source_proposal_state: str | None = None,
    ) -> int:
        if event_kind not in _EVENT_KINDS:
            raise ValueError("unknown causal event kind")
        _parse_timestamp(occurred_at, name="occurred_at")
        return int(
            conn.execute(
                "INSERT INTO residual_group_events(group_id,event_kind,group_revision,source_proposal_state,provider_attempt_id,run_id,proposal_id,occurred_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    group_id,
                    event_kind,
                    group_revision,
                    source_proposal_state,
                    provider_attempt_id,
                    run_id,
                    proposal_id,
                    occurred_at,
                ),
            ).lastrowid
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("discovery store is closed")

    @contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                self._validate_causal_domain(self._connection)
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
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                migration_exists = self._connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
                ).fetchone()
                any_expected = self._connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
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
                        "SELECT version, applied_at FROM schema_migrations ORDER BY version"
                    ).fetchall()
                    if any(row[0] > SCHEMA_VERSION for row in versions):
                        raise ValueError("unsupported schema version")
                    if [row[0] for row in versions] != [SCHEMA_VERSION]:
                        raise ValueError("partial schema")
                    _parse_timestamp(versions[0][1], name="applied_at")
                    self._validate_schema()
                self._validate_causal_domain(self._connection)
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
            journal = self._connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if self.path != ":memory:" and str(journal).lower() != "wal":
                raise ValueError("WAL journal mode could not be enabled")
            self._validate_pragmas()

    def _validate_pragmas(self) -> None:
        if self._connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ValueError("foreign keys are not enabled")
        if self._connection.execute("PRAGMA busy_timeout").fetchone()[0] != 5000:
            raise ValueError("busy timeout is not 5000ms")

    def _create_schema(self) -> None:
        for statement in _SCHEMA_SQL.split(";"):
            statement = statement.strip()
            if statement:
                self._connection.execute(statement)

    def _validate_schema(self) -> None:
        user_objects = {
            (row[0], row[1])
            for row in self._connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        expected_tables = {("table", table) for table in _TABLES}
        expected_indexes = {("index", index) for index in _INDEXES}
        if user_objects != expected_tables | expected_indexes:
            raise ValueError("partial schema: unexpected schema objects")
        expected_table_ddl = {
            statement.split()[2]: _normalized_ddl(statement)
            for statement in _SCHEMA_SQL.split(";")
            if statement.strip().lower().startswith("create table")
        }
        for table, expected in _TABLES.items():
            row = self._connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if row is None:
                raise ValueError("partial schema")
            if _normalized_ddl(row[0]) != expected_table_ddl[table]:
                raise ValueError(f"partial schema: {table} definition")
            xinfo = tuple(
                (item[1], item[2], item[3], item[4], item[5], item[6])
                for item in self._connection.execute(f'PRAGMA table_xinfo("{table}")')
            )
            if tuple(item[0] for item in xinfo) != expected:
                raise ValueError(f"partial schema: {table} columns")
            expected_xinfo = tuple(
                (
                    name,
                    _COLUMN_TYPES[table][index],
                    int(_NOT_NULL[table][index]),
                    None,
                    int(_PRIMARY_KEYS[table][index]),
                    0,
                )
                for index, name in enumerate(expected)
            )
            if xinfo != expected_xinfo:
                raise ValueError(f"partial schema: {table} metadata")
        indexes = {
            row[1]
            for table in _TABLES
            for row in self._connection.execute(f"PRAGMA index_list('{table}')")
            if not row[1].startswith("sqlite_autoindex_")
        }
        if indexes != _INDEXES:
            raise ValueError("partial schema: indexes")
        expected_index_signatures: set[
            tuple[int, str, int, tuple[tuple[int, str, int, str], ...]]
        ] = set()
        for index_name, (table, columns) in _NAMED_INDEX_COLUMNS.items():
            expected_index_signatures.add(
                (
                    int(_NAMED_INDEX_UNIQUE[index_name]),
                    "c",
                    int(_NAMED_INDEX_PARTIAL[index_name]),
                    tuple(
                        (tuple(_TABLES[table]).index(column), column, 0, "BINARY")
                        for column in columns
                    ),
                )
            )
        for table, expected_unique in _UNIQUE_COLUMNS.items():
            expected_index_signatures |= {
                (
                    1,
                    "pk"
                    if columns == ("run_id",)
                    and table == "mining_runs"
                    or columns == ("proposal_id",)
                    and table == "proposals"
                    else "u",
                    0,
                    tuple(
                        (tuple(_TABLES[table]).index(column), column, 0, "BINARY")
                        for column in columns
                    ),
                )
                for columns in expected_unique
            }
        actual_index_signatures: set[
            tuple[int, str, int, tuple[tuple[int, str | None, int, str], ...]]
        ] = set()
        for table in _TABLES:
            for index_row in self._connection.execute(f"PRAGMA index_list('{table}')"):
                index_name = index_row[1]
                xinfo = tuple(
                    (item[1], item[2], item[3], item[4])
                    for item in self._connection.execute(
                        f"PRAGMA index_xinfo('{index_name}')"
                    )
                    if item[5] == 1
                )
                actual_index_signatures.add(
                    (index_row[2], index_row[3], index_row[4], xinfo)
                )
        if actual_index_signatures != expected_index_signatures:
            raise ValueError("partial schema: index metadata")
        for index_name, expected_ddl in _INDEX_DDL.items():
            ddl_row = self._connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                (index_name,),
            ).fetchone()
            if ddl_row is None or _normalized_ddl(ddl_row[0]) != expected_ddl:
                raise ValueError("partial schema: index definition")
        for table in _TABLES:
            ddl = self._connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()[0]
            normalized = _normalized_ddl(ddl)
            if " collate " in normalized or " on conflict " in normalized:
                raise ValueError("partial schema: unique definition")
        for table, expected_unique in _UNIQUE_COLUMNS.items():
            actual_unique = {
                tuple(
                    row[2]
                    for row in self._connection.execute(
                        f"PRAGMA index_info('{index[1]}')"
                    )
                )
                for index in self._connection.execute(f"PRAGMA index_list('{table}')")
                if index[2] == 1
            }
            if actual_unique != expected_unique:
                raise ValueError(f"partial schema: unique constraints on {table}")
        actual_named = {}
        for index_name, (table, _) in _NAMED_INDEX_COLUMNS.items():
            if not self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
                (index_name,),
            ).fetchone():
                raise ValueError(f"partial schema: missing index {index_name}")
            actual_named[index_name] = tuple(
                row[2]
                for row in self._connection.execute(
                    f"PRAGMA index_info('{index_name}')"
                )
            )
            index_row = self._connection.execute(f"PRAGMA index_list('{table}')")
            if any(
                row[1] == index_name and row[2] != int(_NAMED_INDEX_UNIQUE[index_name])
                for row in index_row
            ):
                raise ValueError("partial schema: named index uniqueness")
        if actual_named != {
            name: columns for name, (_, columns) in _NAMED_INDEX_COLUMNS.items()
        }:
            raise ValueError("partial schema: named index columns")
        for table, expected_fks in _FOREIGN_KEYS.items():
            actual_fks = {
                (row[3], row[2], row[4], row[5], row[6])
                for row in self._connection.execute(
                    f"PRAGMA foreign_key_list('{table}')"
                )
            }
            if actual_fks != expected_fks:
                raise ValueError(f"partial schema: foreign keys on {table}")

    def schema_version(self) -> int:
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            return int(row[0])

    def table_columns(self) -> dict[str, tuple[str, ...]]:
        with self._lock:
            self._ensure_open()
            return {
                table: tuple(
                    row[1]
                    for row in self._connection.execute(f'PRAGMA table_info("{table}")')
                )
                for table in _TABLES
            }

    def connection_pragmas(self) -> dict[str, int]:
        with self._lock:
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
        with self._lock:
            self._ensure_open()
            return str(
                self._connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()

    def count_rows(self, table: str) -> int:
        with self._lock:
            self._ensure_open()
            if table not in _TABLES:
                raise ValueError("unknown discovery table")
            return int(
                self._connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[
                    0
                ]
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
            "UPDATE residual_groups SET state=?, eligible_observation_count=eligible_observation_count+?, last_observed_at=?, last_mined_at=?, revision=? WHERE group_id=?",
            (
                next_state.value,
                int(eligible),
                now,
                None
                if current is ResidualGroupState.NO_PROPOSAL
                and next_state is ResidualGroupState.ELIGIBLE
                else row[5],
                revision,
                row[0],
            ),
        )
        return int(row[0]), next_state, revision

    def _validate_attempt_row(
        self,
        row: sqlite3.Row,
        *,
        expected_term_id: int | None = None,
    ) -> tuple[bool, MbaProviderOutcome, MbaObservationContext]:
        eligible, outcome, context = _validate_attempt_payload(
            bytes(row["outcome_payload"])
        )
        payload_identity = _strict_loads(bytes(row["outcome_payload"]))
        if type(payload_identity) is not dict:
            raise ValueError("provider attempt payload authority is corrupt")
        identity = context.function_identity
        input_cost = outcome.input_cost or (None, None)
        output_cost = outcome.output_cost or (None, None)
        canonical = _decode_term(
            bytes(row["authority_canonical_term"]), name="canonical term"
        )
        raw = _decode_term(bytes(row["authority_raw_term"]), name="raw term")
        expected = {
            "session_id": identity.decompilation_session_id,
            "top_level_epoch": identity.top_level_epoch,
            "evidence_generation": identity.evidence_generation,
            "maturity": identity.maturity,
            "instruction_ea": context.instruction_ea,
            "block_serial": context.block_serial,
            "block_ea": context.block_ea,
            "provider": outcome.provider.value,
            "plugin_name": context.plugin_identity.name,
            "plugin_version": context.plugin_identity.version,
            "status": outcome.status.value,
            "input_cost_ops": input_cost[0],
            "input_cost_nodes": input_cost[1],
            "output_cost_ops": output_cost[0],
            "output_cost_nodes": output_cost[1],
            "proof_verdict": None
            if outcome.proof_verdict is None
            else int(outcome.proof_verdict),
            "elapsed_ms": outcome.elapsed_ms,
            "refusal_reason": outcome.refusal_reason,
            "authority_function_ea": identity.function_ea,
            "authority_function_rva": identity.function_rva,
            "authority_function_fingerprint": identity.function_fingerprint,
            "authority_database_uuid": identity.database_uuid,
            "authority_database_identity": identity.database_identity,
            "authority_input_identity": identity.input_identity,
            "authority_identity_provenance": identity.input_identity_provenance,
            "authority_external_evidence_allowed": int(
                identity.external_evidence_allowed
            ),
        }
        if any(row[name] != value for name, value in expected.items()):
            raise ValueError("provider attempt normalized authority is corrupt")
        if (
            str(UUID(row["attempt_uuid"])) != row["attempt_uuid"]
            or row["attempt_uuid"] != payload_identity["attempt_uuid"]
            or row["raw_owner_term_id"] != row["term_id"]
            or expected_term_id is not None
            and row["term_id"] != expected_term_id
            or row["authority_canonical_fingerprint"] != term_fingerprint(canonical)
            or row["authority_canonical_fingerprint"]
            != payload_identity["canonical_fingerprint"]
            or row["authority_raw_fingerprint"] != term_fingerprint(raw)
            or row["authority_raw_fingerprint"] != payload_identity["raw_fingerprint"]
            or row["authority_width"] != canonical.width
            or raw.width != canonical.width
            or row["authority_canonical_codec_version"] != TERM_WIRE_SCHEMA_VERSION
            or row["authority_raw_codec_version"] != TERM_WIRE_SCHEMA_VERSION
            or outcome.fingerprint != term_fingerprint(canonical)
        ):
            raise ValueError("stored term identity is corrupt")
        _parse_timestamp(row["created_at"], name="created_at")
        return eligible, outcome, context

    def record_attempt(self, attempt: DiscoveryAttempt) -> DiscoveryReceipt:
        if not isinstance(attempt, DiscoveryAttempt):
            raise TypeError("attempt must be a DiscoveryAttempt")
        canonical = _term_bytes(attempt.canonical_term, name="canonical term")
        raw = _term_bytes(attempt.raw_term, name="raw term")
        outcome_payload = _attempt_payload_bytes(attempt)
        try:
            with self._transaction(immediate=True) as conn:
                # Check UUID identity before any upsert so both an exact
                # retry and a conflicting collision are mutation-free.
                existing = conn.execute(
                    _ATTEMPT_AUTHORITY_SELECT + " WHERE pa.attempt_uuid=?",
                    (attempt.attempt_uuid,),
                ).fetchone()
                if existing is not None:
                    self._validate_attempt_row(existing)
                    stored_canonical = _decode_term(
                        bytes(existing[37]), name="canonical term"
                    )
                    stored_raw = _decode_term(bytes(existing[39]), name="raw term")
                    if (
                        existing[35] != existing[3]
                        or stored_canonical != attempt.canonical_term
                        or stored_raw != attempt.raw_term
                        or existing[33] != term_fingerprint(stored_canonical)
                        or existing[34] != term_fingerprint(stored_raw)
                        or existing[36] != stored_canonical.width
                        or existing[38] != TERM_WIRE_SCHEMA_VERSION
                        or existing[40] != TERM_WIRE_SCHEMA_VERSION
                    ):
                        raise ValueError("stored term identity is corrupt")
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
                        and existing[36] == attempt.canonical_term.width
                        and existing[37] == canonical
                        and existing[38] == TERM_WIRE_SCHEMA_VERSION
                        and existing[39] == raw
                        and existing[40] == TERM_WIRE_SCHEMA_VERSION
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
                    _stored_eligible, _stored_outcome, _stored_context = (
                        _validate_attempt_payload(bytes(existing[23]))
                    )
                    if _stored_outcome.fingerprint != term_fingerprint(
                        attempt.canonical_term
                    ):
                        raise ValueError("stored attempt outcome is corrupt")
                    group = conn.execute(
                        "SELECT * FROM residual_groups WHERE term_id=?", (existing[3],)
                    ).fetchone()
                    if group is not None:
                        self._validate_relational_lifecycle(conn, int(group[0]))
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
                existing_group = conn.execute(
                    "SELECT group_id FROM residual_groups WHERE term_id=?", (term_id,)
                ).fetchone()
                if existing_group is not None:
                    self._validate_relational_lifecycle(conn, int(existing_group[0]))
                identity = attempt.context.function_identity
                context = attempt.context
                outcome = attempt.outcome
                input_cost = outcome.input_cost or (None, None)
                output_cost = outcome.output_cost or (None, None)
                now = self._now()
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
                            now,
                        ),
                    ).lastrowid
                )
                group_id, state, revision = self._group(
                    conn, term_id, eligible=attempt.eligible_for_mining, now=now
                )
                self._append_event(
                    conn,
                    group_id=group_id,
                    event_kind="observed",
                    group_revision=revision,
                    provider_attempt_id=attempt_id,
                    occurred_at=now,
                )
                self._validate_relational_lifecycle(conn, group_id)
                return DiscoveryReceipt(
                    ReceiptStatus.STORED,
                    attempt_id=attempt_id,
                    group_id=group_id,
                    term_id=term_id,
                    raw_term_id=raw_id,
                    revision=revision,
                    state=state,
                )
        except (sqlite3.IntegrityError, sqlite3.OperationalError, ValueError) as exc:
            reason = (
                "storage_busy"
                if isinstance(exc, sqlite3.OperationalError)
                else str(exc)
            )
            return DiscoveryReceipt(ReceiptStatus.REFUSED, reason=reason)

    def _project_group_local(
        self, conn: sqlite3.Connection, group_id: int
    ) -> ResidualGroup:
        row = conn.execute(
            "SELECT * FROM residual_groups WHERE group_id=?", (group_id,)
        ).fetchone()
        if row is None:
            raise ValueError("unknown group")
        try:
            state = ResidualGroupState(row[2])
        except ValueError as exc:
            raise ValueError("unknown residual group state") from exc
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
        if any(raw.width != canonical.width for raw in raws):
            raise ValueError("raw and canonical term widths are inconsistent")
        eligible_count = 0
        for attempt in conn.execute(
            _ATTEMPT_AUTHORITY_SELECT + " WHERE pa.term_id=? ORDER BY pa.attempt_id",
            (row[1],),
        ):
            _eligible, _outcome, _context = self._validate_attempt_row(
                attempt, expected_term_id=int(row[1])
            )
            eligible_count += int(_eligible)
        if int(row[3]) != eligible_count:
            raise ValueError("eligible observation count is corrupt")
        if state is ResidualGroupState.OBSERVED and eligible_count != 0:
            raise ValueError("observed group cannot contain eligible evidence")
        if state is not ResidualGroupState.OBSERVED and eligible_count == 0:
            raise ValueError("non-observed group requires eligible evidence")
        observed_at = _parse_timestamp(row[4], name="last_observed_at")
        mined_at = _parse_timestamp(row[5], name="last_mined_at", required=False)
        materialized_at = _parse_timestamp(
            row[6], name="materialized_at", required=False
        )
        admitted_at = _parse_timestamp(row[7], name="admitted_at", required=False)
        if state is ResidualGroupState.NO_PROPOSAL and mined_at is None:
            raise ValueError("no-proposal group requires last_mined_at")
        if state is not ResidualGroupState.NO_PROPOSAL and mined_at is not None:
            raise ValueError("non-no-proposal group has last_mined_at")
        if state in {
            ResidualGroupState.OBSERVED,
            ResidualGroupState.ELIGIBLE,
            ResidualGroupState.MINING,
            ResidualGroupState.NO_PROPOSAL,
        } and (materialized_at is not None or admitted_at is not None):
            raise ValueError("pre-proposal group has terminal timestamps")
        if state is ResidualGroupState.MATERIALIZED:
            if materialized_at is None or admitted_at is not None:
                raise ValueError("materialized group timestamps are inconsistent")
        if state is ResidualGroupState.ADMITTED:
            if materialized_at is None or admitted_at is None:
                raise ValueError("admitted group timestamps are incomplete")
        if state is ResidualGroupState.REJECTED and admitted_at is not None:
            raise ValueError("rejected group cannot have admitted_at")
        if state is ResidualGroupState.PROPOSED and (
            materialized_at is not None or admitted_at is not None
        ):
            raise ValueError("proposed group has terminal timestamps")
        if (
            materialized_at is not None
            and mined_at is not None
            and materialized_at < mined_at
        ):
            raise ValueError("group timestamps are out of order")
        if admitted_at is not None and materialized_at is None:
            raise ValueError("admitted group requires materialized_at")
        return ResidualGroup(
            int(row[0]),
            int(row[1]),
            state,
            int(row[3]),
            _timestamp(observed_at),  # type: ignore[arg-type]
            None if mined_at is None else _timestamp(mined_at),
            None if materialized_at is None else _timestamp(materialized_at),
            None if admitted_at is None else _timestamp(admitted_at),
            int(row[8]),
            canonical,
            raws,
        )

    def _decode_raw_term(self, row: sqlite3.Row) -> TypedBvTerm:
        term = _decode_term(bytes(row[3]), name="raw term")
        if row[2] != term_fingerprint(term) or row[4] != TERM_WIRE_SCHEMA_VERSION:
            raise ValueError("raw term identity is corrupt")
        return term

    def _project_run_local(self, row: sqlite3.Row) -> MiningRun:
        try:
            state = MiningRunState(row[5])
        except ValueError as exc:
            raise ValueError("unknown mining run state") from exc
        started = _parse_timestamp(row[6], name="started_at")
        heartbeat = _parse_timestamp(row[7], name="heartbeat_at")
        finished = _parse_timestamp(row[8], name="finished_at", required=False)
        _canonical_text(row[3], name="miner_version")
        _canonical_text(row[4], name="budget_fingerprint")
        if heartbeat < started or finished is not None and finished < heartbeat:
            raise ValueError("mining run timestamps are out of order")
        if state is MiningRunState.ACTIVE:
            if finished is not None or row[9] is not None:
                raise ValueError("active run has terminal fields")
        elif finished is None:
            raise ValueError("terminal run requires finished_at")
        if state is MiningRunState.PROPOSED and row[9] is not None:
            raise ValueError("proposed run cannot have failure_reason")
        if (
            state
            in {
                MiningRunState.NO_PROPOSAL,
                MiningRunState.EXPIRED,
                MiningRunState.FAILED,
                MiningRunState.SUPERSEDED,
            }
            and row[9] is None
        ):
            raise ValueError("terminal run requires failure_reason")
        if row[9] is not None:
            _canonical_text(row[9], name="failure_reason")
        return MiningRun(
            row[0],
            int(row[1]),
            int(row[2]),
            row[3],
            row[4],
            state,
            _timestamp(started),  # type: ignore[arg-type]
            _timestamp(heartbeat),  # type: ignore[arg-type]
            None if finished is None else _timestamp(finished),
            row[9],
        )

    def _project_proposal_local(
        self, conn: sqlite3.Connection, row: sqlite3.Row
    ) -> Proposal:
        replacement = _decode_term(
            bytes(row["replacement_term"]), name="replacement term"
        )
        proposal = _proposal_from_bytes(bytes(row["proposal_payload"]))
        proofs = _proofs_from_payload(bytes(row["proof_receipt_payload"]))
        if (
            row["proposal_fingerprint"] != proposal.fingerprint
            or replacement != proposal.replacement
            or replacement.width != proposal.pattern.width
            or proofs != proposal.proof_receipts
        ):
            raise ValueError("proposal identity is corrupt")
        group = conn.execute(
            "SELECT * FROM residual_groups WHERE group_id=?", (row["group_id"],)
        ).fetchone()
        run = conn.execute(
            "SELECT * FROM mining_runs WHERE run_id=?", (row["run_id"],)
        ).fetchone()
        if group is None or run is None or run[1] != group[0] or run[2] > group[8]:
            raise ValueError("proposal ownership is corrupt")
        self._project_group_local(conn, int(group[0]))
        try:
            self._project_run_local(run)
        except ValueError as exc:
            raise ValueError("proposal lifecycle ownership is corrupt") from exc
        group_term = conn.execute(
            "SELECT width, canonical_term FROM terms WHERE term_id=?", (group[1],)
        ).fetchone()
        if (
            group_term is None
            or group_term[0] != proposal.pattern.width
            or bytes(group_term[1])
            != _term_bytes(proposal.pattern, name="proposal pattern")
        ):
            raise ValueError("proposal source group is corrupt")
        try:
            state = ProposalState(row[7])
            run_state = MiningRunState(run[5])
            group_state = ResidualGroupState(group[2])
        except ValueError as exc:
            raise ValueError(
                "unknown proposal state (ownership state is corrupt)"
            ) from exc
        created_at = _parse_timestamp(row["created_at"], name="created_at")
        materialized_at = _parse_timestamp(
            row["materialized_at"], name="materialized_at", required=False
        )
        admitted_at = _parse_timestamp(
            row["admitted_at"], name="admitted_at", required=False
        )
        materialized_revision = row["materialized_source_revision"]
        terminal_revision = row["terminal_source_revision"]
        for name, value in (
            ("materialized_source_revision", materialized_revision),
            ("terminal_source_revision", terminal_revision),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{name} is corrupt")
        terminal_state_raw = row["terminal_source_state"]
        try:
            terminal_state = (
                None
                if terminal_state_raw is None
                else ProposalState(terminal_state_raw)
            )
        except ValueError as exc:
            raise ValueError("terminal_source_state is corrupt") from exc
        material_fields = (
            row["materialized_path"],
            row["materialized_digest"],
            row["materialized_at"],
            materialized_revision,
        )
        terminal_fields = (terminal_state, terminal_revision)
        if state is ProposalState.PROPOSED:
            if any(
                value is not None
                for value in (
                    *material_fields,
                    row["admitted_rule_id"],
                    row["admitted_at"],
                    *terminal_fields,
                    row["rejection_reason"],
                )
            ):
                raise ValueError("proposed proposal has terminal fields")
        elif state is ProposalState.MATERIALIZED:
            if (
                any(value is None for value in material_fields)
                or row["admitted_rule_id"] is not None
                or row["admitted_at"] is not None
                or any(value is not None for value in terminal_fields)
                or row["rejection_reason"] is not None
            ):
                raise ValueError("materialized proposal fields are inconsistent")
        elif state is ProposalState.ADMITTED:
            if terminal_state is not ProposalState.MATERIALIZED:
                raise ValueError("terminal_source_state is corrupt")
            if (
                any(value is None for value in material_fields)
                or row["admitted_rule_id"] is None
                or row["admitted_at"] is None
                or terminal_revision is None
                or row["rejection_reason"] is not None
            ):
                raise ValueError("admitted proposal fields are inconsistent")
        elif state is ProposalState.REJECTED:
            if terminal_state not in {
                ProposalState.PROPOSED,
                ProposalState.MATERIALIZED,
            }:
                raise ValueError("terminal_source_state is corrupt")
            if (
                row["rejection_reason"] is None
                or row["admitted_rule_id"] is not None
                or row["admitted_at"] is not None
                or terminal_revision is None
            ):
                raise ValueError("rejected proposal fields are inconsistent")
            if terminal_state is ProposalState.PROPOSED and any(
                value is not None for value in material_fields
            ):
                raise ValueError("rejected-from-proposed has materialization fields")
            if terminal_state is ProposalState.MATERIALIZED and any(
                value is None for value in material_fields
            ):
                raise ValueError("rejected materialization fields are incomplete")
        for name, value in (
            ("materialized_path", row["materialized_path"]),
            ("materialized_digest", row["materialized_digest"]),
            ("admitted_rule_id", row["admitted_rule_id"]),
            ("rejection_reason", row["rejection_reason"]),
        ):
            if value is not None:
                _canonical_text(value, name=name)
        if materialized_at is not None and materialized_at < created_at:
            raise ValueError("proposal timestamps are out of order")
        if admitted_at is not None and (
            materialized_at is None or admitted_at < materialized_at
        ):
            raise ValueError("proposal timestamps are out of order")
        expected_group_state = {
            ProposalState.PROPOSED: ResidualGroupState.PROPOSED,
            ProposalState.MATERIALIZED: ResidualGroupState.MATERIALIZED,
            ProposalState.ADMITTED: ResidualGroupState.ADMITTED,
            ProposalState.REJECTED: ResidualGroupState.REJECTED,
        }[state]
        if (
            run_state is not MiningRunState.PROPOSED
            or run[8] is None
            or group_state is not expected_group_state
        ):
            raise ValueError("proposal lifecycle ownership is corrupt")
        return Proposal(
            proposal_id=row["proposal_id"],
            group_id=int(row["group_id"]),
            run_id=row["run_id"],
            proposal_fingerprint=row["proposal_fingerprint"],
            replacement_term=replacement,
            proposal_payload=bytes(row["proposal_payload"]),
            proof_receipt_payload=bytes(row["proof_receipt_payload"]),
            state=state,
            created_at=_timestamp(created_at),  # type: ignore[arg-type]
            materialized_path=row["materialized_path"],
            materialized_digest=row["materialized_digest"],
            materialized_at=(
                None if materialized_at is None else _timestamp(materialized_at)
            ),
            materialized_source_revision=materialized_revision,
            admitted_rule_id=row["admitted_rule_id"],
            admitted_at=None if admitted_at is None else _timestamp(admitted_at),
            terminal_source_state=terminal_state,
            terminal_source_revision=terminal_revision,
            rejection_reason=row["rejection_reason"],
        )

    def _validate_causal_events(
        self,
        conn: sqlite3.Connection,
        group: ResidualGroup,
        runs: dict[str, MiningRun],
        proposals: dict[str, Proposal],
    ) -> None:
        rows = conn.execute(
            "SELECT * FROM residual_group_events WHERE group_id=? ORDER BY event_id",
            (group.group_id,),
        ).fetchall()
        if not rows:
            raise ValueError("residual group requires causal events")
        events = list(rows)
        revision_events = [
            row for row in events if row["event_kind"] in _REVISION_EVENT_KINDS
        ]
        if [row["group_revision"] for row in revision_events] != list(
            range(1, group.revision + 1)
        ):
            raise ValueError("causal revision sequence is corrupt")
        latest_revision = 0
        for row in events:
            kind = row["event_kind"]
            if kind not in _EVENT_KINDS:
                raise ValueError("unknown causal event kind")
            if type(row["group_revision"]) is not int or row["group_revision"] < 1:
                raise ValueError("causal event revision is corrupt")
            _parse_timestamp(row["occurred_at"], name="occurred_at")
            if kind in _REVISION_EVENT_KINDS:
                if row["group_revision"] != latest_revision + 1:
                    raise ValueError("causal revision ordering is corrupt")
                latest_revision = row["group_revision"]
            elif row["group_revision"] != latest_revision:
                raise ValueError("causal event points at a stale revision")
            if kind == "observed":
                if (
                    row["provider_attempt_id"] is None
                    or row["run_id"] is not None
                    or row["proposal_id"] is not None
                    or row["source_proposal_state"] is not None
                ):
                    raise ValueError("observed event owner shape is corrupt")
            elif kind == "claimed":
                if (
                    row["provider_attempt_id"] is not None
                    or row["run_id"] is None
                    or row["proposal_id"] is not None
                    or row["source_proposal_state"] is not None
                ):
                    raise ValueError("claimed event owner shape is corrupt")
            elif kind in _RUN_TERMINAL_EVENT_KINDS - {"proposal_published"}:
                if (
                    row["provider_attempt_id"] is not None
                    or row["run_id"] is None
                    or row["proposal_id"] is not None
                    or row["source_proposal_state"] is not None
                ):
                    raise ValueError("run event owner shape is corrupt")
            elif kind == "proposal_published":
                if (
                    row["provider_attempt_id"] is not None
                    or row["run_id"] is None
                    or row["proposal_id"] is None
                    or row["source_proposal_state"] is not None
                ):
                    raise ValueError("publication event owner shape is corrupt")
            elif kind in {"materialized", "admitted", "rejected"}:
                expected_sources = {
                    "materialized": {"proposed"},
                    "admitted": {"materialized"},
                    "rejected": {"proposed", "materialized"},
                }[kind]
                if (
                    row["provider_attempt_id"] is not None
                    or row["run_id"] is None
                    or row["proposal_id"] is None
                    or row["source_proposal_state"] not in expected_sources
                ):
                    raise ValueError("proposal event owner shape is corrupt")

        attempt_rows = conn.execute(
            "SELECT pa.attempt_id, pa.created_at FROM provider_attempts pa WHERE pa.term_id=?",
            (group.term_id,),
        ).fetchall()
        attempts = {int(row["attempt_id"]): row for row in attempt_rows}
        observed = [row for row in events if row["event_kind"] == "observed"]
        if len(observed) != len(attempts) or {
            row["provider_attempt_id"] for row in observed
        } != set(attempts):
            raise ValueError("provider attempts and observed events disagree")
        for row in observed:
            attempt = attempts.get(row["provider_attempt_id"])
            if attempt is None or row["occurred_at"] != attempt["created_at"]:
                raise ValueError("observed event authority is corrupt")

        run_claims: dict[str, list[sqlite3.Row]] = {run_id: [] for run_id in runs}
        run_events: dict[str, list[sqlite3.Row]] = {run_id: [] for run_id in runs}
        for row in events:
            run_id = row["run_id"]
            if run_id is not None:
                if run_id not in runs:
                    raise ValueError("causal run owner is corrupt")
                run_events[run_id].append(row)
                if row["event_kind"] == "claimed":
                    run_claims[run_id].append(row)
            if row["proposal_id"] is not None and row["proposal_id"] not in proposals:
                raise ValueError("causal proposal owner is corrupt")
        for run_id, run in runs.items():
            claims = run_claims[run_id]
            if len(claims) != 1:
                raise ValueError("mining run claim event count is corrupt")
            claim = claims[0]
            if (
                claim["group_revision"] != run.claimed_revision
                or claim["occurred_at"] != run.started_at
            ):
                raise ValueError("mining run claim authority is corrupt")
            terminals = [
                row
                for row in run_events[run_id]
                if row["event_kind"] in _RUN_TERMINAL_EVENT_KINDS
            ]
            expected_terminal = {
                MiningRunState.ACTIVE: None,
                MiningRunState.NO_PROPOSAL: "run_no_proposal",
                MiningRunState.FAILED: "run_failed",
                MiningRunState.EXPIRED: "run_expired",
                MiningRunState.SUPERSEDED: "run_superseded",
                MiningRunState.PROPOSED: "proposal_published",
            }[run.state]
            if expected_terminal is None:
                if terminals:
                    raise ValueError("active run has a terminal causal event")
            elif len(terminals) != 1 or terminals[0]["event_kind"] != expected_terminal:
                raise ValueError("mining run terminal event disagrees with state")
            if terminals:
                terminal = terminals[0]
                if (
                    terminal["group_revision"] < run.claimed_revision
                    or terminal["occurred_at"] != run.finished_at
                ):
                    raise ValueError("mining run terminal authority is corrupt")

        for proposal_id, proposal in proposals.items():
            proposal_events = [
                row for row in events if row["proposal_id"] == proposal_id
            ]
            publication = [
                row
                for row in proposal_events
                if row["event_kind"] == "proposal_published"
            ]
            if len(publication) != 1:
                raise ValueError("proposal publication event count is corrupt")
            publishing_run = runs.get(proposal.run_id)
            if publishing_run is None:
                raise ValueError("proposal publishing run is corrupt")
            publication_row = publication[0]
            if (
                publication_row["run_id"] != proposal.run_id
                or publication_row["group_revision"] != publishing_run.claimed_revision
                or publication_row["occurred_at"] != proposal.created_at
            ):
                raise ValueError("proposal publication authority is corrupt")
            ordered_kinds = [row["event_kind"] for row in proposal_events]
            expected_kinds = {
                ProposalState.PROPOSED: ["proposal_published"],
                ProposalState.MATERIALIZED: ["proposal_published", "materialized"],
                ProposalState.ADMITTED: [
                    "proposal_published",
                    "materialized",
                    "admitted",
                ],
                ProposalState.REJECTED: ["proposal_published", "rejected"]
                if proposal.terminal_source_state is ProposalState.PROPOSED
                else ["proposal_published", "materialized", "rejected"],
            }[proposal.state]
            if ordered_kinds != expected_kinds:
                raise ValueError("proposal causal transition order is corrupt")
            for row in proposal_events:
                if row["run_id"] != proposal.run_id:
                    raise ValueError("proposal event publishing run is corrupt")
                if row["event_kind"] == "materialized":
                    if (
                        row["group_revision"] != proposal.materialized_source_revision
                        or row["occurred_at"] != proposal.materialized_at
                    ):
                        raise ValueError("materialization event authority is corrupt")
                elif row["event_kind"] == "admitted":
                    if (
                        row["group_revision"] != proposal.terminal_source_revision
                        or row["occurred_at"] != proposal.admitted_at
                    ):
                        raise ValueError("admission event authority is corrupt")
                elif row["event_kind"] == "rejected":
                    if (
                        row["group_revision"] != proposal.terminal_source_revision
                        or row["source_proposal_state"]
                        != proposal.terminal_source_state.value
                    ):
                        raise ValueError("rejection event authority is corrupt")

        if latest_revision != group.revision:
            raise ValueError("causal revision does not match group")

    def _validate_causal_domain(self, conn: sqlite3.Connection) -> None:
        """Reject unowned event rows before any global read or write."""
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("causal domain has foreign-key corruption")
        groups = {
            int(row[0]) for row in conn.execute("SELECT group_id FROM residual_groups")
        }
        events = conn.execute(
            "SELECT event_id, group_id, provider_attempt_id, run_id, proposal_id FROM residual_group_events ORDER BY event_id"
        ).fetchall()
        if len({row["event_id"] for row in events}) != len(events):
            raise ValueError("causal event identity is corrupt")
        for row in events:
            group_id = row["group_id"]
            if group_id not in groups:
                raise ValueError("causal domain contains an orphan event")
            group_term = conn.execute(
                "SELECT term_id FROM residual_groups WHERE group_id=?", (group_id,)
            ).fetchone()[0]
            if row["provider_attempt_id"] is not None:
                attempt = conn.execute(
                    "SELECT term_id FROM provider_attempts WHERE attempt_id=?",
                    (row["provider_attempt_id"],),
                ).fetchone()
                if attempt is None or attempt[0] != group_term:
                    raise ValueError("causal event attempt owner is corrupt")
            if row["run_id"] is not None:
                run = conn.execute(
                    "SELECT group_id FROM mining_runs WHERE run_id=?", (row["run_id"],)
                ).fetchone()
                if run is None or run[0] != group_id:
                    raise ValueError("causal event run owner is corrupt")
            if row["proposal_id"] is not None:
                proposal = conn.execute(
                    "SELECT group_id FROM proposals WHERE proposal_id=?",
                    (row["proposal_id"],),
                ).fetchone()
                if proposal is None or proposal[0] != group_id:
                    raise ValueError("causal event proposal owner is corrupt")
        event_ids = {int(row["event_id"]) for row in events}
        consumed_ids: set[int] = set()
        for group_id in groups:
            consumed_ids.update(
                int(row[0])
                for row in conn.execute(
                    "SELECT event_id FROM residual_group_events WHERE group_id=?",
                    (group_id,),
                )
            )
        if consumed_ids != event_ids:
            raise ValueError("causal event coverage is incomplete")
        for group_id in groups:
            self._validate_relational_lifecycle(conn, group_id)

    def _validate_relational_lifecycle(
        self, conn: sqlite3.Connection, group_id: int
    ) -> tuple[
        ResidualGroup,
        dict[str, MiningRun],
        dict[str, Proposal],
    ]:
        group_row = conn.execute(
            "SELECT * FROM residual_groups WHERE group_id=?", (group_id,)
        ).fetchone()
        if group_row is None:
            raise ValueError("unknown group")
        group = self._project_group_local(conn, group_id)
        run_rows = conn.execute(
            "SELECT * FROM mining_runs WHERE group_id=? ORDER BY claimed_revision, started_at, run_id",
            (group_id,),
        ).fetchall()
        proposal_rows = conn.execute(
            "SELECT * FROM proposals WHERE group_id=? ORDER BY created_at, proposal_id",
            (group_id,),
        ).fetchall()
        try:
            runs = {row[0]: self._project_run_local(row) for row in run_rows}
        except ValueError as exc:
            if proposal_rows:
                raise ValueError(
                    f"proposal lifecycle ownership is corrupt: {exc}"
                ) from exc
            raise
        proposals = {
            row[0]: self._project_proposal_local(conn, row) for row in proposal_rows
        }
        attempt_rows = conn.execute(
            "SELECT created_at FROM provider_attempts WHERE term_id=? ORDER BY attempt_id",
            (group.term_id,),
        ).fetchall()
        if not attempt_rows:
            raise ValueError("residual group requires provider attempts")
        attempt_times = [
            _parse_timestamp(row[0], name="created_at") for row in attempt_rows
        ]
        observed_at = _parse_timestamp(group.last_observed_at, name="last_observed_at")
        if any(created > observed_at for created in attempt_times):
            raise ValueError("provider attempt timestamps exceed last observation")
        if group.revision != len(attempt_rows) + len(run_rows):
            raise ValueError("group revision ownership is corrupt")

        active = [run for run in runs.values() if run.state is MiningRunState.ACTIVE]
        if len(active) > 1:
            raise ValueError("duplicate active mining owners")
        ordered_runs = list(runs.values())
        for index, run in enumerate(ordered_runs):
            if run.claimed_revision < index + 2:
                raise ValueError("mining run claimed revision precedes evidence")
            if run.claimed_revision > group.revision:
                raise ValueError("mining run claimed revision is corrupt")
            if index:
                previous = ordered_runs[index - 1]
                if run.claimed_revision <= previous.claimed_revision:
                    raise ValueError("mining run claimed revisions are out of order")
                previous_finished = _parse_timestamp(
                    previous.finished_at, name="finished_at", required=False
                )
                current_started = _parse_timestamp(run.started_at, name="started_at")
                if previous_finished is None or previous_finished > current_started:
                    raise ValueError("mining run history is out of order")
        latest_run = ordered_runs[-1] if ordered_runs else None
        if group.state is ResidualGroupState.MINING:
            if len(active) != 1:
                raise ValueError("mining group requires exactly one active owner")
            if active[0].claimed_revision > group.revision:
                raise ValueError("active mining owner revision is corrupt")
            if latest_run is not active[0]:
                raise ValueError("active mining owner is not the latest run")
        elif active:
            raise ValueError("active mining owner requires a mining group")

        proposal_states = {
            ResidualGroupState.PROPOSED,
            ResidualGroupState.MATERIALIZED,
            ResidualGroupState.ADMITTED,
            ResidualGroupState.REJECTED,
        }
        if group.state in proposal_states and len(proposals) != 1:
            raise ValueError("proposal lifecycle requires exactly one proposal")
        if group.state not in proposal_states and proposals:
            raise ValueError("pre-proposal group owns a proposal")
        proposed_runs = {
            run.run_id for run in runs.values() if run.state is MiningRunState.PROPOSED
        }
        proposal_run_ids = {proposal.run_id for proposal in proposals.values()}
        if proposed_runs != proposal_run_ids:
            raise ValueError("proposed run history does not own exactly one proposal")
        if group.state is ResidualGroupState.OBSERVED and run_rows:
            raise ValueError("observed group cannot own mining runs")
        if group.state is ResidualGroupState.NO_PROPOSAL:
            if latest_run is None or latest_run.state is not MiningRunState.NO_PROPOSAL:
                raise ValueError(
                    "no-proposal group requires the latest no-proposal run"
                )
            if latest_run.finished_at != group.last_mined_at:
                raise ValueError("no-proposal completion timestamp is inconsistent")
        if group.state in proposal_states and (
            latest_run is None or latest_run.state is not MiningRunState.PROPOSED
        ):
            raise ValueError("proposal lifecycle requires the latest proposed run")
        if group.state is ResidualGroupState.ELIGIBLE and latest_run is not None:
            if latest_run.state not in {
                MiningRunState.NO_PROPOSAL,
                MiningRunState.EXPIRED,
                MiningRunState.FAILED,
                MiningRunState.SUPERSEDED,
            }:
                raise ValueError("eligible group has an incoherent run history")

        raw_runs = {row[0]: row for row in run_rows}
        raw_proposals = {row[0]: row for row in proposal_rows}
        for proposal_id, proposal in proposals.items():
            run = runs.get(proposal.run_id)
            run_row = raw_runs.get(proposal.run_id)
            proposal_row = raw_proposals[proposal_id]
            if (
                run is None
                or run_row is None
                or run.group_id != group_id
                or run.claimed_revision > group.revision
                or run.state is not MiningRunState.PROPOSED
                or run.finished_at is None
                or proposal.created_at != run.finished_at
            ):
                raise ValueError("proposal publication lifecycle is corrupt")
            if proposal.materialized_at != group.materialized_at:
                raise ValueError("materialized timestamps are inconsistent")
            if proposal.admitted_at != group.admitted_at:
                raise ValueError("admitted timestamps are inconsistent")
            if proposal.state is ProposalState.REJECTED:
                has_materialization = proposal.materialized_at is not None
                if has_materialization != (group.materialized_at is not None):
                    raise ValueError("rejection source lifecycle is corrupt")
            if proposal_row["created_at"] != run_row["finished_at"]:
                raise ValueError("proposal publication timestamps are inconsistent")
            materialized_revision = proposal_row["materialized_source_revision"]
            terminal_state = proposal_row["terminal_source_state"]
            terminal_revision = proposal_row["terminal_source_revision"]
            if proposal.state is ProposalState.PROPOSED:
                if (
                    materialized_revision is not None
                    or terminal_state is not None
                    or terminal_revision is not None
                ):
                    raise ValueError("proposed lifecycle retry identity is corrupt")
            elif proposal.state is ProposalState.MATERIALIZED:
                if (
                    materialized_revision is None
                    or terminal_state is not None
                    or terminal_revision is not None
                ):
                    raise ValueError("materialized lifecycle retry identity is corrupt")
            elif proposal.state is ProposalState.ADMITTED:
                if (
                    materialized_revision is None
                    or terminal_state != ProposalState.MATERIALIZED.value
                    or terminal_revision is None
                ):
                    raise ValueError("admitted lifecycle retry identity is corrupt")
            elif proposal.state is ProposalState.REJECTED:
                expected_source = (
                    ProposalState.MATERIALIZED.value
                    if proposal.materialized_at is not None
                    else ProposalState.PROPOSED.value
                )
                if (
                    terminal_state != expected_source
                    or terminal_revision is None
                    or (proposal.materialized_at is None)
                    != (materialized_revision is None)
                ):
                    raise ValueError("rejected lifecycle retry identity is corrupt")
            for revision in (materialized_revision, terminal_revision):
                if revision is not None and not (
                    run.claimed_revision <= revision <= group.revision
                ):
                    raise ValueError("lifecycle retry revision is corrupt")
            if (
                materialized_revision is not None
                and terminal_revision is not None
                and materialized_revision > terminal_revision
            ):
                raise ValueError("lifecycle retry revision chronology is corrupt")
        self._validate_causal_events(conn, group, runs, proposals)
        return group, runs, proposals

    def _project_group(self, conn: sqlite3.Connection, group_id: int) -> ResidualGroup:
        return self._validate_relational_lifecycle(conn, group_id)[0]

    def _project_run(self, row: sqlite3.Row) -> MiningRun:
        _group, runs, _proposals = self._validate_relational_lifecycle(
            self._connection, int(row[1])
        )
        try:
            return runs[row[0]]
        except KeyError as exc:
            raise ValueError("unknown mining run") from exc

    def _project_proposal(self, conn: sqlite3.Connection, row: sqlite3.Row) -> Proposal:
        _group, _runs, proposals = self._validate_relational_lifecycle(
            conn, int(row[1])
        )
        try:
            return proposals[row[0]]
        except KeyError as exc:
            raise ValueError("unknown proposal") from exc

    def claim_next_group(
        self,
        miner_version: str,
        budget_fingerprint: str,
        lease_timeout: object | None = None,
    ) -> ClaimReceipt:
        _canonical_text(miner_version, name="miner_version")
        _canonical_text(budget_fingerprint, name="budget_fingerprint")
        timeout = DISCOVERY_LEASE_TIMEOUT_SECONDS
        if lease_timeout is not None and _seconds(lease_timeout) != timeout:
            return ClaimReceipt(
                ReceiptStatus.REFUSED, reason="unsupported_lease_timeout"
            )
        try:
            with self._transaction(immediate=True) as conn:
                now = self._now()
                cutoff = _parse_timestamp(now, name="claim timestamp") - timedelta(
                    seconds=timeout
                )
                for group_row in conn.execute(
                    "SELECT group_id FROM residual_groups ORDER BY group_id"
                ):
                    self._validate_relational_lifecycle(conn, int(group_row[0]))
                active_rows = conn.execute(
                    "SELECT * FROM mining_runs WHERE state=? ORDER BY heartbeat_at, run_id",
                    (MiningRunState.ACTIVE.value,),
                ).fetchall()
                expired = [
                    old
                    for old in active_rows
                    if _parse_timestamp(old[7], name="heartbeat_at") <= cutoff
                ]
                for old in expired:
                    group = conn.execute(
                        "SELECT * FROM residual_groups WHERE group_id=?", (old[1],)
                    ).fetchone()
                    if group is None:
                        raise ValueError("active mining owner group is missing")
                    if not valid_group_transition(
                        ResidualGroupState.MINING, ResidualGroupState.ELIGIBLE
                    ):
                        raise ValueError("invalid lease reclaim transition")
                    run_updated = conn.execute(
                        "UPDATE mining_runs SET state=?, finished_at=?, failure_reason=? WHERE run_id=? AND group_id=? AND claimed_revision=? AND state=? AND heartbeat_at=?",
                        (
                            MiningRunState.EXPIRED.value,
                            now,
                            "lease_expired",
                            old[0],
                            old[1],
                            old[2],
                            MiningRunState.ACTIVE.value,
                            old[7],
                        ),
                    ).rowcount
                    group_updated = conn.execute(
                        "UPDATE residual_groups SET state=? WHERE group_id=? AND state=? AND revision=?",
                        (
                            ResidualGroupState.ELIGIBLE.value,
                            old[1],
                            ResidualGroupState.MINING.value,
                            group[8],
                        ),
                    ).rowcount
                    if run_updated != 1 or group_updated != 1:
                        raise ValueError("lease_reclaim_conflict")
                    self._append_event(
                        conn,
                        group_id=int(old[1]),
                        event_kind="run_expired",
                        group_revision=int(group[8]),
                        run_id=old[0],
                        occurred_at=now,
                    )
                candidate = conn.execute(
                    "SELECT group_id, revision FROM residual_groups WHERE state=? ORDER BY last_observed_at, group_id LIMIT 1",
                    (ResidualGroupState.ELIGIBLE.value,),
                ).fetchone()
                if candidate is None:
                    return ClaimReceipt(
                        ReceiptStatus.REFUSED, reason="no_eligible_group"
                    )
                if not valid_group_transition(
                    ResidualGroupState.ELIGIBLE, ResidualGroupState.MINING
                ):
                    raise ValueError("invalid claim transition")
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
                        MiningRunState.ACTIVE.value,
                        now,
                        now,
                    ),
                )
                self._append_event(
                    conn,
                    group_id=int(candidate[0]),
                    event_kind="claimed",
                    group_revision=claimed_revision,
                    run_id=run_id,
                    occurred_at=now,
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
        run_id = _canonical_uuid(run_id, name="run_id")
        if type(claimed_revision) is not int or claimed_revision < 0:
            raise ValueError("claimed_revision must be non-negative")
        with self._transaction(immediate=True) as conn:
            existing_run = conn.execute(
                "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if existing_run is None:
                return HeartbeatReceipt(
                    ReceiptStatus.REFUSED, reason="stale_or_not_owner"
                )
            self._validate_relational_lifecycle(conn, int(existing_run[1]))
            now = self._now()
            updated = conn.execute(
                "UPDATE mining_runs SET heartbeat_at=? WHERE run_id=? AND claimed_revision=? AND state=? AND group_id IN (SELECT group_id FROM residual_groups WHERE state=? AND revision=?)",
                (
                    now,
                    run_id,
                    claimed_revision,
                    MiningRunState.ACTIVE.value,
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
        run_id = _canonical_uuid(run_id, name="run_id")
        if type(claimed_revision) is not int or claimed_revision < 0:
            raise ValueError("claimed_revision must be non-negative")
        _canonical_text(reason, name="failure_reason")
        with self._transaction(immediate=True) as conn:
            now = self._now()
            run = conn.execute(
                "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="unknown_run")
            if run[5] != MiningRunState.ACTIVE.value or run[2] != claimed_revision:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="not_active")
            group = conn.execute(
                "SELECT state, revision FROM residual_groups WHERE group_id=?",
                (run[1],),
            ).fetchone()
            self._validate_relational_lifecycle(conn, int(run[1]))
            if (
                group is None
                or group[0] != ResidualGroupState.MINING.value
                or group[1] != claimed_revision
            ):
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            if not valid_group_transition(ResidualGroupState.MINING, group_state):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            updated = conn.execute(
                "UPDATE mining_runs SET state=?, finished_at=?, failure_reason=? WHERE run_id=? AND state=? AND claimed_revision=?",
                (
                    run_state.value,
                    now,
                    reason,
                    run_id,
                    MiningRunState.ACTIVE.value,
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
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            self._append_event(
                conn,
                group_id=int(run[1]),
                event_kind={
                    MiningRunState.NO_PROPOSAL: "run_no_proposal",
                    MiningRunState.FAILED: "run_failed",
                    MiningRunState.EXPIRED: "run_expired",
                    MiningRunState.SUPERSEDED: "run_superseded",
                }.get(run_state, "run_failed"),
                group_revision=claimed_revision,
                run_id=run_id,
                occurred_at=now,
            )
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
        proposal_fingerprint: str | MbaRuleProposal,
        replacement_term: TypedBvTerm,
        proposal_payload: object,
        proof_receipt_payload: object = None,
    ) -> LifecycleReceipt:
        run_id = _canonical_uuid(run_id, name="run_id")
        if type(claimed_revision) is not int or claimed_revision < 0:
            raise ValueError("claimed_revision must be non-negative")
        try:
            if isinstance(proposal_fingerprint, MbaRuleProposal):
                proposal = proposal_fingerprint
                supplied_fingerprint = proposal.fingerprint
            elif (
                type(proposal_fingerprint) is str
                and proposal_fingerprint
                and proposal_fingerprint.strip() == proposal_fingerprint
            ):
                supplied_fingerprint = proposal_fingerprint
                proposal, _ = _coerce_proposal_payload(proposal_payload)
            else:
                raise ValueError("proposal_fingerprint must be canonical")
            proposal_bytes = _proposal_payload_bytes(proposal)
            if supplied_fingerprint != proposal.fingerprint:
                raise ValueError(
                    "proposal fingerprint does not match canonical payload"
                )
            if (
                type(replacement_term) is not TypedBvTerm
                or replacement_term != proposal.replacement
            ):
                raise ValueError("replacement term does not match proposal")
            replacement = _term_bytes(replacement_term, name="replacement term")
            proof_bytes = _coerce_proof_payload(proof_receipt_payload, proposal)
        except (TypeError, ValueError, KeyError, IndexError) as exc:
            return LifecycleReceipt(ReceiptStatus.REFUSED, reason=str(exc))
        with self._transaction(immediate=True) as conn:
            run = conn.execute(
                "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="unknown_run")
            group = conn.execute(
                "SELECT * FROM residual_groups WHERE group_id=?", (run[1],)
            ).fetchone()
            if group is not None:
                self._validate_relational_lifecycle(conn, int(group[0]))
            existing = conn.execute(
                "SELECT * FROM proposals WHERE proposal_fingerprint=?",
                (supplied_fingerprint,),
            ).fetchone()
            if existing is None and (
                run[5] != MiningRunState.ACTIVE.value
                or run[2] != claimed_revision
                or group is None
                or group[2] != ResidualGroupState.MINING.value
                or group[8] != claimed_revision
            ):
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            if existing is None and not valid_group_transition(
                ResidualGroupState.MINING, ResidualGroupState.PROPOSED
            ):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            if run[2] != claimed_revision:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            canonical_row = conn.execute(
                "SELECT canonical_term FROM terms WHERE term_id=?", (group[1],)
            ).fetchone()
            if canonical_row is None:
                raise ValueError("proposal source group is corrupt")
            if proposal.pattern != _decode_term(
                bytes(canonical_row[0]), name="canonical term"
            ):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="proposal_source_mismatch"
                )
            if existing is not None:
                existing_projection = self._project_proposal(conn, existing)
                existing_run = conn.execute(
                    "SELECT claimed_revision FROM mining_runs WHERE run_id=?",
                    (existing[2],),
                ).fetchone()
                exact = (
                    existing[1] == group[0]
                    and existing[2] == run_id
                    and existing_run is not None
                    and existing_run[0] == claimed_revision
                    and bytes(existing[4]) == replacement
                    and bytes(existing[5]) == proposal_bytes
                    and bytes(existing[6]) == proof_bytes
                )
                return LifecycleReceipt(
                    ReceiptStatus.DUPLICATE if exact else ReceiptStatus.REFUSED,
                    proposal=existing_projection if exact else None,
                    reason=None if exact else "proposal_fingerprint_conflict",
                )
            proposal_id = self._new_uuid()
            now = self._now()
            try:
                conn.execute(
                    "INSERT INTO proposals(proposal_id,group_id,run_id,proposal_fingerprint,replacement_term,proposal_payload,proof_receipt_payload,state,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        proposal_id,
                        group[0],
                        run_id,
                        supplied_fingerprint,
                        replacement,
                        proposal_bytes,
                        proof_bytes,
                        ProposalState.PROPOSED.value,
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                conn.rollback()
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="proposal_integrity_collision"
                )
            if (
                conn.execute(
                    "UPDATE mining_runs SET state=?, finished_at=? WHERE run_id=? AND state=? AND claimed_revision=?",
                    (
                        MiningRunState.PROPOSED.value,
                        now,
                        run_id,
                        MiningRunState.ACTIVE.value,
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
            self._append_event(
                conn,
                group_id=int(group[0]),
                event_kind="proposal_published",
                group_revision=claimed_revision,
                run_id=run_id,
                proposal_id=proposal_id,
                occurred_at=now,
            )
            proposal = self._project_proposal(
                conn,
                conn.execute(
                    "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                ).fetchone(),
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
        proposal_id = _canonical_uuid(proposal_id, name="proposal_id")
        _canonical_text(path, name="materialized_path")
        _canonical_text(digest, name="materialized_digest")
        with self._transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="unknown_proposal"
                )
            if expected_state is None or expected_revision is None:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="expected_state_required"
                )
            if type(expected_revision) is not int or expected_revision < 0:
                raise ValueError("expected_revision must be non-negative")
            try:
                requested_state = ProposalState(expected_state)
                current_state = ProposalState(row["state"])
            except ValueError as exc:
                raise ValueError("unknown proposal state") from exc
            group = conn.execute(
                "SELECT * FROM residual_groups WHERE group_id=?", (row[1],)
            ).fetchone()
            if group is None:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            self._project_proposal(conn, row)
            run = conn.execute(
                "SELECT claimed_revision FROM mining_runs WHERE run_id=?", (row[2],)
            ).fetchone()
            if run is None:
                raise ValueError("proposal publishing run is corrupt")
            if current_state is ProposalState.MATERIALIZED:
                if group[2] != ResidualGroupState.MATERIALIZED.value:
                    return LifecycleReceipt(
                        ReceiptStatus.REFUSED, reason="invalid_transition"
                    )
                original_retry = (
                    requested_state is ProposalState.PROPOSED
                    and row["materialized_source_revision"] == expected_revision
                )
                if (
                    row["materialized_path"] == path
                    and row["materialized_digest"] == digest
                    and original_retry
                ):
                    return LifecycleReceipt(
                        ReceiptStatus.DUPLICATE,
                        proposal=self._project_proposal(conn, row),
                    )
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="materialization_conflict"
                )
            if current_state is not ProposalState.PROPOSED:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            if requested_state is not ProposalState.PROPOSED:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            if group[8] != expected_revision:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            if (
                group is None
                or group[2] != ResidualGroupState.PROPOSED.value
                or not valid_group_transition(
                    ResidualGroupState.PROPOSED, ResidualGroupState.MATERIALIZED
                )
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
                    "UPDATE proposals SET state=?, materialized_path=?, materialized_digest=?, materialized_at=?, materialized_source_revision=? WHERE proposal_id=? AND state=?",
                    (
                        ProposalState.MATERIALIZED.value,
                        path,
                        digest,
                        now,
                        expected_revision,
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
                        expected_revision,
                    ),
                ).rowcount
                != 1
            ):
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            self._append_event(
                conn,
                group_id=int(row[1]),
                event_kind="materialized",
                group_revision=expected_revision,
                source_proposal_state=ProposalState.PROPOSED.value,
                run_id=row[2],
                proposal_id=proposal_id,
                occurred_at=now,
            )
            return LifecycleReceipt(
                ReceiptStatus.MATERIALIZED,
                proposal=self._project_proposal(
                    conn,
                    conn.execute(
                        "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                    ).fetchone(),
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
        proposal_id = _canonical_uuid(proposal_id, name="proposal_id")
        value = rule_id if target is ProposalState.ADMITTED else reason
        _canonical_text(
            value,
            name=(
                "admitted_rule_id"
                if target is ProposalState.ADMITTED
                else "rejection_reason"
            ),
        )
        with self._transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="unknown_proposal"
                )
            if expected_state is None or expected_revision is None:
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="expected_state_required"
                )
            if type(expected_revision) is not int or expected_revision < 0:
                raise ValueError("expected_revision must be non-negative")
            try:
                requested_state = ProposalState(expected_state)
                current = ProposalState(row["state"])
            except ValueError as exc:
                raise ValueError("unknown proposal state") from exc
            if requested_state is not current:
                if current is not target:
                    return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            group = conn.execute(
                "SELECT * FROM residual_groups WHERE group_id=?", (row[1],)
            ).fetchone()
            if group is None:
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_revision")
            self._project_proposal(conn, row)
            run = conn.execute(
                "SELECT claimed_revision FROM mining_runs WHERE run_id=?", (row[2],)
            ).fetchone()
            if run is None:
                raise ValueError("proposal publishing run is corrupt")
            if current is target:
                if group[2] != group_target.value:
                    return LifecycleReceipt(
                        ReceiptStatus.REFUSED, reason="invalid_transition"
                    )
                original_retry = (
                    row["terminal_source_state"] == requested_state.value
                    and row["terminal_source_revision"] == expected_revision
                )
                if (
                    target is ProposalState.ADMITTED
                    and row["admitted_rule_id"] == rule_id
                    or target is ProposalState.REJECTED
                    and row["rejection_reason"] == reason
                ) and original_retry:
                    return LifecycleReceipt(
                        ReceiptStatus.DUPLICATE,
                        proposal=self._project_proposal(conn, row),
                    )
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="lifecycle_conflict"
                )
            if not valid_proposal_transition(current, target):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            expected_group = (
                ResidualGroupState.MATERIALIZED
                if current is ProposalState.MATERIALIZED
                else ResidualGroupState.PROPOSED
            )
            if (
                group is None
                or ResidualGroupState(group[2]) is not expected_group
                or requested_state is not current
                or group[8] != expected_revision
                or not valid_group_transition(expected_group, group_target)
            ):
                return LifecycleReceipt(
                    ReceiptStatus.REFUSED, reason="invalid_transition"
                )
            now = self._now()
            if target is ProposalState.ADMITTED:
                updated = conn.execute(
                    "UPDATE proposals SET state=?, admitted_rule_id=?, admitted_at=?, terminal_source_state=?, terminal_source_revision=? WHERE proposal_id=? AND state=?",
                    (
                        target.value,
                        rule_id,
                        now,
                        current.value,
                        expected_revision,
                        proposal_id,
                        current.value,
                    ),
                ).rowcount
            else:
                updated = conn.execute(
                    "UPDATE proposals SET state=?, rejection_reason=?, terminal_source_state=?, terminal_source_revision=? WHERE proposal_id=? AND state=?",
                    (
                        target.value,
                        reason,
                        current.value,
                        expected_revision,
                        proposal_id,
                        current.value,
                    ),
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
                    expected_revision,
                ),
            ).rowcount
            if group_updated != 1:
                conn.rollback()
                return LifecycleReceipt(ReceiptStatus.REFUSED, reason="stale_state")
            self._append_event(
                conn,
                group_id=int(row[1]),
                event_kind="admitted"
                if target is ProposalState.ADMITTED
                else "rejected",
                group_revision=expected_revision,
                source_proposal_state=current.value,
                run_id=row[2],
                proposal_id=proposal_id,
                occurred_at=now,
            )
            return LifecycleReceipt(
                ReceiptStatus.ADMITTED
                if target is ProposalState.ADMITTED
                else ReceiptStatus.REJECTED,
                proposal=self._project_proposal(
                    conn,
                    conn.execute(
                        "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                    ).fetchone(),
                ),
                group=self._project_group(conn, int(row[1])),
            )

    def status_counts(self) -> DiscoveryStatus:
        with self._lock:
            self._ensure_open()
            self._connection.execute("BEGIN")
            try:
                self._validate_causal_domain(self._connection)
                for row in self._connection.execute("SELECT * FROM residual_groups"):
                    self._project_group(self._connection, int(row[0]))
                for row in self._connection.execute("SELECT * FROM mining_runs"):
                    self._project_run(row)
                for row in self._connection.execute("SELECT * FROM proposals"):
                    self._project_proposal(self._connection, row)
                group_rows = self._connection.execute(
                    "SELECT state, COUNT(*) FROM residual_groups GROUP BY state"
                ).fetchall()
                run_rows = self._connection.execute(
                    "SELECT state, COUNT(*) FROM mining_runs GROUP BY state"
                ).fetchall()
                proposal_rows = self._connection.execute(
                    "SELECT state, COUNT(*) FROM proposals GROUP BY state"
                ).fetchall()
                group_values = {row[0]: int(row[1]) for row in group_rows}
                run_values = {row[0]: int(row[1]) for row in run_rows}
                proposal_values = {row[0]: int(row[1]) for row in proposal_rows}
                if set(group_values) - {state.value for state in ResidualGroupState}:
                    raise ValueError("unknown residual group state")
                if set(run_values) - {state.value for state in MiningRunState}:
                    raise ValueError("unknown mining run state")
                if set(proposal_values) - {state.value for state in ProposalState}:
                    raise ValueError("unknown proposal state")
                if (
                    sum(group_values.values())
                    != self._connection.execute(
                        "SELECT COUNT(*) FROM residual_groups"
                    ).fetchone()[0]
                ):
                    raise ValueError("residual group status total mismatch")
                if (
                    sum(run_values.values())
                    != self._connection.execute(
                        "SELECT COUNT(*) FROM mining_runs"
                    ).fetchone()[0]
                ):
                    raise ValueError("mining run status total mismatch")
                if (
                    sum(proposal_values.values())
                    != self._connection.execute(
                        "SELECT COUNT(*) FROM proposals"
                    ).fetchone()[0]
                ):
                    raise ValueError("proposal status total mismatch")
                groups = tuple(
                    (state, group_values.get(state.value, 0))
                    for state in ResidualGroupState
                )
                runs = tuple(
                    (state, run_values.get(state.value, 0)) for state in MiningRunState
                )
                proposals = tuple(
                    (state, proposal_values.get(state.value, 0))
                    for state in ProposalState
                )
                cutoff = _timestamp(
                    datetime.fromisoformat(self._now().replace("Z", "+00:00"))
                    - DISCOVERY_LEASE_TIMEOUT
                )
                expired = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM mining_runs WHERE state=? AND heartbeat_at<=?",
                        (MiningRunState.ACTIVE.value, cutoff),
                    ).fetchone()[0]
                )
                outstanding = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM mining_runs WHERE state=? AND heartbeat_at>?",
                        (MiningRunState.ACTIVE.value, cutoff),
                    ).fetchone()[0]
                )
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
            return DiscoveryStatus(groups, runs, proposals, outstanding, expired)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True


__all__ = ["DISCOVERY_LEASE_TIMEOUT", "MbaDiscoveryStore", "SCHEMA_VERSION"]
