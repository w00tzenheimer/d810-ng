from __future__ import annotations

import json
import hashlib
import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import d810.mba.discovery_store as discovery_store_module

from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PluginIdentity
from d810.mba.discovery_models import (
    DiscoveryAttempt,
    MiningRunState,
    ProposalState,
    ResidualGroupState,
)
from d810.mba.bounded_synthesis import ProofReceipt
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.rule_proposal import MbaRuleProposal
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
    term_cost,
    term_fingerprint,
)


def _term(value: int = 1) -> TypedBvTerm:
    return TypedBvTerm(None, 32, value=value)


def _identity() -> FunctionExecutionIdentity:
    return FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="idb-one",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="function-fp",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=2,
    )


def _attempt(
    *,
    attempt_uuid: str | None = None,
    raw: TypedBvTerm | None = None,
    canonical: TypedBvTerm | None = None,
    eligible: bool = True,
    value: int = 1,
) -> DiscoveryAttempt:
    raw = raw or _term(value)
    canonical = canonical or canonicalize_ac_term(raw)
    outcome = MbaProviderOutcome(
        provider=MbaProviderKind.EGRAPH,
        status=ProviderOutcomeStatus.UNCHANGED,
        fingerprint=term_fingerprint(canonical),
        input_cost=(1, 1),
        elapsed_ms=1.25,
    )
    return DiscoveryAttempt(
        attempt_uuid=attempt_uuid or str(uuid4()),
        context=MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity(
                name="plugin", distribution="plugin-dist", version="1.0", origin="test"
            ),
            instruction_ea=0x401002,
            block_serial=3,
            block_ea=0x401000,
        ),
        raw_term=raw,
        canonical_term=canonical,
        outcome=outcome,
        eligible_for_mining=eligible,
    )


def _proposal(pattern: TypedBvTerm) -> MbaRuleProposal:
    leaf = TypedBvTerm(None, pattern.width, leaf_key=("register", "x"))
    replacement = leaf
    proofs = tuple(
        ProofReceipt(width=width, verdict=True, elapsed_ms=0.1)
        for width in (8, 16, 32, 64)
    )
    return MbaRuleProposal(
        proposal_fingerprint=None,
        source_fingerprints=(term_fingerprint(pattern),),
        occurrence_count=1,
        pattern=pattern,
        replacement=replacement,
        source_cost=term_cost(pattern),
        replacement_cost=term_cost(replacement),
        atomization_bindings=(),
        proof_receipts=proofs,
        class_name="MbaResidualRule",
        family="residual",
        description="A certified residual proposal",
        provenance=("provider:test",),
        fixture={"case_id": "test"},
    )


_CAUSAL_DOMAIN_TABLES = (
    "inputs",
    "databases",
    "functions",
    "terms",
    "raw_terms",
    "provider_attempts",
    "residual_groups",
    "mining_runs",
    "proposals",
    "residual_group_events",
)


def _logical_domain_snapshot(store: MbaDiscoveryStore) -> tuple[object, ...]:
    """Capture every causal owner/event column in primary-key order."""
    snapshot: list[object] = []
    connection = store._connection
    for table in _CAUSAL_DOMAIN_TABLES:
        columns = tuple(
            row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")
        )
        primary_key = tuple(
            row[1]
            for row in sorted(
                connection.execute(f"PRAGMA table_info('{table}')").fetchall(),
                key=lambda row: row[5],
            )
            if row[5]
        )
        order = ", ".join(f'"{column}"' for column in primary_key)
        rows = tuple(
            tuple(row)
            for row in connection.execute(
                f'SELECT * FROM "{table}" ORDER BY {order}'
            ).fetchall()
        )
        snapshot.append((table, columns, rows))
    return tuple(snapshot)


def _call_without_domain_mutation(store: MbaDiscoveryStore, call: object) -> object:
    before = _logical_domain_snapshot(store)
    try:
        return call()  # type: ignore[operator]
    finally:
        assert _logical_domain_snapshot(store) == before


def test_schema_migration_is_exact_and_reopen_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "discovery.sqlite3"
    store = MbaDiscoveryStore(path)
    assert store.connection_pragmas() == {"foreign_keys": 1, "busy_timeout": 5000}
    assert store.journal_mode() == "wal"
    tables = set(store.table_columns())
    assert tables == {
        "schema_migrations",
        "inputs",
        "databases",
        "functions",
        "terms",
        "raw_terms",
        "provider_attempts",
        "residual_groups",
        "mining_runs",
        "proposals",
        "residual_group_events",
    }
    assert store.schema_version() == 1
    assert store.table_columns()["proposals"] == (
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
    )
    connection = sqlite3.connect(path)
    assert {
        row[1]
        for table in (
            "residual_groups",
            "mining_runs",
            "provider_attempts",
            "proposals",
        )
        for row in connection.execute(f"PRAGMA index_list('{table}')")
    } >= {
        "idx_residual_groups_claim",
        "idx_mining_runs_lease",
        "idx_provider_attempts_term",
        "idx_provider_attempts_function",
        "idx_provider_attempts_provider",
        "idx_proposals_group_state",
    }
    assert connection.execute("PRAGMA foreign_key_list(provider_attempts)").fetchall()
    assert connection.execute("PRAGMA foreign_key_list(proposals)").fetchall()
    unique_indexes = {
        row[1] for row in connection.execute("PRAGMA index_list(terms)") if row[2]
    }
    assert unique_indexes
    connection.close()
    store.close()
    reopened = MbaDiscoveryStore(path)
    assert reopened.schema_version() == 1
    reopened.close()


def test_causal_event_schema_and_owner_shape_checks_are_exact(
    tmp_path: Path,
) -> None:
    path = tmp_path / "causal.sqlite3"
    store = MbaDiscoveryStore(path)
    assert "residual_group_events" in store.table_columns()
    connection = sqlite3.connect(path)
    indexes = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        )
    }
    assert {
        "idx_residual_group_events_revision",
        "idx_residual_group_events_attempt_owner",
        "idx_residual_group_events_run_kind",
        "idx_residual_group_events_proposal_kind",
        "idx_residual_group_events_run_terminal",
        "idx_residual_group_events_proposal_terminal",
        "idx_residual_group_events_group_order",
    } <= indexes
    connection.execute(
        "INSERT INTO inputs(input_identity, identity_provenance, external_evidence_allowed) VALUES ('i', 'p', 0)"
    )
    connection.execute(
        "INSERT INTO databases(database_uuid, database_identity, input_id) VALUES ('d', 'db', 1)"
    )
    connection.execute(
        "INSERT INTO functions(database_id, function_ea, function_fingerprint) VALUES (1, 1, 'f')"
    )
    connection.execute(
        "INSERT INTO terms(canonical_fingerprint, width, canonical_term, canonical_codec_version) VALUES ('t', 8, x'7b7d', 1)"
    )
    connection.execute(
        "INSERT INTO residual_groups(term_id, state, eligible_observation_count, last_observed_at, revision) VALUES (1, 'eligible', 1, '2026-01-01T00:00:00.000000Z', 1)"
    )
    connection.execute(
        "INSERT INTO mining_runs(run_id, group_id, claimed_revision, miner_version, budget_fingerprint, state, started_at, heartbeat_at) VALUES ('r', 1, 2, 'm', 'b', 'active', '2026-01-01T00:00:00.000000Z', '2026-01-01T00:00:00.000000Z')"
    )
    connection.commit()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO residual_group_events(group_id, event_kind, group_revision, run_id, occurred_at) VALUES (1, 'materialized', 2, 'r', '2026-01-01T00:00:00.000000Z')"
        )
    connection.close()
    store.close()


@pytest.mark.parametrize("event_kind", ("admitted", "rejected"))
def test_causal_event_direct_insert_rejects_null_proposal_source(
    tmp_path: Path, event_kind: str
) -> None:
    store, _proposal, published = _published_store(
        tmp_path, f"direct-null-{event_kind}"
    )
    assert published.proposal is not None and published.group is not None
    group_revision = published.group.revision
    if event_kind == "admitted":
        materialized = store.mark_materialized(
            published.proposal.proposal_id,
            "/rule.py",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=group_revision,
        )
        assert materialized.group is not None
        group_revision = materialized.group.revision
    connection = sqlite3.connect(store.path)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO residual_group_events(group_id,event_kind,group_revision,source_proposal_state,run_id,proposal_id,occurred_at) VALUES (?,?,?,?,?,?,?)",
            (
                published.group.group_id,
                event_kind,
                group_revision,
                None,
                published.run.run_id,
                published.proposal.proposal_id,
                "2026-01-01T00:00:00.000000Z",
            ),
        )
    connection.close()
    store.close()


@pytest.mark.parametrize(
    ("name", "needle", "replacement"),
    (
        (
            "event-check",
            "CHECK (group_revision >= 1)",
            "CHECK (group_revision > 1)",
        ),
        (
            "event-owner-check",
            "source_proposal_state = 'proposed'",
            "source_proposal_state = 'materialized'",
        ),
        (
            "event-fk",
            "group_id INTEGER NOT NULL REFERENCES residual_groups",
            "group_id INTEGER NOT NULL REFERENCES residual_groups ON DELETE CASCADE",
        ),
        (
            "event-partial-index",
            "WHERE event_kind IN ('observed', 'claimed')",
            "WHERE event_kind IN ('observed')",
        ),
    ),
)
def test_reopen_rejects_each_causal_event_schema_drift(
    tmp_path: Path, name: str, needle: str, replacement: str
) -> None:
    source = tmp_path / f"event-source-{name}.sqlite3"
    mutated = tmp_path / f"event-mutated-{name}.sqlite3"
    store = MbaDiscoveryStore(source)
    store.close()
    source_connection = sqlite3.connect(source)
    dump = list(source_connection.iterdump())
    source_connection.close()
    changed = False
    with sqlite3.connect(mutated) as connection:
        for statement in dump:
            if statement.startswith("CREATE TABLE residual_group_events "):
                if needle in statement:
                    statement = statement.replace(needle, replacement, 1)
                    changed = True
            if statement.startswith(
                "CREATE UNIQUE INDEX idx_residual_group_events_revision"
            ):
                if needle in statement:
                    statement = statement.replace(needle, replacement, 1)
                    changed = True
            connection.execute(statement)
        connection.commit()
    assert changed
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(mutated)


def test_causal_events_order_equal_timestamps_and_reject_stale_claim(
    tmp_path: Path,
) -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = MbaDiscoveryStore(tmp_path / "causal.sqlite3", clock=lambda: timestamp)
    first = store.record_attempt(_attempt(value=1))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    second = store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(1), _term(2))),
            canonical=_term(1),
        )
    )
    assert first.revision == 1 and second.revision == 3
    assert store.heartbeat(claim.claim.run.run_id, 2).status == "refused"
    assert store.finish_no_proposal(claim.claim.run.run_id, 2).status == "refused"
    events = store._connection.execute(
        "SELECT event_id, event_kind, group_revision FROM residual_group_events ORDER BY event_id"
    ).fetchall()
    assert [(row[1], row[2]) for row in events] == [
        ("observed", 1),
        ("claimed", 2),
        ("observed", 3),
    ]
    store.close()


def test_causal_events_cover_proposal_lifecycle_and_exact_retries(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "causal.sqlite3")
    pattern = TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")), _term(2)),
    )
    store.record_attempt(
        _attempt(raw=pattern, canonical=canonicalize_mba_term(pattern).canonical_term)
    )
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    proposal = _proposal(pattern)
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal.fingerprint,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/tmp/rule.py",
        "sha256:abc",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.proposal is not None
    admitted = store.mark_admitted(
        published.proposal.proposal_id,
        "rule-id",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=materialized.group.revision,
    )
    assert admitted.proposal is not None
    assert (
        store.mark_admitted(
            published.proposal.proposal_id,
            "rule-id",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        ).status
        == "duplicate"
    )
    events = store._connection.execute(
        "SELECT event_kind, source_proposal_state, run_id, proposal_id FROM residual_group_events ORDER BY event_id"
    ).fetchall()
    assert [row[0] for row in events] == [
        "observed",
        "claimed",
        "proposal_published",
        "materialized",
        "admitted",
    ]
    assert events[-2][1] == "proposed"
    assert events[-1][1] == "materialized"
    store.close()


def test_duplicate_and_refused_calls_append_no_causal_event(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "causal.sqlite3")
    attempt = _attempt()
    assert store.record_attempt(attempt).status == "stored"
    assert store.record_attempt(attempt).status == "duplicate"
    assert (
        store.record_attempt(replace(attempt, eligible_for_mining=False)).status
        == "refused"
    )
    assert store.count_rows("residual_group_events") == 1
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    assert (
        store.finish_no_proposal(
            claim.claim.run.run_id, claim.claim.run.claimed_revision + 1
        ).status
        == "refused"
    )
    assert store.count_rows("residual_group_events") == 2
    store.close()


def test_causal_validation_rejects_missing_and_mismatched_events(
    tmp_path: Path,
) -> None:
    path = tmp_path / "causal.sqlite3"
    store = MbaDiscoveryStore(path)
    stored = store.record_attempt(_attempt())
    assert stored.attempt_id is not None
    store._connection.execute(
        "UPDATE residual_group_events SET occurred_at=?",
        ("2026-01-01T00:00:00.000000Z",),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="observed event authority"):
        store.status_counts()
    store.close()
    before = path.read_bytes()
    with pytest.raises(ValueError, match="observed event authority"):
        MbaDiscoveryStore(path)
    assert path.read_bytes() == before


def test_two_stores_concurrent_observations_have_contiguous_causal_order(
    tmp_path: Path,
) -> None:
    path = tmp_path / "causal-concurrent.sqlite3"
    stores = (MbaDiscoveryStore(path), MbaDiscoveryStore(path))
    barrier = threading.Barrier(2)
    receipts: list[object] = []

    def record(store: MbaDiscoveryStore, value: int) -> None:
        barrier.wait()
        receipts.append(store.record_attempt(_attempt(value=value)))

    threads = [
        threading.Thread(target=record, args=(store, value))
        for store, value in zip(stores, (1, 2))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(receipt.status == "stored" for receipt in receipts)
    events = (
        stores[0]
        ._connection.execute(
            "SELECT event_id, event_kind, group_revision FROM residual_group_events ORDER BY event_id"
        )
        .fetchall()
    )
    assert [row[0] for row in events] == [1, 2]
    assert [row[1] for row in events] == ["observed", "observed"]
    assert [row[2] for row in events] == [1, 1]
    for store in stores:
        store.close()


def test_causal_event_append_failure_rolls_back_owner_mutation(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "causal.sqlite3")
    store._connection.execute(
        "CREATE TRIGGER fail_causal_event BEFORE INSERT ON residual_group_events BEGIN SELECT RAISE(ABORT, 'event append failed'); END"
    )
    receipt = store.record_attempt(_attempt())
    assert receipt.status == "refused"
    assert receipt.reason == "event append failed"
    assert store.count_rows("provider_attempts") == 0
    assert store.count_rows("residual_groups") == 0
    assert store.count_rows("residual_group_events") == 0
    store.close()


def test_external_orphan_event_fails_closed_for_status_and_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan.sqlite3"
    store = MbaDiscoveryStore(path)
    store.record_attempt(_attempt())
    external = sqlite3.connect(path)
    external.execute("PRAGMA foreign_keys=OFF")
    external.execute(
        "INSERT INTO residual_group_events(group_id,event_kind,group_revision,run_id,occurred_at) VALUES (999,'claimed',2,'orphan-run','2026-01-01T00:00:00.000000Z')"
    )
    external.commit()
    external.close()
    with pytest.raises(ValueError, match="orphan|unconsumed|foreign"):
        store.status_counts()
    store.close()
    with pytest.raises(ValueError, match="orphan|unconsumed|foreign"):
        MbaDiscoveryStore(path)


@pytest.mark.parametrize("writer_schedule", ("during_validation", "after_reopen"))
def test_reopen_causal_validation_uses_one_snapshot_with_concurrent_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer_schedule: str,
) -> None:
    path = tmp_path / "reopen-race.sqlite3"
    seed = MbaDiscoveryStore(path)
    seed.record_attempt(_attempt())
    seed.close()
    writer = MbaDiscoveryStore(path)
    validation_started = threading.Event()
    release_validation = threading.Event()
    allow_writer = threading.Event()
    writer_begin_attempted = threading.Event()
    writer_done = threading.Event()
    writer_receipts: list[object] = []
    writer_errors: list[BaseException] = []
    original_connect = discovery_store_module.sqlite3.connect
    traced_connection = False
    reopen_connections: list[sqlite3.Connection] = []
    reopen_sql: list[str] = []
    trace_errors: list[BaseException] = []

    causal_group_query = "SELECT group_id FROM residual_groups"
    causal_event_query = (
        "SELECT event_id, group_id, provider_attempt_id, run_id, proposal_id "
        "FROM residual_group_events ORDER BY event_id"
    )
    causal_owner_query_prefix = "SELECT term_id FROM residual_groups WHERE group_id="

    def normalize_sql(statement: str) -> str:
        return " ".join(statement.strip().split())

    def trace_writer(statement: str) -> None:
        if statement == "BEGIN IMMEDIATE":
            writer_begin_attempted.set()

    writer._connection.set_trace_callback(trace_writer)

    def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal traced_connection
        connection = original_connect(*args, **kwargs)
        if not traced_connection and str(args[0]) == str(path):
            traced_connection = True
            reopen_connections.append(connection)

            def trace(statement: str) -> None:
                normalized = normalize_sql(statement)
                reopen_sql.append(normalized)
                if normalized == causal_group_query:
                    validation_started.set()
                    if not release_validation.wait(5):
                        trace_errors.append(
                            AssertionError("reopen validation barrier timed out")
                        )

            connection.set_trace_callback(trace)
        return connection

    monkeypatch.setattr(discovery_store_module.sqlite3, "connect", connect)
    reopened: list[MbaDiscoveryStore] = []
    reopen_errors: list[BaseException] = []

    def reopen() -> None:
        try:
            reopened.append(MbaDiscoveryStore(path))
        except BaseException as exc:
            reopen_errors.append(exc)

    reopen_thread = threading.Thread(target=reopen)

    def write() -> None:
        try:
            assert allow_writer.wait(5)
            writer_receipts.append(writer.record_attempt(_attempt(value=2)))
        except BaseException as exc:
            writer_errors.append(exc)
        finally:
            writer_done.set()

    writer_thread = threading.Thread(target=write)
    validation_observed = False
    writer_thread_started = False
    writer_begin_observed = False
    reopen_thread.start()
    try:
        validation_observed = validation_started.wait(5)
        if validation_observed:
            writer_thread.start()
            writer_thread_started = True
            if writer_schedule == "during_validation":
                allow_writer.set()
                writer_begin_observed = writer_begin_attempted.wait(5)
            release_validation.set()
        reopen_thread.join(5)
        assert not reopen_thread.is_alive()
        if reopen_errors:
            raise reopen_errors[0]
        if trace_errors:
            raise trace_errors[0]
        assert validation_observed
        assert len(reopened) == 1

        if writer_schedule == "after_reopen":
            allow_writer.set()
        writer_thread.join(5)
        assert not writer_thread.is_alive()
        if writer_errors:
            raise writer_errors[0]
        assert writer_thread_started
        if writer_schedule == "during_validation":
            assert writer_begin_observed
        assert writer_done.is_set()
        assert len(writer_receipts) == 1
        assert writer_receipts[0].status == "stored"

        begin_index = reopen_sql.index("BEGIN IMMEDIATE")
        group_index = reopen_sql.index(causal_group_query)
        event_index = reopen_sql.index(causal_event_query)
        owner_index = next(
            index
            for index, statement in enumerate(reopen_sql)
            if statement.startswith(causal_owner_query_prefix)
        )
        commit_index = reopen_sql.index("COMMIT")
        assert begin_index < group_index < event_index < owner_index < commit_index

        status = reopened[0].status_counts()
        assert status.group_counts == (
            (ResidualGroupState.OBSERVED, 0),
            (ResidualGroupState.ELIGIBLE, 2),
            (ResidualGroupState.MINING, 0),
            (ResidualGroupState.NO_PROPOSAL, 0),
            (ResidualGroupState.PROPOSED, 0),
            (ResidualGroupState.MATERIALIZED, 0),
            (ResidualGroupState.ADMITTED, 0),
            (ResidualGroupState.REJECTED, 0),
        )
        rows = (
            reopened[0]
            ._connection.execute(
                "SELECT e.event_id, e.group_id, e.event_kind, e.group_revision, "
                "e.provider_attempt_id, e.run_id, e.proposal_id, g.state, g.revision, "
                "g.term_id, pa.term_id "
                "FROM residual_group_events AS e "
                "JOIN residual_groups AS g ON g.group_id = e.group_id "
                "JOIN provider_attempts AS pa ON pa.attempt_id = e.provider_attempt_id "
                "ORDER BY e.event_id"
            )
            .fetchall()
        )
        assert [tuple(row) for row in rows] == [
            (1, 1, "observed", 1, 1, None, None, "eligible", 1, 1, 1),
            (2, 2, "observed", 1, 2, None, None, "eligible", 1, 2, 2),
        ]
    finally:
        release_validation.set()
        allow_writer.set()
        reopen_thread.join(5)
        if writer_thread_started:
            writer_thread.join(5)
        writer._connection.set_trace_callback(None)
        for connection in reopen_connections:
            try:
                connection.set_trace_callback(None)
            except sqlite3.ProgrammingError:
                pass
        for store in reopened:
            store.close()
        writer.close()


def test_claimed_revision_transfer_fails_all_authority_paths_without_mutation(
    tmp_path: Path,
) -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = MbaDiscoveryStore(
        tmp_path / "stale-claim-transfer.sqlite3", clock=lambda: timestamp
    )
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None and claim.claim.group is not None
    store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(2), _term(3))),
            canonical=pattern,
        )
    )
    run_id = claim.claim.run.run_id
    store._connection.execute(
        "UPDATE mining_runs SET claimed_revision=3 WHERE run_id=?", (run_id,)
    )
    store._connection.commit()
    with pytest.raises(ValueError):
        _call_without_domain_mutation(store, store.status_counts)
    with pytest.raises(ValueError):
        _call_without_domain_mutation(
            store,
            lambda: store._project_run(
                store._connection.execute(
                    "SELECT * FROM mining_runs WHERE run_id=?", (run_id,)
                ).fetchone()
            ),
        )
    proposal = _proposal(pattern)
    calls = (
        lambda: store.heartbeat(run_id, 3),
        lambda: store.finish_no_proposal(run_id, 3),
        lambda: store.publish_proposal(
            run_id, 3, proposal, proposal.replacement, proposal
        ),
    )
    for call in calls:
        try:
            receipt = _call_without_domain_mutation(store, call)
        except ValueError:
            continue
        assert receipt.status == "refused"
    store.close()


@pytest.mark.parametrize(
    "transition",
    ("materialized", "admitted", "rejected_proposed", "rejected_materialized"),
)
def test_forward_receipt_revision_transfer_fails_after_equal_time_evidence(
    tmp_path: Path, transition: str
) -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store, proposal, published = _published_store(
        tmp_path, f"receipt-transfer-{transition}", clock=lambda: timestamp
    )
    assert published.proposal is not None and published.group is not None
    proposal_id = published.proposal.proposal_id
    source_state = ProposalState.PROPOSED
    source_revision = published.group.revision
    if transition in {"admitted", "rejected_materialized"}:
        materialized = store.mark_materialized(
            proposal_id,
            "/rule.py",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=source_revision,
        )
        assert materialized.group is not None
        source_state = ProposalState.MATERIALIZED
        source_revision = materialized.group.revision
    if transition == "admitted":
        admitted = store.mark_admitted(
            proposal_id,
            "rule-id",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        assert admitted.status == "admitted"
        column = "terminal_source_revision"
    elif transition.startswith("rejected"):
        rejected = store.mark_rejected(
            proposal_id,
            "unsafe",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        assert rejected.status == "rejected"
        column = "terminal_source_revision"
    else:
        materialized = store.mark_materialized(
            proposal_id,
            "/rule.py",
            "digest",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        assert materialized.status == "materialized"
        column = "materialized_source_revision"
    store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(2), _term(3))),
            canonical=proposal.pattern,
        )
    )
    later_revision = store._connection.execute(
        "SELECT revision FROM residual_groups WHERE group_id=?",
        (published.group.group_id,),
    ).fetchone()[0]
    assert later_revision > source_revision
    store._connection.execute(
        f"UPDATE proposals SET {column}=? WHERE proposal_id=?",
        (later_revision, proposal_id),
    )
    store._connection.commit()
    with pytest.raises(ValueError):
        _call_without_domain_mutation(store, store.status_counts)
    with pytest.raises(ValueError):
        _call_without_domain_mutation(
            store,
            lambda: store._project_proposal(
                store._connection,
                store._connection.execute(
                    "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                ).fetchone(),
            ),
        )
    if transition == "materialized":
        calls = (
            lambda: store.mark_materialized(
                proposal_id,
                "/rule.py",
                "digest",
                expected_state=ProposalState.PROPOSED,
                expected_revision=source_revision,
            ),
            lambda: store.mark_materialized(
                proposal_id,
                "/other.py",
                "other",
                expected_state=ProposalState.PROPOSED,
                expected_revision=source_revision,
            ),
        )
    elif transition == "admitted":
        calls = (
            lambda: store.mark_admitted(
                proposal_id,
                "rule-id",
                expected_state=ProposalState.MATERIALIZED,
                expected_revision=source_revision,
            ),
            lambda: store.mark_admitted(
                proposal_id,
                "other-rule",
                expected_state=ProposalState.MATERIALIZED,
                expected_revision=source_revision,
            ),
        )
    else:
        calls = (
            lambda: store.mark_rejected(
                proposal_id,
                "unsafe",
                expected_state=source_state,
                expected_revision=source_revision,
            ),
            lambda: store.mark_rejected(
                proposal_id,
                "different",
                expected_state=source_state,
                expected_revision=source_revision,
            ),
        )
    for call in calls:
        with pytest.raises(ValueError):
            _call_without_domain_mutation(store, call)
    store.close()


@pytest.mark.parametrize(
    "operation",
    (
        "record",
        "claim",
        "heartbeat",
        "finish",
        "publication",
        "materialize",
        "admit",
        "reject",
    ),
)
def test_external_orphan_event_blocks_every_public_write(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / f"orphan-{operation}.sqlite3"
    if operation in {"materialize", "admit", "reject"}:
        store, _published_proposal, published = _published_store(
            tmp_path, f"orphan-{operation}"
        )
        assert published.proposal is not None and published.group is not None
    elif operation == "publication":
        store = MbaDiscoveryStore(path)
        pattern = TypedBvTerm(
            "add",
            32,
            children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
        )
        proposal = _proposal(pattern)
        store.record_attempt(_attempt(raw=pattern, canonical=pattern))
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
    else:
        store = MbaDiscoveryStore(path)
        store.record_attempt(_attempt())
        claim = None
        if operation in {"heartbeat", "finish"}:
            claim = store.claim_next_group("miner", "budget")
            assert claim.claim is not None
    before = store._connection.execute(
        "SELECT COUNT(*) FROM residual_group_events"
    ).fetchone()[0]
    external = sqlite3.connect(path)
    external.execute("PRAGMA foreign_keys=OFF")
    external.execute(
        "INSERT INTO residual_group_events(group_id,event_kind,group_revision,run_id,occurred_at) VALUES (999,'claimed',2,'orphan-run','2026-01-01T00:00:00.000000Z')"
    )
    external.commit()
    external.close()
    result = None
    try:
        if operation == "record":
            result = store.record_attempt(_attempt(value=2))
        elif operation == "claim":
            result = store.claim_next_group("miner", "budget")
        elif operation == "heartbeat":
            assert claim is not None and claim.claim is not None
            result = store.heartbeat(
                claim.claim.run.run_id, claim.claim.run.claimed_revision
            )
        elif operation == "finish":
            assert claim is not None and claim.claim is not None
            result = store.finish_no_proposal(
                claim.claim.run.run_id, claim.claim.run.claimed_revision
            )
        elif operation == "publication":
            assert claim is not None and claim.claim is not None
            result = store.publish_proposal(
                claim.claim.run.run_id,
                claim.claim.run.claimed_revision,
                proposal,
                proposal.replacement,
                proposal,
            )
        elif operation == "materialize":
            result = store.mark_materialized(
                published.proposal.proposal_id,
                "/rule.py",
                "digest",
                expected_state=ProposalState.PROPOSED,
                expected_revision=published.group.revision,
            )
        elif operation == "admit":
            materialized = store.mark_materialized(
                published.proposal.proposal_id,
                "/rule.py",
                "digest",
                expected_state=ProposalState.PROPOSED,
                expected_revision=published.group.revision,
            )
            assert materialized.group is not None
            result = store.mark_admitted(
                published.proposal.proposal_id,
                "rule-id",
                expected_state=ProposalState.MATERIALIZED,
                expected_revision=materialized.group.revision,
            )
        else:
            result = store.mark_rejected(
                published.proposal.proposal_id,
                "unsafe",
                expected_state=ProposalState.PROPOSED,
                expected_revision=published.group.revision,
            )
    except ValueError as exc:
        assert any(
            word in str(exc) for word in ("orphan", "foreign", "owner", "domain")
        )
    else:
        assert result is not None and result.status == "refused"
    # The externally injected orphan is the only row added; the refused call
    # must not append another causal event.
    assert store.count_rows("residual_group_events") == before + 1
    store.close()


def test_external_orphan_event_blocks_actual_admission_without_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "orphan-admit-real.sqlite3"
    store, _proposal, published = _published_store(tmp_path, "orphan-admit-real")
    assert published.proposal is not None and published.group is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/rule.py",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.group is not None
    external = sqlite3.connect(path)
    external.execute("PRAGMA foreign_keys=OFF")
    external.execute(
        "INSERT INTO residual_group_events(group_id,event_kind,group_revision,run_id,occurred_at) VALUES (999,'claimed',2,'orphan-run','2026-01-01T00:00:00.000000Z')"
    )
    external.commit()
    external.close()
    before = _logical_domain_snapshot(store)
    with pytest.raises(ValueError, match="orphan|foreign|domain"):
        _call_without_domain_mutation(
            store,
            lambda: store.mark_admitted(
                published.proposal.proposal_id,
                "rule-id",
                expected_state=ProposalState.MATERIALIZED,
                expected_revision=materialized.group.revision,
            ),
        )
    assert _logical_domain_snapshot(store) == before
    store.close()


def test_external_orphan_event_blocks_reclaim_without_mutation(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    path = tmp_path / "orphan-reclaim.sqlite3"
    store = MbaDiscoveryStore(path, clock=lambda: now[0])
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    external = sqlite3.connect(path)
    external.execute("PRAGMA foreign_keys=OFF")
    external.execute(
        "INSERT INTO residual_group_events(group_id,event_kind,group_revision,run_id,occurred_at) VALUES (999,'claimed',2,'orphan-run','2026-01-01T00:00:00.000000Z')"
    )
    external.commit()
    external.close()
    now[0] += timedelta(seconds=301)
    before = _logical_domain_snapshot(store)
    result = _call_without_domain_mutation(
        store, lambda: store.claim_next_group("miner", "budget")
    )
    assert result.status == "refused"
    assert _logical_domain_snapshot(store) == before
    store.close()


@pytest.mark.parametrize(
    "terminal", ("admitted", "rejected_proposed", "rejected_materialized")
)
def test_exact_and_conflicting_lifecycle_retries_append_no_event(
    tmp_path: Path, terminal: str
) -> None:
    store, proposal, published = _published_store(tmp_path, f"no-event-{terminal}")
    assert published.proposal is not None and published.group is not None
    proposal_id = published.proposal.proposal_id
    run_id = published.run.run_id
    duplicate_publication = _call_without_domain_mutation(
        store,
        lambda: store.publish_proposal(
            run_id,
            published.run.claimed_revision,
            proposal,
            proposal.replacement,
            proposal,
        ),
    )
    assert duplicate_publication.status == "duplicate"
    conflicting_publication = _call_without_domain_mutation(
        store,
        lambda: store.publish_proposal(
            run_id,
            published.run.claimed_revision,
            proposal,
            TypedBvTerm(None, 32, value=99),
            proposal,
        ),
    )
    assert conflicting_publication.status == "refused"
    source_state = ProposalState.PROPOSED
    source_revision = published.group.revision
    if terminal in {"admitted", "rejected_materialized"}:
        materialized = store.mark_materialized(
            proposal_id,
            "/rule.py",
            "digest",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        assert materialized.group is not None
        source_state = ProposalState.MATERIALIZED
        source_revision = materialized.group.revision
        materialized_count = _logical_domain_snapshot(store)
        assert (
            _call_without_domain_mutation(
                store,
                lambda: store.mark_materialized(
                    proposal_id,
                    "/rule.py",
                    "digest",
                    expected_state=ProposalState.PROPOSED,
                    expected_revision=source_revision,
                ),
            ).status
            == "duplicate"
        )
        assert (
            _call_without_domain_mutation(
                store,
                lambda: store.mark_materialized(
                    proposal_id,
                    "/different.py",
                    "different",
                    expected_state=ProposalState.PROPOSED,
                    expected_revision=source_revision,
                ),
            ).status
            == "refused"
        )
        assert _logical_domain_snapshot(store) == materialized_count
    if terminal == "admitted":
        admitted = store.mark_admitted(
            proposal_id,
            "rule-id",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        assert admitted.status == "admitted"
        assert (
            _call_without_domain_mutation(
                store,
                lambda: store.mark_admitted(
                    proposal_id,
                    "rule-id",
                    expected_state=source_state,
                    expected_revision=source_revision,
                ),
            ).status
            == "duplicate"
        )
        assert (
            _call_without_domain_mutation(
                store,
                lambda: store.mark_admitted(
                    proposal_id,
                    "different-rule",
                    expected_state=source_state,
                    expected_revision=source_revision,
                ),
            ).status
            == "refused"
        )
    else:
        rejected = store.mark_rejected(
            proposal_id,
            "unsafe",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        assert rejected.status == "rejected"
        assert (
            _call_without_domain_mutation(
                store,
                lambda: store.mark_rejected(
                    proposal_id,
                    "unsafe",
                    expected_state=source_state,
                    expected_revision=source_revision,
                ),
            ).status
            == "duplicate"
        )
        assert (
            _call_without_domain_mutation(
                store,
                lambda: store.mark_rejected(
                    proposal_id,
                    "different",
                    expected_state=source_state,
                    expected_revision=source_revision,
                ),
            ).status
            == "refused"
        )
    store.close()


def test_same_group_concurrent_observations_and_claim_have_causal_order(
    tmp_path: Path,
) -> None:
    path = tmp_path / "same-group-causal-race.sqlite3"
    setup = MbaDiscoveryStore(path)
    setup.close()
    observation_stores = (MbaDiscoveryStore(path), MbaDiscoveryStore(path))
    observation_barrier = threading.Barrier(2)
    receipts: list[object] = []
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )

    def observe(store: MbaDiscoveryStore, value: int) -> None:
        observation_barrier.wait()
        receipts.append(
            store.record_attempt(
                _attempt(
                    raw=TypedBvTerm("xor", 32, children=(_term(value), _term(3))),
                    canonical=pattern,
                )
            )
        )

    threads = [
        threading.Thread(target=observe, args=(store, value))
        for store, value in zip(observation_stores, (2, 4))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(receipt.status == "stored" for receipt in receipts)
    event_rows = (
        observation_stores[0]
        ._connection.execute(
            "SELECT event_kind, group_revision FROM residual_group_events ORDER BY event_id"
        )
        .fetchall()
    )
    assert [(row[0], row[1]) for row in event_rows] == [
        ("observed", 1),
        ("observed", 2),
    ]
    for store in observation_stores:
        store.close()

    claim_stores = (MbaDiscoveryStore(path), MbaDiscoveryStore(path))
    claim_barrier = threading.Barrier(2)
    claims: list[object] = []

    def claim(store: MbaDiscoveryStore) -> None:
        claim_barrier.wait()
        claims.append(store.claim_next_group("miner", "budget"))

    threads = [threading.Thread(target=claim, args=(store,)) for store in claim_stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(result.status == "claimed" for result in claims) == 1
    assert sum(result.status == "refused" for result in claims) == 1
    event_rows = (
        claim_stores[0]
        ._connection.execute(
            "SELECT event_kind, group_revision FROM residual_group_events ORDER BY event_id"
        )
        .fetchall()
    )
    assert [(row[0], row[1]) for row in event_rows] == [
        ("observed", 1),
        ("observed", 2),
        ("claimed", 3),
    ]
    assert claim_stores[0].count_rows("mining_runs") == 1
    for store in claim_stores:
        store.close()


@pytest.mark.parametrize("materialize_first", (False, True))
def test_rejected_event_source_must_match_normalized_terminal_source(
    tmp_path: Path, materialize_first: bool
) -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store, _proposal, published = _published_store(
        tmp_path,
        f"reject-source-{materialize_first}",
        clock=lambda: timestamp,
    )
    assert published.proposal is not None and published.group is not None
    proposal_id = published.proposal.proposal_id
    expected_state = ProposalState.PROPOSED
    if materialize_first:
        materialized = store.mark_materialized(
            proposal_id,
            "/rule.py",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert materialized.group is not None
        expected_state = ProposalState.MATERIALIZED
    # Rejection must retain its source authority even after later equal-time
    # evidence advances the group revision.
    store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(2), _term(3))),
            canonical=_proposal.pattern,
        )
    )
    revision = store._connection.execute(
        "SELECT revision FROM residual_groups WHERE group_id=?",
        (published.group.group_id,),
    ).fetchone()[0]
    rejected = store.mark_rejected(
        proposal_id,
        "unsafe",
        expected_state=expected_state,
        expected_revision=revision,
    )
    assert rejected.proposal is not None
    wrong_source = "proposed" if materialize_first else "materialized"
    store._connection.execute(
        "UPDATE residual_group_events SET source_proposal_state=? WHERE proposal_id=? AND event_kind='rejected'",
        (wrong_source, proposal_id),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="rejection event"):
        store.status_counts()
    with pytest.raises(ValueError, match="rejection event"):
        store.mark_rejected(
            proposal_id,
            "unsafe",
            expected_state=expected_state,
            expected_revision=revision,
        )
    store.close()


def test_claimed_event_application_owner_shape_rejects_forbidden_source(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "claimed-shape.sqlite3")
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    store._connection.execute("PRAGMA ignore_check_constraints=ON")
    store._connection.execute(
        "UPDATE residual_group_events SET source_proposal_state='proposed' WHERE event_kind='claimed'"
    )
    store._connection.execute("PRAGMA ignore_check_constraints=OFF")
    store._connection.commit()
    with pytest.raises(ValueError, match="claimed event owner shape"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize("field", ("provider_attempt_id", "proposal_id"))
def test_claimed_event_application_owner_shape_rejects_forbidden_owner_columns(
    tmp_path: Path, field: str
) -> None:
    store, _proposal, published = _published_store(tmp_path, f"claimed-{field}")
    assert published.proposal is not None
    if field == "provider_attempt_id":
        store.record_attempt(
            _attempt(
                raw=TypedBvTerm("xor", 32, children=(_term(2), _term(3))),
                canonical=_proposal.pattern,
            )
        )
        value = store._connection.execute(
            "SELECT attempt_id FROM provider_attempts ORDER BY attempt_id DESC LIMIT 1"
        ).fetchone()[0]
        store._connection.execute("PRAGMA ignore_check_constraints=ON")
        store._connection.execute(
            "UPDATE residual_group_events SET provider_attempt_id=NULL WHERE event_kind='observed' AND event_id=(SELECT MAX(event_id) FROM residual_group_events WHERE event_kind='observed')"
        )
    else:
        value = published.proposal.proposal_id
    store._connection.execute("PRAGMA ignore_check_constraints=ON")
    store._connection.execute(
        f"UPDATE residual_group_events SET {field}=? WHERE event_kind='claimed'",
        (value,),
    )
    store._connection.execute("PRAGMA ignore_check_constraints=OFF")
    store._connection.commit()
    with pytest.raises(ValueError, match="claimed event owner shape"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize("event_kind", ("materialized", "admitted", "rejected"))
def test_all_proposal_event_shapes_reject_null_source_on_corrupt_read(
    tmp_path: Path, event_kind: str
) -> None:
    store, _proposal, published = _published_store(tmp_path, f"null-{event_kind}")
    assert published.proposal is not None and published.group is not None
    proposal_id = published.proposal.proposal_id
    if event_kind == "materialized":
        result = store.mark_materialized(
            proposal_id,
            "/rule.py",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
    elif event_kind == "admitted":
        result = store.mark_materialized(
            proposal_id,
            "/rule.py",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert result.group is not None
        result = store.mark_admitted(
            proposal_id,
            "rule-id",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=result.group.revision,
        )
    else:
        result = store.mark_rejected(
            proposal_id,
            "unsafe",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
    assert result.status in {"materialized", "admitted", "rejected"}
    store._connection.execute("PRAGMA ignore_check_constraints=ON")
    store._connection.execute(
        "UPDATE residual_group_events SET source_proposal_state=NULL WHERE proposal_id=? AND event_kind=?",
        (proposal_id, event_kind),
    )
    store._connection.execute("PRAGMA ignore_check_constraints=OFF")
    store._connection.commit()
    with pytest.raises(ValueError, match="owner shape|rejection event"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize(
    "corruption",
    (
        "missing",
        "wrong_kind",
        "wrong_owner",
        "noncontiguous",
        "reordered",
        "cross_group",
    ),
)
def test_causal_event_corruption_matrix_fails_closed(
    tmp_path: Path, corruption: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"event-corruption-{corruption}.sqlite3")
    store.record_attempt(_attempt())
    if corruption == "missing":
        store._connection.execute("DELETE FROM residual_group_events")
    elif corruption == "noncontiguous":
        store._connection.execute(
            "UPDATE residual_group_events SET group_revision=2 WHERE event_kind='observed'"
        )
    elif corruption == "wrong_kind":
        store._connection.execute("PRAGMA ignore_check_constraints=ON")
        store._connection.execute(
            "UPDATE residual_group_events SET event_kind='claimed' WHERE event_kind='observed'"
        )
        store._connection.execute("PRAGMA ignore_check_constraints=OFF")
    elif corruption == "wrong_owner":
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        store._connection.execute("PRAGMA ignore_check_constraints=ON")
        store._connection.execute(
            "UPDATE residual_group_events SET run_id=? WHERE event_kind='observed'",
            (claim.claim.run.run_id,),
        )
        store._connection.execute("PRAGMA ignore_check_constraints=OFF")
    elif corruption == "reordered":
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        store._connection.execute(
            "UPDATE residual_group_events SET event_id=0 WHERE event_kind='claimed'"
        )
    else:
        store.record_attempt(_attempt(value=2))
        event_groups = store._connection.execute(
            "SELECT event_id, group_id FROM residual_group_events ORDER BY event_id"
        ).fetchall()
        assert len(event_groups) == 2
        store._connection.execute(
            "UPDATE residual_group_events SET group_id=?, group_revision=2 WHERE event_id=?",
            (event_groups[1][1], event_groups[0][0]),
        )
    store._connection.commit()
    with pytest.raises(ValueError):
        store.status_counts()
    store.close()


@pytest.mark.parametrize(
    "corruption", ("duplicate", "contradictory_run_terminal", "admitted_and_rejected")
)
def test_causal_terminal_and_duplicate_event_corruptions_fail_closed(
    tmp_path: Path, corruption: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"event-terminal-{corruption}.sqlite3")
    if corruption == "duplicate":
        store.record_attempt(_attempt())
        attempt_id = store._connection.execute(
            "SELECT attempt_id FROM provider_attempts"
        ).fetchone()[0]
        store._connection.execute("DROP INDEX idx_residual_group_events_revision")
        store._connection.execute("DROP INDEX idx_residual_group_events_attempt_owner")
        store._connection.execute(
            "INSERT INTO residual_group_events(group_id,event_kind,group_revision,provider_attempt_id,occurred_at) VALUES (1,'observed',1,?,?)",
            (attempt_id, "2026-01-01T00:00:00.000000Z"),
        )
    elif corruption == "contradictory_run_terminal":
        store.record_attempt(_attempt())
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        store.finish_no_proposal(
            claim.claim.run.run_id, claim.claim.run.claimed_revision
        )
        store._connection.execute("DROP INDEX idx_residual_group_events_run_kind")
        store._connection.execute("DROP INDEX idx_residual_group_events_run_terminal")
        store._connection.execute(
            "INSERT INTO residual_group_events(group_id,event_kind,group_revision,run_id,occurred_at) VALUES (1,'run_failed',2,?,?)",
            (claim.claim.run.run_id, "2026-01-01T00:00:00.000000Z"),
        )
    else:
        store, _proposal, published = _published_store(
            tmp_path, "event-terminal-admitted"
        )
        assert published.proposal is not None and published.group is not None
        materialized = store.mark_materialized(
            published.proposal.proposal_id,
            "/rule.py",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert materialized.group is not None
        admitted = store.mark_admitted(
            published.proposal.proposal_id,
            "rule-id",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
        assert admitted.status == "admitted"
        store._connection.execute(
            "DROP INDEX idx_residual_group_events_proposal_terminal"
        )
        store._connection.execute(
            "INSERT INTO residual_group_events(group_id,event_kind,group_revision,source_proposal_state,run_id,proposal_id,occurred_at) VALUES (1,'rejected',2,'materialized',?,?,?)",
            (
                published.run.run_id,
                published.proposal.proposal_id,
                "2026-01-01T00:00:00.000000Z",
            ),
        )
    store._connection.commit()
    with pytest.raises(ValueError):
        store.status_counts()
    store.close()


def test_causal_event_append_failure_rolls_back_every_lifecycle_path(
    tmp_path: Path,
) -> None:
    def fail_append(*_args: object, **_kwargs: object) -> int:
        raise RuntimeError("event append failed")

    for operation in (
        "record",
        "claim",
        "reclaim",
        "finish",
        "publish",
        "materialize",
        "admit",
        "reject",
    ):
        case = tmp_path / operation
        case.mkdir()
        if operation in {"publish", "materialize", "admit", "reject"}:
            if operation == "publish":
                store = MbaDiscoveryStore(case / "store.sqlite3")
                pattern = TypedBvTerm(
                    "add",
                    32,
                    children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
                )
                proposal = _proposal(pattern)
                store.record_attempt(_attempt(raw=pattern, canonical=pattern))
                claim = store.claim_next_group("miner", "budget")
                assert claim.claim is not None
            else:
                store, _published_proposal, published = _published_store(
                    case, operation
                )
                assert published.proposal is not None and published.group is not None
        else:
            now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
            store = MbaDiscoveryStore(case / "store.sqlite3", clock=lambda: now[0])
            store.record_attempt(_attempt())
            claim = None
            if operation in {"reclaim", "finish"}:
                claim = store.claim_next_group("miner", "budget")
                assert claim.claim is not None
            if operation == "reclaim":
                now[0] += timedelta(seconds=301)
        before = tuple(
            store.count_rows(table)
            for table in (
                "provider_attempts",
                "mining_runs",
                "proposals",
                "residual_groups",
                "residual_group_events",
            )
        )
        store._append_event = fail_append  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="event append failed"):
            if operation == "record":
                store.record_attempt(_attempt(value=2))
            elif operation in {"claim", "reclaim"}:
                store.claim_next_group("miner", "budget")
            elif operation == "finish":
                assert claim is not None and claim.claim is not None
                store.finish_no_proposal(
                    claim.claim.run.run_id, claim.claim.run.claimed_revision
                )
            elif operation == "publish":
                assert claim is not None and claim.claim is not None
                store.publish_proposal(
                    claim.claim.run.run_id,
                    claim.claim.run.claimed_revision,
                    proposal,
                    proposal.replacement,
                    proposal,
                )
            elif operation == "materialize":
                store.mark_materialized(
                    published.proposal.proposal_id,
                    "/rule.py",
                    "digest",
                    expected_state=ProposalState.PROPOSED,
                    expected_revision=published.group.revision,
                )
            elif operation == "admit":
                materialized = store.mark_materialized(
                    published.proposal.proposal_id,
                    "/rule.py",
                    "digest",
                    expected_state=ProposalState.PROPOSED,
                    expected_revision=published.group.revision,
                )
                assert materialized.group is not None
                store.mark_admitted(
                    published.proposal.proposal_id,
                    "rule-id",
                    expected_state=ProposalState.MATERIALIZED,
                    expected_revision=materialized.group.revision,
                )
            else:
                store.mark_rejected(
                    published.proposal.proposal_id,
                    "unsafe",
                    expected_state=ProposalState.PROPOSED,
                    expected_revision=published.group.revision,
                )
        after = tuple(
            store.count_rows(table)
            for table in (
                "provider_attempts",
                "mining_runs",
                "proposals",
                "residual_groups",
                "residual_group_events",
            )
        )
        assert after == before
        store.close()


def test_record_deduplicates_terms_raw_shapes_and_exact_attempt(tmp_path: Path) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    first = _attempt(
        raw=TypedBvTerm("xor", 32, children=(_term(1), _term(2))),
        canonical=canonicalize_ac_term(
            TypedBvTerm("xor", 32, children=(_term(1), _term(2)))
        ),
    )
    stored = store.record_attempt(first)
    assert stored.status == "stored"
    assert stored.revision == 1
    duplicate = store.record_attempt(first)
    assert duplicate.status == "duplicate"
    assert duplicate.revision == 1
    assert store.count_rows("provider_attempts") == 1
    assert store.count_rows("terms") == 1
    assert store.count_rows("raw_terms") == 1
    store.close()


def test_distinct_raw_shapes_share_one_canonical_group(tmp_path: Path) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    canonical = _term(1)
    first = _attempt(raw=_term(1), canonical=canonical)
    second = _attempt(
        raw=TypedBvTerm("xor", 32, children=(_term(2), _term(3))),
        canonical=canonical,
    )
    one = store.record_attempt(first)
    two = store.record_attempt(second)
    assert one.group_id == two.group_id
    assert one.revision == 1 and two.revision == 2
    assert store.count_rows("terms") == 1
    assert store.count_rows("raw_terms") == 2
    store.close()


def test_claim_order_is_oldest_observation_then_group_id(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3", clock=lambda: now[0])
    first = _attempt(value=1)
    second = _attempt(value=2)
    assert store.record_attempt(first).status == "stored"
    now[0] += timedelta(seconds=1)
    assert store.record_attempt(second).status == "stored"
    first_claim = store.claim_next_group("miner", "budget")
    assert first_claim.claim is not None
    assert first_claim.claim.group.canonical_term == _term(1)
    store.finish_no_proposal(
        first_claim.claim.run.run_id, first_claim.claim.run.claimed_revision
    )
    second_claim = store.claim_next_group("miner", "budget")
    assert second_claim.claim is not None
    assert second_claim.claim.group.canonical_term == _term(2)
    store.close()


def test_new_evidence_updates_revision_without_invalidating_proposal(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    first = _attempt(eligible=False)
    assert store.record_attempt(first).state is ResidualGroupState.OBSERVED
    second = _attempt(
        raw=TypedBvTerm("xor", 32, children=(_term(1), _term(2))),
        canonical=_term(1),
    )
    promoted = store.record_attempt(second)
    assert promoted.state is ResidualGroupState.ELIGIBLE
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    finished = store.finish_no_proposal(
        claim.claim.run.run_id, claim.claim.run.claimed_revision
    )
    assert finished.group is not None
    assert finished.group.state is ResidualGroupState.NO_PROPOSAL
    again = store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(3), _term(4))),
            canonical=_term(1),
        )
    )
    assert again.state is ResidualGroupState.ELIGIBLE
    assert again.revision == finished.group.revision + 1
    store.close()


def test_payloads_are_blobs_and_corrupt_projection_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    store = MbaDiscoveryStore(path)
    store.record_attempt(_attempt())
    connection = sqlite3.connect(path)
    classes = connection.execute(
        "SELECT typeof(canonical_term), typeof(raw_term) FROM terms JOIN raw_terms USING(term_id)"
    ).fetchone()
    assert classes == ("blob", "blob")
    connection.close()
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    store._connection.execute("UPDATE terms SET canonical_term=?", (b"{}",))
    with pytest.raises(ValueError, match="invalid canonical term bytes"):
        store._project_group(store._connection, claim.claim.group.group_id)
    store.close()


def test_claim_heartbeat_expiry_reclaim_and_stale_finish(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3", clock=lambda: now[0])
    attempt = _attempt()
    store.record_attempt(attempt)
    claim = store.claim_next_group("miner", "budget")
    assert claim.status == "claimed"
    assert claim.claim is not None
    assert claim.claim.group.state is ResidualGroupState.MINING
    assert claim.claim.run.state is MiningRunState.ACTIVE
    assert (
        store.heartbeat(claim.claim.run.run_id, claim.claim.run.claimed_revision).status
        == "heartbeated"
    )
    new = _attempt(
        raw=TypedBvTerm("xor", 32, children=(_term(1), _term(2))),
        canonical=_term(1),
    )
    store.record_attempt(new)
    stale = store.finish_no_proposal(
        claim.claim.run.run_id, claim.claim.run.claimed_revision, "none"
    )
    assert stale.status == "refused"
    assert stale.reason == "stale_revision"
    now[0] += timedelta(seconds=301)
    reclaimed = store.claim_next_group("miner", "budget")
    assert reclaimed.status == "claimed"
    assert reclaimed.claim is not None
    assert reclaimed.claim.run.run_id != claim.claim.run.run_id
    store.close()


def test_proposal_lifecycle_and_invalid_order_are_typed_refusals(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    pattern = TypedBvTerm(
        "add",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("register", "x")),
            TypedBvTerm(None, 32, leaf_key=("register", "x")),
        ),
    )
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    run = claim.claim.run
    proposal_input = _proposal(pattern)
    published = store.publish_proposal(
        run.run_id,
        run.claimed_revision,
        proposal_input,
        proposal_input.replacement,
        proposal_input,
    )
    assert published.status == "published"
    assert published.proposal is not None
    proposal = published.proposal
    assert proposal.state is ProposalState.PROPOSED
    retried_publish = store.publish_proposal(
        run.run_id,
        run.claimed_revision,
        proposal_input,
        proposal_input.replacement,
        proposal_input,
    )
    assert retried_publish.status == "duplicate"
    assert (
        store.mark_admitted(proposal.proposal_id, "rule-1").reason
        == "expected_state_required"
    )
    materialized = store.mark_materialized(
        proposal.proposal_id,
        "/review/rule.py",
        "sha256:abc",
        expected_state=ProposalState.PROPOSED,
        expected_revision=claim.claim.group.revision,
    )
    assert materialized.status == "materialized"
    retried_materialized = store.mark_materialized(
        proposal.proposal_id,
        "/review/rule.py",
        "sha256:abc",
        expected_state=ProposalState.PROPOSED,
        expected_revision=claim.claim.group.revision,
    )
    assert retried_materialized.status == "duplicate"
    admitted = store.mark_admitted(
        proposal.proposal_id,
        "rule-1",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=materialized.group.revision,
    )
    assert admitted.status == "admitted"
    retried_admitted = store.mark_admitted(
        proposal.proposal_id,
        "rule-1",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=materialized.group.revision,
    )
    assert retried_admitted.status == "duplicate"
    assert (
        store.mark_rejected(
            proposal.proposal_id,
            "too-late",
            expected_state=ProposalState.ADMITTED,
            expected_revision=admitted.group.revision,
        ).reason
        == "invalid_transition"
    )
    store.close()


@pytest.mark.parametrize("materialize_first", (False, True))
def test_rejection_exact_and_conflicting_retries_are_typed(
    tmp_path: Path, materialize_first: bool
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"reject-{materialize_first}.sqlite3")
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )
    proposal = _proposal(pattern)
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    expected_state = ProposalState.PROPOSED
    expected_revision = claim.claim.group.revision
    if materialize_first:
        materialized = store.mark_materialized(
            published.proposal.proposal_id,
            "/x",
            "d",
            expected_state=ProposalState.PROPOSED,
            expected_revision=expected_revision,
        )
        assert materialized.group is not None
        expected_state = ProposalState.MATERIALIZED
        expected_revision = materialized.group.revision
    rejected = store.mark_rejected(
        published.proposal.proposal_id,
        "not-safe",
        expected_state=expected_state,
        expected_revision=expected_revision,
    )
    assert rejected.status == "rejected"
    retried = store.mark_rejected(
        published.proposal.proposal_id,
        "not-safe",
        expected_state=expected_state,
        expected_revision=claim.claim.group.revision,
    )
    assert retried.status == "duplicate"
    conflict = store.mark_rejected(
        published.proposal.proposal_id,
        "different",
        expected_state=expected_state,
        expected_revision=claim.claim.group.revision,
    )
    assert conflict.status == "refused"
    store.close()


def test_every_public_operation_fails_deterministically_after_close(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "closed.sqlite3")
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )
    proposal = _proposal(pattern)
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    store.close()
    store.close()
    calls = (
        lambda: store.schema_version(),
        lambda: store.table_columns(),
        lambda: store.connection_pragmas(),
        lambda: store.journal_mode(),
        lambda: store.count_rows("terms"),
        lambda: store.record_attempt(_attempt(raw=pattern, canonical=pattern)),
        lambda: store.claim_next_group("miner", "budget"),
        lambda: store.heartbeat(
            claim.claim.run.run_id, claim.claim.run.claimed_revision
        ),
        lambda: store.finish_no_proposal(
            claim.claim.run.run_id, claim.claim.run.claimed_revision
        ),
        lambda: store.publish_proposal(
            claim.claim.run.run_id,
            claim.claim.run.claimed_revision,
            proposal,
            proposal.replacement,
            proposal,
        ),
        lambda: store.mark_materialized(
            published.proposal.proposal_id,
            "/x",
            "d",
            expected_state=ProposalState.PROPOSED,
            expected_revision=claim.claim.group.revision,
        ),
        lambda: store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=ProposalState.PROPOSED,
            expected_revision=claim.claim.group.revision,
        ),
        lambda: store.mark_rejected(
            published.proposal.proposal_id,
            "reason",
            expected_state=ProposalState.PROPOSED,
            expected_revision=claim.claim.group.revision,
        ),
        lambda: store.status_counts(),
    )
    for call in calls:
        with pytest.raises(RuntimeError, match="closed"):
            call()


def test_two_stores_only_one_claim_wins(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    first = MbaDiscoveryStore(path)
    second = MbaDiscoveryStore(path)
    first.record_attempt(_attempt())
    results: list[object] = []

    def claim(store: MbaDiscoveryStore) -> None:
        results.append(store.claim_next_group("miner", "budget"))

    threads = [
        threading.Thread(target=claim, args=(store,)) for store in (first, second)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(result.status for result in results) == ["claimed", "refused"]
    first.close()
    second.close()


def test_two_stores_record_distinct_attempts_atomically(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    stores = (MbaDiscoveryStore(path), MbaDiscoveryStore(path))
    barrier = threading.Barrier(2)
    results: list[object] = []

    def record(store: MbaDiscoveryStore, suffix: int) -> None:
        barrier.wait()
        results.append(
            store.record_attempt(
                _attempt(attempt_uuid=f"bbbbbbbb-bbbb-4bbb-8bbb-{suffix:012d}")
            )
        )

    threads = [
        threading.Thread(target=record, args=(store, index))
        for index, store in enumerate(stores, 1)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(result.status for result in results) == ["stored", "stored"]
    assert stores[0].count_rows("provider_attempts") == 2
    for store in stores:
        store.close()


def test_future_or_partial_schema_fails_closed(tmp_path: Path) -> None:
    future = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(future)
    connection.execute(
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    connection.execute("INSERT INTO schema_migrations VALUES (99, 'now')")
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="unsupported schema version"):
        MbaDiscoveryStore(future)

    partial = tmp_path / "partial.sqlite3"
    connection = sqlite3.connect(partial)
    connection.execute("CREATE TABLE inputs(input_id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(partial)


def test_close_is_idempotent_and_post_close_is_deterministic(tmp_path: Path) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    store.close()
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.status_counts()


def test_proposal_authority_rejects_each_independent_mismatch_without_transition(
    tmp_path: Path,
) -> None:
    pattern = TypedBvTerm(
        "add",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("register", "x")),
            TypedBvTerm(None, 32, leaf_key=("register", "x")),
        ),
    )
    proposal = _proposal(pattern)
    for name, fingerprint, replacement, payload, proofs in (
        ("fingerprint", "f" * 64, proposal.replacement, proposal, None),
        ("replacement", proposal.fingerprint, _term(3), proposal, None),
        (
            "payload",
            proposal.fingerprint,
            proposal.replacement,
            {"arbitrary": True},
            None,
        ),
        ("proof", proposal.fingerprint, proposal.replacement, proposal, []),
    ):
        store = MbaDiscoveryStore(tmp_path / f"{name}.sqlite3")
        store.record_attempt(_attempt(raw=pattern, canonical=pattern))
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        receipt = store.publish_proposal(
            claim.claim.run.run_id,
            claim.claim.run.claimed_revision,
            fingerprint,
            replacement,
            payload,
            proofs,
        )
        assert receipt.status == "refused"
        assert store.count_rows("proposals") == 0
        state = store._connection.execute(
            "SELECT state FROM residual_groups WHERE group_id=?",
            (claim.claim.group.group_id,),
        ).fetchone()[0]
        run_state = store._connection.execute(
            "SELECT state FROM mining_runs WHERE run_id=?", (claim.claim.run.run_id,)
        ).fetchone()[0]
        assert state == ResidualGroupState.MINING.value
        assert run_state == MiningRunState.ACTIVE.value
        store.close()


def test_proposal_projection_revalidates_fingerprint_and_proof_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "db.sqlite3"
    pattern = TypedBvTerm(
        "add",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("register", "x")),
            TypedBvTerm(None, 32, leaf_key=("register", "x")),
        ),
    )
    proposal = _proposal(pattern)
    store = MbaDiscoveryStore(path)
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    store._connection.execute(
        "UPDATE proposals SET proof_receipt_payload=? WHERE proposal_id=?",
        (b"[]", published.proposal.proposal_id),
    )
    with pytest.raises(ValueError, match="proof receipt"):
        store._project_proposal(
            store._connection,
            store._connection.execute(
                "SELECT * FROM proposals WHERE proposal_id=?",
                (published.proposal.proposal_id,),
            ).fetchone(),
        )
    store.close()


def test_eligibility_is_immutable_attempt_identity(tmp_path: Path) -> None:
    attempt_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    first = store.record_attempt(_attempt(attempt_uuid=attempt_uuid, eligible=False))
    assert first.status == "stored"
    second = store.record_attempt(_attempt(attempt_uuid=attempt_uuid, eligible=True))
    assert second.status == "refused"
    assert second.reason == "attempt_uuid_conflict"
    assert store.count_rows("provider_attempts") == 1
    store.close()


def test_heterogeneous_lease_override_is_refused_and_status_uses_authority(
    tmp_path: Path,
) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    path = tmp_path / "db.sqlite3"
    first = MbaDiscoveryStore(path, clock=lambda: now[0])
    second = MbaDiscoveryStore(path, clock=lambda: now[0])
    first.record_attempt(_attempt())
    claim = first.claim_next_group("miner", "budget")
    assert claim.claim is not None
    assert (
        second.claim_next_group("miner", "budget", 1).reason
        == "unsupported_lease_timeout"
    )
    now[0] += timedelta(seconds=1)
    assert second.status_counts().expired_leases == 0
    now[0] += timedelta(seconds=300)
    assert second.status_counts().expired_leases == 1
    first.close()
    second.close()


def test_naive_clock_is_rejected_and_default_clock_is_utc(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="aware"):
        MbaDiscoveryStore(
            tmp_path / "naive.sqlite3", clock=lambda: datetime(2026, 1, 1)
        )
    store = MbaDiscoveryStore(tmp_path / "utc.sqlite3")
    store.record_attempt(_attempt())
    timestamp = store._connection.execute(
        "SELECT created_at FROM provider_attempts"
    ).fetchone()[0]
    assert timestamp.endswith("Z")
    assert datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is not None
    store.close()


def test_status_rejects_unknown_state_and_group_projection_rejects_width_drift(
    tmp_path: Path,
) -> None:
    path = tmp_path / "db.sqlite3"
    store = MbaDiscoveryStore(path)
    store.record_attempt(_attempt())
    group_id = store._connection.execute(
        "SELECT group_id FROM residual_groups"
    ).fetchone()[0]
    raw_id = store._connection.execute("SELECT raw_term_id FROM raw_terms").fetchone()[
        0
    ]
    eight = TypedBvTerm(None, 8, value=1)
    from d810.mba.term_codec import typed_term_to_dict

    payload = json.dumps(
        typed_term_to_dict(eight), separators=(",", ":"), sort_keys=True
    ).encode()
    store._connection.execute(
        "UPDATE raw_terms SET raw_term=?, raw_fingerprint=? WHERE raw_term_id=?",
        (payload, term_fingerprint(eight), raw_id),
    )
    with pytest.raises(ValueError, match="width"):
        store._project_group(store._connection, group_id)
    store._connection.execute(
        "UPDATE residual_groups SET state='bogus' WHERE group_id=?", (group_id,)
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="unknown residual group state"):
        store.status_counts()
    store.close()


def test_finish_no_proposal_rolls_back_when_group_cas_fails(tmp_path: Path) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    store._connection.execute(
        """
        CREATE TRIGGER ignore_no_proposal
        BEFORE UPDATE OF state ON residual_groups
        WHEN NEW.state = 'no_proposal'
        BEGIN SELECT RAISE(IGNORE); END
        """
    )
    store._connection.commit()
    receipt = store.finish_no_proposal(
        claim.claim.run.run_id, claim.claim.run.claimed_revision
    )
    assert receipt.status == "refused"
    assert (
        store._connection.execute("SELECT state FROM mining_runs").fetchone()[0]
        == "active"
    )
    assert (
        store._connection.execute("SELECT state FROM residual_groups").fetchone()[0]
        == "mining"
    )
    store.close()


@pytest.mark.parametrize(
    ("name", "statement"),
    (
        (
            "hidden",
            "ALTER TABLE terms ADD COLUMN shadow INTEGER GENERATED ALWAYS AS (width + 1) VIRTUAL",
        ),
        ("table", "CREATE TABLE surprise(value TEXT)"),
        ("index", "CREATE INDEX surprise_idx ON terms(width)"),
        ("index_order", "DROP INDEX idx_residual_groups_claim"),
    ),
)
def test_reopen_rejects_each_schema_object_drift(
    tmp_path: Path, name: str, statement: str
) -> None:
    path = tmp_path / f"{name}.sqlite3"
    store = MbaDiscoveryStore(path)
    store.close()
    connection = sqlite3.connect(path)
    connection.execute(statement)
    if name == "index_order":
        connection.execute(
            "CREATE INDEX idx_residual_groups_claim ON residual_groups(group_id, state, last_observed_at)"
        )
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(path)


def test_unversioned_foreign_database_is_not_adopted(tmp_path: Path) -> None:
    path = tmp_path / "foreign.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE unrelated(value TEXT)")
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(path)
    connection = sqlite3.connect(path)
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall() == [("unrelated",)]
    connection.close()


@pytest.mark.parametrize(
    ("name", "table", "needle", "replacement"),
    (
        ("type", "terms", "width INTEGER NOT NULL", "width TEXT NOT NULL"),
        ("null", "terms", "width INTEGER NOT NULL", "width INTEGER"),
        (
            "default",
            "terms",
            "width INTEGER NOT NULL",
            "width INTEGER NOT NULL DEFAULT 0",
        ),
        ("pk", "terms", "term_id INTEGER PRIMARY KEY", "term_id INTEGER"),
        (
            "fk-target",
            "raw_terms",
            "term_id INTEGER NOT NULL REFERENCES terms",
            "term_id INTEGER NOT NULL REFERENCES inputs",
        ),
        (
            "fk-action",
            "raw_terms",
            "term_id INTEGER NOT NULL REFERENCES terms",
            "term_id INTEGER NOT NULL REFERENCES terms ON DELETE CASCADE",
        ),
    ),
)
def test_reopen_rejects_each_declared_metadata_or_fk_drift(
    tmp_path: Path, name: str, table: str, needle: str, replacement: str
) -> None:
    source = tmp_path / f"source-{name}.sqlite3"
    mutated = tmp_path / f"mutated-{name}.sqlite3"
    store = MbaDiscoveryStore(source)
    store.close()
    source_connection = sqlite3.connect(source)
    dump = list(source_connection.iterdump())
    source_connection.close()
    changed = False
    with sqlite3.connect(mutated) as connection:
        for statement in dump:
            if statement.startswith(f"CREATE TABLE {table} "):
                assert needle in statement
                statement = statement.replace(needle, replacement, 1)
                changed = True
            connection.execute(statement)
        connection.commit()
    assert changed
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(mutated)


@pytest.mark.parametrize("column", ("canonical_term", "width", "raw_term_id"))
def test_attempt_duplicate_path_rejects_corrupt_term_identity(
    tmp_path: Path, column: str
) -> None:
    path = tmp_path / f"{column}.sqlite3"
    store = MbaDiscoveryStore(path)
    attempt = _attempt()
    assert store.record_attempt(attempt).status == "stored"
    if column == "canonical_term":
        store._connection.execute("UPDATE terms SET canonical_term=?", (b"{}",))
    elif column == "width":
        store._connection.execute("UPDATE terms SET width=8")
    else:
        store._connection.execute("UPDATE raw_terms SET raw_codec_version=99")
    store._connection.commit()
    retry = store.record_attempt(attempt)
    assert retry.status == "refused"
    assert retry.reason in {
        "stored term identity is corrupt",
        "invalid canonical term bytes",
        "canonical term identity is corrupt",
        "raw term identity is corrupt",
    }
    store.close()


def test_proposal_projection_rejects_corrupt_publishing_run_before_mutation(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )
    proposal = _proposal(pattern)
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    store._connection.execute(
        "UPDATE mining_runs SET state='failed', finished_at=NULL WHERE run_id=?",
        (claim.claim.run.run_id,),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="proposal lifecycle ownership"):
        store.mark_materialized(
            published.proposal.proposal_id,
            "/x",
            "d",
            expected_state=ProposalState.PROPOSED,
            expected_revision=claim.claim.group.revision,
        )
    assert (
        store._connection.execute("SELECT state FROM proposals").fetchone()[0]
        == "proposed"
    )
    store.close()


def test_unknown_proposal_state_is_corruption_before_request_comparison(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "unknown-proposal.sqlite3")
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )
    proposal = _proposal(pattern)
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    store._connection.execute(
        "UPDATE proposals SET state='bogus' WHERE proposal_id=?",
        (published.proposal.proposal_id,),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="unknown proposal state"):
        store.mark_materialized(
            published.proposal.proposal_id,
            "/x",
            "d",
            expected_state=ProposalState.PROPOSED,
            expected_revision=claim.claim.group.revision,
        )
    store.close()


@pytest.mark.parametrize(
    ("name", "ddl"),
    (
        (
            "partial",
            "CREATE INDEX idx_residual_groups_claim ON residual_groups(state, last_observed_at, group_id) WHERE state IS NOT NULL",
        ),
        (
            "descending",
            "CREATE INDEX idx_residual_groups_claim ON residual_groups(state DESC, last_observed_at, group_id)",
        ),
        (
            "nocase",
            "CREATE INDEX idx_residual_groups_claim ON residual_groups(state COLLATE NOCASE, last_observed_at, group_id)",
        ),
    ),
)
def test_reopen_rejects_index_semantics_drift(
    tmp_path: Path, name: str, ddl: str
) -> None:
    path = tmp_path / f"index-{name}.sqlite3"
    store = MbaDiscoveryStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP INDEX idx_residual_groups_claim")
        connection.execute(ddl)
        connection.commit()
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(path)


def test_unversioned_rejection_preserves_file_and_journal_mode(tmp_path: Path) -> None:
    path = tmp_path / "foreign-hash.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('keep')")
        connection.commit()
        before_journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
    before_hash = hashlib.sha256(path.read_bytes()).digest()
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(path)
    assert hashlib.sha256(path.read_bytes()).digest() == before_hash
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == before_journal
        assert connection.execute("SELECT * FROM unrelated").fetchall() == [("keep",)]


@pytest.mark.parametrize(
    "suffix", ("COLLATE NOCASE UNIQUE", "UNIQUE ON CONFLICT REPLACE")
)
def test_reopen_rejects_unique_collation_and_conflict_policy_drift(
    tmp_path: Path, suffix: str
) -> None:
    source = tmp_path / "unique-source.sqlite3"
    mutated = tmp_path / f"unique-{suffix.split()[0].lower()}.sqlite3"
    store = MbaDiscoveryStore(source)
    store.close()
    with sqlite3.connect(source) as connection:
        dump = list(connection.iterdump())
    changed = False
    with sqlite3.connect(mutated) as connection:
        for statement in dump:
            if statement.startswith("CREATE TABLE terms "):
                needle = "canonical_fingerprint TEXT NOT NULL UNIQUE"
                assert needle in statement
                statement = statement.replace(
                    needle, f"canonical_fingerprint TEXT NOT NULL {suffix}", 1
                )
                changed = True
            connection.execute(statement)
        connection.commit()
    assert changed
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(mutated)


def _published_store(
    tmp_path: Path, name: str = "lifecycle", *, clock=None
) -> tuple[MbaDiscoveryStore, MbaRuleProposal, object]:
    store = MbaDiscoveryStore(
        tmp_path / f"{name}.sqlite3", **({"clock": clock} if clock is not None else {})
    )
    pattern = TypedBvTerm(
        "add",
        32,
        children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2,
    )
    proposal = _proposal(pattern)
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    published = store.publish_proposal(
        claim.claim.run.run_id,
        claim.claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert published.proposal is not None
    return store, proposal, published


def test_post_evidence_retries_use_current_group_revision(tmp_path: Path) -> None:
    store, proposal, published = _published_store(tmp_path)
    assert published.group is not None
    store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(2), _term(3))),
            canonical=proposal.pattern,
        )
    )
    current = store._connection.execute(
        "SELECT revision FROM residual_groups WHERE group_id=?",
        (published.group.group_id,),
    ).fetchone()[0]
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/new",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=current,
    )
    assert materialized.status == "materialized"
    retry = store.mark_materialized(
        published.proposal.proposal_id,
        "/new",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=current,
    )
    assert retry.status == "duplicate"
    store.close()


def test_proposal_snapshot_is_typed_and_read_only(tmp_path: Path) -> None:
    store, _proposal, published = _published_store(tmp_path, "snapshot")
    assert published.proposal is not None
    before = _logical_domain_snapshot(store)
    snapshot = store.proposal_snapshot(published.proposal.proposal_id)
    assert snapshot is not None
    assert snapshot.proposal.proposal_id == published.proposal.proposal_id
    assert snapshot.group.group_id == published.proposal.group_id
    assert _logical_domain_snapshot(store) == before
    assert store.proposal_snapshot("00000000-0000-0000-0000-000000000000") is None
    assert _logical_domain_snapshot(store) == before
    store.close()


def test_post_evidence_admission_retry_uses_current_group_revision(
    tmp_path: Path,
) -> None:
    store, proposal, published = _published_store(tmp_path, "admit-evidence")
    assert published.group is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/new",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.group is not None
    store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(6), _term(7))),
            canonical=proposal.pattern,
        )
    )
    revision = store._connection.execute(
        "SELECT revision FROM residual_groups WHERE group_id=?",
        (published.group.group_id,),
    ).fetchone()[0]
    admitted = store.mark_admitted(
        published.proposal.proposal_id,
        "rule-id",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=revision,
    )
    assert admitted.status == "admitted"
    retry = store.mark_admitted(
        published.proposal.proposal_id,
        "rule-id",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=revision,
    )
    assert retry.status == "duplicate"
    store.close()


@pytest.mark.parametrize("materialize_first", (False, True))
def test_post_evidence_rejection_exact_retry_and_wrong_source(
    tmp_path: Path, materialize_first: bool
) -> None:
    store, proposal, published = _published_store(
        tmp_path, f"reject-evidence-{materialize_first}"
    )
    assert published.group is not None
    expected_state = ProposalState.PROPOSED
    if materialize_first:
        materialized = store.mark_materialized(
            published.proposal.proposal_id,
            "/new",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert materialized.group is not None
        expected_state = ProposalState.MATERIALIZED
    store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(4), _term(5))),
            canonical=proposal.pattern,
        )
    )
    revision = store._connection.execute(
        "SELECT revision FROM residual_groups WHERE group_id=?",
        (published.group.group_id,),
    ).fetchone()[0]
    rejected = store.mark_rejected(
        published.proposal.proposal_id,
        "not-safe",
        expected_state=expected_state,
        expected_revision=revision,
    )
    assert rejected.status == "rejected"
    retry = store.mark_rejected(
        published.proposal.proposal_id,
        "not-safe",
        expected_state=expected_state,
        expected_revision=revision,
    )
    assert retry.status == "duplicate"
    wrong = store.mark_materialized(
        published.proposal.proposal_id,
        "/new",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=revision,
    )
    assert wrong.status == "refused"
    store.close()


def test_attempt_duplicate_rejects_cross_linked_raw_term(tmp_path: Path) -> None:
    store = MbaDiscoveryStore(tmp_path / "cross-link.sqlite3")
    first = _attempt(value=1)
    second = _attempt(value=2)
    assert store.record_attempt(first).status == "stored"
    assert store.record_attempt(second).status == "stored"
    raw_ids = [
        row[0]
        for row in store._connection.execute(
            "SELECT raw_term_id FROM raw_terms ORDER BY raw_term_id"
        )
    ]
    attempt_id = store._connection.execute(
        "SELECT attempt_id FROM provider_attempts WHERE attempt_uuid=?",
        (first.attempt_uuid,),
    ).fetchone()[0]
    store._connection.execute(
        "UPDATE provider_attempts SET raw_term_id=? WHERE attempt_id=?",
        (raw_ids[1], attempt_id),
    )
    store._connection.commit()
    retry = store.record_attempt(first)
    assert retry.status == "refused"
    assert retry.reason == "stored term identity is corrupt"
    store.close()


@pytest.mark.parametrize("field", ("last_mined_at", "materialized_at", "admitted_at"))
def test_group_projection_rejects_state_timestamp_field_ghosts(
    tmp_path: Path, field: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"group-{field}.sqlite3")
    store.record_attempt(_attempt())
    group_id = store._connection.execute(
        "SELECT group_id FROM residual_groups"
    ).fetchone()[0]
    store._connection.execute(
        f"UPDATE residual_groups SET {field}='2026-01-01T00:00:00.000000Z' WHERE group_id=?",
        (group_id,),
    )
    store._connection.commit()
    with pytest.raises(ValueError):
        store.status_counts()
    store.close()


@pytest.mark.parametrize(
    ("name", "table", "needle", "replacement"),
    (
        (
            "deferred-fk",
            "raw_terms",
            "term_id INTEGER NOT NULL REFERENCES terms",
            "term_id INTEGER NOT NULL REFERENCES terms DEFERRABLE INITIALLY DEFERRED",
        ),
        (
            "check",
            "inputs",
            "external_evidence_allowed INTEGER NOT NULL",
            "external_evidence_allowed INTEGER NOT NULL CHECK(external_evidence_allowed IN (0,1))",
        ),
    ),
)
def test_reopen_rejects_enforcement_changing_table_ddl_without_mutation(
    tmp_path: Path, name: str, table: str, needle: str, replacement: str
) -> None:
    source = tmp_path / "canonical.sqlite3"
    mutated = tmp_path / f"{name}.sqlite3"
    MbaDiscoveryStore(source).close()
    with sqlite3.connect(source) as connection:
        dump = list(connection.iterdump())
    changed = False
    with sqlite3.connect(mutated) as connection:
        for statement in dump:
            if statement.startswith(f"CREATE TABLE {table} "):
                assert needle in statement
                statement = statement.replace(needle, replacement, 1)
                changed = True
            connection.execute(statement)
        connection.commit()
    assert changed
    before = mutated.read_bytes()
    with sqlite3.connect(mutated) as connection:
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
    with pytest.raises(ValueError, match="partial schema"):
        MbaDiscoveryStore(mutated)
    assert mutated.read_bytes() == before
    with sqlite3.connect(mutated) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == journal


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            "UPDATE residual_groups SET eligible_observation_count=1, state='observed'",
            "eligible",
        ),
        (
            "UPDATE residual_groups SET materialized_at=created_at FROM proposals WHERE proposals.group_id=residual_groups.group_id",
            "proposed",
        ),
        (
            "UPDATE proposals SET created_at='2026-01-02T00:00:00.000000Z'",
            "publication",
        ),
        (
            "UPDATE proposals SET materialized_at='2026-01-02T00:00:00.000000Z'",
            "timestamps",
        ),
    ),
)
def test_status_rejects_relational_lifecycle_corruption(
    tmp_path: Path, mutation: str, message: str
) -> None:
    store, _proposal_input, published = _published_store(
        tmp_path, f"relational-{message}"
    )
    assert published.proposal is not None and published.group is not None
    if "materialized_at" in mutation and mutation.startswith("UPDATE proposals"):
        materialized = store.mark_materialized(
            published.proposal.proposal_id,
            "/x",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert materialized.status == "materialized"
        mutation = "UPDATE proposals SET materialized_at='2026-01-02T00:00:00.000000Z'"
    store._connection.execute(mutation)
    store._connection.commit()
    with pytest.raises(ValueError, match=message):
        store.status_counts()
    store.close()


def test_mark_admitted_refuses_mismatched_materialized_timestamp_without_mutation(
    tmp_path: Path,
) -> None:
    store, _proposal_input, published = _published_store(tmp_path, "admit-pair")
    assert published.proposal is not None and published.group is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.status == "materialized"
    store._connection.execute(
        "UPDATE residual_groups SET materialized_at='2026-01-02T00:00:00.000000Z'"
    )
    store._connection.commit()
    before = tuple(
        store._connection.execute(
            "SELECT state, admitted_at FROM residual_groups"
        ).fetchone()
    )
    with pytest.raises(ValueError, match="materialized"):
        store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
    assert (
        tuple(
            store._connection.execute(
                "SELECT state, admitted_at FROM residual_groups"
            ).fetchone()
        )
        == before
    )
    assert (
        store._connection.execute("SELECT state FROM proposals").fetchone()[0]
        == "materialized"
    )
    store.close()


@pytest.mark.parametrize(
    "corruption",
    ("malformed", "out_of_order", "group_state", "group_revision", "duplicate_owner"),
)
def test_status_and_reclaim_refuse_corrupt_active_lease_without_mutation(
    tmp_path: Path, corruption: str
) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = MbaDiscoveryStore(
        tmp_path / f"lease-{corruption}.sqlite3", clock=lambda: now[0]
    )
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    run = claim.claim.run
    if corruption == "malformed":
        store._connection.execute("UPDATE mining_runs SET heartbeat_at='0000'")
    elif corruption == "out_of_order":
        store._connection.execute(
            "UPDATE mining_runs SET heartbeat_at='2025-12-31T23:59:59.000000Z'"
        )
    elif corruption == "group_state":
        store._connection.execute("UPDATE residual_groups SET state='eligible'")
    elif corruption == "group_revision":
        store._connection.execute(
            "UPDATE residual_groups SET revision=?", (run.claimed_revision - 1,)
        )
    else:
        store._connection.execute(
            "INSERT INTO mining_runs(run_id,group_id,claimed_revision,miner_version,budget_fingerprint,state,started_at,heartbeat_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                run.group_id,
                run.claimed_revision,
                "other",
                "budget",
                "active",
                run.started_at,
                run.heartbeat_at,
            ),
        )
    store._connection.commit()
    snapshot = tuple(
        store._connection.execute(
            "SELECT run_id,state,heartbeat_at FROM mining_runs ORDER BY run_id"
        )
    )
    with pytest.raises(ValueError):
        store.status_counts()
    now[0] += timedelta(seconds=301)
    refused = store.claim_next_group("miner", "budget")
    assert refused.status == "refused"
    assert (
        tuple(
            store._connection.execute(
                "SELECT run_id,state,heartbeat_at FROM mining_runs ORDER BY run_id"
            )
        )
        == snapshot
    )
    store.close()


@pytest.mark.parametrize("cas", ("run", "group"))
def test_reclaim_rolls_back_when_either_cas_loses(tmp_path: Path, cas: str) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = MbaDiscoveryStore(tmp_path / f"reclaim-{cas}.sqlite3", clock=lambda: now[0])
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    target = "mining_runs" if cas == "run" else "residual_groups"
    target_state = "expired" if cas == "run" else "eligible"
    store._connection.execute(
        f"""
        CREATE TRIGGER ignore_reclaim_{cas}
        BEFORE UPDATE OF state ON {target}
        WHEN NEW.state = '{target_state}'
        BEGIN SELECT RAISE(IGNORE); END
        """
    )
    store._connection.commit()
    now[0] += timedelta(seconds=301)
    receipt = store.claim_next_group("miner", "budget")
    assert receipt.status == "refused"
    assert [
        tuple(row) for row in store._connection.execute("SELECT state FROM mining_runs")
    ] == [("active",)]
    assert [
        tuple(row)
        for row in store._connection.execute("SELECT state FROM residual_groups")
    ] == [("mining",)]
    store.close()


def _record_later_evidence(
    store: MbaDiscoveryStore, pattern: TypedBvTerm, value: int
) -> int:
    receipt = store.record_attempt(
        _attempt(
            raw=TypedBvTerm("xor", 32, children=(_term(value), _term(value + 1))),
            canonical=pattern,
        )
    )
    assert receipt.revision is not None
    return receipt.revision


def test_materialization_exact_original_retry_survives_later_evidence(
    tmp_path: Path,
) -> None:
    store, proposal, published = _published_store(tmp_path, "materialize-durable")
    assert published.proposal is not None and published.group is not None
    source_revision = published.group.revision
    first = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=source_revision,
    )
    assert first.status == "materialized"
    current_revision = _record_later_evidence(store, proposal.pattern, 10)
    exact = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=source_revision,
    )
    assert exact.status == "duplicate"
    changed = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=current_revision,
    )
    assert changed.status == "refused"
    store.close()


@pytest.mark.parametrize(
    "transition", ("admit", "reject_proposed", "reject_materialized")
)
def test_terminal_exact_original_retry_survives_later_evidence(
    tmp_path: Path, transition: str
) -> None:
    store, proposal, published = _published_store(tmp_path, f"terminal-{transition}")
    assert published.proposal is not None and published.group is not None
    source_state = ProposalState.PROPOSED
    source_revision = published.group.revision
    if transition in {"admit", "reject_materialized"}:
        materialized = store.mark_materialized(
            published.proposal.proposal_id,
            "/x",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=source_revision,
        )
        assert materialized.status == "materialized" and materialized.group is not None
        source_state = ProposalState.MATERIALIZED
        source_revision = materialized.group.revision
    if transition == "admit":
        first = store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=source_state,
            expected_revision=source_revision,
        )
    else:
        first = store.mark_rejected(
            published.proposal.proposal_id,
            "reason",
            expected_state=source_state,
            expected_revision=source_revision,
        )
    assert first.status in {"admitted", "rejected"}
    current_revision = _record_later_evidence(store, proposal.pattern, 20)
    if transition == "admit":
        exact = store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        changed = store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=ProposalState.ADMITTED,
            expected_revision=current_revision,
        )
    else:
        exact = store.mark_rejected(
            published.proposal.proposal_id,
            "reason",
            expected_state=source_state,
            expected_revision=source_revision,
        )
        changed = store.mark_rejected(
            published.proposal.proposal_id,
            "reason",
            expected_state=ProposalState.REJECTED,
            expected_revision=current_revision,
        )
    assert exact.status == "duplicate"
    assert changed.status == "refused"
    store.close()


@pytest.mark.parametrize(
    ("column", "value"),
    (
        ("session_id", "different-session"),
        ("top_level_epoch", 99),
        ("evidence_generation", 99),
        ("maturity", "ir.lifted"),
        ("instruction_ea", 1),
        ("block_serial", 9),
        ("block_ea", 9),
        ("provider", "unknown"),
        ("plugin_name", "different"),
        ("plugin_version", "2.0"),
        ("status", "error"),
        ("input_cost_ops", 99),
        ("input_cost_nodes", 99),
        ("output_cost_ops", 99),
        ("output_cost_nodes", 99),
        ("proof_verdict", 0),
        ("elapsed_ms", 99.0),
        ("refusal_reason", "different"),
    ),
)
def test_status_rejects_every_corrupt_normalized_attempt_column(
    tmp_path: Path, column: str, value: object
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"attempt-{column}.sqlite3")
    base = _attempt()
    outcome = replace(
        base.outcome,
        output_cost=(2, 3),
        proof_verdict=True,
        refusal_reason="expected",
    )
    attempt = replace(base, outcome=outcome)
    assert store.record_attempt(attempt).status == "stored"
    store._connection.execute(f"UPDATE provider_attempts SET {column}=?", (value,))
    store._connection.commit()
    with pytest.raises(ValueError, match="provider attempt"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize(
    ("target", "column", "value"),
    (
        ("inputs", "identity_provenance", "idb_local"),
        ("inputs", "external_evidence_allowed", 1),
        ("databases", "database_identity", "different"),
        ("functions", "function_rva", 2),
        ("functions", "function_fingerprint", "different"),
    ),
)
def test_status_rejects_corrupt_attempt_identity_authority(
    tmp_path: Path, target: str, column: str, value: object
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"identity-{target}-{column}.sqlite3")
    store.record_attempt(_attempt())
    store._connection.execute(f"UPDATE {target} SET {column}=?", (value,))
    store._connection.commit()
    with pytest.raises(ValueError, match="provider attempt"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize(
    ("target_state", "trigger_table", "trigger_value"),
    (
        ("publish_run", "mining_runs", "proposed"),
        ("publish", "residual_groups", "proposed"),
        ("materialize", "residual_groups", "materialized"),
        ("admit", "residual_groups", "admitted"),
        ("reject", "residual_groups", "rejected"),
    ),
)
def test_lifecycle_second_cas_failure_rolls_back_first_mutation(
    tmp_path: Path, target_state: str, trigger_table: str, trigger_value: str
) -> None:
    store, proposal, published = _published_store(tmp_path, f"cas-{target_state}")
    assert published.proposal is not None and published.group is not None
    if target_state.startswith("publish"):
        store.close()
        store = MbaDiscoveryStore(tmp_path / "cas-publish-fresh.sqlite3")
        store.record_attempt(_attempt(raw=proposal.pattern, canonical=proposal.pattern))
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        proposal_id = None
    else:
        claim = None
        proposal_id = published.proposal.proposal_id
    if target_state in {"admit", "reject"}:
        materialized = store.mark_materialized(
            proposal_id,
            "/x",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert materialized.status == "materialized" and materialized.group is not None
    store._connection.execute(
        f"""
        CREATE TRIGGER ignore_second_{target_state}
        BEFORE UPDATE OF state ON {trigger_table}
        WHEN NEW.state = '{trigger_value}'
        BEGIN SELECT RAISE(IGNORE); END
        """
    )
    store._connection.commit()
    if target_state.startswith("publish"):
        receipt = store.publish_proposal(
            claim.claim.run.run_id,
            claim.claim.run.claimed_revision,
            proposal,
            proposal.replacement,
            proposal,
        )
        assert receipt.status == "refused"
        assert store.count_rows("proposals") == 0
        assert (
            store._connection.execute("SELECT state FROM mining_runs").fetchone()[0]
            == "active"
        )
    elif target_state == "materialize":
        receipt = store.mark_materialized(
            proposal_id,
            "/x",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert receipt.status == "refused"
        assert (
            store._connection.execute("SELECT state FROM proposals").fetchone()[0]
            == "proposed"
        )
    elif target_state == "admit":
        receipt = store.mark_admitted(
            proposal_id,
            "rule",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
        assert receipt.status == "refused"
        assert (
            store._connection.execute("SELECT state FROM proposals").fetchone()[0]
            == "materialized"
        )
    else:
        receipt = store.mark_rejected(
            proposal_id,
            "reason",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
        assert receipt.status == "refused"
        assert (
            store._connection.execute("SELECT state FROM proposals").fetchone()[0]
            == "materialized"
        )
    store.close()


@pytest.mark.parametrize("collision", ("input", "function", "canonical", "raw"))
def test_identity_and_fingerprint_collisions_roll_back_every_partial_row(
    tmp_path: Path, collision: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"rollback-{collision}.sqlite3")
    first = _attempt()
    assert store.record_attempt(first).status == "stored"
    before = {
        table: store.count_rows(table)
        for table in (
            "inputs",
            "databases",
            "functions",
            "terms",
            "raw_terms",
            "provider_attempts",
            "residual_groups",
        )
    }
    if collision == "input":
        identity = replace(_identity(), input_identity_provenance="idb_local")
        context = replace(first.context, function_identity=identity)
        conflicting = replace(first, attempt_uuid=str(uuid4()), context=context)
    elif collision == "function":
        identity = replace(_identity(), function_rva=0x2000)
        context = replace(first.context, function_identity=identity)
        conflicting = replace(first, attempt_uuid=str(uuid4()), context=context)
    else:
        conflicting = replace(first, attempt_uuid=str(uuid4()))
        if collision == "canonical":
            store._connection.execute("UPDATE terms SET canonical_term=?", (b"{}",))
        else:
            store._connection.execute("UPDATE raw_terms SET raw_term=?", (b"{}",))
        store._connection.commit()
    refused = store.record_attempt(conflicting)
    assert refused.status == "refused"
    assert {table: store.count_rows(table) for table in before} == before
    store.close()


def test_heartbeat_refuses_unknown_terminal_and_wrong_revision_without_mutation(
    tmp_path: Path,
) -> None:
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    store = MbaDiscoveryStore(
        tmp_path / "heartbeat-matrix.sqlite3", clock=lambda: now[0]
    )
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    run = claim.claim.run
    original = run.heartbeat_at
    assert store.heartbeat(str(uuid4()), run.claimed_revision).status == "refused"
    assert store.heartbeat(run.run_id, run.claimed_revision + 1).status == "refused"
    assert (
        store._connection.execute("SELECT heartbeat_at FROM mining_runs").fetchone()[0]
        == original
    )
    finished = store.finish_no_proposal(run.run_id, run.claimed_revision)
    assert finished.status == "finished"
    assert store.heartbeat(run.run_id, run.claimed_revision).status == "refused"
    assert (
        store._connection.execute("SELECT heartbeat_at FROM mining_runs").fetchone()[0]
        == original
    )
    store.close()


def test_proposal_id_collision_rolls_back_run_group_and_insert(tmp_path: Path) -> None:
    values = iter(
        (
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
            "00000000-0000-4000-8000-000000000003",
            "00000000-0000-4000-8000-000000000002",
        )
    )
    store = MbaDiscoveryStore(
        tmp_path / "proposal-id-collision.sqlite3", uuid_factory=lambda: next(values)
    )
    first_pattern = TypedBvTerm(
        "add", 32, children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2
    )
    second_pattern = TypedBvTerm(
        "xor", 32, children=(TypedBvTerm(None, 32, leaf_key=("register", "x")),) * 2
    )
    store.record_attempt(_attempt(raw=first_pattern, canonical=first_pattern))
    store.record_attempt(_attempt(raw=second_pattern, canonical=second_pattern))
    first_claim = store.claim_next_group("miner", "budget")
    assert first_claim.claim is not None
    first_proposal = _proposal(first_pattern)
    assert (
        store.publish_proposal(
            first_claim.claim.run.run_id,
            first_claim.claim.run.claimed_revision,
            first_proposal,
            first_proposal.replacement,
            first_proposal,
        ).status
        == "published"
    )
    second_claim = store.claim_next_group("miner", "budget")
    assert second_claim.claim is not None
    second_proposal = _proposal(second_pattern)
    receipt = store.publish_proposal(
        second_claim.claim.run.run_id,
        second_claim.claim.run.claimed_revision,
        second_proposal,
        second_proposal.replacement,
        second_proposal,
    )
    assert receipt.status == "refused"
    assert store.count_rows("proposals") == 1
    assert (
        store._connection.execute(
            "SELECT state FROM mining_runs WHERE run_id=?",
            (second_claim.claim.run.run_id,),
        ).fetchone()[0]
        == "active"
    )
    assert (
        store._connection.execute(
            "SELECT state FROM residual_groups WHERE group_id=?",
            (second_claim.claim.group.group_id,),
        ).fetchone()[0]
        == "mining"
    )
    store.close()


def test_proposal_run_group_cross_link_is_corruption_on_status_and_duplicate(
    tmp_path: Path,
) -> None:
    store, proposal, published = _published_store(tmp_path, "proposal-cross-link")
    assert published.proposal is not None
    store.record_attempt(_attempt(value=9))
    other = store.claim_next_group("miner", "budget")
    assert other.claim is not None
    store._connection.execute(
        "UPDATE proposals SET run_id=? WHERE proposal_id=?",
        (other.claim.run.run_id, published.proposal.proposal_id),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="ownership"):
        store.status_counts()
    with pytest.raises(ValueError, match="ownership"):
        store.publish_proposal(
            published.run.run_id,
            published.run.claimed_revision,
            proposal,
            proposal.replacement,
            proposal,
        )
    store.close()


def test_normalized_attempt_corruption_blocks_claim_and_exact_duplicate(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "attempt-shared-read.sqlite3")
    attempt = _attempt()
    store.record_attempt(attempt)
    store._connection.execute("UPDATE provider_attempts SET elapsed_ms=99")
    store._connection.commit()
    assert store.claim_next_group("miner", "budget").status == "refused"
    duplicate = store.record_attempt(attempt)
    assert duplicate.status == "refused"
    assert duplicate.reason == "provider attempt normalized authority is corrupt"
    store.close()


def test_same_store_read_write_close_race_has_only_deterministic_close_errors(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "same-store-close.sqlite3")
    barrier = threading.Barrier(4)
    errors: list[BaseException] = []

    def exercise(kind: str) -> None:
        try:
            barrier.wait()
            for index in range(50):
                try:
                    if kind == "write":
                        store.record_attempt(
                            _attempt(
                                attempt_uuid=f"cccccccc-cccc-4ccc-8ccc-{index:012d}"
                            )
                        )
                    else:
                        store.status_counts()
                except RuntimeError as exc:
                    assert str(exc) == "discovery store is closed"
                    return
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=exercise, args=(kind,))
        for kind in ("write", "read", "read")
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    store.close()
    for thread in threads:
        thread.join()
    assert errors == []
    store.close()


def _established_proof_payload(proposal: MbaRuleProposal) -> bytes:
    return json.dumps(
        [
            {
                "width": proof.width,
                "verdict": proof.verdict,
                "elapsed_ms": proof.elapsed_ms,
                "counterexample": None,
                "error": None,
            }
            for proof in proposal.proof_receipts
        ],
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@pytest.mark.parametrize(
    "transition",
    ("materialized", "admitted", "rejected_proposed", "rejected_materialized"),
)
def test_proof_payload_is_immutable_and_retry_columns_survive_reopen(
    tmp_path: Path, transition: str
) -> None:
    path = tmp_path / f"proof-immutable-{transition}.sqlite3"
    store, proposal, published = _published_store(
        tmp_path, f"proof-immutable-{transition}"
    )
    assert published.proposal is not None and published.group is not None
    proposal_id = published.proposal.proposal_id
    original = _established_proof_payload(proposal)
    assert published.proposal.proof_receipt_payload == original
    source_revision = published.group.revision
    materialized_revision = None
    if transition in {"materialized", "admitted", "rejected_materialized"}:
        materialized = store.mark_materialized(
            proposal_id,
            "/review/rule.py",
            "sha256:digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=source_revision,
        )
        assert materialized.proposal is not None and materialized.group is not None
        assert materialized.proposal.proof_receipt_payload == original
        assert materialized.proposal.materialized_source_revision == source_revision
        materialized_revision = materialized.group.revision
    if transition == "admitted":
        terminal = store.mark_admitted(
            proposal_id,
            "rule-id",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized_revision,
        )
    elif transition.startswith("rejected"):
        source_state = (
            ProposalState.MATERIALIZED
            if transition == "rejected_materialized"
            else ProposalState.PROPOSED
        )
        terminal = store.mark_rejected(
            proposal_id,
            "unsafe",
            expected_state=source_state,
            expected_revision=materialized_revision or source_revision,
        )
    else:
        terminal = None
    if terminal is not None:
        assert terminal.proposal is not None
        assert terminal.proposal.proof_receipt_payload == original
        expected_terminal_source = (
            source_state
            if transition.startswith("rejected")
            else ProposalState.MATERIALIZED
        )
        assert terminal.proposal.terminal_source_state is expected_terminal_source
        assert terminal.proposal.terminal_source_revision == (
            materialized_revision or source_revision
        )
    stored = store._connection.execute(
        "SELECT proof_receipt_payload FROM proposals WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()[0]
    assert bytes(stored) == original
    store.close()
    reopened = MbaDiscoveryStore(path)
    row = reopened._connection.execute(
        "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
    ).fetchone()
    projected = reopened._project_proposal(reopened._connection, row)
    assert projected.proof_receipt_payload == original
    reopened.close()


@pytest.mark.parametrize(
    "corruption", ("orphan_proposed", "orphan_no_proposal", "duplicate_proposed")
)
def test_bidirectional_terminal_run_history_rejects_orphans_and_duplicates(
    tmp_path: Path, corruption: str
) -> None:
    if corruption == "duplicate_proposed":
        store, _proposal_input, published = _published_store(
            tmp_path, "history-duplicate-proposed"
        )
        assert published.group is not None and published.run is not None
        next_revision = published.group.revision + 1
        store._connection.execute(
            "UPDATE residual_groups SET revision=? WHERE group_id=?",
            (next_revision, published.group.group_id),
        )
        store._connection.execute(
            "INSERT INTO mining_runs(run_id,group_id,claimed_revision,miner_version,budget_fingerprint,state,started_at,heartbeat_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                published.group.group_id,
                next_revision,
                "miner",
                "budget",
                "proposed",
                published.run.finished_at,
                published.run.finished_at,
                published.run.finished_at,
            ),
        )
    else:
        store = MbaDiscoveryStore(tmp_path / f"history-{corruption}.sqlite3")
        store.record_attempt(_attempt())
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        finished = store.finish_no_proposal(
            claim.claim.run.run_id, claim.claim.run.claimed_revision
        )
        assert finished.status == "finished"
        if corruption == "orphan_proposed":
            store._connection.execute(
                "UPDATE mining_runs SET state='proposed', failure_reason=NULL"
            )
        else:
            store._connection.execute(
                "UPDATE mining_runs SET state='expired', failure_reason='lease_expired'"
            )
    store._connection.commit()
    with pytest.raises(ValueError, match="proposal|no-proposal"):
        store.status_counts()
    store.close()


def test_corrupt_terminal_run_rewrite_cannot_propagate_through_public_writes(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "history-propagation.sqlite3")
    pattern = _term()
    store.record_attempt(_attempt(raw=pattern, canonical=pattern))
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    store.finish_no_proposal(claim.claim.run.run_id, claim.claim.run.claimed_revision)
    store._connection.execute(
        "UPDATE mining_runs SET state='proposed', failure_reason=NULL"
    )
    store._connection.commit()
    assert (
        store.record_attempt(_attempt(raw=pattern, canonical=pattern)).status
        == "refused"
    )
    assert store.count_rows("provider_attempts") == 1
    assert store.claim_next_group("miner", "budget").status == "refused"
    assert store.count_rows("mining_runs") == 1
    store.close()


@pytest.mark.parametrize("value", ("", " ", " bad "))
@pytest.mark.parametrize(
    ("run_state", "group_state"),
    (
        ("no_proposal", "no_proposal"),
        ("expired", "eligible"),
        ("failed", "eligible"),
        ("superseded", "eligible"),
    ),
)
def test_every_terminal_run_reason_must_be_canonical_non_empty_text(
    tmp_path: Path, run_state: str, group_state: str, value: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"run-text-{run_state}-{value!r}.sqlite3")
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    store.finish_no_proposal(claim.claim.run.run_id, claim.claim.run.claimed_revision)
    store._connection.execute(
        "UPDATE mining_runs SET state=?, failure_reason=?", (run_state, value)
    )
    store._connection.execute(
        "UPDATE residual_groups SET state=?, last_mined_at=?",
        (
            group_state,
            None if group_state == "eligible" else claim.claim.run.started_at,
        ),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="failure_reason"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize("value", ("", " ", " bad "))
def test_proposed_terminal_run_forbids_every_failure_reason_value(
    tmp_path: Path, value: str
) -> None:
    store, _proposal_input, _published = _published_store(
        tmp_path, f"proposed-run-reason-{value!r}"
    )
    store._connection.execute(
        "UPDATE mining_runs SET failure_reason=? WHERE state='proposed'", (value,)
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="failure_reason"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize("column", ("miner_version", "budget_fingerprint"))
@pytest.mark.parametrize("value", ("", " ", " bad "))
def test_mining_identity_text_is_canonical_before_reads_or_claims(
    tmp_path: Path, column: str, value: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"run-{column}-{value!r}.sqlite3")
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget")
    assert claim.claim is not None
    store._connection.execute(f"UPDATE mining_runs SET {column}=?", (value,))
    store._connection.commit()
    with pytest.raises(ValueError, match=column):
        store.status_counts()
    assert store.claim_next_group("miner", "budget").status == "refused"
    store.close()


@pytest.mark.parametrize("value", ("", " ", " bad "))
@pytest.mark.parametrize(
    ("state", "column"),
    (
        ("materialized", "materialized_path"),
        ("materialized", "materialized_digest"),
        ("admitted", "materialized_path"),
        ("admitted", "materialized_digest"),
        ("admitted", "admitted_rule_id"),
        ("rejected_proposed", "rejection_reason"),
        ("rejected_materialized", "materialized_path"),
        ("rejected_materialized", "materialized_digest"),
        ("rejected_materialized", "rejection_reason"),
    ),
)
def test_every_required_proposal_lifecycle_text_is_canonical(
    tmp_path: Path, state: str, column: str, value: str
) -> None:
    store, _proposal_input, published = _published_store(
        tmp_path, f"proposal-text-{state}-{column}-{value!r}"
    )
    assert published.proposal is not None and published.group is not None
    proposal_id = published.proposal.proposal_id
    if state in {"materialized", "admitted", "rejected_materialized"}:
        materialized = store.mark_materialized(
            proposal_id,
            "/x",
            "digest",
            expected_state=ProposalState.PROPOSED,
            expected_revision=published.group.revision,
        )
        assert materialized.group is not None
    if state == "admitted":
        store.mark_admitted(
            proposal_id,
            "rule",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
    elif state.startswith("rejected"):
        source = (
            ProposalState.MATERIALIZED
            if state == "rejected_materialized"
            else ProposalState.PROPOSED
        )
        revision = (
            materialized.group.revision
            if source is ProposalState.MATERIALIZED
            else published.group.revision
        )
        store.mark_rejected(
            proposal_id,
            "reason",
            expected_state=source,
            expected_revision=revision,
        )
    store._connection.execute(f"UPDATE proposals SET {column}=?", (value,))
    store._connection.commit()
    with pytest.raises(ValueError, match=column):
        store.status_counts()
    store.close()


def test_admission_refuses_corrupt_empty_materialized_path_without_mutation(
    tmp_path: Path,
) -> None:
    store, _proposal_input, published = _published_store(tmp_path, "empty-path-admit")
    assert published.proposal is not None and published.group is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.group is not None
    store._connection.execute("UPDATE proposals SET materialized_path=''")
    store._connection.commit()
    with pytest.raises(ValueError, match="materialized_path"):
        store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
    assert (
        store._connection.execute("SELECT state FROM proposals").fetchone()[0]
        == "materialized"
    )
    assert (
        store._connection.execute("SELECT state FROM residual_groups").fetchone()[0]
        == "materialized"
    )
    store.close()


@pytest.mark.parametrize(
    ("column", "value"),
    (
        ("materialized_source_revision", 0),
        ("materialized_source_revision", 999),
        ("terminal_source_state", "proposed"),
        ("terminal_source_state", "admitted"),
        ("terminal_source_revision", 0),
        ("terminal_source_revision", 999),
    ),
)
def test_retry_source_column_corruption_fails_before_duplicate_recognition(
    tmp_path: Path, column: str, value: object
) -> None:
    store, _proposal_input, published = _published_store(
        tmp_path, f"retry-column-{column}-{value}"
    )
    assert published.proposal is not None and published.group is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.group is not None
    admitted = store.mark_admitted(
        published.proposal.proposal_id,
        "rule",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=materialized.group.revision,
    )
    assert admitted.status == "admitted"
    store._connection.execute(f"UPDATE proposals SET {column}=?", (value,))
    store._connection.commit()
    with pytest.raises(ValueError, match="retry|source|revision"):
        store.mark_admitted(
            published.proposal.proposal_id,
            "rule",
            expected_state=ProposalState.MATERIALIZED,
            expected_revision=materialized.group.revision,
        )
    store.close()


def test_equal_and_later_terminal_revisions_are_causal_after_materialization(
    tmp_path: Path,
) -> None:
    store, proposal, published = _published_store(tmp_path, "retry-chronology-valid")
    assert published.proposal is not None and published.group is not None
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert materialized.group is not None
    equal = store.mark_admitted(
        published.proposal.proposal_id,
        "rule",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=materialized.group.revision,
    )
    assert equal.status == "admitted"
    store.close()

    store, proposal, published = _published_store(tmp_path, "retry-chronology-later")
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    later_revision = _record_later_evidence(store, proposal.pattern, 90)
    later = store.mark_rejected(
        published.proposal.proposal_id,
        "reason",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=later_revision,
    )
    assert later.status == "rejected"
    assert later.proposal.terminal_source_revision == later_revision
    store.close()


@pytest.mark.parametrize(
    "timestamp",
    (
        "garbage",
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.000000-08:00",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.123Z",
    ),
)
def test_reopen_rejects_noncanonical_migration_timestamp(
    tmp_path: Path, timestamp: str
) -> None:
    path = (
        tmp_path / f"migration-{hashlib.sha256(timestamp.encode()).hexdigest()}.sqlite3"
    )
    store = MbaDiscoveryStore(path)
    store.close()
    connection = sqlite3.connect(path)
    connection.execute("UPDATE schema_migrations SET applied_at=?", (timestamp,))
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="applied_at"):
        MbaDiscoveryStore(path)


@pytest.mark.parametrize(
    "corruption",
    ("observed_has_run", "claimed_before_evidence", "duplicate_revision", "overlap"),
)
def test_group_run_history_rejects_impossible_sequences_and_revisions(
    tmp_path: Path, corruption: str
) -> None:
    store = MbaDiscoveryStore(tmp_path / f"history-sequence-{corruption}.sqlite3")
    if corruption == "observed_has_run":
        stored = store.record_attempt(_attempt(eligible=False))
        assert stored.group_id is not None
        now = "2026-01-01T00:00:00.000000Z"
        store._connection.execute(
            "UPDATE residual_groups SET revision=2 WHERE group_id=?", (stored.group_id,)
        )
        store._connection.execute(
            "INSERT INTO mining_runs(run_id,group_id,claimed_revision,miner_version,budget_fingerprint,state,started_at,heartbeat_at,finished_at,failure_reason) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                stored.group_id,
                2,
                "miner",
                "budget",
                "expired",
                now,
                now,
                now,
                "lease_expired",
            ),
        )
    else:
        store.record_attempt(_attempt())
        first = store.claim_next_group("miner", "budget")
        assert first.claim is not None
        store.finish_no_proposal(
            first.claim.run.run_id, first.claim.run.claimed_revision
        )
        store.record_attempt(_attempt())
        second = store.claim_next_group("miner", "budget")
        assert second.claim is not None
        if corruption == "claimed_before_evidence":
            store._connection.execute(
                "UPDATE mining_runs SET claimed_revision=1 WHERE run_id=?",
                (first.claim.run.run_id,),
            )
        elif corruption == "duplicate_revision":
            store._connection.execute(
                "UPDATE mining_runs SET claimed_revision=? WHERE run_id=?",
                (first.claim.run.claimed_revision, second.claim.run.run_id),
            )
        else:
            store._connection.execute(
                "UPDATE mining_runs SET finished_at='9999-01-01T00:00:00.000000Z' WHERE run_id=?",
                (first.claim.run.run_id,),
            )
    store._connection.commit()
    with pytest.raises(ValueError, match="observed|revision|history|order"):
        store.status_counts()
    store.close()


def test_terminal_revision_cannot_precede_materialization_revision(
    tmp_path: Path,
) -> None:
    store, proposal, published = _published_store(tmp_path, "retry-inversion")
    assert published.proposal is not None and published.group is not None
    materialization_revision = _record_later_evidence(store, proposal.pattern, 100)
    materialized = store.mark_materialized(
        published.proposal.proposal_id,
        "/x",
        "digest",
        expected_state=ProposalState.PROPOSED,
        expected_revision=materialization_revision,
    )
    assert materialized.status == "materialized"
    terminal_revision = _record_later_evidence(store, proposal.pattern, 110)
    rejected = store.mark_rejected(
        published.proposal.proposal_id,
        "reason",
        expected_state=ProposalState.MATERIALIZED,
        expected_revision=terminal_revision,
    )
    assert rejected.status == "rejected"
    store._connection.execute(
        "UPDATE proposals SET terminal_source_revision=?",
        (published.run.claimed_revision,),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="chronology"):
        store.status_counts()
    store.close()


def test_rejected_from_proposed_forbids_materialization_receipt(
    tmp_path: Path,
) -> None:
    store, _proposal_input, published = _published_store(
        tmp_path, "reject-proposed-receipt"
    )
    assert published.proposal is not None and published.group is not None
    rejected = store.mark_rejected(
        published.proposal.proposal_id,
        "reason",
        expected_state=ProposalState.PROPOSED,
        expected_revision=published.group.revision,
    )
    assert rejected.proposal is not None
    assert rejected.proposal.materialized_source_revision is None
    store._connection.execute(
        "UPDATE proposals SET materialized_source_revision=?",
        (published.group.revision,),
    )
    store._connection.commit()
    with pytest.raises(ValueError, match="materialization"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize("identifier", ("run_id", "proposal_id"))
@pytest.mark.parametrize("value", ("", " ", "not-a-uuid"))
def test_persisted_lifecycle_identifiers_are_canonical(
    tmp_path: Path, identifier: str, value: str
) -> None:
    if identifier == "run_id":
        store = MbaDiscoveryStore(tmp_path / f"stored-{identifier}-{value!r}.sqlite3")
        store.record_attempt(_attempt())
        claim = store.claim_next_group("miner", "budget")
        assert claim.claim is not None
        store.finish_no_proposal(
            claim.claim.run.run_id, claim.claim.run.claimed_revision
        )
        store._connection.execute("PRAGMA foreign_keys=OFF")
        store._connection.execute("UPDATE mining_runs SET run_id=?", (value,))
    else:
        store, _proposal_input, _published = _published_store(
            tmp_path, f"stored-{identifier}-{value!r}"
        )
        store._connection.execute("PRAGMA foreign_keys=OFF")
        store._connection.execute("UPDATE proposals SET proposal_id=?", (value,))
    store._connection.commit()
    with pytest.raises((TypeError, ValueError), match=f"{identifier}|causal domain"):
        store.status_counts()
    store.close()


@pytest.mark.parametrize("operation", ("heartbeat", "finish", "materialize", "reject"))
def test_public_lifecycle_identifiers_require_canonical_uuid_spelling(
    tmp_path: Path, operation: str
) -> None:
    store, _proposal_input, published = _published_store(
        tmp_path, f"public-id-{operation}"
    )
    assert published.proposal is not None and published.group is not None
    with pytest.raises(ValueError, match="canonical"):
        if operation == "heartbeat":
            store.heartbeat(
                "{" + published.run.run_id + "}", published.run.claimed_revision
            )
        elif operation == "finish":
            store.finish_no_proposal(
                "{" + published.run.run_id + "}", published.run.claimed_revision
            )
        elif operation == "materialize":
            store.mark_materialized(
                "{" + published.proposal.proposal_id + "}",
                "/x",
                "digest",
                expected_state=ProposalState.PROPOSED,
                expected_revision=published.group.revision,
            )
        else:
            store.mark_rejected(
                "{" + published.proposal.proposal_id + "}",
                "reason",
                expected_state=ProposalState.PROPOSED,
                expected_revision=published.group.revision,
            )
    store.close()
