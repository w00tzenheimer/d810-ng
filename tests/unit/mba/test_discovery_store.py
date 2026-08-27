from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

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
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_fingerprint


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
    }
    assert store.schema_version() == 1
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
    claim = store.claim_next_group("miner", "budget", 60)
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
    claim = store.claim_next_group("miner", "budget", 60)
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
    claim = store.claim_next_group("miner", "budget", timedelta(seconds=10))
    assert claim.status == "claimed"
    assert claim.claim is not None
    assert claim.claim.group.state is ResidualGroupState.MINING
    assert claim.claim.run.state is MiningRunState.CLAIMED
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
    now[0] += timedelta(seconds=11)
    reclaimed = store.claim_next_group("miner", "budget", timedelta(seconds=10))
    assert reclaimed.status == "claimed"
    assert reclaimed.claim is not None
    assert reclaimed.claim.run.run_id != claim.claim.run.run_id
    store.close()


def test_proposal_lifecycle_and_invalid_order_are_typed_refusals(
    tmp_path: Path,
) -> None:
    store = MbaDiscoveryStore(tmp_path / "db.sqlite3")
    store.record_attempt(_attempt())
    claim = store.claim_next_group("miner", "budget", timedelta(seconds=10))
    assert claim.claim is not None
    run = claim.claim.run
    replacement = _term(3)
    published = store.publish_proposal(
        run.run_id,
        run.claimed_revision,
        "proposal-1",
        replacement,
        {"z": 1, "a": [True]},
        {"verdict": True},
    )
    assert published.status == "published"
    assert published.proposal is not None
    proposal = published.proposal
    assert proposal.state is ProposalState.PROPOSED
    assert (
        store.mark_admitted(proposal.proposal_id, "rule-1").reason
        == "invalid_transition"
    )
    materialized = store.mark_materialized(
        proposal.proposal_id, "/review/rule.py", "sha256:abc"
    )
    assert materialized.status == "materialized"
    admitted = store.mark_admitted(proposal.proposal_id, "rule-1")
    assert admitted.status == "admitted"
    assert (
        store.mark_rejected(proposal.proposal_id, "too-late").reason
        == "invalid_transition"
    )
    store.close()


def test_two_stores_only_one_claim_wins(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite3"
    first = MbaDiscoveryStore(path)
    second = MbaDiscoveryStore(path)
    first.record_attempt(_attempt())
    results: list[object] = []

    def claim(store: MbaDiscoveryStore) -> None:
        results.append(store.claim_next_group("miner", "budget", 60))

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
