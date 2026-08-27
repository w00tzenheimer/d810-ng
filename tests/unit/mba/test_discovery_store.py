from __future__ import annotations

import json
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
from d810.mba.bounded_synthesis import ProofReceipt
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.rule_proposal import MbaRuleProposal
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
