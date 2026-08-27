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
    tmp_path: Path, name: str = "lifecycle"
) -> tuple[MbaDiscoveryStore, MbaRuleProposal, object]:
    store = MbaDiscoveryStore(tmp_path / f"{name}.sqlite3")
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
