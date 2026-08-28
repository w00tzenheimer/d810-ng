"""Database-oriented MBA discovery miner contracts."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from d810.core.function_execution_identity import FunctionExecutionIdentity, MbaObservationContext
from d810.core.plugins import PluginIdentity
from d810.mba.bounded_synthesis import (
    CERTIFICATION_WIDTHS,
    MbaExhaustionReceipt,
    MbaCertification,
    MbaSynthesisResult,
    MbaSynthesisBudget,
    ProofReceipt,
)
from d810.mba.discovery_models import (
    DiscoveryAttempt,
    HeartbeatReceipt,
    LifecycleReceipt,
    ReceiptStatus,
)
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.subterm_atomization import atomize_repeated_subterms
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_cost, term_fingerprint


def _attempt(term: TypedBvTerm) -> DiscoveryAttempt:
    identity = FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="test",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="function",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=1,
    )
    canonical = canonicalize_ac_term(term)
    return DiscoveryAttempt(
        attempt_uuid=str(uuid4()),
        context=MbaObservationContext(
            function_identity=identity,
            plugin_identity=PluginIdentity("egglog", "egglog", "1", "test"),
            instruction_ea=0x401010,
            block_serial=1,
            block_ea=0x401000,
        ),
        raw_term=term,
        canonical_term=canonical,
        outcome=MbaProviderOutcome(
            provider=MbaProviderKind.EGRAPH,
            status=ProviderOutcomeStatus.UNCHANGED,
            fingerprint=term_fingerprint(canonical),
            elapsed_ms=1.0,
        ),
        eligible_for_mining=True,
    )

def test_discovery_miner_exposes_sqlite_claim_api() -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    assert callable(DiscoveryMiner.mine_claim)


def test_miner_finishes_a_bounded_no_proposal_in_sqlite(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "discovery.sqlite3")
    store.record_attempt(_attempt(term))
    miner = DiscoveryMiner(store, budget=MbaSynthesisBudget(max_atoms=0))
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "no_proposal"
    assert outcome.reason == "not_cheaper"
    assert store.status_counts().group_counts[3][1] == 1
    store.close()


def test_certified_claim_publishes_and_exposes_immutable_snapshot(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source=source,
        replacement=x,
        source_cost=term_cost(source),
        replacement_cost=term_cost(x),
        certification=MbaCertification(proofs),
        exhaustion=None,
    )
    store = MbaDiscoveryStore(tmp_path / "discovery.sqlite3")
    store.record_attempt(_attempt(source))
    budget = MbaSynthesisBudget()
    miner = DiscoveryMiner(
        store,
        budget=budget,
        synthesizer=lambda atomized, budget: result,
    )
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "published"
    assert outcome.proposal is not None
    proposal_id = outcome.proposal_id
    assert proposal_id is not None
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    assert snapshot.proposal.proposal_payload
    assert snapshot.group.revision == claim.run.claimed_revision
    assert snapshot.proposal.proposal_payload is not None
    store.close()


def test_exact_publication_retry_is_duplicate_without_new_proposal(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source,
        x,
        term_cost(source),
        term_cost(x),
        MbaCertification(proofs),
        None,
    )
    store = MbaDiscoveryStore(tmp_path / "publication-retry.sqlite3")
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "published"
    assert outcome.proposal is not None
    retry = store.publish_proposal(
        claim.run.run_id,
        claim.run.claimed_revision,
        outcome.proposal.fingerprint,
        outcome.proposal.replacement,
        outcome.proposal,
    )
    assert retry.status is ReceiptStatus.DUPLICATE
    assert retry.proposal is not None
    assert retry.proposal.proposal_id == outcome.proposal_id
    store.close()


def test_synthesis_exception_leaves_claim_active(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "synthesis-error.sqlite3")
    store.record_attempt(_attempt(term))

    def fail_synthesis(*_args, **_kwargs):
        raise RuntimeError("bounded synthesis infrastructure failed")

    miner = DiscoveryMiner(store, synthesizer=fail_synthesis)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "error"
    assert "bounded synthesis infrastructure failed" in (outcome.reason or "")
    assert store.status_counts().run_counts[0][1] == 1
    assert store.status_counts().group_counts[2][1] == 1
    store.close()


@pytest.mark.parametrize(
    "reason",
    ["generation_budget", "proof_failed", "not_cheaper", "no_signature_match", "too_many_variables"],
)
def test_bounded_exhaustion_finishes_stably(tmp_path, reason) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / f"{reason}.sqlite3")
    store.record_attempt(_attempt(term))
    budget = MbaSynthesisBudget()
    result = MbaSynthesisResult(
        term,
        None,
        term_cost(term),
        None,
        MbaCertification(()),
        MbaExhaustionReceipt(reason, 0, budget),
    )
    miner = DiscoveryMiner(store, budget=budget, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "no_proposal"
    assert outcome.reason == reason
    assert store.status_counts().run_counts[1][1] == 1
    store.close()


def test_process_interruption_leaves_claim_active(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "interrupted.sqlite3")
    store.record_attempt(_attempt(term))

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt()

    miner = DiscoveryMiner(store, synthesizer=interrupt)
    claim = miner.claim().claim
    assert claim is not None
    with pytest.raises(KeyboardInterrupt):
        miner.mine_claim(claim)
    assert store.status_counts().run_counts[0][1] == 1
    store.close()


def test_final_publication_cas_refusal_leaves_claim_active(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source,
        x,
        term_cost(source),
        term_cost(x),
        MbaCertification(proofs),
        None,
    )
    store = MbaDiscoveryStore(tmp_path / "publication-race.sqlite3")
    store.record_attempt(_attempt(source))
    monkeypatch.setattr(
        store,
        "publish_proposal",
        lambda *_args, **_kwargs: LifecycleReceipt(
            ReceiptStatus.REFUSED, reason="publication_conflict"
        ),
    )
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "refused"
    assert outcome.reason == "publication_conflict"
    assert store.status_counts().run_counts[0][1] == 1
    assert store.status_counts().group_counts[2][1] == 1
    store.close()


def test_expired_claim_cannot_mutate_competing_owner_publication(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source, x, term_cost(source), term_cost(x), MbaCertification(proofs), None
    )
    store = MbaDiscoveryStore(
        tmp_path / "competing-publication.sqlite3", clock=lambda: now[0]
    )
    store.record_attempt(_attempt(source))
    stale_miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    stale_claim = stale_miner.claim().claim
    assert stale_claim is not None
    now[0] += timedelta(seconds=301)
    owner_miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    owner_claim = owner_miner.claim().claim
    assert owner_claim is not None
    assert owner_claim.run.run_id != stale_claim.run.run_id
    published = owner_miner.mine_claim(owner_claim)
    assert published.status == "published"
    assert published.proposal_id is not None
    before_events = store.count_rows("residual_group_events")
    before_proposals = store.count_rows("proposals")

    refused = stale_miner.mine_claim(stale_claim)

    assert refused.status == "refused"
    assert refused.reason == "stale_revision"
    assert store.count_rows("residual_group_events") == before_events
    assert store.count_rows("proposals") == before_proposals
    snapshot = store.proposal_snapshot(published.proposal_id)
    assert snapshot is not None
    assert snapshot.proposal.run_id == owner_claim.run.run_id
    store.close()


def test_repeated_raw_subterm_publishes_atomized_identity(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    a = TypedBvTerm(None, 32, leaf_key=("register", "a"))
    b = TypedBvTerm(None, 32, leaf_key=("register", "b"))
    repeated = TypedBvTerm("add", 32, children=(a, b))
    source = TypedBvTerm("or", 32, children=(repeated, repeated))
    atomized = atomize_repeated_subterms(source)
    atom = atomized.atomized_term.children[0]
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source=atomized.atomized_term,
        replacement=atom,
        source_cost=term_cost(atomized.atomized_term),
        replacement_cost=term_cost(atom),
        certification=MbaCertification(proofs),
        exhaustion=None,
    )
    store = MbaDiscoveryStore(tmp_path / "repeated.sqlite3")
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "published"
    assert outcome.proposal is not None
    assert outcome.proposal.atomization_bindings
    store.close()


def test_raw_noncanonical_ac_order_publishes_against_canonical_group(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    a = TypedBvTerm(None, 32, leaf_key=("register", "a"))
    b = TypedBvTerm(None, 32, leaf_key=("register", "b"))
    raw = TypedBvTerm("add", 32, children=(b, a))
    canonical = canonicalize_ac_term(raw)
    replacement = a
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source=raw,
        replacement=replacement,
        source_cost=term_cost(raw),
        replacement_cost=term_cost(replacement),
        certification=MbaCertification(proofs),
        exhaustion=None,
    )
    store = MbaDiscoveryStore(tmp_path / "raw-canonical.sqlite3")
    store.record_attempt(_attempt(raw))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    assert miner.mine_claim(claim).status == "published"
    assert canonical != raw
    store.close()


@pytest.mark.parametrize("field", ["source_fingerprints", "provenance", "fixture"])
def test_store_rejects_mined_proposal_identity_mismatch(tmp_path, field) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner, _proposal_for

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source,
        x,
        term_cost(source),
        term_cost(x),
        MbaCertification(proofs),
        None,
    )
    store = MbaDiscoveryStore(tmp_path / f"identity-{field}.sqlite3")
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    atomized = atomize_repeated_subterms(claim.group.raw_terms[0], max_atoms=4)
    proposal = _proposal_for(claim, atomized, result)
    if field == "source_fingerprints":
        proposal = replace(proposal, proposal_fingerprint=None, source_fingerprints=("wrong",))
    elif field == "provenance":
        proposal = replace(proposal, proposal_fingerprint=None, provenance=("wrong",))
    else:
        fixture = dict(proposal.fixture)
        fixture["source_fingerprint"] = "wrong"
        proposal = replace(proposal, proposal_fingerprint=None, fixture=fixture)
    receipt = store.publish_proposal(
        claim.run.run_id,
        claim.run.claimed_revision,
        proposal,
        proposal.replacement,
        proposal,
    )
    assert receipt.status is ReceiptStatus.REFUSED
    assert store.status_counts().run_counts[0][1] == 1
    store.close()


def test_provider_test_provenance_cannot_bypass_public_source_validation(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner, _proposal_for

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source, x, term_cost(source), term_cost(x), MbaCertification(proofs), None
    )
    store = MbaDiscoveryStore(tmp_path / "provider-test-forged.sqlite3")
    store.record_attempt(_attempt(source))
    claim = DiscoveryMiner(store).claim().claim
    assert claim is not None
    atomized = atomize_repeated_subterms(claim.group.raw_terms[0], max_atoms=4)
    forged = replace(
        _proposal_for(claim, atomized, result),
        proposal_fingerprint=None,
        source_fingerprints=("forged-source",),
        provenance=("provider:test",),
        fixture={"forged": True},
    )
    receipt = store.publish_proposal(
        claim.run.run_id,
        claim.run.claimed_revision,
        forged,
        forged.replacement,
        forged,
    )
    assert receipt.status is ReceiptStatus.REFUSED
    assert store.status_counts().run_counts[0][1] == 1
    store.close()


def test_heartbeat_exception_leaves_claim_active(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "heartbeat-error.sqlite3")
    store.record_attempt(_attempt(term))

    def fail_heartbeat(*_args, **_kwargs):
        raise RuntimeError("heartbeat infrastructure failed")

    monkeypatch.setattr(store, "heartbeat", fail_heartbeat)
    miner = DiscoveryMiner(
        store,
        heartbeat_interval=0.001,
        synthesizer=lambda atomized, budget: __import__("time").sleep(0.03)
        or MbaSynthesisResult(
            atomized.atomized_term,
            None,
            term_cost(atomized.atomized_term),
            None,
            MbaCertification(()),
            None,
        ),
    )
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "error"
    assert store.status_counts().run_counts[0][1] == 1
    store.close()


def test_heartbeat_refusal_leaves_claim_active(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "heartbeat-refused.sqlite3")
    store.record_attempt(_attempt(term))
    monkeypatch.setattr(
        store,
        "heartbeat",
        lambda *_args, **_kwargs: HeartbeatReceipt(ReceiptStatus.REFUSED, reason="lost"),
    )
    miner = DiscoveryMiner(
        store,
        heartbeat_interval=0.001,
        synthesizer=lambda atomized, budget: __import__("time").sleep(0.03)
        or MbaSynthesisResult(
            atomized.atomized_term,
            None,
            term_cost(atomized.atomized_term),
            None,
            MbaCertification(()),
            None,
        ),
    )
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "refused"
    assert store.status_counts().run_counts[0][1] == 1
    store.close()


def test_heartbeat_refreshes_during_bounded_synthesis(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "heartbeat-refresh.sqlite3")
    store.record_attempt(_attempt(term))
    calls = []
    original_heartbeat = store.heartbeat

    def heartbeat(*args, **kwargs):
        calls.append(args)
        return original_heartbeat(*args, **kwargs)

    monkeypatch.setattr(store, "heartbeat", heartbeat)

    def bounded_no_proposal(atomized, budget):
        __import__("time").sleep(0.03)
        return MbaSynthesisResult(
            atomized.atomized_term,
            None,
            term_cost(atomized.atomized_term),
            None,
            MbaCertification(()),
            None,
        )

    miner = DiscoveryMiner(store, heartbeat_interval=0.001, synthesizer=bounded_no_proposal)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.status == "no_proposal"
    assert calls
    store.close()


def test_delayed_heartbeat_is_joined_before_mine_returns(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "heartbeat-join.sqlite3")
    store.record_attempt(_attempt(term))
    entered = threading.Event()
    release = threading.Event()

    def delayed_heartbeat(*_args, **_kwargs):
        entered.set()
        release.wait(timeout=2.0)
        return HeartbeatReceipt(ReceiptStatus.HEARTBEATED)

    monkeypatch.setattr(store, "heartbeat", delayed_heartbeat)
    miner = DiscoveryMiner(
        store,
        heartbeat_interval=0.001,
        synthesizer=lambda atomized, budget: time.sleep(0.03)
        or MbaSynthesisResult(
            atomized.atomized_term,
            None,
            term_cost(atomized.atomized_term),
            None,
            MbaCertification(()),
            None,
        ),
    )
    claim = miner.claim().claim
    assert claim is not None
    result = []
    worker = threading.Thread(target=lambda: result.append(miner.mine_claim(claim)))
    worker.start()
    assert entered.wait(timeout=1.0)
    assert worker.is_alive()
    release.set()
    worker.join(timeout=2.0)
    assert not worker.is_alive()
    assert result and result[0].status == "no_proposal"
    store.close()


def test_heartbeat_lock_stall_refuses_within_deadline_and_joins_worker(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    store = MbaDiscoveryStore(tmp_path / "heartbeat-lock-stall.sqlite3")
    store.record_attempt(_attempt(term))
    miner = DiscoveryMiner(
        store,
        heartbeat_interval=0.001,
        synthesizer=lambda atomized, budget: time.sleep(0.03)
        or MbaSynthesisResult(
            atomized.atomized_term,
            None,
            term_cost(atomized.atomized_term),
            None,
            MbaCertification(()),
            None,
        ),
    )
    claim = miner.claim().claim
    assert claim is not None
    result = []
    store._lock.acquire()
    try:
        worker = threading.Thread(target=lambda: result.append(miner.mine_claim(claim)))
        worker.start()
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        assert result and result[0].status == "refused"
        assert result[0].reason == "storage_busy"
    finally:
        store._lock.release()
        store.close()


def test_external_sqlite_writer_bounds_heartbeat_and_store_close(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    term = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    database = tmp_path / "heartbeat-sqlite-contention.sqlite3"
    store = MbaDiscoveryStore(database)
    store.record_attempt(_attempt(term))
    miner = DiscoveryMiner(
        store,
        heartbeat_interval=0.001,
        synthesizer=lambda atomized, budget: time.sleep(0.03)
        or MbaSynthesisResult(
            atomized.atomized_term,
            None,
            term_cost(atomized.atomized_term),
            None,
            MbaCertification(()),
            None,
        ),
    )
    claim = miner.claim().claim
    assert claim is not None
    existing_threads = set(threading.enumerate())
    writer = sqlite3.connect(database, timeout=0.0)
    writer.execute("BEGIN IMMEDIATE")
    close_thread: threading.Thread | None = None
    started = time.monotonic()
    try:
        outcome = miner.mine_claim(claim)
        elapsed = time.monotonic() - started
        assert elapsed < 1.0
        assert outcome.status == "refused"
        assert outcome.reason == "storage_busy"
        assert writer.execute(
            "SELECT state FROM mining_runs WHERE run_id=?", (claim.run.run_id,)
        ).fetchone() == ("active",)
        assert writer.execute(
            "SELECT state FROM residual_groups WHERE group_id=?",
            (claim.group.group_id,),
        ).fetchone() == ("mining",)
        assert writer.execute(
            "SELECT event_kind FROM residual_group_events WHERE run_id=? ORDER BY event_id",
            (claim.run.run_id,),
        ).fetchall() == [("claimed",)]
        assert not [
            thread
            for thread in threading.enumerate()
            if thread not in existing_threads and thread.is_alive()
        ]
        assert store.connection_pragmas()["busy_timeout"] == 5000
        close_thread = threading.Thread(target=store.close)
        close_thread.start()
        close_thread.join(timeout=0.5)
        assert not close_thread.is_alive()
    finally:
        writer.rollback()
        writer.close()
        if close_thread is not None:
            close_thread.join(timeout=2.0)
        store.close()


def test_materialization_is_exactly_rule_and_fixture_and_retryable(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner, materialize_proposal

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source=source,
        replacement=x,
        source_cost=term_cost(source),
        replacement_cost=term_cost(x),
        certification=MbaCertification(proofs),
        exhaustion=None,
    )
    store = MbaDiscoveryStore(tmp_path / "discovery.sqlite3")
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    published = miner.mine_claim(claim)
    assert published.status == "published"
    proposal_id = published.proposal_id
    assert proposal_id is not None
    output = tmp_path / "review"
    path, digest = materialize_proposal(store, proposal_id, output)
    assert path == str(output.resolve())
    assert digest
    stem = store.proposal_snapshot(proposal_id).proposal.proposal_fingerprint
    assert sorted(item.name for item in output.iterdir()) == [
        f"{stem}.fixture.json",
        f"{stem}.rule.py",
    ]
    fixture = json.loads((output / f"{stem}.fixture.json").read_text())
    assert {
        "original",
        "atomized",
        "certified_atomized_replacement",
        "restored_replacement",
        "atomization_bindings",
        "proof_widths",
        "source_fingerprint",
    } == set(fixture)
    assert fixture["proof_widths"] == [8, 16, 32, 64]
    assert materialize_proposal(store, proposal_id, output) == (path, digest)
    store.close()


def test_mined_proposal_survives_later_evidence_before_materialization(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner, materialize_proposal

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source, x, term_cost(source), term_cost(x), MbaCertification(proofs), None
    )
    store = MbaDiscoveryStore(tmp_path / "later-evidence.sqlite3")
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    published = miner.mine_claim(claim)
    assert published.status == "published"
    assert published.proposal_id is not None
    later = store.record_attempt(_attempt(source))
    assert later.status.value == "stored"
    snapshot = store.proposal_snapshot(published.proposal_id)
    assert snapshot is not None
    assert snapshot.group.revision == claim.run.claimed_revision + 1
    output = tmp_path / "later-evidence-review"
    materialize_proposal(store, published.proposal_id, output)
    latest = store.record_attempt(_attempt(source))
    assert latest.status.value == "stored"
    materialized = store.proposal_snapshot(published.proposal_id)
    assert materialized is not None
    assert materialized.proposal.state.value == "materialized"
    assert materialized.group.revision == claim.run.claimed_revision + 2
    store.close()


def test_materialization_unknown_and_terminal_proposals_fail_closed(tmp_path) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    try:
        with pytest.raises(ValueError, match="unknown_proposal"):
            materialize_proposal(store, "12345678-1234-5678-1234-567812345678", tmp_path / "unknown")
        materialize_proposal(store, proposal_id, tmp_path / "terminal")
        with pytest.raises(ValueError, match="proposal_not_proposed"):
            materialize_proposal(store, proposal_id, tmp_path / "other")
    finally:
        store.close()


def _published_for_materialization(tmp_path, name="materialize-safety"):
    from d810.mba.discovery_miner import DiscoveryMiner

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    source = TypedBvTerm("add", 32, children=(x, x))
    proofs = tuple(ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS)
    result = MbaSynthesisResult(
        source, x, term_cost(source), term_cost(x), MbaCertification(proofs), None
    )
    store = MbaDiscoveryStore(tmp_path / f"{name}.sqlite3")
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.proposal_id is not None
    return store, outcome.proposal_id


@pytest.mark.parametrize("terminal", ["admitted", "rejected"])
def test_materialization_refuses_admitted_and_rejected_proposals(
    tmp_path, terminal
) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path, terminal)
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    if terminal == "admitted":
        materialize_proposal(store, proposal_id, tmp_path / "admitted-review")
        snapshot = store.proposal_snapshot(proposal_id)
        assert snapshot is not None
        receipt = store.mark_admitted(
            proposal_id,
            "rule-id",
            expected_state=snapshot.proposal.state,
            expected_revision=snapshot.group.revision,
        )
    else:
        receipt = store.mark_rejected(
            proposal_id,
            "unsafe",
            expected_state=snapshot.proposal.state,
            expected_revision=snapshot.group.revision,
        )
    assert receipt.status.value == terminal
    try:
        with pytest.raises(ValueError, match="proposal_not_proposed"):
            materialize_proposal(store, proposal_id, tmp_path / f"{terminal}-other")
    finally:
        store.close()


def test_materialization_stale_revision_refusal_cleans_only_owned_tree(
    tmp_path, monkeypatch
) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path, "stale-materialize")
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    output = tmp_path / "stale-review"
    original_mark = store.mark_materialized
    inserted = False

    def add_evidence_at_cas(*args, **kwargs):
        nonlocal inserted
        if not inserted:
            inserted = True
            store.record_attempt(_attempt(snapshot.group.raw_terms[0]))
        return original_mark(*args, **kwargs)

    monkeypatch.setattr(store, "mark_materialized", add_evidence_at_cas)
    try:
        with pytest.raises(RuntimeError, match="stale_revision"):
            materialize_proposal(store, proposal_id, output)
        current = store.proposal_snapshot(proposal_id)
        assert current is not None
        assert current.proposal.state.value == "proposed"
        assert current.group.revision == snapshot.group.revision + 1
        assert not output.exists()
        assert not tuple(tmp_path.glob(".stale-review.*"))
    finally:
        store.close()


def test_materialization_rejects_lexical_root_symlink(tmp_path) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    target = tmp_path / "target"
    output = tmp_path / "review-link"
    output.symlink_to(target, target_is_directory=True)
    try:
        with pytest.raises((OSError, ValueError)):
            materialize_proposal(store, proposal_id, output)
        assert not target.exists()
    finally:
        store.close()


def test_materialization_rejects_artifact_symlink(tmp_path) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "artifact-link"
    output.mkdir()
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    stem = snapshot.proposal.proposal_fingerprint
    (output / f"{stem}.rule.py").symlink_to(tmp_path / "outside.py")
    (output / f"{stem}.fixture.json").write_text("{}")
    try:
        with pytest.raises(FileExistsError):
            materialize_proposal(store, proposal_id, output)
    finally:
        store.close()


def test_materialization_destination_race_never_clobbers_empty_tree(tmp_path, monkeypatch) -> None:
    from d810.mba import discovery_miner
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "race"
    def race_publish(parent_fd, source, destination):
        output.mkdir()
        raise FileExistsError("destination appeared")

    monkeypatch.setattr(discovery_miner, "_exclusive_rename", race_publish)
    try:
        with pytest.raises(FileExistsError):
            materialize_proposal(store, proposal_id, output)
        assert output.is_dir()
        assert not tuple(output.iterdir())
    finally:
        if output.exists():
            output.rmdir()
        store.close()


def test_materialization_publishes_complete_tree_before_reader_can_observe_it(
    tmp_path, monkeypatch
) -> None:
    from d810.mba import discovery_miner
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "visibility"
    original_publish = discovery_miner._exclusive_rename
    observed = []

    def observe_publish(parent_fd, source, destination):
        assert not output.exists()
        original_publish(parent_fd, source, destination)
        observed.append(tuple(sorted(item.name for item in output.iterdir())))

    monkeypatch.setattr(discovery_miner, "_exclusive_rename", observe_publish)
    try:
        materialize_proposal(store, proposal_id, output)
        assert len(observed) == 1
        assert len(observed[0]) == 2
    finally:
        store.close()


def test_materialization_rejects_parent_replacement_before_cas(tmp_path, monkeypatch) -> None:
    from d810.mba import discovery_miner
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    parent = tmp_path / "renamed-parent"
    parent.mkdir()
    output = parent / "review"
    original_publish = discovery_miner._exclusive_rename
    replaced = False

    def publish_then_replace_parent(parent_fd, source, destination):
        nonlocal replaced
        original_publish(parent_fd, source, destination)
        if replaced:
            return
        replaced = True
        moved = tmp_path / "moved-parent"
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)

    monkeypatch.setattr(discovery_miner, "_exclusive_rename", publish_then_replace_parent)
    try:
        with pytest.raises((OSError, ValueError), match="parent|symlink"):
            materialize_proposal(store, proposal_id, output)
        snapshot = store.proposal_snapshot(proposal_id)
        assert snapshot is not None
        assert snapshot.proposal.state.value == "proposed"
        assert not (tmp_path / "moved-parent" / "review").exists()
        assert tuple((tmp_path / "moved-parent").iterdir()) == ()
    finally:
        if parent.is_symlink():
            parent.unlink()
        if (tmp_path / "moved-parent").exists():
            (tmp_path / "moved-parent").rmdir()
        store.close()


def test_materialization_rejects_parent_replacement_at_store_cas_boundary(
    tmp_path, monkeypatch
) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    parent = tmp_path / "cas-parent"
    parent.mkdir()
    output = parent / "review"
    moved = tmp_path / "cas-parent-moved"
    original_mark = store.mark_materialized
    before_events = store.count_rows("residual_group_events")

    def replace_parent_at_cas(*args, **kwargs):
        parent.rename(moved)
        parent.mkdir()
        return original_mark(*args, **kwargs)

    monkeypatch.setattr(store, "mark_materialized", replace_parent_at_cas)
    try:
        with pytest.raises((OSError, ValueError), match="parent"):
            materialize_proposal(store, proposal_id, output)
        snapshot = store.proposal_snapshot(proposal_id)
        assert snapshot is not None
        assert snapshot.proposal.state.value == "proposed"
        assert store.count_rows("residual_group_events") == before_events
        assert not output.exists()
        assert tuple(parent.iterdir()) == ()
        assert tuple(moved.iterdir()) == ()
    finally:
        if parent.exists():
            shutil.rmtree(parent)
        if moved.exists():
            shutil.rmtree(moved)
        store.close()


@pytest.mark.parametrize("interrupt_type", (KeyboardInterrupt, SystemExit))
def test_materialization_pre_commit_baseexception_restores_store_and_artifacts(
    tmp_path, monkeypatch, interrupt_type
) -> None:
    from d810.mba import discovery_miner
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(
        tmp_path, f"pre-commit-{interrupt_type.__name__}"
    )
    output = tmp_path / f"pre-commit-{interrupt_type.__name__}-review"
    original_verify = discovery_miner._verify_parent_path
    verify_calls = 0

    def interrupt_second_verification(path, parent_fd):
        nonlocal verify_calls
        verify_calls += 1
        if verify_calls == 2:
            raise interrupt_type("controlled pre-commit interruption")
        return original_verify(path, parent_fd)

    monkeypatch.setattr(
        discovery_miner, "_verify_parent_path", interrupt_second_verification
    )
    before_events = store.count_rows("residual_group_events")
    try:
        with pytest.raises(interrupt_type, match="controlled pre-commit interruption"):
            materialize_proposal(store, proposal_id, output)

        assert verify_calls == 2
        assert not output.exists()
        assert not store._connection.in_transaction
        assert tuple(store._connection.execute(
            "SELECT state FROM proposals WHERE proposal_id=?", (proposal_id,)
        ).fetchone()) == ("proposed",)
        assert [
            tuple(row)
            for row in store._connection.execute(
                "SELECT event_kind FROM residual_group_events WHERE proposal_id=? ORDER BY event_id",
                (proposal_id,),
            ).fetchall()
        ] == [("proposal_published",)]
        assert store.count_rows("residual_group_events") == before_events
        with sqlite3.connect(store.path) as external:
            assert external.execute(
                "SELECT state FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone() == ("proposed",)
            assert external.execute(
                "SELECT event_kind FROM residual_group_events WHERE proposal_id=? ORDER BY event_id",
                (proposal_id,),
            ).fetchall() == [("proposal_published",)]
        snapshot = store.proposal_snapshot(proposal_id)
        assert snapshot is not None
        assert snapshot.proposal.state.value == "proposed"
    finally:
        store.close()


def test_materialization_process_crash_leaves_exact_orphan_adoptable(tmp_path) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    db = tmp_path / "materialize-safety.sqlite3"
    output = tmp_path / "crash-recovery"
    store.close()
    script = """
import os
from d810.mba import discovery_miner
from d810.mba.discovery_miner import materialize_proposal
from d810.mba.discovery_store import MbaDiscoveryStore

original = discovery_miner._exclusive_rename
def crash_after_publish(parent_fd, source, destination):
    original(parent_fd, source, destination)
    os._exit(77)

discovery_miner._exclusive_rename = crash_after_publish
store = MbaDiscoveryStore({db!r})
materialize_proposal(store, {proposal_id!r}, {output!r})
""".format(db=str(db), proposal_id=proposal_id, output=str(output))
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parents[3] / "src")
    crashed = subprocess.run(
        [sys.executable, "-c", script], env=env, capture_output=True, check=False
    )
    assert crashed.returncode == 77
    assert len(tuple(output.iterdir())) == 2
    recovered = MbaDiscoveryStore(db)
    try:
        materialize_proposal(recovered, proposal_id, output)
        snapshot = recovered.proposal_snapshot(proposal_id)
        assert snapshot is not None
        assert snapshot.proposal.state.value == "materialized"
    finally:
        recovered.close()


def test_materialization_write_failure_leaves_proposed_and_cleans_stage(
    tmp_path, monkeypatch
) -> None:
    from d810.mba import discovery_miner
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "write-failure"
    original_write = discovery_miner.os.write
    writes = 0

    def fail_fixture_write(fd, content):
        nonlocal writes
        writes += 1
        if writes > 1:
            raise OSError("fixture write failed")
        return original_write(fd, content)

    monkeypatch.setattr(discovery_miner.os, "write", fail_fixture_write)
    try:
        with pytest.raises(OSError, match="fixture write failed"):
            materialize_proposal(store, proposal_id, output)
        snapshot = store.proposal_snapshot(proposal_id)
        assert snapshot is not None
        assert snapshot.proposal.state.value == "proposed"
        assert not output.exists()
        assert not tuple(tmp_path.glob(".write-failure.*"))
    finally:
        store.close()


def test_materialization_cas_exception_rolls_back_owned_tree(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import materialize_proposal

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "cas-failure"

    def fail_mark(*_args, **_kwargs):
        raise RuntimeError("recording failed")

    monkeypatch.setattr(
        store,
        "mark_materialized",
        fail_mark,
    )
    try:
        with pytest.raises(RuntimeError, match="recording failed"):
            materialize_proposal(store, proposal_id, output)
        assert not output.exists()
        assert not tuple(tmp_path.glob(".cas-failure.*"))
        snapshot = store.proposal_snapshot(proposal_id)
        assert snapshot is not None
        assert snapshot.proposal.state.value == "proposed"
    finally:
        store.close()


def test_materialization_cas_refusal_preserves_replacement_owner(tmp_path, monkeypatch) -> None:
    from d810.mba.discovery_miner import materialize_proposal
    from d810.mba.discovery_models import LifecycleReceipt, ReceiptStatus

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "owned"
    original_mark = store.mark_materialized

    def replace_then_refuse(*args, **kwargs):
        shutil.rmtree(output)
        output.mkdir()
        (output / "other-owner.txt").write_text("keep")
        return LifecycleReceipt(ReceiptStatus.REFUSED, reason="race")

    monkeypatch.setattr(store, "mark_materialized", replace_then_refuse)
    try:
        with pytest.raises(RuntimeError, match="race"):
            materialize_proposal(store, proposal_id, output)
        assert (output / "other-owner.txt").read_text() == "keep"
    finally:
        monkeypatch.setattr(store, "mark_materialized", original_mark)
        shutil.rmtree(output)
        store.close()


@pytest.mark.parametrize("mutation", ["extra", "content", "symlink", "directory"])
def test_materialization_rollback_preserves_same_inode_foreign_changes(
    tmp_path, monkeypatch, mutation
) -> None:
    from d810.mba.discovery_miner import materialize_proposal
    from d810.mba.discovery_models import LifecycleReceipt, ReceiptStatus

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "same-owner"
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    stem = snapshot.proposal.proposal_fingerprint

    def mutate_then_refuse(*args, **kwargs):
        if mutation == "extra":
            (output / "other-owner.txt").write_text("keep")
        elif mutation == "content":
            (output / f"{stem}.rule.py").write_text("foreign")
        else:
            artifact = output / f"{stem}.rule.py"
            artifact.unlink()
            if mutation == "symlink":
                artifact.symlink_to(tmp_path / "outside.py")
            else:
                artifact.mkdir()
        return LifecycleReceipt(ReceiptStatus.REFUSED, reason="race")

    monkeypatch.setattr(store, "mark_materialized", mutate_then_refuse)
    try:
        with pytest.raises(RuntimeError, match="recovery conflict"):
            materialize_proposal(store, proposal_id, output)
        if mutation == "extra":
            assert (output / "other-owner.txt").read_text() == "keep"
        elif mutation == "content":
            assert (output / f"{stem}.rule.py").read_text() == "foreign"
        elif mutation == "symlink":
            assert (output / f"{stem}.rule.py").is_symlink()
        else:
            assert (output / f"{stem}.rule.py").is_dir()
    finally:
        shutil.rmtree(output)
        store.close()


def test_materialization_rollback_preserves_private_quarantine_on_restore_race(
    tmp_path, monkeypatch
) -> None:
    from d810.mba import discovery_miner
    from d810.mba.discovery_miner import materialize_proposal
    from d810.mba.discovery_models import LifecycleReceipt, ReceiptStatus

    store, proposal_id = _published_for_materialization(tmp_path)
    output = tmp_path / "restore-race"
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    stem = snapshot.proposal.proposal_fingerprint
    original_rename = discovery_miner._exclusive_rename
    calls = 0

    def rename_then_race(parent_fd, source, destination):
        nonlocal calls
        calls += 1
        result = original_rename(parent_fd, source, destination)
        if calls == 2:
            output.mkdir()
            (output / "foreign.txt").write_text("keep")
        return result

    def mutate_then_refuse(*args, **kwargs):
        (output / f"{stem}.rule.py").write_text("foreign")
        return LifecycleReceipt(ReceiptStatus.REFUSED, reason="race")

    monkeypatch.setattr(discovery_miner, "_exclusive_rename", rename_then_race)
    monkeypatch.setattr(store, "mark_materialized", mutate_then_refuse)
    try:
        with pytest.raises(RuntimeError) as raised:
            materialize_proposal(store, proposal_id, output)
        assert (output / "foreign.txt").read_text() == "keep"
        quarantine = tuple(tmp_path.glob(".restore-race.quarantine-*"))
        assert len(quarantine) == 1
        assert str(raised.value) == (
            "materialization recovery conflict: visible destination preserved at "
            f"{output.resolve()}; quarantined owned tree retained at "
            f"{quarantine[0].resolve()}"
        )
    finally:
        shutil.rmtree(output)
        for item in tmp_path.glob(".restore-race.quarantine-*"):
            shutil.rmtree(item)
        store.close()


def test_heartbeat_interval_must_be_finite(tmp_path) -> None:
    from d810.mba.discovery_miner import DiscoveryMiner

    store = MbaDiscoveryStore(tmp_path / "finite.sqlite3")
    try:
        with pytest.raises(ValueError):
            DiscoveryMiner(store, heartbeat_interval=float("inf"))
    finally:
        store.close()
