"""Database-oriented MBA discovery miner contracts."""

from __future__ import annotations

from uuid import uuid4

from d810.core.function_execution_identity import FunctionExecutionIdentity, MbaObservationContext
from d810.core.plugins import PluginIdentity
from d810.mba.bounded_synthesis import (
    CERTIFICATION_WIDTHS,
    MbaCertification,
    MbaSynthesisResult,
    MbaSynthesisBudget,
    ProofReceipt,
)
from d810.mba.discovery_models import DiscoveryAttempt
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
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
    proposal_id = store._connection.execute("SELECT proposal_id FROM proposals").fetchone()[0]
    snapshot = store.proposal_snapshot(proposal_id)
    assert snapshot is not None
    assert snapshot.proposal.proposal_payload
    assert snapshot.group.revision == claim.run.claimed_revision
    assert snapshot.proposal.proposal_payload is not None
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
    assert miner.mine_claim(claim).status == "published"
    proposal_id = store._connection.execute("SELECT proposal_id FROM proposals").fetchone()[0]
    output = tmp_path / "review"
    path, digest = materialize_proposal(store, proposal_id, output)
    assert path == str(output.resolve())
    assert digest
    stem = store.proposal_snapshot(proposal_id).proposal.proposal_fingerprint
    assert sorted(item.name for item in output.iterdir()) == [
        f"{stem}.fixture.json",
        f"{stem}.rule.py",
    ]
    assert materialize_proposal(store, proposal_id, output) == (path, digest)
    store.close()
