"""Portable SQLite-backed mining and explicit review materialization."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from d810.mba.bounded_synthesis import (
    MbaSynthesisBudget,
    MbaSynthesisResult,
    synthesize_residual,
)
from d810.mba.discovery_models import (
    MiningClaim,
    ProposalState,
    ReceiptStatus,
)
from d810.mba.discovery_store import (
    DISCOVERY_LEASE_TIMEOUT_SECONDS,
    MbaDiscoveryStore,
    decode_proposal_payload,
)
from d810.mba.rule_proposal import MbaRuleProposal, render_rule_source
from d810.mba.subterm_atomization import AtomizedMbaTerm, atomize_repeated_subterms
from d810.mba.term_codec import typed_term_to_dict
from d810.mba.typed_term import term_fingerprint


@dataclass(frozen=True, slots=True)
class MineOutcome:
    """One bounded claim outcome suitable for deterministic CLI reporting."""

    status: str
    reason: str | None = None
    proposal: MbaRuleProposal | None = None


def budget_fingerprint(budget: MbaSynthesisBudget) -> str:
    """Return the stable identity of one synthesis budget."""

    if not isinstance(budget, MbaSynthesisBudget):
        raise TypeError("budget must be an MbaSynthesisBudget")
    payload = {
        name: getattr(budget, name)
        for name in (
            "max_atoms",
            "max_variables",
            "max_candidate_operator_nodes",
            "max_generated_terms",
            "max_candidate_attempts",
            "witness_count",
        )
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(("mba-discovery-budget-v1:" + encoded).encode("ascii")).hexdigest()


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _proposal_for(
    claim: MiningClaim,
    atomized: AtomizedMbaTerm,
    result: MbaSynthesisResult,
) -> MbaRuleProposal:
    if result.replacement is None or not result.certified:
        raise ValueError("cannot create proposal from uncertified synthesis")
    restored = atomized.restore(result.replacement)
    source_fingerprint = term_fingerprint(claim.group.canonical_term)
    class_name = "MbaResidualRule_" + hashlib.sha256(
        source_fingerprint.encode("ascii")
    ).hexdigest()[:12]
    fixture = {
        "source_fingerprint": source_fingerprint,
        "expected_restored_replacement": typed_term_to_dict(restored),
    }
    return MbaRuleProposal(
        proposal_fingerprint=None,
        source_fingerprints=(
            source_fingerprint,
        ),
        occurrence_count=claim.group.eligible_observation_count,
        pattern=result.source,
        replacement=result.replacement,
        source_cost=result.source_cost,
        replacement_cost=result.replacement_cost,
        atomization_bindings=atomized.bindings,
        proof_receipts=result.proof_receipts,
        class_name=class_name,
        family=result.replacement.operation or result.source.operation or "residual",
        description="Proof-certified simplification discovered from an MBA residual",
        provenance=(
            f"discovery_db:group:{claim.group.group_id}:revision:{claim.run.claimed_revision}",
        ),
        fixture=fixture,
        fixed_operation_descriptors=result.fixed_operation_descriptors,
        synthesis_result=result,
    )


class DiscoveryMiner:
    """Mine one store claim at a time without producing filesystem artifacts."""

    def __init__(
        self,
        store: MbaDiscoveryStore,
        *,
        miner_version: str = "d810-discovery-miner-v1",
        budget: MbaSynthesisBudget | None = None,
        atomizer: Callable[..., AtomizedMbaTerm] = atomize_repeated_subterms,
        synthesizer: Callable[..., MbaSynthesisResult] = synthesize_residual,
        heartbeat_interval: float | None = None,
    ) -> None:
        if not isinstance(store, MbaDiscoveryStore):
            raise TypeError("store must be an MbaDiscoveryStore")
        if type(miner_version) is not str or not miner_version or miner_version.strip() != miner_version:
            raise ValueError("miner_version must be a canonical non-empty string")
        self.store = store
        self.miner_version = miner_version
        self.budget = MbaSynthesisBudget() if budget is None else budget
        if not isinstance(self.budget, MbaSynthesisBudget):
            raise TypeError("budget must be an MbaSynthesisBudget")
        self.atomizer = atomizer
        self.synthesizer = synthesizer
        self.heartbeat_interval = (
            DISCOVERY_LEASE_TIMEOUT_SECONDS / 2
            if heartbeat_interval is None
            else heartbeat_interval
        )
        if type(self.heartbeat_interval) not in (int, float) or self.heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")

    def claim(self) -> object:
        """Claim the next eligible group using this miner's stable identity."""

        return self.store.claim_next_group(
            self.miner_version, budget_fingerprint(self.budget)
        )

    def mine_claim(
        self, claim: MiningClaim, budget: MbaSynthesisBudget | None = None
    ) -> MineOutcome:
        if not isinstance(claim, MiningClaim):
            raise TypeError("claim must be a MiningClaim")
        selected_budget = self.budget if budget is None else budget
        if not isinstance(selected_budget, MbaSynthesisBudget):
            raise TypeError("budget must be an MbaSynthesisBudget")
        if claim.run.budget_fingerprint != budget_fingerprint(selected_budget):
            return MineOutcome("refused", "budget_fingerprint_mismatch")
        if not claim.group.raw_terms:
            return MineOutcome("refused", "empty_raw_evidence")

        stop = threading.Event()
        stale = threading.Event()

        def refresh() -> None:
            while not stop.wait(float(self.heartbeat_interval)):
                receipt = self.store.heartbeat(
                    claim.run.run_id, claim.run.claimed_revision
                )
                if receipt.status is not ReceiptStatus.HEARTBEATED:
                    stale.set()
                    return

        heartbeat_thread = threading.Thread(target=refresh, daemon=True)
        heartbeat_thread.start()
        try:
            atomized = self.atomizer(
                claim.group.raw_terms[0], max_atoms=selected_budget.max_atoms
            )
            result = self.synthesizer(atomized, budget=selected_budget)
            if stale.is_set():
                return MineOutcome("refused", "stale_or_not_owner")
            if result.certified:
                proposal = _proposal_for(claim, atomized, result)
                receipt = self.store.publish_proposal(
                    claim.run.run_id,
                    claim.run.claimed_revision,
                    proposal,
                    proposal.replacement,
                    proposal,
                )
                if receipt.status in (ReceiptStatus.PUBLISHED, ReceiptStatus.DUPLICATE):
                    return MineOutcome("published", receipt.status.value, proposal)
                return MineOutcome("refused", receipt.reason or receipt.status.value)
            reason = (
                result.exhaustion.reason
                if result.exhaustion is not None
                else "proof_failed"
            )
            finished = self.store.finish_no_proposal(
                claim.run.run_id, claim.run.claimed_revision, reason
            )
            if finished.status is ReceiptStatus.FINISHED:
                return MineOutcome("no_proposal", reason)
            return MineOutcome("refused", finished.reason or finished.status.value)
        except Exception as exc:
            return MineOutcome("error", f"{type(exc).__name__}: {exc}")
        finally:
            stop.set()
            heartbeat_thread.join(timeout=max(float(self.heartbeat_interval), 1.0))


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _fixture_json(value: Mapping[str, object]) -> str:
    return json.dumps(_json_ready(value), allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def materialize_proposal(
    store: MbaDiscoveryStore,
    proposal_id: str,
    output_dir: Path,
) -> tuple[str, str]:
    """Atomically render exactly rule and fixture artifacts for one proposal."""

    snapshot = store.proposal_snapshot(proposal_id)
    if snapshot is None:
        raise ValueError("unknown_proposal")
    proposal_row = snapshot.proposal
    proposal = decode_proposal_payload(proposal_row.proposal_payload)
    if proposal.fingerprint != proposal_row.proposal_fingerprint:
        raise ValueError("proposal_payload_identity_mismatch")
    output_dir = output_dir.expanduser().resolve()
    names = {
        f"{proposal.fingerprint}.rule.py": render_rule_source(proposal),
        f"{proposal.fingerprint}.fixture.json": _fixture_json(proposal.fixture),
    }
    output_dir.parent.mkdir(parents=True, exist_ok=True)

    def exact_tree() -> bool:
        if not output_dir.is_dir() or output_dir.is_symlink():
            return False
        existing = {
            path.name: path.read_bytes()
            for path in output_dir.iterdir()
            if path.is_file()
        }
        expected = {name: value.encode("utf-8") for name, value in names.items()}
        return existing == expected and len(tuple(output_dir.iterdir())) == len(expected)

    if proposal_row.state is ProposalState.MATERIALIZED:
        digest = _tree_digest(output_dir) if exact_tree() else ""
        if (
            str(output_dir) == proposal_row.materialized_path
            and digest
            and digest == proposal_row.materialized_digest
        ):
            return str(output_dir), digest
        raise ValueError("proposal_not_proposed")
    if proposal_row.state is not ProposalState.PROPOSED:
        raise ValueError("proposal_not_proposed")

    if output_dir.exists():
        if not output_dir.is_dir() or output_dir.is_symlink():
            raise FileExistsError("output tree conflicts with a file")
        if not exact_tree():
            raise FileExistsError("output tree conflicts with existing artifacts")
        digest = _tree_digest(output_dir)
        receipt = store.mark_materialized(
            proposal_id,
            str(output_dir),
            digest,
            expected_state=proposal_row.state,
            expected_revision=snapshot.group.revision,
        )
        if receipt.status not in (ReceiptStatus.MATERIALIZED, ReceiptStatus.DUPLICATE):
            raise RuntimeError(receipt.reason or receipt.status.value)
        return str(output_dir), digest

    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    shutil.rmtree(stage)
    created_final = False
    committed = False
    try:
        stage.mkdir()
        for name, content in names.items():
            target = stage / name
            with target.open("w", encoding="utf-8", newline="") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        digest = _tree_digest(stage)
        os.replace(stage, output_dir)
        created_final = True
        receipt = store.mark_materialized(
            proposal_id,
            str(output_dir),
            digest,
            expected_state=proposal_row.state,
            expected_revision=snapshot.group.revision,
        )
        if receipt.status not in (ReceiptStatus.MATERIALIZED, ReceiptStatus.DUPLICATE):
            raise RuntimeError(receipt.reason or receipt.status.value)
        committed = True
        return str(output_dir), digest
    finally:
        if stage.exists():
            shutil.rmtree(stage)
        if created_final and not committed and output_dir.exists():
            shutil.rmtree(output_dir)


__all__ = [
    "DiscoveryMiner",
    "MineOutcome",
    "_tree_digest",
    "budget_fingerprint",
    "materialize_proposal",
]
