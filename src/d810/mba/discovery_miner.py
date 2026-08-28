"""Portable SQLite-backed mining and explicit review materialization."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
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
    ClaimReceipt,
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
    proposal_id: str | None = None


class _HeartbeatCoordinator:
    def __init__(self, store: MbaDiscoveryStore, claim: MiningClaim, interval: float) -> None:
        self._store = store
        self._claim = claim
        self._interval = interval
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._refusal: str | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            while not self._stop.wait(self._interval):
                receipt = self._store.heartbeat(
                    self._claim.run.run_id, self._claim.run.claimed_revision
                )
                if receipt.status is not ReceiptStatus.HEARTBEATED:
                    self._refusal = receipt.reason or receipt.status.value
                    return
        except BaseException as exc:
            self._error = exc

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> tuple[str | None, BaseException | None, bool]:
        self._stop.set()
        self._thread.join(timeout=max(self._interval * 2.0, 1.0))
        return self._refusal, self._error, not self._thread.is_alive()


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
        "original": typed_term_to_dict(atomized.original_term),
        "atomized": typed_term_to_dict(atomized.atomized_term),
        "certified_atomized_replacement": typed_term_to_dict(result.replacement),
        "restored_replacement": typed_term_to_dict(restored),
        "atomization_bindings": [
            {
                "leaf_key": list(binding.leaf_key),
                "original_subterm": typed_term_to_dict(binding.original_subterm),
                "occurrence_count": binding.occurrence_count,
                "saved_operator_nodes": binding.saved_operator_nodes,
            }
            for binding in atomized.bindings
        ],
        "proof_widths": [receipt.width for receipt in result.proof_receipts],
        "source_fingerprint": source_fingerprint,
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
        if (
            type(self.heartbeat_interval) not in (int, float)
            or not math.isfinite(float(self.heartbeat_interval))
            or self.heartbeat_interval <= 0
        ):
            raise ValueError("heartbeat_interval must be positive")

    def claim(self) -> ClaimReceipt:
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

        coordinator = _HeartbeatCoordinator(
            self.store, claim, float(self.heartbeat_interval)
        )
        coordinator.start()
        stopped_cleanly = False
        try:
            atomized = self.atomizer(
                claim.group.raw_terms[0], max_atoms=selected_budget.max_atoms
            )
            result = self.synthesizer(atomized, budget=selected_budget)
            refusal, error, stopped_cleanly = coordinator.stop()
            if not stopped_cleanly:
                return MineOutcome("error", "heartbeat_worker_did_not_stop")
            if error is not None:
                return MineOutcome("error", f"heartbeat_error: {type(error).__name__}: {error}")
            if refusal is not None:
                return MineOutcome("refused", refusal)
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
                    return MineOutcome(
                        "published",
                        receipt.status.value,
                        proposal,
                        None if receipt.proposal is None else receipt.proposal.proposal_id,
                    )
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
            if not stopped_cleanly:
                _refusal, _error, stopped_cleanly = coordinator.stop()


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


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_symlink_components(path: Path) -> None:
    """Reject any existing symlink in the lexical output path."""

    current = Path(path.anchor) if path.anchor else Path()
    for component in path.parts:
        if component == path.anchor:
            continue
        current /= component
        if os.path.lexists(current) and stat.S_ISLNK(os.lstat(current).st_mode):
            raise FileExistsError("output path cannot contain symlinks")


def _owned_identity(path: Path) -> tuple[int, int]:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise FileExistsError("materialization root is not a directory")
    return info.st_dev, info.st_ino


def _remove_owned_tree(path: Path, identity: tuple[int, int]) -> bool:
    try:
        if _owned_identity(path) != identity:
            return False
        shutil.rmtree(path)
        _fsync_dir(path.parent)
        return True
    except FileNotFoundError:
        return False


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
    output_dir = Path(os.path.abspath(os.fspath(Path(output_dir).expanduser())))
    _reject_symlink_components(output_dir)
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
            if stat.S_ISREG(os.lstat(path).st_mode)
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
        _fsync_dir(output_dir)
        _fsync_dir(output_dir.parent)
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
    created_final = False
    committed = False
    identity: tuple[int, int] | None = None
    try:
        for name, content in names.items():
            target = stage / name
            with target.open("w", encoding="utf-8", newline="") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        _fsync_dir(stage)
        digest = _tree_digest(stage)
        # Reserve the destination with mkdir.  Unlike directory rename, this
        # is an atomic no-clobber operation even when an empty tree appears in
        # the race window after our preflight check.
        os.mkdir(output_dir)
        created_final = True
        identity = _owned_identity(output_dir)
        for name in names:
            source = stage / name
            target = output_dir / name
            os.link(source, target)
            source.unlink()
        stage.rmdir()
        _fsync_dir(output_dir)
        _fsync_dir(output_dir.parent)
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
        if created_final and not committed and identity is not None:
            _remove_owned_tree(output_dir, identity)


__all__ = [
    "DiscoveryMiner",
    "MineOutcome",
    "_tree_digest",
    "budget_fingerprint",
    "materialize_proposal",
]
