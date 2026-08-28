"""SQLite residual miner CLI contracts."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from d810.core.function_execution_identity import FunctionExecutionIdentity, MbaObservationContext
from d810.core.plugins import PluginIdentity
from d810.mba.bounded_synthesis import (
    CERTIFICATION_WIDTHS,
    MbaCertification,
    MbaSynthesisResult,
    ProofReceipt,
)
from d810.mba.discovery_miner import DiscoveryMiner, materialize_proposal
from d810.mba.discovery_models import (
    DiscoveryAttempt,
    MiningRunState,
    ProposalState,
    ResidualGroupState,
)
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
    term_cost,
    term_fingerprint,
)

ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "tools" / "scripts" / "mba_residual_rule_miner.py"


def _attempt(term: TypedBvTerm, *, eligible: bool = True) -> DiscoveryAttempt:
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
        eligible_for_mining=eligible,
    )


def _load_cli_module():
    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _publish(store: MbaDiscoveryStore, leaf_name: str):
    leaf = TypedBvTerm(None, 32, leaf_key=("register", leaf_name))
    source = TypedBvTerm("add", 32, children=(leaf, leaf))
    proofs = tuple(
        ProofReceipt(width, True, 0.1) for width in CERTIFICATION_WIDTHS
    )
    result = MbaSynthesisResult(
        source,
        leaf,
        term_cost(source),
        term_cost(leaf),
        MbaCertification(proofs),
        None,
    )
    store.record_attempt(_attempt(source))
    miner = DiscoveryMiner(store, synthesizer=lambda atomized, budget: result)
    claim = miner.claim().claim
    assert claim is not None
    outcome = miner.mine_claim(claim)
    assert outcome.proposal_id is not None
    snapshot = store.proposal_snapshot(outcome.proposal_id)
    assert snapshot is not None
    return snapshot


def _published_database(tmp_path: Path, name: str = "cli-published"):
    db = tmp_path / f"{name}.sqlite3"
    store = MbaDiscoveryStore(db)
    snapshot = _publish(store, name)
    return db, store, snapshot


def _database_snapshot(path: Path) -> tuple[object, ...]:
    tables = (
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
    with sqlite3.connect(path) as connection:
        return tuple(
            (table, tuple(connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')))
            for table in tables
        )


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
    )


def test_empty_database_and_limit_zero_are_normal_non_mutating_outcomes(tmp_path: Path) -> None:
    db = tmp_path / "discovery.sqlite3"
    store = MbaDiscoveryStore(db)
    store.close()
    before = db.read_bytes()
    result = _run("mine", "--db", str(db), "--limit", "0")
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"errors": 0, "no_proposal": 0, "published": 0, "refused": 0}
    assert db.read_bytes() == before
    result = _run("mine", "--db", str(db))
    assert result.returncode == 0
    assert json.loads(result.stdout)["published"] == 0


def test_status_is_machine_readable_and_mine_writes_no_artifacts(tmp_path: Path) -> None:
    db = tmp_path / "discovery.sqlite3"
    store = MbaDiscoveryStore(db)
    store.record_attempt(_attempt(TypedBvTerm(None, 32, leaf_key=("register", "x"))))
    store.close()
    result = _run("mine", "--db", str(db), "--max-generated-terms", "0")
    assert result.returncode == 0
    assert json.loads(result.stdout)["no_proposal"] == 1
    assert not list(tmp_path.glob("*.json"))
    assert not list(tmp_path.glob("*.py"))
    status = _run("status", "--db", str(db))
    assert status.returncode == 0
    payload = json.loads(status.stdout)
    assert payload["groups"]["no_proposal"] == 1


def test_cli_rejects_json_corpus_input_and_forbidden_runtime_imports() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--input" not in source
    assert "residual_corpus" not in source
    for module in ("idaapi", "ida_hexrays", "d810_cobra", "d810_egglog"):
        assert f"import {module}" not in source
        assert f"from {module}" not in source


def test_cli_materialize_writes_exact_tree_and_retries_idempotently(
    tmp_path: Path,
) -> None:
    db, store, snapshot = _published_database(tmp_path)
    proposal_id = snapshot.proposal.proposal_id
    fingerprint = snapshot.proposal.proposal_fingerprint
    store.close()
    output = tmp_path / "cli-review"

    first = _run(
        "materialize",
        "--db",
        str(db),
        "--proposal",
        proposal_id,
        "--output-dir",
        str(output),
    )
    assert first.returncode == 0
    payload = json.loads(first.stdout)
    assert payload["path"] == str(output.resolve())
    assert payload["digest"]
    assert sorted(item.name for item in output.iterdir()) == [
        f"{fingerprint}.fixture.json",
        f"{fingerprint}.rule.py",
    ]
    retry = _run(
        "materialize",
        "--db",
        str(db),
        "--proposal",
        proposal_id,
        "--output-dir",
        str(output),
    )
    assert retry.returncode == 0
    assert json.loads(retry.stdout) == payload
    reopened = MbaDiscoveryStore(db)
    try:
        current = reopened.proposal_snapshot(proposal_id)
        assert current is not None
        assert current.proposal.state is ProposalState.MATERIALIZED
        assert current.proposal.materialized_path == str(output.resolve())
        assert current.proposal.materialized_digest == payload["digest"]
    finally:
        reopened.close()


def test_cli_materialize_unknown_corrupt_and_terminal_proposals_fail_actionably(
    tmp_path: Path,
) -> None:
    empty_db = tmp_path / "empty.sqlite3"
    empty = MbaDiscoveryStore(empty_db)
    empty.close()
    unknown = _run(
        "materialize",
        "--db",
        str(empty_db),
        "--proposal",
        "00000000-0000-0000-0000-000000000000",
        "--output-dir",
        str(tmp_path / "unknown"),
    )
    assert unknown.returncode == 2
    assert "unknown_proposal" in unknown.stderr

    corrupt_db, corrupt_store, corrupt_snapshot = _published_database(
        tmp_path, "corrupt"
    )
    corrupt_store.close()
    with sqlite3.connect(corrupt_db) as connection:
        connection.execute(
            "UPDATE proposals SET proposal_payload=? WHERE proposal_id=?",
            (b"{}", corrupt_snapshot.proposal.proposal_id),
        )
        connection.commit()
    corrupt = _run(
        "materialize",
        "--db",
        str(corrupt_db),
        "--proposal",
        corrupt_snapshot.proposal.proposal_id,
        "--output-dir",
        str(tmp_path / "corrupt-review"),
    )
    assert corrupt.returncode == 2
    assert "proposal" in corrupt.stderr.lower()

    rejected_db, rejected_store, rejected_snapshot = _published_database(
        tmp_path, "rejected"
    )
    rejected = rejected_store.mark_rejected(
        rejected_snapshot.proposal.proposal_id,
        "unsafe",
        expected_state=rejected_snapshot.proposal.state,
        expected_revision=rejected_snapshot.group.revision,
    )
    assert rejected.status.value == "rejected"
    rejected_store.close()
    terminal = _run(
        "materialize",
        "--db",
        str(rejected_db),
        "--proposal",
        rejected_snapshot.proposal.proposal_id,
        "--output-dir",
        str(tmp_path / "rejected-review"),
    )
    assert terminal.returncode == 2
    assert "proposal_not_proposed" in terminal.stderr

    admitted_db, admitted_store, admitted_snapshot = _published_database(
        tmp_path, "admitted"
    )
    admitted_output = tmp_path / "admitted-existing"
    materialize_proposal(
        admitted_store, admitted_snapshot.proposal.proposal_id, admitted_output
    )
    admitted_current = admitted_store.proposal_snapshot(
        admitted_snapshot.proposal.proposal_id
    )
    assert admitted_current is not None
    assert admitted_store.mark_admitted(
        admitted_snapshot.proposal.proposal_id,
        "rule-id",
        expected_state=admitted_current.proposal.state,
        expected_revision=admitted_current.group.revision,
    ).status.value == "admitted"
    admitted_store.close()
    admitted_terminal = _run(
        "materialize",
        "--db",
        str(admitted_db),
        "--proposal",
        admitted_snapshot.proposal.proposal_id,
        "--output-dir",
        str(tmp_path / "admitted-other"),
    )
    assert admitted_terminal.returncode == 2
    assert "proposal_not_proposed" in admitted_terminal.stderr


@pytest.mark.parametrize("outcome_status", ["error", "refused"])
def test_cli_mine_error_or_refusal_is_nonzero_and_stops_loop(
    tmp_path: Path, monkeypatch, capsys, outcome_status: str
) -> None:
    module = _load_cli_module()
    calls = {"claim": 0, "mine": 0}

    class RefusingMiner:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def claim(self):
            calls["claim"] += 1
            return SimpleNamespace(claim=object(), reason=None)

        def mine_claim(self, *_args, **_kwargs):
            calls["mine"] += 1
            return SimpleNamespace(status=outcome_status)

    monkeypatch.setattr(module, "DiscoveryMiner", RefusingMiner)
    result = module.main(
        ["mine", "--db", str(tmp_path / f"{outcome_status}.sqlite3")]
    )
    assert result == 2
    assert calls == {"claim": 1, "mine": 1}
    counts = json.loads(capsys.readouterr().out)
    expected = {"errors": 0, "no_proposal": 0, "published": 0, "refused": 0}
    expected["errors" if outcome_status == "error" else "refused"] = 1
    assert counts == expected


def test_cli_status_reports_every_state_key_and_does_not_mutate(
    tmp_path: Path,
) -> None:
    db = tmp_path / "all-status.sqlite3"
    now = [datetime.now(timezone.utc)]
    store = MbaDiscoveryStore(db, clock=lambda: now[0])
    _publish(store, "proposed")
    materialized = _publish(store, "materialized")
    materialized_output = tmp_path / "materialized-output"
    materialize_proposal(
        store, materialized.proposal.proposal_id, materialized_output
    )
    admitted = _publish(store, "admitted")
    admitted_output = tmp_path / "admitted-output"
    materialize_proposal(store, admitted.proposal.proposal_id, admitted_output)
    admitted_current = store.proposal_snapshot(admitted.proposal.proposal_id)
    assert admitted_current is not None
    assert store.mark_admitted(
        admitted.proposal.proposal_id,
        "rule-id",
        expected_state=admitted_current.proposal.state,
        expected_revision=admitted_current.group.revision,
    ).status.value == "admitted"
    rejected = _publish(store, "rejected")
    assert store.mark_rejected(
        rejected.proposal.proposal_id,
        "unsafe",
        expected_state=rejected.proposal.state,
        expected_revision=rejected.group.revision,
    ).status.value == "rejected"
    store.record_attempt(_attempt(TypedBvTerm(None, 32, value=100), eligible=False))
    store.record_attempt(_attempt(TypedBvTerm(None, 32, value=101)))
    active = store.claim_next_group("status-miner", "active-budget")
    assert active.claim is not None
    store.record_attempt(_attempt(TypedBvTerm(None, 32, value=102)))
    now[0] += timedelta(seconds=301)
    reclaimed = store.claim_next_group("status-miner", "reclaimed-budget")
    assert reclaimed.claim is not None
    assert reclaimed.claim.run.run_id != active.claim.run.run_id
    no_proposal = store.claim_next_group("status-miner", "finished-budget")
    assert no_proposal.claim is not None
    assert store.finish_no_proposal(
        no_proposal.claim.run.run_id, no_proposal.claim.run.claimed_revision
    ).status.value == "finished"
    store.record_attempt(_attempt(TypedBvTerm(None, 32, value=103)))
    store.close()
    before = _database_snapshot(db)

    status = _run("status", "--db", str(db))

    assert status.returncode == 0
    payload = json.loads(status.stdout)
    assert set(payload["groups"]) == {state.value for state in ResidualGroupState}
    assert set(payload["runs"]) == {state.value for state in MiningRunState}
    assert set(payload["proposals"]) == {state.value for state in ProposalState}
    assert payload["groups"] == {
        "observed": 1,
        "eligible": 1,
        "mining": 1,
        "no_proposal": 1,
        "proposed": 1,
        "materialized": 1,
        "admitted": 1,
        "rejected": 1,
    }
    assert payload["proposals"] == {
        "proposed": 1,
        "materialized": 1,
        "admitted": 1,
        "rejected": 1,
    }
    assert payload["runs"]["active"] == 1
    assert payload["runs"]["no_proposal"] == 1
    assert payload["runs"]["proposed"] == 4
    assert payload["runs"]["expired"] == 1
    assert _database_snapshot(db) == before


def test_cli_stderr_preserves_exact_quarantine_recovery_paths(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    module = _load_cli_module()
    db = tmp_path / "recovery.sqlite3"
    store = MbaDiscoveryStore(db)
    store.close()
    visible = (tmp_path / "visible").resolve()
    quarantine = (tmp_path / ".visible.quarantine-1234").resolve()
    message = (
        "materialization recovery conflict: visible destination preserved at "
        f"{visible}; quarantined owned tree retained at {quarantine}"
    )

    def fail_with_paths(*_args, **_kwargs):
        raise RuntimeError(message)

    monkeypatch.setattr(module, "materialize_proposal", fail_with_paths)
    result = module.main(
        [
            "materialize",
            "--db",
            str(db),
            "--proposal",
            "00000000-0000-0000-0000-000000000000",
            "--output-dir",
            str(visible),
        ]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == f"mba residual miner: {message}\n"
