"""SQLite residual miner CLI contracts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from d810.core.function_execution_identity import FunctionExecutionIdentity, MbaObservationContext
from d810.core.plugins import PluginIdentity
from d810.mba.discovery_models import DiscoveryAttempt
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_fingerprint

ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "tools" / "scripts" / "mba_residual_rule_miner.py"


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
