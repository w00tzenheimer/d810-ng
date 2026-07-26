"""Executable parity ledger for the portable CFG transaction donor."""

from __future__ import annotations

import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
GATE_PATH = REPO_ROOT / "tools" / "scripts" / "portable_cfg_transaction_parity_gate.py"
LEDGER_PATH = (
    REPO_ROOT / "tools" / "scripts" / "portable_cfg_transaction_parity_ledger.json"
)


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "portable_cfg_transaction_parity_gate",
        GATE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parity_ledger_is_complete_and_all_anchors_resolve() -> None:
    gate = _load_gate()

    ledger = gate.load_ledger(LEDGER_PATH)
    report = gate.audit_ledger(ledger, repo_root=REPO_ROOT)

    assert report.errors == ()
    assert {entry["id"] for entry in ledger["guarantees"]} == set(
        gate.REQUIRED_GUARANTEE_IDS
    )
    assert ledger["donor"]["commit"] == ("ab769f182942f83191d883151d74b78fecac43cb")


def test_strict_gate_accepts_complete_runtime_integration() -> None:
    gate = _load_gate()

    ledger = gate.load_ledger(LEDGER_PATH)
    report = gate.audit_ledger(
        ledger,
        repo_root=REPO_ROOT,
        require_integrated=True,
    )

    assert report.errors == ()
    assert report.pending_ids == ()
    assert report.passed is True
