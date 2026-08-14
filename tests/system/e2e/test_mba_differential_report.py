"""Docker-safe E2E coverage for the IDA-free MBA differential report CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CLI = _REPO_ROOT / "tools/scripts/mba_differential_report.py"


def _profile() -> dict[str, object]:
    return {
        "width_bits": 32,
        "operator_count": 2,
        "total_node_count": 5,
        "distinct_leaf_count": 2,
        "constant_count": 1,
        "operations": [["add", 1], ["and", 1]],
        "has_boolean": True,
        "has_arithmetic": True,
        "nonlinear_product_count": 0,
        "island_class": "linear_mba",
        "blockers": [],
        "fingerprint": "docker-case",
    }


def _outcome(provider: str, status: str) -> dict[str, object]:
    return {
        "provider": provider,
        "status": status,
        "fingerprint": "docker-case",
        "input_cost": [3, 5],
        "output_cost": [1, 2] if status == "applied" else None,
        "proof_verdict": True if status == "applied" else None,
        "elapsed_ms": 1.0,
        "source_provenance": [],
        "refusal_reason": None,
        "metadata": {},
        "matcher": None,
    }


def _write_rows(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(rows), encoding="utf-8")


def _run_cli(tmp_path: Path, *input_paths: Path) -> subprocess.CompletedProcess[str]:
    out_path = tmp_path / "report.json"
    env = os.environ | {"PYTHONPATH": str(_REPO_ROOT / "src")}
    return subprocess.run(
        [
            sys.executable,
            str(_CLI),
            "--out",
            str(out_path),
            "--providers",
            "catalogue,egglog",
            *(str(path) for path in input_paths),
        ],
        cwd=_REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_differential_report_cli_requires_one_explicit_provider_row_per_case(
    tmp_path: Path,
) -> None:
    catalogue_path = tmp_path / "catalogue.json"
    egglog_path = tmp_path / "egglog.json"
    _write_rows(
        catalogue_path,
        [
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": _profile(),
                "outcome": _outcome("catalogue", "applied"),
            }
        ],
    )
    _write_rows(
        egglog_path,
        [
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": _profile(),
                "outcome": _outcome("egglog", "unavailable"),
            }
        ],
    )

    completed = _run_cli(tmp_path, catalogue_path, egglog_path)

    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["by_provider"]["egglog"]["unavailable"] == 1
    assert "| egglog |" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_differential_report_cli_rejects_omitted_provider_rows(tmp_path: Path) -> None:
    catalogue_path = tmp_path / "catalogue.json"
    _write_rows(
        catalogue_path,
        [
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": _profile(),
                "outcome": _outcome("catalogue", "applied"),
            }
        ],
    )

    completed = _run_cli(tmp_path, catalogue_path)

    assert completed.returncode == 2
    assert "missing outcome rows for egglog" in completed.stderr


def test_differential_report_cli_rejects_duplicate_applied_mutations(
    tmp_path: Path,
) -> None:
    catalogue_path = tmp_path / "catalogue.json"
    egglog_path = tmp_path / "egglog.json"
    _write_rows(
        catalogue_path,
        [
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": _profile(),
                "outcome": _outcome("catalogue", "applied"),
            }
        ],
    )
    _write_rows(
        egglog_path,
        [
            {
                "case_id": "case",
                "stratum": "direct",
                "profile": _profile(),
                "outcome": _outcome("egglog", "applied"),
            }
        ],
    )

    completed = _run_cli(tmp_path, catalogue_path, egglog_path)

    assert completed.returncode == 2
    assert "at most one applied provider" in completed.stderr
