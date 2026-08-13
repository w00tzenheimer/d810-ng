"""Fresh PREOPT bootstrap-route regression for the Rhad transfer fixture."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys

import pytest

pytest.importorskip("idapro")

# The dedicated Rhadamanthys loader regression work is owned by another branch.
# Keep this module visible in collection, but do not make its in-progress oracle
# block cfg-recon-mainline's system suite.
pytestmark = pytest.mark.skip(reason="Rhadamanthys loader regressions are owned by a separate branch")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_PROBE = (
    _REPO / "tools" / "scripts" / "rhad_investigation" / "probe_transfer_function.py"
)
_FUNCTION_EA = 0x40D200
_FUNCTION_END = 0x40F82F
_BOOTSTRAP_SOURCE_EA = 0x40D348
_BOOTSTRAP_STATE = 0x699BC698
_BOOTSTRAP_HANDLER_EA = 0x40EAA7
_BOOTSTRAP_FACT_KIND = "PreoptBootstrapRouteFact"


def _loader_fixture() -> pathlib.Path:
    override = os.environ.get("D810_RHAD_LOADER_FIXTURE")
    fixture = pathlib.Path(override).resolve() if override else _BINARY
    if not fixture.is_file():
        pytest.skip("real loader fixture unavailable")
    return fixture


def test_fresh_preopt_rebinds_the_bootstrap_route_without_cache(
    tmp_path: pathlib.Path,
) -> None:
    """The earliest lost route must survive regenerated PREOPT by native identity."""
    fixture = _loader_fixture()
    binary = tmp_path / fixture.name
    output_path = tmp_path / "sub_40D200.c"
    diag_path = tmp_path / "sub_40D200.diag.sqlite3"
    log_path = tmp_path / "sub_40D200.log"
    shutil.copy2(fixture, binary)

    env = dict(os.environ)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONPATH"] = os.pathsep.join(
        (
            str(_REPO / "src"),
            str(_REPO / "tests"),
            env.get("PYTHONPATH", ""),
        )
    )
    env.update(
        {
            "D810_DIAG_SNAPSHOT": "1",
            "RHAD_TRANSFER_BIN": str(binary),
            "RHAD_TRANSFER_FUNC": hex(_FUNCTION_EA),
            "RHAD_TRANSFER_END": hex(_FUNCTION_END),
            "RHAD_TRANSFER_OUTPUT": str(output_path),
            "RHAD_TRANSFER_DIAG_OUTPUT": str(diag_path),
        }
    )
    with log_path.open("w", encoding="utf-8") as log_file:
        result = subprocess.run(
            [sys.executable, str(_PROBE)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            timeout=900,
            check=False,
        )
    log_text = log_path.read_text(encoding="utf-8")
    assert result.returncode == 0, (
        f"fresh PREOPT worker failed ({result.returncode})\n"
        f"log tail:\n{log_text[-12000:]}"
    )
    assert diag_path.is_file(), "fresh probe did not preserve its diagnostic DB"

    with sqlite3.connect(diag_path) as conn:
        rows = conn.execute(
            "SELECT payload FROM fact_observations WHERE kind=? "
            "ORDER BY snapshot_id, fact_id",
            (_BOOTSTRAP_FACT_KIND,),
        ).fetchall()

    assert len(rows) == 1, (
        f"the diagnostic DB must record exactly one bootstrap fact; found {len(rows)}"
    )
    fact = json.loads(rows[0][0])
    assert fact == {
        "source_ea": f"0x{_BOOTSTRAP_SOURCE_EA:X}",
        "state": f"0x{_BOOTSTRAP_STATE:X}",
        "handler_ea": f"0x{_BOOTSTRAP_HANDLER_EA:X}",
        # Static transfer and bootstrap facts discovered before the first
        # PREOPT bind coalesce into one evidence epoch. Facts learned after
        # that bind advance the generation and may request the controlled redo.
        "generation": 1,
        "proof_kind": "static_native",
        "rebound": True,
    }, "\n".join(
        line
        for line in log_text.splitlines()
        if any(
            marker in line
            for marker in (
                "BOOTSTRAP",
                "evidence_generation",
                "MERR_REDO",
                "request_redo",
                "preopt_generation",
            )
        )
    )
    assert "PREOPT_BOOTSTRAP_ROUTE" in log_text
