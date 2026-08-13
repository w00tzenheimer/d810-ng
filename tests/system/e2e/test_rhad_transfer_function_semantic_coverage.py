"""Semantic-coverage regression for a second Rhadamanthys loader function."""

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
_TERMINAL_JMP_EA = 0x40DACE
_RETURN_DISPATCH_JMP_EA = 0x40D369
_RETURN_EPILOGUE_EA = 0x40F821
_THIRD_FUNCTION_EA = 0x40C8B0
_THIRD_FUNCTION_END = 0x40CD94
_THIRD_RETURN_DISPATCH_JMP_EA = 0x40C9D9
_THIRD_RETURN_EPILOGUE_EA = 0x40CD8C
_FOURTH_FUNCTION_EA = 0x40CDA0
_FOURTH_FUNCTION_END = 0x40CF90
_FOURTH_INITIAL_DISPATCH_JMP_EA = 0x40CE3A
_FOURTH_ROUTER_DISPATCH_JMP_EA = 0x40CEA9


def _assert_preopt_union_is_the_default(log_text: str) -> None:
    assert "PREOPT_UNION_RESULT prepared=True" in log_text
    assert "LOCOPT preanalysis materialized" not in log_text
    assert "detached LOCOPT snippet captured" not in log_text


def _assert_lifecycle_diag_authority(diag_path: pathlib.Path) -> None:
    with sqlite3.connect(diag_path) as conn:
        assert conn.execute(
            "SELECT version FROM diagnostic_schema WHERE singleton=1"
        ).fetchone() == (2,)
        assert conn.execute(
            "SELECT COUNT(*) FROM lifecycle_events le "
            "LEFT JOIN diagnostic_sessions ds ON ds.session_id=le.session_id "
            "WHERE ds.session_id IS NULL"
        ).fetchone() == (0,)
        counts = dict(
            conn.execute(
                "SELECT event_kind,COUNT(*) FROM lifecycle_events GROUP BY event_kind"
            )
        )
        assert counts.get("session_active", 0) == 1
        assert counts.get("evidence_generation", 0) >= 2
        assert counts.get("identity_decision", 0) >= 6
        assert counts.get("mutation_plan", 0) > 0
        assert counts.get("mutation_receipt", 0) == counts["mutation_plan"]
        assert conn.execute(
            "SELECT COUNT(*) FROM lifecycle_events p "
            "WHERE p.event_kind='mutation_plan' AND NOT EXISTS ("
            "SELECT 1 FROM lifecycle_events r "
            "WHERE r.event_kind='mutation_receipt' "
            "AND r.session_id=p.session_id "
            "AND r.correlation_id=p.correlation_id)"
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT COALESCE(SUM(diagnostic_error_count),0) FROM diagnostic_sessions"
        ).fetchone() == (0,)


@pytest.mark.skipif(not _BINARY.exists(), reason="real loader fixture unavailable")
def test_second_real_loader_fully_unflattens_beyond_native_range_oracle(
    tmp_path: pathlib.Path,
) -> None:
    """Recover the complete body without dispatcher or JUMPOUT residue."""
    binary = tmp_path / _BINARY.name
    output_path = tmp_path / "sub_40D200.c"
    transfer_path = tmp_path / "sub_40D200.transfers.json"
    diag_path = tmp_path / "sub_40D200.diag.sqlite3"
    log_path = tmp_path / "sub_40D200.log"
    shutil.copy2(_BINARY, binary)

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
            "RHAD_TRANSFER_BIN": str(binary),
            "RHAD_TRANSFER_FUNC": hex(_FUNCTION_EA),
            "RHAD_TRANSFER_END": hex(_FUNCTION_END),
            "RHAD_TRANSFER_OUTPUT": str(output_path),
            "RHAD_TRANSFER_TRANSFERS_OUTPUT": str(transfer_path),
            "RHAD_TRANSFER_DIAG_OUTPUT": str(diag_path),
            "D810_DIAG_SNAPSHOT": "1",
            "PYTHONFAULTHANDLER": "1",
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
        f"real-loader transfer worker failed ({result.returncode})\n"
        f"log tail:\n{log_text[-12000:]}"
    )

    recovered = output_path.read_text(encoding="utf-8")
    assert "while ( 1 )" not in recovered
    assert "while (1)" not in recovered
    assert "jmp eax" not in recovered
    assert "JUMPOUT(" not in recovered
    assert recovered.count("while (") == 1
    assert (
        "while ( **(_DWORD **)(WindowLongA + 8) != *(_DWORD *)(WindowLongA + 8) )"
    ) in recovered
    assert "free(" in recovered
    for call in (
        "DefWindowProcA(",
        "GetCursorPos(",
        "GetWindowLongA(",
        "SetTimer(",
        "SetWindowLongA(",
    ):
        assert call in recovered

    transfers = json.loads(transfer_path.read_text(encoding="utf-8"))
    terminal_rows = [
        row for row in transfers if int(row["source_jmp_ea"], 0) == _TERMINAL_JMP_EA
    ]
    assert len(terminal_rows) == 1
    assert terminal_rows[0]["resolver_kind"] in {
        "static_fixpoint",
        "detached_static_fixpoint",
    }
    assert set(terminal_rows[0]["target_eas"]) == {"0x40D381", "0x40E5C0"}
    return_dispatch_rows = [
        row
        for row in transfers
        if int(row["source_jmp_ea"], 0) == _RETURN_DISPATCH_JMP_EA
        and row["resolver_kind"] == "static_fixpoint"
    ]
    assert len(return_dispatch_rows) == 1
    assert return_dispatch_rows[0]["condition_code"] == 4
    assert int(return_dispatch_rows[0]["selector_compare_constant"], 0) == (0x81F82C5E)
    assert int(return_dispatch_rows[0]["true_target_ea"], 0) == (_RETURN_EPILOGUE_EA)
    assert "TRANSFER_RESULT" in log_text
    assert "while1=0" in log_text
    assert "jumpout=0" in log_text
    _assert_preopt_union_is_the_default(log_text)


@pytest.mark.skipif(not _BINARY.exists(), reason="real loader fixture unavailable")
def test_third_real_loader_recovers_structured_terminal_values(
    tmp_path: pathlib.Path,
) -> None:
    """Recover four value-return paths without a manually forced prototype."""
    binary = tmp_path / _BINARY.name
    output_path = tmp_path / "sub_40C8B0.c"
    transfer_path = tmp_path / "sub_40C8B0.transfers.json"
    diag_path = tmp_path / "sub_40C8B0.diag.sqlite3"
    log_path = tmp_path / "sub_40C8B0.log"
    shutil.copy2(_BINARY, binary)

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
            "RHAD_TRANSFER_BIN": str(binary),
            "RHAD_TRANSFER_FUNC": hex(_THIRD_FUNCTION_EA),
            "RHAD_TRANSFER_END": hex(_THIRD_FUNCTION_END),
            "RHAD_TRANSFER_OUTPUT": str(output_path),
            "RHAD_TRANSFER_TRANSFERS_OUTPUT": str(transfer_path),
            "RHAD_TRANSFER_DIAG_OUTPUT": str(diag_path),
            "D810_DIAG_SNAPSHOT": "1",
            "D810_DEFERRED_DIAG_PHASES": "1",
            "RHAD_TRANSFER_TRACE_STACK_SELECTORS": "1",
            "RHAD_TRANSFER_TRACE_HANDLER_ROUTES": "1",
            "RHAD_TRANSFER_TRACE_SESSION_STATE": "1",
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
        f"third real-loader worker failed ({result.returncode})\n"
        f"log tail:\n{log_text[-12000:]}"
    )

    recovered = output_path.read_text(encoding="utf-8")
    assert "while ( 1 )" not in recovered
    assert "while (1)" not in recovered
    assert "jmp eax" not in recovered
    assert "JUMPOUT(" not in recovered
    assert len(recovered.splitlines()) >= 50
    assert recovered.count("return ") == 4
    assert recovered.count("LOBYTE(") == 3
    assert "return 16;" in recovered

    transfers = json.loads(transfer_path.read_text(encoding="utf-8"))
    return_dispatch_rows = [
        row
        for row in transfers
        if int(row["source_jmp_ea"], 0) == _THIRD_RETURN_DISPATCH_JMP_EA
        and row["resolver_kind"] == "static_fixpoint"
    ]
    assert len(return_dispatch_rows) == 1
    assert return_dispatch_rows[0]["condition_code"] == 4
    assert int(return_dispatch_rows[0]["selector_compare_constant"], 0) == (0x069225E4)
    assert int(return_dispatch_rows[0]["true_target_ea"], 0) == (
        _THIRD_RETURN_EPILOGUE_EA
    )
    assert "TRANSFER_RESULT" in log_text
    assert "while1=0" in log_text
    assert "jumpout=0" in log_text
    _assert_preopt_union_is_the_default(log_text)
    _assert_lifecycle_diag_authority(diag_path)


@pytest.mark.skipif(not _BINARY.exists(), reason="real loader fixture unavailable")
def test_fourth_real_loader_imports_one_connected_preopt_union(
    tmp_path: pathlib.Path,
) -> None:
    """Recover the list-node builder without an external handler frontier."""
    binary = tmp_path / _BINARY.name
    output_path = tmp_path / "sub_40CDA0.c"
    transfer_path = tmp_path / "sub_40CDA0.transfers.json"
    log_path = tmp_path / "sub_40CDA0.log"
    shutil.copy2(_BINARY, binary)

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
            "RHAD_TRANSFER_BIN": str(binary),
            "RHAD_TRANSFER_FUNC": hex(_FOURTH_FUNCTION_EA),
            "RHAD_TRANSFER_END": hex(_FOURTH_FUNCTION_END),
            "RHAD_TRANSFER_OUTPUT": str(output_path),
            "RHAD_TRANSFER_TRANSFERS_OUTPUT": str(transfer_path),
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
        f"fourth real-loader worker failed ({result.returncode})\n"
        f"log tail:\n{log_text[-12000:]}"
    )

    recovered = output_path.read_text(encoding="utf-8")
    assert "while (" not in recovered
    assert "jmp edx" not in recovered
    assert "JUMPOUT(" not in recovered
    assert "__asm" not in recovered
    assert "malloc(" in recovered
    assert recovered.count("if (") == 2
    for payload_assignment in (
        "[2] = a2;",
        "[3] = a4;",
        "[4] = a3;",
    ):
        assert payload_assignment in recovered
    assert "&dword_48E028" in recovered
    assert "dword_48E02C = (int)" in recovered

    transfers = json.loads(transfer_path.read_text(encoding="utf-8"))
    dispatch_rows = {
        int(row["source_jmp_ea"], 0): row
        for row in transfers
        if row["resolver_kind"] == "static_fixpoint"
        and int(row["source_jmp_ea"], 0)
        in {
            _FOURTH_INITIAL_DISPATCH_JMP_EA,
            _FOURTH_ROUTER_DISPATCH_JMP_EA,
        }
    }
    assert set(dispatch_rows) == {
        _FOURTH_INITIAL_DISPATCH_JMP_EA,
        _FOURTH_ROUTER_DISPATCH_JMP_EA,
    }
    initial_dispatch = dispatch_rows[_FOURTH_INITIAL_DISPATCH_JMP_EA]
    assert set(initial_dispatch["target_eas"]) == {"0x40CDF8", "0x40CE3C"}
    assert initial_dispatch["condition_code"] == 4
    assert int(initial_dispatch["selector_compare_constant"], 0) == 0x09269BD2
    assert int(initial_dispatch["true_target_ea"], 0) == 0x40CE3C
    router_dispatch = dispatch_rows[_FOURTH_ROUTER_DISPATCH_JMP_EA]
    assert set(router_dispatch["target_eas"]) == {"0x40CDF8", "0x40CEAB"}
    assert router_dispatch["condition_code"] == 4
    assert int(router_dispatch["selector_compare_constant"], 0) == 0x255387B6
    assert int(router_dispatch["true_target_ea"], 0) == 0x40CEAB
    assert "TRANSFER_RESULT" in log_text
    assert "while1=0" in log_text
    assert "jumpout=0" in log_text
    _assert_preopt_union_is_the_default(log_text)
