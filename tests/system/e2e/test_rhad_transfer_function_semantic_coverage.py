"""Semantic-coverage regression for a second Rhadamanthys loader function."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("idapro")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_PROBE = (
    _REPO
    / "tools"
    / "scripts"
    / "rhad_investigation"
    / "probe_transfer_function.py"
)
_FUNCTION_EA = 0x40D200
_FUNCTION_END = 0x40F82F
_TERMINAL_JMP_EA = 0x40DACE


@pytest.mark.skipif(not _BINARY.exists(), reason="real loader fixture unavailable")
def test_second_real_loader_recovers_more_semantics_than_native_range_oracle(
    tmp_path: pathlib.Path,
) -> None:
    """Recover more body semantics without claiming complete unflattening."""
    binary = tmp_path / _BINARY.name
    output_path = tmp_path / "sub_40D200.c"
    transfer_path = tmp_path / "sub_40D200.transfers.json"
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
    # Two proven frontiers still render as JUMPOUTs today. Improvements may
    # remove them, but a regression must not introduce additional frontiers.
    assert recovered.count("JUMPOUT(") <= 2
    assert recovered.count("while (") == 1
    assert (
        "while ( **(_DWORD **)(WindowLongA + 8) "
        "!= *(_DWORD *)(WindowLongA + 8) )"
    ) in recovered
    assert "free(v149);" in recovered
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
        row
        for row in transfers
        if int(row["source_jmp_ea"], 0) == _TERMINAL_JMP_EA
        and row["resolver_kind"] == "detached_static_fixpoint"
    ]
    assert len(terminal_rows) == 1
    assert set(terminal_rows[0]["target_eas"]) == {"0x40D381", "0x40E5C0"}
    assert "TRANSFER_RESULT" in log_text
    assert "while1=0" in log_text
