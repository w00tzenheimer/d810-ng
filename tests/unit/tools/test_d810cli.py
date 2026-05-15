"""Tests for the renamed D810 operator CLI and legacy shim."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS = REPO_ROOT / "tools"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    src = str(REPO_ROOT / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src}:{existing}" if existing else src
    return env


def _run_tool(tool: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOLS / tool), *args],
        capture_output=True,
        text=True,
        env=_env(),
        cwd=str(REPO_ROOT),
        timeout=30,
    )


@pytest.mark.parametrize("tool", ["d810cli.py", "cff_debug.py"])
def test_cli_help_works_through_new_name_and_legacy_shim(tool: str) -> None:
    result = _run_tool(tool, "--help")

    assert result.returncode == 0, (result.returncode, result.stderr)
    assert "usage: d810cli" in result.stdout
    if tool == "cff_debug.py":
        assert "[deprecated]" in result.stderr
        assert "tools/d810cli.py" in result.stderr


@pytest.mark.parametrize("tool", ["d810cli.py", "cff_debug.py"])
def test_after_help_works_through_new_name_and_legacy_shim(tool: str) -> None:
    result = _run_tool(tool, "after", "--help")

    assert result.returncode == 0, (result.returncode, result.stderr)
    assert "usage: d810cli after" in result.stdout
    if tool == "cff_debug.py":
        assert "[deprecated]" in result.stderr


def test_d810cli_pseudocode_capture_from_existing_dump(tmp_path: Path) -> None:
    dump = tmp_path / "dump.txt"
    db = tmp_path / "capture.sqlite3"
    dump.write_text(
        "\n".join(
            [
                "FUNCTION: test_xor @ 0x180012340",
                "BINARY: libobfuscated.dll",
                "PROJECT: example_libobfuscated.json",
                "CODE_CHANGED: True",
                "RULES_FIRED (instruction):",
                "  XorRule",
                "",
                "--- BEFORE ---",
                "int test_xor()",
                "{",
                "  return a + b - 2 * (a & b);",
                "}",
                "",
                "--- AFTER ---",
                "int test_xor()",
                "{",
                "  return a ^ b;",
                "}",
                "=== STATS: test_xor ===",
            ]
        )
        + "\n"
    )

    result = _run_tool(
        "d810cli.py",
        "pseudocode",
        "capture",
        "--function",
        "test_xor",
        "--project",
        "example_libobfuscated.json",
        "--db",
        str(db),
        "--dump",
        str(dump),
    )

    assert result.returncode == 0, (result.returncode, result.stderr)
    assert "FUNCTION=test_xor" in result.stdout
    assert f"DB={db}" in result.stdout
    conn = sqlite3.connect(db)
    try:
        stored = conn.execute(
            "SELECT function_name, project_config, code_changed FROM pseudocode_capture"
        ).fetchone()
    finally:
        conn.close()
    assert stored == ("test_xor", "example_libobfuscated.json", 1)
