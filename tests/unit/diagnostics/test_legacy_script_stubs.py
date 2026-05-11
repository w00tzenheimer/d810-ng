"""Tests that the deprecated tools/scripts/*.py stubs do not silently
fall back to old logic, and that wrappers forward to the right
``d810.diagnostics`` subcommand.

The implementations these scripts used to host were migrated as part of
the 2026-05-11 debug-tooling roadmap; see
``docs/debug-tooling-migration.md`` for the command map.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "tools" / "scripts"


def _subprocess_env() -> dict:
    """Inject the worktree's src/ into PYTHONPATH so the stub's
    forward-exec finds d810.diagnostics."""
    import os
    env = os.environ.copy()
    src = str(REPO_ROOT / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src}:{existing}" if existing else src
    return env


# ---------------------------------------------------------------------------
# Wrapper stubs (terminal_tail_audit, gate_audit, reconcile_dispatcher_redirects)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "script,diag_command",
    [
        ("terminal_tail_audit.py", "terminal-tail-audit"),
        ("gate_audit.py", "gate-audit"),
        ("reconcile_dispatcher_redirects.py", "redirect-reconcile"),
    ],
)
def test_wrapper_stub_emits_deprecation_notice_and_forwards_help(
    script: str, diag_command: str,
) -> None:
    """The wrapper stub must print a `[deprecated]` line on stderr and
    exec into ``python -m d810.diagnostics <subcommand> --help``."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / script), "--help"],
        capture_output=True,
        text=True,
        env=_subprocess_env(),
        cwd=str(REPO_ROOT),
    )
    # Forward succeeded (--help always exits 0).
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert "[deprecated]" in result.stderr
    assert f"d810.diagnostics {diag_command}" in result.stderr
    # The forwarded command's usage line should mention the diag subcommand.
    assert f"d810.diagnostics {diag_command}" in result.stdout


@pytest.mark.parametrize(
    "script",
    [
        "terminal_tail_audit.py",
        "gate_audit.py",
        "reconcile_dispatcher_redirects.py",
    ],
)
def test_wrapper_stub_contains_no_legacy_implementation(script: str) -> None:
    """The stub file must not retain the old SQL / report logic."""
    text = (SCRIPTS / script).read_text()
    assert "[deprecated]" in text
    # Sanity check: no SQL string, no Counter/dataclass-heavy logic.
    assert "SELECT" not in text
    assert "Counter(" not in text
    # Stub should not redefine the legacy "main()" entry point.
    assert "def main(" not in text


# ---------------------------------------------------------------------------
# Failing stub: return_family_ledger
# ---------------------------------------------------------------------------


def test_return_family_ledger_stub_fails_with_replacement_message() -> None:
    """Legacy `return_family_ledger.py` had a positional dump-file CLI that
    auto-discovered the diag DB; that does not map to the new
    --db / --dump shape, so the stub must FAIL rather than silently
    translate arguments."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "return_family_ledger.py"), ".tmp/somefile.txt"],
        capture_output=True,
        text=True,
        env=_subprocess_env(),
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 2
    assert "[deprecated]" in result.stderr
    assert "cff_debug.py returns" in result.stderr
    assert "d810.diagnostics return-ledger" in result.stderr


def test_return_family_ledger_stub_contains_no_legacy_implementation() -> None:
    text = (SCRIPTS / "return_family_ledger.py").read_text()
    assert "[deprecated]" in text
    assert "SELECT" not in text
    assert "BLT_STOP" not in text
    assert "def main(" not in text


# ---------------------------------------------------------------------------
# inspect_hodur_dump.sh (bash wrapper with positional -> flag translation)
# ---------------------------------------------------------------------------


def test_inspect_hodur_dump_sh_forwards_to_cff_debug_inspect(
    tmp_path: Path,
) -> None:
    """The bash stub must accept a positional dump file and forward to
    `./tools/cff_debug.py inspect --dump <file>`."""
    if shutil.which("bash") is None:
        pytest.skip("bash not available")
    dump = tmp_path / "tiny.txt"
    dump.write_text("=== nothing interesting ===\n")
    result = subprocess.run(
        ["bash", str(SCRIPTS / "inspect_hodur_dump.sh"), str(dump)],
        capture_output=True,
        text=True,
        env=_subprocess_env(),
        cwd=str(REPO_ROOT),
        timeout=30,
    )
    # Forward succeeded; the inspect command should run cleanly even on a
    # minimal dump (every probe just prints "(none)" if no match).
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert "[deprecated]" in result.stderr
    assert "cff_debug.py inspect" in result.stderr
    # The forwarded command emits banner lines for each probe.
    assert "=== Gate Failures ===" in result.stdout


def test_inspect_hodur_dump_sh_contains_no_legacy_implementation() -> None:
    text = (SCRIPTS / "inspect_hodur_dump.sh").read_text()
    assert "[deprecated]" in text
    # No legacy rg/sed probe blocks should remain.
    assert "Gate accounting" not in text
    assert "RECON DAG: accepted" not in text
    assert "verify_failed" not in text
