"""Tests for the renamed D810 operator CLI and legacy shim."""
from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tools import d810cli


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


def _worktree_log_dir(repo_root: Path, worktree: str) -> Path:
    """Create the d810 log layout under pytest's tempfile-backed tmp_path."""
    path = (
        repo_root
        / ".worktrees"
        / worktree
        / ".tmp"
        / "logs"
        / "d810_logs"
    )
    path.mkdir(parents=True)
    return path


def _make_temp_repo_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Create the minimal repo/worktree shape d810cli expects in tmp_path."""
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    wt = tmp_path / ".worktrees" / "wt"
    (wt / "src").mkdir(parents=True)
    return wt


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


def test_dump_help_recommends_full_diagnostics_recipe() -> None:
    result = _run_tool("d810cli.py", "dump", "--help")

    assert result.returncode == 0, (result.returncode, result.stderr)
    normalized_stdout = " ".join(result.stdout.split()).replace("- ", "-")
    assert "--full-diagnostics" in result.stdout
    assert "d810cli dump -f FUNC_NAME" in result.stdout
    if d810cli.DEFAULT_WORKTREE:
        assert (
            f"default: {d810cli.DEFAULT_WORKTREE}, inferred from script path"
            in normalized_stdout
        )
    else:
        assert "default: current root checkout" in normalized_stdout
    assert "short name" in result.stdout
    assert "Unflattening debug recipe" in result.stdout
    assert "--dump-microcode-maturity LOCOPT,CALLS,GLBOPT1" in result.stdout
    assert "--dump-bst-maturity CALLS,GLBOPT1,GLBOPT2" in result.stdout


def test_root_checkout_defaults_to_repo_root_without_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(d810cli, "DEFAULT_WORKTREE", None)
    parser = d810cli.build_parser()
    args = parser.parse_args(["paths"])

    assert args.worktree is None
    assert d810cli.worktree_dir(args.worktree) == tmp_path


def test_users_can_pass_worktree_by_short_or_long_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "DEFAULT_WORKTREE", None)
    parser = d810cli.build_parser()

    short_args = parser.parse_args(["paths", "-w", "engine-wrapper-parity"])
    long_args = parser.parse_args(["paths", "--worktree", "badwhile-followup-lanes"])

    assert short_args.worktree == "engine-wrapper-parity"
    assert long_args.worktree == "badwhile-followup-lanes"


def test_worktree_checkout_can_infer_current_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(d810cli, "DEFAULT_WORKTREE", "current-feature")
    wt = tmp_path / ".worktrees" / "current-feature"
    wt.mkdir(parents=True)
    parser = d810cli.build_parser()
    args = parser.parse_args(["paths"])

    assert args.worktree == "current-feature"
    assert d810cli.worktree_dir(args.worktree) == wt


def test_dump_full_diagnostics_expands_recon_diag_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wt = _make_temp_repo_worktree(tmp_path, monkeypatch)
    monkeypatch.setattr(d810cli, "DOCKER_RUNNER", tmp_path / "run_system_tests_docker.sh")

    calls: list[tuple[list[str], dict[str, str], str]] = []

    def fake_call(
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> int:
        assert env is not None
        assert cwd is not None
        calls.append((argv, env, cwd))
        db = wt / ".tmp" / "logs" / "d810_logs" / "fresh.diag.sqlite3"
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_bytes(b"sqlite data")
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)

    rc = d810cli.cmd_dump(
        argparse.Namespace(
            worktree="wt",
            function="test_function_ollvm_fla_bcf_sub",
            project="default_unflattening_ollvm.json",
            prefix="dump",
            label="ollvm",
            capture_post_maturity="8",
            no_debug_logging=False,
            full_diagnostics=True,
            extra=None,
        )
    )

    assert rc == 0
    assert len(calls) == 1
    argv, env, cwd = calls[0]
    assert cwd == str(tmp_path)
    assert env["D810_CAPTURE_POST_MATURITY"] == "8"
    assert argv[:2] == [str(tmp_path / "run_system_tests_docker.sh"), "dump"]
    assert argv[argv.index("-w") + 1] == "wt"
    assert "-l" in argv
    assert "--enable-debug-logging" in argv
    assert "--enable-diag-snapshot" in argv
    assert "-m" in argv
    assert "pseudocode_dump" in argv
    assert "--dump-microcode-maturity" in argv
    assert "LOCOPT,CALLS,GLBOPT1" in argv
    assert "--dump-microcode-d810" in argv
    assert "--dump-terminal-return-valranges" in argv
    assert "--dump-bst-maturity" in argv
    assert "CALLS,GLBOPT1,GLBOPT2" in argv


def test_dump_without_worktree_uses_root_checkout_and_omits_runner_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(d810cli, "DOCKER_RUNNER", tmp_path / "run_system_tests_docker.sh")
    (tmp_path / "src").mkdir()
    calls: list[tuple[list[str], dict[str, str], str]] = []

    def fake_call(
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> int:
        assert env is not None
        assert cwd is not None
        calls.append((argv, env, cwd))
        db = tmp_path / ".tmp" / "logs" / "d810_logs" / "fresh.diag.sqlite3"
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_bytes(b"sqlite data")
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)

    rc = d810cli.cmd_dump(
        argparse.Namespace(
            worktree=None,
            function="test_function_ollvm_fla_bcf_sub",
            project="default_unflattening_ollvm.json",
            prefix="dump",
            label="ollvm",
            capture_post_maturity="8",
            no_debug_logging=False,
            full_diagnostics=True,
            extra=None,
        )
    )

    assert rc == 0
    assert len(calls) == 1
    argv, env, cwd = calls[0]
    assert cwd == str(tmp_path)
    assert env["D810_REPO_ROOT"] == str(tmp_path)
    assert "-w" not in argv
    assert (tmp_path / ".tmp" / "logs" / "d810_logs" / "d810.log").is_file()


def _write_minimal_capture_dump(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "FUNCTION: test_xor @ 0x180012340",
                "BINARY: libobfuscated.dll",
                "PROJECT: example_libobfuscated.json",
                "CODE_CHANGED: True",
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


def test_pseudocode_capture_without_dump_uses_default_dump_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wt = _make_temp_repo_worktree(tmp_path, monkeypatch)
    monkeypatch.setattr(d810cli, "DOCKER_RUNNER", tmp_path / "run_system_tests_docker.sh")
    db = tmp_path / "capture.sqlite3"
    calls: list[list[str]] = []

    def fake_call(argv: list[str], **_kwargs) -> int:
        calls.append(argv)
        output_name = argv[argv.index("-o") + 1]
        _write_minimal_capture_dump(wt / ".tmp" / output_name)
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)

    rc = d810cli.cmd_pseudocode_capture(
        argparse.Namespace(
            worktree="wt",
            function="test_xor",
            project="example_libobfuscated.json",
            db=str(db),
            dump=None,
            binary_name=None,
            prefix="pseudocode_capture",
            label="capture",
            capture_post_maturity="8",
            no_debug_logging=False,
            extra=None,
        )
    )

    assert rc == 0
    assert len(calls) == 1
    assert "-m" in calls[0]
    assert "pseudocode_dump" in calls[0]
    assert "--enable-diag-snapshot" not in calls[0]
    assert db.is_file()


def test_trace_uses_default_dump_diagnostics_without_full_diagnostics_attr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_temp_repo_worktree(tmp_path, monkeypatch)
    monkeypatch.setattr(d810cli, "DOCKER_RUNNER", tmp_path / "run_system_tests_docker.sh")
    calls: list[list[str]] = []

    def fake_call(argv: list[str], **_kwargs) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)

    rc = d810cli.cmd_trace(
        argparse.Namespace(
            worktree="wt",
            function="sub_7FFD3338C040",
            project="hodur_flag2.json",
            prefix="trace",
            label="hcc",
            capture_post_maturity="8",
            no_debug_logging=False,
            extra=None,
            json_output=False,
        )
    )

    assert rc == 0
    assert len(calls) == 2
    assert calls[0][:2] == [str(tmp_path / "run_system_tests_docker.sh"), "dump"]
    assert "-m" in calls[0]
    assert "pseudocode_dump" in calls[0]
    assert "--enable-diag-snapshot" not in calls[0]
    assert calls[1][1:3] == ["-m", "d810.diagnostics"]


def test_latest_db_ignores_zero_byte_sqlite_placeholders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    log_dir = _worktree_log_dir(tmp_path, "wt")
    good = log_dir / "good.diag.sqlite3"
    good.write_bytes(b"sqlite data")
    empty = log_dir / "newer-empty.diag.sqlite3"
    empty.write_bytes(b"")

    # Make the empty placeholder newer than the valid DB.
    good.touch()
    empty.touch()

    assert d810cli.latest_db("wt") == good


def test_latest_db_errors_when_only_empty_sqlite_placeholders_exist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    log_dir = _worktree_log_dir(tmp_path, "wt")
    (log_dir / "empty.diag.sqlite3").write_bytes(b"")

    with pytest.raises(SystemExit):
        d810cli.latest_db("wt")


def _write_diag_db(path: Path, *, indirect_rows: bool) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE state_dispatcher_rows (dispatcher_kind TEXT)"
        )
        if indirect_rows:
            conn.execute(
                "INSERT INTO state_dispatcher_rows VALUES ('INDIRECT_JUMP')"
            )
        conn.commit()
    finally:
        conn.close()


def test_latest_indirect_transfer_db_skips_newer_non_indirect_db(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    log_dir = _worktree_log_dir(tmp_path, "wt")
    indirect = log_dir / "older-indirect.diag.sqlite3"
    non_indirect = log_dir / "newer-other.diag.sqlite3"
    _write_diag_db(indirect, indirect_rows=True)
    _write_diag_db(non_indirect, indirect_rows=False)

    indirect.touch()
    non_indirect.touch()

    assert d810cli.latest_indirect_transfer_db("wt") == indirect


def test_latest_indirect_transfer_db_errors_without_indirect_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    log_dir = _worktree_log_dir(tmp_path, "wt")
    _write_diag_db(log_dir / "other.diag.sqlite3", indirect_rows=False)

    with pytest.raises(SystemExit):
        d810cli.latest_indirect_transfer_db("wt")


def test_after_stats_appends_stats_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wt = _make_temp_repo_worktree(tmp_path, monkeypatch)
    dump = wt / ".tmp" / "dump.txt"
    dump.parent.mkdir()
    dump.write_text("--- AFTER ---\nbody\n=== STATS: f ===\nAFTER: lines=1\n")

    subprocess_calls: list[list[str]] = []
    stats_calls: list[argparse.Namespace] = []

    def fake_call(
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
    ) -> int:
        subprocess_calls.append(argv)
        assert env is not None
        assert str(wt / "src") in env["PYTHONPATH"]
        return 0

    def fake_stats(args: argparse.Namespace) -> int:
        stats_calls.append(args)
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)
    monkeypatch.setattr(d810cli, "cmd_stats", fake_stats)

    rc = d810cli.cmd_after(
        argparse.Namespace(
            worktree="wt",
            dump=str(dump),
            line_numbers=True,
            stats=True,
        )
    )

    assert rc == 0
    assert subprocess_calls
    assert subprocess_calls[0][-1] == "-n"
    assert len(stats_calls) == 1
    assert stats_calls[0].worktree == "wt"
    assert stats_calls[0].dump == str(dump.resolve())


def test_after_stats_does_not_run_when_after_renderer_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wt = _make_temp_repo_worktree(tmp_path, monkeypatch)
    dump = wt / ".tmp" / "dump.txt"
    dump.parent.mkdir()
    dump.write_text("--- AFTER ---\nbody\n")

    monkeypatch.setattr(subprocess, "call", lambda *args, **kwargs: 7)

    def fail_stats(args: argparse.Namespace) -> int:
        raise AssertionError("stats should not run after dump-after failure")

    monkeypatch.setattr(d810cli, "cmd_stats", fail_stats)

    rc = d810cli.cmd_after(
        argparse.Namespace(
            worktree="wt",
            dump=str(dump),
            line_numbers=False,
            stats=True,
        )
    )

    assert rc == 7


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
