from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pytest

from tools import d810cli


def _log_dir(repo_root: Path, worktree: str) -> Path:
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


def test_latest_db_ignores_zero_byte_sqlite_placeholders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    log_dir = _log_dir(tmp_path, "wt")
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
    log_dir = _log_dir(tmp_path, "wt")
    (log_dir / "empty.diag.sqlite3").write_bytes(b"")

    with pytest.raises(SystemExit):
        d810cli.latest_db("wt")


def _make_worktree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(d810cli, "REPO_ROOT", tmp_path)
    wt = tmp_path / ".worktrees" / "wt"
    (wt / "src").mkdir(parents=True)
    return wt


def test_after_stats_appends_stats_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wt = _make_worktree(tmp_path, monkeypatch)
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
    wt = _make_worktree(tmp_path, monkeypatch)
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
