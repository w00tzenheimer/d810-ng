from __future__ import annotations

from pathlib import Path

import pytest

from tools import cff_debug


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
    monkeypatch.setattr(cff_debug, "REPO_ROOT", tmp_path)
    log_dir = _log_dir(tmp_path, "wt")
    good = log_dir / "good.diag.sqlite3"
    good.write_bytes(b"sqlite data")
    empty = log_dir / "newer-empty.diag.sqlite3"
    empty.write_bytes(b"")

    # Make the empty placeholder newer than the valid DB.
    good.touch()
    empty.touch()

    assert cff_debug.latest_db("wt") == good


def test_latest_db_errors_when_only_empty_sqlite_placeholders_exist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cff_debug, "REPO_ROOT", tmp_path)
    log_dir = _log_dir(tmp_path, "wt")
    (log_dir / "empty.diag.sqlite3").write_bytes(b"")

    with pytest.raises(SystemExit):
        cff_debug.latest_db("wt")
