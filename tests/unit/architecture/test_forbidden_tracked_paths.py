"""Repository policy for local-only planning and SDD artifacts."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.check_forbidden_tracked_paths import (
    FORBIDDEN_TRACKED_PREFIXES,
    forbidden_tracked_paths,
    main,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_forbidden_prefixes_cover_every_local_only_work_tree() -> None:
    assert FORBIDDEN_TRACKED_PREFIXES == (
        ".superpowers/sdd",
        "docs/plans",
        "docs/superpowers",
    )
    assert forbidden_tracked_paths(
        (
            ".superpowers/sdd/task/report.md",
            "docs/plans/design.md",
            "docs/superpowers/specs/spec.md",
            "docs/features/public.md",
            "src/d810/passes/example.py",
        )
    ) == (
        ".superpowers/sdd/task/report.md",
        "docs/plans/design.md",
        "docs/superpowers/specs/spec.md",
    )


def test_current_repository_tracks_no_local_only_work_artifacts() -> None:
    tracked = subprocess.run(
        ("git", "ls-files", "-z"),
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8").split("\0")

    assert forbidden_tracked_paths(tracked) == ()


def test_staged_and_tree_modes_reject_forced_additions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    subprocess.run(("git", "init", "-q"), cwd=tmp_path, check=True)
    forbidden = tmp_path / "docs" / "plans" / "private.md"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("local plan\n", encoding="utf-8")
    subprocess.run(("git", "add", "-f", "docs/plans/private.md"), cwd=tmp_path, check=True)

    assert main(("--repo-root", str(tmp_path), "--staged")) == 1
    captured = capsys.readouterr()
    assert "docs/plans/private.md" in captured.err

    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Policy Test",
            "-c",
            "user.email=policy@example.invalid",
            "commit",
            "-qm",
            "forced addition",
        ),
        cwd=tmp_path,
        check=True,
    )
    assert main(("--repo-root", str(tmp_path), "--tree", "HEAD")) == 1
    captured = capsys.readouterr()
    assert "docs/plans/private.md" in captured.err
