"""Unit coverage for the SQLite-over-cifs locking probe's classifiers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools" / "scripts" / "sqlite_cifs_probe.py"


def _load_module():
    specification = importlib.util.spec_from_file_location("sqlite_cifs_probe", MODULE_PATH)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


probe = _load_module()


@pytest.mark.parametrize(
    "error,seconds,rows,expected",
    [
        ("database is locked", 2.1, 1, "blocked-then-locked"),
        ("database is busy", 1.6, 1, "blocked-then-locked"),
        ("database is locked", 0.05, 1, "immediate-error"),
        ("disk I/O error", 0.05, 1, "error"),
        (None, 0.1, 2, "lost-isolation"),
        (None, 0.1, 1, "unexpected-success"),
    ],
)
def test_contention_classification(
    error: str | None, seconds: float, rows: int, expected: str
) -> None:
    """Waiting then reporting 'locked' is CORRECT; an instant error is not."""
    assert probe.classify_contention(error, seconds, rows, 1) == expected


@pytest.mark.parametrize(
    "cifs,local,expected",
    [
        ("blocked-then-locked", "blocked-then-locked", "same as local"),
        ("ok", "ok", "same as local"),
        ("immediate-error", "blocked-then-locked", "CIFS FAILURE"),
        ("failed", "ok", "CIFS FAILURE"),
        ("lost-isolation", "blocked-then-locked", "CIFS FAILURE (isolation lost)"),
        ("unexpected-success", "blocked-then-locked", "differs (unexpected-success vs blocked-then-locked)"),
    ],
)
def test_verdict_compares_against_the_local_control(
    cifs: str, local: str, expected: str
) -> None:
    assert probe.verdict_for(cifs, local) == expected


def test_overall_verdict_needs_a_demonstrated_failure() -> None:
    ok_rows = [("P3", "blocked-then-locked", "blocked-then-locked", "same as local")]
    bad_rows = ok_rows + [("P4", "lost-isolation", "blocked-then-locked", "CIFS FAILURE (isolation lost)")]

    assert probe.overall_verdict(ok_rows) == "VERDICT: cifs locking OK"
    assert probe.overall_verdict(bad_rows) == "VERDICT: cifs locking FAILURE demonstrated"
    # a not-measured row must never turn into an indictment
    assert probe.overall_verdict(
        ok_rows + [("P5", "not-run (needs two containers)", "n/a", "not measured")]
    ) == "VERDICT: cifs locking OK"


def test_table_uses_minimal_separators() -> None:
    table = probe.render_table([("P1", "ok", "ok", "same as local")])

    assert "|-|-|-|-|" in table
    assert "|---" not in table
    assert not set(table) & set("┌┬─│└┘├┤┼")


def test_probes_run_against_a_real_database(tmp_path: Path) -> None:
    results = probe.run_suite(tmp_path / "probe")

    assert [result.name for result in results] == ["P1", "P2", "P3", "P4"]
    assert results[0].outcome == "ok"
    assert "integrity=ok" in results[0].detail
    # contention must be observed, not assumed
    assert results[2].outcome in {"blocked-then-locked", "immediate-error", "lost-isolation"}


def test_each_case_uses_a_new_database_file(tmp_path: Path) -> None:
    """Reuse would let one case's leftover lock decide another case's verdict."""
    first = probe._fresh_database(tmp_path, "P3")
    second = probe._fresh_database(tmp_path, "P3")

    assert first != second
    assert first.name.startswith("p3_")

    results = probe.run_suite(tmp_path / "suite")
    databases = sorted(
        path.name for path in (tmp_path / "suite").glob("*.sqlite3")
    )
    assert len(databases) == len(results)
    assert len({name.split("_")[0] for name in databases}) == len(results)


def test_pass_requires_row_count_and_integrity(tmp_path: Path) -> None:
    results = {result.name: result for result in probe.run_suite(tmp_path / "suite")}

    for name in ("P1", "P2", "P3", "P4"):
        assert "integrity=ok" in results[name].detail
        assert "(expected 1)" in results[name].detail
    assert probe.overall_verdict(
        [("P1", "integrity-or-rowcount-failed", "ok", "differs (x vs y)")]
    ) == "VERDICT: cifs locking FAILURE demonstrated"
