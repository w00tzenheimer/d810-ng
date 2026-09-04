from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.scripts import batch_profile


REPO = Path(__file__).resolve().parents[3]


def _write_jsonl(tmp_path: Path, records: list[dict]) -> Path:
    path = tmp_path / "system_batches.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")
    return path


def _record(**overrides) -> dict:
    base = {
        "run_id": "r1",
        "batch_index": 1,
        "batch_total": 1,
        "first_nodeid": "tests/system/a.py::test_a",
        "test_count": 1,
        "start_epoch": 0.0,
        "end_epoch": 1.0,
        "wall_seconds": 1.0,
        "exit_code": 0,
        "counts": {"passed": 1},
        "durations": [],
    }
    base.update(overrides)
    return base


def test_total_wall_seconds_sums_across_all_records() -> None:
    records = [_record(wall_seconds=5.0), _record(wall_seconds=25.0)]
    assert batch_profile.total_wall_seconds(records) == pytest.approx(30.0)


def test_top_files_by_duration_groups_and_computes_cumulative_share() -> None:
    records = [
        _record(
            durations=[
                {"nodeid": "tests/system/a.py::t0", "phase": "call", "seconds": 3.0},
                {"nodeid": "tests/system/a.py::t1", "phase": "setup", "seconds": 1.0},
                {"nodeid": "tests/system/b.py::t2", "phase": "call", "seconds": 1.0},
            ]
        )
    ]

    rows, total = batch_profile.top_files_by_duration(records, limit=20)

    assert total == pytest.approx(5.0)
    assert [row["file"] for row in rows] == ["tests/system/a.py", "tests/system/b.py"]
    assert rows[0]["seconds"] == pytest.approx(4.0)
    assert rows[0]["share_pct"] == pytest.approx(80.0)
    assert rows[0]["cumulative_share_pct"] == pytest.approx(80.0)
    assert rows[1]["cumulative_share_pct"] == pytest.approx(100.0)


def test_top_files_by_duration_respects_limit() -> None:
    records = [
        _record(
            durations=[
                {"nodeid": f"tests/system/f{i}.py::t", "phase": "call", "seconds": float(i)}
                for i in range(5)
            ]
        )
    ]

    rows, _total = batch_profile.top_files_by_duration(records, limit=2)

    assert len(rows) == 2
    assert rows[0]["file"] == "tests/system/f4.py"
    assert rows[1]["file"] == "tests/system/f3.py"


def test_top_slowest_tests_flattens_and_sorts_descending() -> None:
    records = [
        _record(
            batch_index=1,
            durations=[
                {"nodeid": "tests/system/a.py::t0", "phase": "call", "seconds": 1.0}
            ],
        ),
        _record(
            batch_index=2,
            durations=[
                {"nodeid": "tests/system/b.py::t1", "phase": "call", "seconds": 9.0}
            ],
        ),
    ]

    ranked = batch_profile.top_slowest_tests(records, limit=20)

    assert [entry["nodeid"] for entry in ranked] == [
        "tests/system/b.py::t1",
        "tests/system/a.py::t0",
    ]
    assert ranked[0]["batch_index"] == 2


def test_slow_batches_flags_only_batches_over_the_factor() -> None:
    records = [
        _record(batch_index=1, wall_seconds=10.0),
        _record(batch_index=2, wall_seconds=11.0),
        _record(batch_index=3, wall_seconds=100.0),
    ]

    flagged, median = batch_profile.slow_batches(records, factor=3.0)

    assert median == pytest.approx(11.0)
    assert [record["batch_index"] for record in flagged] == [3]


def test_slow_batches_returns_empty_with_fewer_than_two_records() -> None:
    flagged, median = batch_profile.slow_batches([_record(wall_seconds=4.0)], factor=3.0)
    assert flagged == []
    assert median == pytest.approx(4.0)


def test_render_report_contains_every_required_section(tmp_path: Path) -> None:
    records = [
        _record(
            batch_index=1,
            wall_seconds=5.0,
            durations=[
                {"nodeid": "tests/system/a.py::t0", "phase": "call", "seconds": 3.0}
            ],
        ),
        _record(
            batch_index=2,
            wall_seconds=50.0,
            durations=[
                {"nodeid": "tests/system/b.py::t1", "phase": "call", "seconds": 20.0}
            ],
        ),
    ]

    report = batch_profile.render_report(records, top_n=20, factor=3.0)

    assert "total wall" in report
    assert "top 20 files by summed captured duration" in report
    assert "top 20 slowest individual tests" in report
    assert "batches slower than 3x the median batch wall time" in report
    assert "tests/system/b.py" in report
    assert "batch=2" in report


def test_load_records_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "batches.jsonl"
    path.write_text(
        json.dumps(_record()) + "\n\n" + json.dumps(_record(batch_index=2)) + "\n"
    )

    records = batch_profile.load_records(str(path))

    assert len(records) == 2
    assert [r["batch_index"] for r in records] == [1, 2]


def test_main_exits_nonzero_and_reports_when_file_is_missing(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.jsonl"
    assert batch_profile.main([str(missing)]) == 2


def test_main_exits_nonzero_when_file_has_no_records(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("\n")
    assert batch_profile.main([str(path)]) == 1


def test_main_prints_report_and_returns_zero(tmp_path, capsys) -> None:
    path = _write_jsonl(tmp_path, [_record()])
    result = batch_profile.main([str(path)])
    assert result == 0
    out = capsys.readouterr().out
    assert "== summary ==" in out


def test_module_runs_as_python_dash_m(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path, [_record()])
    completed = subprocess.run(
        [sys.executable, "-m", "tools.scripts.batch_profile", str(path)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "== summary ==" in completed.stdout
