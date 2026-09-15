"""Unit tests for merging per-shard system-suite ledgers into one."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/scripts/merge_system_batch_ledgers.py"


def _module():
    spec = importlib.util.spec_from_file_location("merge_system_batch_ledgers", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record(**overrides):
    record = {
        "run_id": "r",
        "shard": 0,
        "shard_count": 1,
        "batch_index": 1,
        "batch_total": 1,
        "first_nodeid": "t.py::A::a",
        "test_count": 1,
        "start_epoch": 0.0,
        "end_epoch": 1.0,
        "wall_seconds": 1.0,
        "exit_code": 0,
        "counts": {"passed": 1},
        "durations": [],
    }
    record.update(overrides)
    return record


def _write(path: Path, records) -> Path:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


def test_merge_orders_by_shard_then_batch_index(tmp_path) -> None:
    merge = _module()
    a = _write(
        tmp_path / "a.jsonl",
        [_record(shard=1, batch_index=5), _record(shard=1, batch_index=2)],
    )
    b = _write(
        tmp_path / "b.jsonl",
        [_record(shard=0, batch_index=9), _record(shard=0, batch_index=1)],
    )
    merged = merge.merge_records([str(a), str(b)])
    assert [(r["shard"], r["batch_index"]) for r in merged] == [
        (0, 1),
        (0, 9),
        (1, 2),
        (1, 5),
    ]


def test_merge_defaults_a_shardless_serial_record_to_shard_zero(tmp_path) -> None:
    merge = _module()
    path = _write(tmp_path / "serial.jsonl", [{"batch_index": 3, "wall_seconds": 2.0}])
    merged = merge.merge_records([str(path)])
    assert merged[0]["shard"] == 0


def test_merge_keeps_the_last_record_for_a_rerun_batch(tmp_path) -> None:
    merge = _module()
    path = _write(
        tmp_path / "a.jsonl",
        [
            _record(batch_index=4, exit_code=1, counts={"failed": 1}),
            _record(batch_index=4, exit_code=0, counts={"passed": 1}),
        ],
    )
    merged = merge.merge_records([str(path)])
    assert len(merged) == 1
    assert merged[0]["exit_code"] == 0


def test_merge_keeps_distinct_run_ids_apart(tmp_path) -> None:
    merge = _module()
    path = _write(
        tmp_path / "a.jsonl",
        [_record(run_id="one", batch_index=1), _record(run_id="two", batch_index=1)],
    )
    assert len(merge.merge_records([str(path)])) == 2


def test_merge_can_select_only_the_latest_run_from_each_shard(tmp_path) -> None:
    merge = _module()
    shard_zero = _write(
        tmp_path / "shard-zero.jsonl",
        [
            _record(run_id="old-zero", shard=0, exit_code=1, counts={"failed": 1}),
            _record(run_id="new-zero", shard=0, counts={"passed": 1}),
        ],
    )
    shard_one = _write(
        tmp_path / "shard-one.jsonl",
        [
            _record(run_id="old-one", shard=1, exit_code=1, counts={"failed": 1}),
            _record(run_id="new-one", shard=1, counts={"passed": 1}),
        ],
    )

    merged = merge.merge_records(
        [str(shard_zero), str(shard_one)],
        latest_run_per_input=True,
    )

    assert [(record["shard"], record["run_id"]) for record in merged] == [
        (0, "new-zero"),
        (1, "new-one"),
    ]


def test_merge_can_select_one_explicit_run_without_trusting_final_record(
    tmp_path,
) -> None:
    merge = _module()
    path = _write(
        tmp_path / "shard.jsonl",
        [
            _record(run_id="current", counts={"passed": 1}),
            _record(run_id="stale-later", exit_code=1, counts={"failed": 1}),
        ],
    )

    merged = merge.merge_records([str(path)], run_id="current")

    assert [record["run_id"] for record in merged] == ["current"]


def test_main_latest_run_per_input_excludes_historical_failures(
    tmp_path, capsys
) -> None:
    merge = _module()
    path = _write(
        tmp_path / "shard.jsonl",
        [
            _record(run_id="old", exit_code=1, counts={"failed": 1}),
            _record(run_id="current", counts={"passed": 1}),
        ],
    )
    out = tmp_path / "merged.jsonl"

    assert merge.main(["--latest-run-per-input", "--out", str(out), str(path)]) == 0
    assert "failed" not in capsys.readouterr().out
    assert [json.loads(line)["run_id"] for line in out.read_text().splitlines()] == [
        "current"
    ]


def test_main_explicit_run_id_excludes_later_stale_failure(tmp_path, capsys) -> None:
    merge = _module()
    path = _write(
        tmp_path / "shard.jsonl",
        [
            _record(run_id="current", counts={"passed": 1}),
            _record(run_id="stale", exit_code=1, counts={"failed": 1}),
        ],
    )
    out = tmp_path / "merged.jsonl"

    assert merge.main(["--run-id", "current", "--out", str(out), str(path)]) == 0
    assert "failed" not in capsys.readouterr().out
    assert [json.loads(line)["run_id"] for line in out.read_text().splitlines()] == [
        "current"
    ]


def test_merge_skips_a_missing_input(tmp_path) -> None:
    merge = _module()
    path = _write(tmp_path / "a.jsonl", [_record()])
    merged = merge.merge_records([str(path), str(tmp_path / "absent.jsonl")])
    assert len(merged) == 1


def test_summarize_adds_counts_across_shards(tmp_path) -> None:
    merge = _module()
    records = [
        _record(shard=0, batch_index=1, counts={"passed": 20, "skipped": 2}),
        _record(shard=1, batch_index=1, counts={"passed": 15, "xfailed": 1}),
    ]
    summary = merge.summarize(records)
    assert summary.counts == {"passed": 35, "skipped": 2, "xfailed": 1}


def test_summarize_reports_wall_as_the_slowest_shard_not_the_sum(tmp_path) -> None:
    merge = _module()
    records = [
        _record(
            shard=0,
            batch_index=1,
            start_epoch=100.0,
            end_epoch=160.0,
            wall_seconds=60.0,
        ),
        _record(
            shard=0,
            batch_index=2,
            start_epoch=160.0,
            end_epoch=200.0,
            wall_seconds=40.0,
        ),
        _record(
            shard=1,
            batch_index=1,
            start_epoch=100.0,
            end_epoch=130.0,
            wall_seconds=30.0,
        ),
    ]
    summary = merge.summarize(records)
    assert summary.per_shard_wall == {0: pytest.approx(100.0), 1: pytest.approx(30.0)}
    assert summary.critical_path_shard == 0
    assert summary.wall_seconds == pytest.approx(100.0)
    assert summary.serial_seconds == pytest.approx(130.0)


def test_summarize_collects_failing_batches_with_their_first_nodeid() -> None:
    merge = _module()
    records = [
        _record(shard=0, batch_index=1),
        _record(
            shard=1,
            batch_index=7,
            exit_code=1,
            counts={"failed": 1, "passed": 19},
            first_nodeid="t.py::Shadow::test_native_shadow",
        ),
    ]
    summary = merge.summarize(records)
    assert [(f["shard"], f["batch_index"]) for f in summary.failing_batches] == [(1, 7)]
    assert (
        summary.failing_batches[0]["first_nodeid"] == "t.py::Shadow::test_native_shadow"
    )


def test_summarize_counts_tests_and_batches() -> None:
    merge = _module()
    records = [
        _record(shard=0, batch_index=1, test_count=20),
        _record(shard=1, batch_index=1, test_count=13),
    ]
    summary = merge.summarize(records)
    assert summary.batches == 2
    assert summary.tests == 33


def test_summarize_of_nothing_is_empty_not_an_error() -> None:
    merge = _module()
    summary = merge.summarize([])
    assert summary.batches == 0
    assert summary.wall_seconds == pytest.approx(0.0)
    assert summary.critical_path_shard is None


def test_main_writes_the_merged_ledger_and_prints_the_summary(tmp_path, capsys) -> None:
    merge = _module()
    a = _write(tmp_path / "a.jsonl", [_record(shard=0, batch_index=1)])
    b = _write(tmp_path / "b.jsonl", [_record(shard=1, batch_index=1)])
    out = tmp_path / "merged.jsonl"
    assert merge.main(["--out", str(out), str(a), str(b)]) == 0
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["shard"] == 0
    assert "shards=2" in capsys.readouterr().out


def test_main_exits_nonzero_when_a_shard_failed(tmp_path) -> None:
    merge = _module()
    a = _write(tmp_path / "a.jsonl", [_record(exit_code=1, counts={"failed": 1})])
    out = tmp_path / "merged.jsonl"
    assert merge.main(["--out", str(out), str(a)]) == 1
