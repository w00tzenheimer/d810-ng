from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/scripts/run_system_test_batches.py"


def _module():
    # spec_from_file_location does not put the script's directory on sys.path
    # the way ``python tools/scripts/run_system_test_batches.py`` does, and the
    # driver imports its sibling planner module by name.
    if str(SCRIPT.parent) not in sys.path:
        sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("run_system_test_batches", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakePopen:
    """Minimal ``subprocess.Popen`` stand-in for batch-execution tests.

    Serves canned stdout/stderr text through ``.readline()``-compatible
    ``io.StringIO`` pipes (matching what ``_stream_and_capture`` reads), so
    tests never spawn a real ``/runtime/python`` process.
    """

    def __init__(self, command, *, stdout_text: str, stderr_text: str, returncode: int):
        self.args = list(command)
        self.pid = 4242
        self.stdout = io.StringIO(stdout_text)
        self.stderr = io.StringIO(stderr_text)
        self._returncode = returncode

    def wait(self) -> int:
        return self._returncode


def _fake_popen_factory(results: list[tuple[str, str, int]]):
    """Return a ``popen`` callable that yields *results* in call order."""

    calls: list[list[str]] = []
    remaining = list(results)

    def fake_popen(command, **kwargs):
        calls.append(list(command))
        stdout_text, stderr_text, returncode = remaining.pop(0)
        return _FakePopen(
            command,
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            returncode=returncode,
        )

    fake_popen.calls = calls
    return fake_popen


def test_parse_collected_nodeids_ignores_summary_and_warnings() -> None:
    module = _module()

    assert module.parse_collected_nodeids(
        "tests/system/test_a.py::test_one\n"
        "tests/system/test_b.py::TestB::test_two[x]\n"
        "2 tests collected in 0.01s\n"
    ) == (
        "tests/system/test_a.py::test_one",
        "tests/system/test_b.py::TestB::test_two[x]",
    )


def test_run_batches_uses_fresh_pytest_processes_and_stops_on_failure() -> None:
    module = _module()
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(
                    f"tests/system/test_x.py::test_{index}" for index in range(5)
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 7 if len(calls) == 3 else 0)

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=("-q",),
        batch_size=2,
        run=fake_run,
    )

    assert result == 7
    assert calls[0][:4] == [
        "/runtime/python",
        "-m",
        "pytest",
        "--collect-only",
    ]
    assert calls[1][3:5] == ["-v", "tests/system/test_x.py::test_0"]
    assert calls[1][-1] == "--durations=25"
    assert calls[2][3:5] == ["-v", "tests/system/test_x.py::test_2"]
    assert len(calls) == 3


def test_run_batches_can_resume_at_a_diagnostic_batch_boundary() -> None:
    module = _module()
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(
                    f"tests/system/test_x.py::test_{index}" for index in range(5)
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0)

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        start_batch=3,
        run=fake_run,
    )

    assert result == 0
    assert len(calls) == 2
    assert calls[1][3:] == ["-v", "tests/system/test_x.py::test_4", "--durations=25"]


def test_run_batches_runs_memory_heavy_oracle_after_regular_batches() -> None:
    module = _module()
    calls: list[list[str]] = []
    oracle = (
        "tests/system/e2e/test_ollvm_fla_bcf_sub_oracle.py::"
        "TestOllvmFlaBcfSubOracle::test_fla_bcf_sub_oracle"
    )

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(
                    (
                        "tests/system/test_x.py::test_0",
                        oracle,
                        "tests/system/test_x.py::test_1",
                        "tests/system/test_x.py::test_2",
                    )
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0)

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        run=fake_run,
    )

    assert result == 0
    assert [call[4:] for call in calls[1:]] == [
        [
            "tests/system/test_x.py::test_0",
            "tests/system/test_x.py::test_1",
            "--durations=25",
        ],
        ["tests/system/test_x.py::test_2", "--durations=25"],
        [oracle, "--durations=25"],
    ]


def test_augment_pytest_args_does_not_duplicate_existing_durations_flag() -> None:
    module = _module()

    assert module._augment_pytest_args_with_durations(("-q", "--durations=5"), 25) == (
        "-q",
        "--durations=5",
    )
    assert module._augment_pytest_args_with_durations(("-q",), 0) == ("-q",)
    assert module._augment_pytest_args_with_durations(("-q",), 25) == (
        "-q",
        "--durations=25",
    )


def test_parse_pytest_summary_counts_handles_wrapped_and_bare_lines() -> None:
    module = _module()

    assert module.parse_pytest_summary_counts(
        "collecting ...\n"
        "============== 1 failed, 1 passed, 1 skipped, 1 xfailed in 0.18s ===============\n"
    ) == {"failed": 1, "passed": 1, "skipped": 1, "xfailed": 1}

    assert module.parse_pytest_summary_counts("668 passed in 29.57s\n") == {
        "passed": 668
    }

    assert module.parse_pytest_summary_counts(
        "============== 605.62s (0:10:05) 3 passed ==============\n"
        "no summary here\n"
    ) == {}


def test_parse_pytest_durations_extracts_slowest_block_and_stops_at_footer() -> None:
    module = _module()
    output = (
        "============================= slowest 5 durations =============================\n"
        "1.78s call     tests/x.py::test_a\n"
        "0.52s setup    tests/y.py::test_b\n"
        "\n"
        "(3 durations < 0.005s hidden.  Use -vv to show these durations.)\n"
        "=========================== short test summary info ============================\n"
        "1 passed in 2.30s\n"
    )

    assert module.parse_pytest_durations(output) == [
        {"nodeid": "tests/x.py::test_a", "phase": "call", "seconds": 1.78},
        {"nodeid": "tests/y.py::test_b", "phase": "setup", "seconds": 0.52},
    ]


def test_parse_pytest_durations_returns_empty_when_block_absent() -> None:
    module = _module()

    assert module.parse_pytest_durations("2 passed in 0.01s\n") == []


def test_run_batches_writes_one_jsonl_record_per_batch(tmp_path) -> None:
    module = _module()
    calls: list[list[str]] = []
    batch_output = (
        "tests/system/test_x.py::test_0 PASSED\n"
        "============================= slowest 25 durations =============================\n"
        "1.23s call     tests/system/test_x.py::test_0\n"
        "\n"
        "============== 2 passed in 1.50s ===============\n"
    )

    def fake_run(command, **kwargs):
        calls.append(list(command))
        assert "--collect-only" in command
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="\n".join(
                f"tests/system/test_x.py::test_{index}" for index in range(4)
            ),
            stderr="",
        )

    fake_popen = _fake_popen_factory(
        [(batch_output, "", 0), (batch_output, "", 0)]
    )
    times = iter([100.0, 101.5, 200.0, 202.0])

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        run=fake_run,
        popen=fake_popen,
        log_dir=str(tmp_path),
        run_id="run-abc",
        now=lambda: next(times),
    )

    assert result == 0
    log_path = tmp_path / module.BATCH_LOG_FILENAME
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


    first = json.loads(lines[0])
    assert first["run_id"] == "run-abc"
    assert first["batch_index"] == 1
    assert first["batch_total"] == 2
    assert first["first_nodeid"] == "tests/system/test_x.py::test_0"
    assert first["test_count"] == 2
    assert first["start_epoch"] == 100.0
    assert first["end_epoch"] == 101.5
    assert first["wall_seconds"] == pytest.approx(1.5)
    assert first["exit_code"] == 0
    assert first["counts"] == {"passed": 2}
    assert first["durations"] == [
        {"nodeid": "tests/system/test_x.py::test_0", "phase": "call", "seconds": 1.23}
    ]

    second = json.loads(lines[1])
    assert second["batch_index"] == 2
    assert second["run_id"] == "run-abc"


def test_run_batches_resume_appends_to_the_same_jsonl_file(tmp_path) -> None:
    module = _module()

    def fake_run(command, **kwargs):
        assert "--collect-only" in command
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="\n".join(
                f"tests/system/test_x.py::test_{index}" for index in range(4)
            ),
            stderr="",
        )

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        run=fake_run,
        popen=_fake_popen_factory(
            [("2 passed in 0.10s\n", "", 0), ("2 passed in 0.10s\n", "", 0)]
        ),
        log_dir=str(tmp_path),
        run_id="run-one",
    )
    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        start_batch=2,
        run=fake_run,
        popen=_fake_popen_factory([("2 passed in 0.10s\n", "", 0)]),
        log_dir=str(tmp_path),
        run_id="run-two",
    )

    log_path = tmp_path / module.BATCH_LOG_FILENAME
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3


    run_ids = [json.loads(line)["run_id"] for line in lines]
    assert run_ids == ["run-one", "run-one", "run-two"]


def test_run_batches_without_log_dir_streams_and_does_not_capture(tmp_path) -> None:
    module = _module()
    seen_kwargs: list[dict] = []

    def fake_run(command, **kwargs):
        seen_kwargs.append(kwargs)
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="tests/system/test_x.py::test_0",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0)

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        run=fake_run,
    )

    assert result == 0
    assert not (tmp_path / module.BATCH_LOG_FILENAME).exists()
    # batch invocation (index 1) must not request capture_output when unlogged.
    assert "capture_output" not in seen_kwargs[1]


def test_main_wires_log_dir_through_to_run_batches(monkeypatch, tmp_path) -> None:
    module = _module()
    captured: dict = {}

    def fake_run_batches(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(module, "run_batches", fake_run_batches)

    module.main(["--log-dir", str(tmp_path), "tests/system"])
    assert captured["log_dir"] == str(tmp_path)

    module.main(["tests/system"])
    assert captured["log_dir"] is None


def test_stream_and_capture_tees_output_live_not_after_exit(tmp_path) -> None:
    """A line printed by the child must reach the parent's sink while the
    child is still running, not be buffered until it exits.

    Regression for the ``capture_output=True`` bug: a 20-minute batch
    produced nothing until it finished, looking hung. Runs a real
    subprocess (not a fake) that prints, sleeps, then prints again, and
    asserts the first line's arrival timestamp precedes the second by
    roughly the sleep duration -- proof it was teed line-by-line rather
    than delivered in one bulk write after the process exited.
    """
    module = _module()

    script = tmp_path / "slow_child.py"
    script.write_text(
        "import sys, time\n"
        "print('first-line', flush=True)\n"
        "time.sleep(0.3)\n"
        "print('second-line', flush=True)\n",
        encoding="utf-8",
    )

    class _RecordingStream:
        def __init__(self) -> None:
            self.events: list[tuple[str, float]] = []

        def write(self, text: str) -> None:
            if text.strip():
                self.events.append((text, time.monotonic()))

        def flush(self) -> None:
            pass

    out = _RecordingStream()
    err = _RecordingStream()

    result = module._stream_and_capture(
        [sys.executable, str(script)],
        stdout_sink=out,
        stderr_sink=err,
    )

    assert result.completed.returncode == 0
    assert result.completed.stdout == "first-line\nsecond-line\n"

    first_ts = next(ts for text, ts in out.events if "first-line" in text)
    second_ts = next(ts for text, ts in out.events if "second-line" in text)
    # A batched/capture_output-style implementation would deliver both
    # lines together after the child exits, so this gap would collapse to
    # ~0s. True line-by-line teeing preserves the sleep gap.
    assert second_ts - first_ts > 0.2


# ---------------------------------------------------------------------------
# Cost-aware packing and N-way sharding
#
# Both are opt-in: with neither requested the driver keeps the fixed
# ``--batch-size`` split, which the tests above pin.
# ---------------------------------------------------------------------------


def _collect_stub(nodeids):
    """Return a ``run`` double that answers collection with *nodeids*."""

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command, 0, stdout="\n".join(nodeids), stderr=""
            )
        return subprocess.CompletedProcess(command, 0)

    fake_run.calls = calls
    return fake_run


def _batch_selections(calls):
    """The node ids each non-collection pytest invocation was given."""
    return [
        [arg for arg in call if arg.startswith("tests/") and "::" in arg]
        for call in calls
        if "--collect-only" not in call
    ]


def test_run_batches_packs_by_cost_instead_of_by_count_when_asked() -> None:
    module = _module()
    nodeids = [f"tests/system/test_x.py::TestA::test_{index}" for index in range(60)]
    fake_run = _collect_stub(nodeids)

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        plan="cost",
        cost_ledgers=(),
        run=fake_run,
    )

    assert result == 0
    selections = _batch_selections(fake_run.calls)
    # One class -> one database-open group -> one interpreter, not three.
    assert len(selections) == 1
    assert selections[0] == nodeids


def test_run_batches_packing_still_bounds_database_open_groups() -> None:
    module = _module()
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_a" for index in range(45)]
    fake_run = _collect_stub(nodeids)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        plan="cost",
        cost_ledgers=(),
        max_group_keys=20,
        run=fake_run,
    )

    selections = _batch_selections(fake_run.calls)
    assert [len(selection) for selection in selections] == [20, 20, 5]


def test_run_batches_runs_only_the_batches_assigned_to_its_shard() -> None:
    module = _module()
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_a" for index in range(6)]

    seen: list[list[str]] = []
    for shard_index in range(3):
        fake_run = _collect_stub(nodeids)
        assert (
            module.run_batches(
                python="/runtime/python",
                root="tests/system",
                pytest_args=(),
                batch_size=2,
                shard_index=shard_index,
                shard_count=3,
                run=fake_run,
            )
            == 0
        )
        seen.append(
            [nodeid for selection in _batch_selections(fake_run.calls) for nodeid in selection]
        )

    assert sorted(nodeid for shard in seen for nodeid in shard) == sorted(nodeids)
    assert all(shard for shard in seen)


def test_run_batches_records_the_shard_in_every_ledger_line(tmp_path) -> None:
    module = _module()
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_a" for index in range(4)]
    fake_run = _collect_stub(nodeids)
    popen = _fake_popen_factory([("1 passed in 0.1s\n", "", 0)] * 4)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=1,
        shard_index=1,
        shard_count=2,
        run=fake_run,
        popen=popen,
        log_dir=str(tmp_path),
        run_id="fixed",
    )

    lines = (tmp_path / module.BATCH_LOG_FILENAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in lines.splitlines()]
    assert records
    assert {record["shard"] for record in records} == {1}
    assert {record["shard_count"] for record in records} == {2}
    assert [record["batch_index"] for record in records] == list(
        range(1, len(records) + 1)
    )
    assert all(record["global_batch_index"] >= 1 for record in records)


def test_run_batches_serial_ledger_line_still_reports_shard_zero(tmp_path) -> None:
    module = _module()
    nodeids = ["tests/system/test_x.py::test_a"]
    fake_run = _collect_stub(nodeids)
    popen = _fake_popen_factory([("1 passed in 0.1s\n", "", 0)])

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        run=fake_run,
        popen=popen,
        log_dir=str(tmp_path),
        run_id="fixed",
    )

    record = json.loads(
        (tmp_path / module.BATCH_LOG_FILENAME).read_text(encoding="utf-8").strip()
    )
    assert record["shard"] == 0
    assert record["shard_count"] == 1
    assert record["batch_index"] == record["global_batch_index"] == 1


def test_run_batches_start_batch_is_relative_to_the_shard() -> None:
    module = _module()
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_a" for index in range(8)]
    fake_run = _collect_stub(nodeids)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=1,
        shard_index=0,
        shard_count=2,
        start_batch=3,
        run=fake_run,
    )

    # Shard 0 owns 4 of the 8 single-test batches; resuming at 3 leaves 2.
    assert len(_batch_selections(fake_run.calls)) == 2


def test_run_batches_rejects_a_shard_index_outside_the_shard_count() -> None:
    module = _module()
    fake_run = _collect_stub(["tests/system/test_x.py::test_a"])
    assert (
        module.run_batches(
            python="/runtime/python",
            root="tests/system",
            pytest_args=(),
            batch_size=20,
            shard_index=2,
            shard_count=2,
            run=fake_run,
        )
        == 5
    )


def test_run_batches_uses_ledger_costs_to_isolate_a_heavy_test(tmp_path) -> None:
    module = _module()
    heavy = "tests/system/test_x.py::TestHeavy::test_big"
    nodeids = [
        "tests/system/test_x.py::TestA::test_a",
        heavy,
        "tests/system/test_x.py::TestB::test_b",
    ]
    ledger = tmp_path / "system_batches.jsonl"
    ledger.write_text(
        json.dumps(
            {
                "batch_index": 1,
                "test_count": 3,
                "wall_seconds": 340.0,
                "durations": [{"nodeid": heavy, "phase": "call", "seconds": 334.0}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    fake_run = _collect_stub(nodeids)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        plan="cost",
        cost_ledgers=(str(ledger),),
        cost_budget_seconds=120.0,
        run=fake_run,
    )

    assert _batch_selections(fake_run.calls) == [
        ["tests/system/test_x.py::TestA::test_a"],
        [heavy],
        ["tests/system/test_x.py::TestB::test_b"],
    ]


def test_main_wires_packing_and_shard_flags_through(monkeypatch) -> None:
    module = _module()
    captured: dict = {}

    def fake_run_batches(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(module, "run_batches", fake_run_batches)
    assert (
        module.main(
            # Options precede the positional root: pytest_args is an
            # argparse REMAINDER, so anything after the root belongs to pytest.
            [
                "--plan",
                "cost",
                "--cost-ledger",
                "/l/one.jsonl",
                "--cost-ledger",
                "/l/two.jsonl",
                "--cost-budget-seconds",
                "90",
                "--max-group-keys",
                "12",
                "--shard-index",
                "2",
                "--shard-count",
                "3",
                "tests/system",
            ]
        )
        == 0
    )
    assert captured["plan"] == "cost"
    assert captured["cost_ledgers"] == ("/l/one.jsonl", "/l/two.jsonl")
    assert captured["cost_budget_seconds"] == 90.0
    assert captured["max_group_keys"] == 12
    assert captured["shard_index"] == 2
    assert captured["shard_count"] == 3



def test_run_batches_lane_plan_runs_the_fast_tests_in_one_interpreter(tmp_path) -> None:
    module = _module()
    heavy = "tests/system/test_x.py::TestHeavy::test_big"
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_a" for index in range(40)]
    nodeids.insert(20, heavy)
    ledger = tmp_path / "system_batches.jsonl"
    ledger.write_text(
        json.dumps(
            {
                "batch_index": 1,
                "test_count": 41,
                "wall_seconds": 360.0,
                "durations": [{"nodeid": heavy, "phase": "call", "seconds": 334.0}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    fake_run = _collect_stub(nodeids)

    assert (
        module.run_batches(
            python="/runtime/python",
            root="tests/system",
            pytest_args=(),
            batch_size=20,
            plan="lane",
            cost_ledgers=(str(ledger),),
            run=fake_run,
        )
        == 0
    )

    selections = _batch_selections(fake_run.calls)
    assert len(selections) == 2
    assert len(selections[0]) == 40
    assert selections[1] == [heavy]


def test_run_batches_lane_plan_spreads_lane_batches_over_the_shards(tmp_path) -> None:
    module = _module()
    slow = [f"tests/system/test_x.py::TestSlow{index}::test_a" for index in range(4)]
    nodeids = ["tests/system/test_x.py::TestFast::test_a", *slow]
    ledger = tmp_path / "system_batches.jsonl"
    ledger.write_text(
        "".join(
            json.dumps(
                {
                    "batch_index": index + 1,
                    "test_count": 1,
                    "wall_seconds": 100.0,
                    "durations": [
                        {"nodeid": nodeid, "phase": "call", "seconds": 100.0}
                    ],
                },
                sort_keys=True,
            )
            + "\n"
            for index, nodeid in enumerate(slow)
        ),
        encoding="utf-8",
    )

    seen = []
    for shard_index in range(3):
        fake_run = _collect_stub(nodeids)
        module.run_batches(
            python="/runtime/python",
            root="tests/system",
            pytest_args=(),
            batch_size=20,
            plan="lane",
            cost_ledgers=(str(ledger),),
            shard_index=shard_index,
            shard_count=3,
            run=fake_run,
        )
        seen.append(
            [nodeid for batch in _batch_selections(fake_run.calls) for nodeid in batch]
        )

    # Plain LPT: the four 100 s slow tests dominate, so the fast lane rides
    # along on whichever shard is lightest. Every shard has work and nothing
    # is run twice or dropped.
    assert sorted(nodeid for shard in seen for nodeid in shard) == sorted(nodeids)
    assert all(shard for shard in seen)


def test_run_batches_records_the_lane_in_the_ledger(tmp_path) -> None:
    module = _module()
    fake_run = _collect_stub(["tests/system/test_x.py::TestFast::test_a"])
    popen = _fake_popen_factory([("1 passed in 0.1s\n", "", 0)])
    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        plan="lane",
        run=fake_run,
        popen=popen,
        log_dir=str(tmp_path),
        run_id="fixed",
    )
    record = json.loads(
        (tmp_path / module.BATCH_LOG_FILENAME).read_text(encoding="utf-8").strip()
    )
    assert record["lane"] == "fast"


def test_run_batches_rejects_an_unknown_plan_mode() -> None:
    module = _module()
    fake_run = _collect_stub(["tests/system/test_x.py::test_a"])
    assert (
        module.run_batches(
            python="/runtime/python",
            root="tests/system",
            pytest_args=(),
            batch_size=20,
            plan="magic",
            run=fake_run,
        )
        == 5
    )


# ---------------------------------------------------------------------------
# Risk closure: node-id selection through a file, and peak RSS in the ledger
# ---------------------------------------------------------------------------


def test_a_large_selection_goes_through_a_file_not_the_argv(tmp_path) -> None:
    module = _module()
    nodeids = [
        f"tests/system/e2e/test_very_long_module_name_{index}.py::TestClass::test_case[{index}]"
        for index in range(2000)
    ]
    fake_run = _collect_stub(nodeids)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=len(nodeids),
        run=fake_run,
        selection_dir=str(tmp_path),
    )

    command = [call for call in fake_run.calls if "--collect-only" not in call][0]
    at_args = [arg for arg in command if arg.startswith("@")]
    assert len(at_args) == 1
    assert not [arg for arg in command if arg.startswith("tests/")]
    selection = Path(at_args[0][1:])
    assert selection.read_text(encoding="utf-8").splitlines() == nodeids


def test_a_small_selection_still_goes_through_the_argv(tmp_path) -> None:
    module = _module()
    nodeids = ["tests/system/test_x.py::test_a", "tests/system/test_x.py::test_b"]
    fake_run = _collect_stub(nodeids)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        run=fake_run,
        selection_dir=str(tmp_path),
    )

    command = [call for call in fake_run.calls if "--collect-only" not in call][0]
    assert not [arg for arg in command if arg.startswith("@")]
    assert command[4:6] == nodeids


def test_selection_files_are_named_per_shard_and_batch(tmp_path) -> None:
    module = _module()
    # Each batch must clear SELECTION_FILE_BYTES for the file path to be taken.
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_{'a' * 7000}" for index in range(20)]
    fake_run = _collect_stub(nodeids)

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=10,
        shard_index=0,
        shard_count=1,
        run=fake_run,
        selection_dir=str(tmp_path),
    )

    names = sorted(path.name for path in Path(tmp_path).glob("*.txt"))
    assert names == ["selection-shard0-batch1.txt", "selection-shard0-batch2.txt"]


def test_peak_rss_is_recorded_for_every_batch(tmp_path) -> None:
    module = _module()
    nodeids = ["tests/system/test_x.py::test_a"]
    fake_run = _collect_stub(nodeids)
    popen = _fake_popen_factory([("1 passed in 0.1s\n", "", 0)])

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        run=fake_run,
        popen=popen,
        log_dir=str(tmp_path),
        run_id="fixed",
        rss_reader=lambda pid: 1_234_567,
    )

    record = json.loads(
        (tmp_path / module.BATCH_LOG_FILENAME).read_text(encoding="utf-8").strip()
    )
    assert record["peak_rss_kib"] == 1_234_567


def test_peak_rss_is_null_when_the_platform_cannot_report_it(tmp_path) -> None:
    module = _module()
    fake_run = _collect_stub(["tests/system/test_x.py::test_a"])
    popen = _fake_popen_factory([("1 passed in 0.1s\n", "", 0)])

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        run=fake_run,
        popen=popen,
        log_dir=str(tmp_path),
        run_id="fixed",
        rss_reader=lambda pid: None,
    )

    record = json.loads(
        (tmp_path / module.BATCH_LOG_FILENAME).read_text(encoding="utf-8").strip()
    )
    assert record["peak_rss_kib"] is None


def test_read_peak_rss_kib_parses_vmhwm(tmp_path) -> None:
    module = _module()
    status = tmp_path / "status"
    status.write_text(
        "Name:\tpython3\nVmPeak:\t 9999999 kB\nVmHWM:\t 1441792 kB\nVmRSS:\t 1000 kB\n",
        encoding="utf-8",
    )
    assert module.read_peak_rss_kib(1, status_path=str(status)) == 1_441_792


def test_read_peak_rss_kib_returns_none_without_proc(tmp_path) -> None:
    module = _module()
    assert module.read_peak_rss_kib(1, status_path=str(tmp_path / "absent")) is None


def test_main_wires_the_fast_lane_flags_through(monkeypatch) -> None:
    module = _module()
    captured: dict = {}
    monkeypatch.setattr(module, "run_batches", lambda **kwargs: captured.update(kwargs) or 0)
    assert (
        module.main(
            [
                "--plan",
                "lane",
                "--fast-lanes",
                "2",
                "--fast-lane-budget-seconds",
                "540",
                "--selection-dir",
                "/logs/sel",
                "tests/system",
            ]
        )
        == 0
    )
    assert captured["fast_lanes"] == 2
    assert captured["fast_lane_budget_seconds"] == 540.0
    assert captured["selection_dir"] == "/logs/sel"


def test_selection_dir_defaults_to_the_run_log_dir(tmp_path) -> None:
    """The runner always passes --log-dir, so the selection file lands beside
    the ledger with no extra wiring and is retained with the run's artifacts."""
    module = _module()
    nodeids = [f"tests/system/test_x.py::TestG{index}::test_{'a' * 7000}" for index in range(20)]
    fake_run = _collect_stub(nodeids)
    popen = _fake_popen_factory([("20 passed in 1s\n", "", 0)])

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=20,
        run=fake_run,
        popen=popen,
        log_dir=str(tmp_path),
        run_id="fixed",
    )

    written = sorted(path.name for path in (tmp_path / "selection").glob("*.txt"))
    assert written == ["selection-shard0-batch1.txt"]
    record = json.loads(
        (tmp_path / module.BATCH_LOG_FILENAME).read_text(encoding="utf-8").strip()
    )
    assert record["selection_file"].endswith("selection-shard0-batch1.txt")


def test_collection_ignores_caller_verbosity_flags() -> None:
    """`-- -q` from the caller plus the driver's own `-q` is `-qq`, at which
    pytest prints "path: N" instead of node ids and the driver collects
    nothing. Verbosity is a reporting choice for the BATCHES; the collect pass
    owns its own."""
    module = _module()
    fake_run = _collect_stub(["tests/system/test_x.py::test_a"])

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=("-q", "--quiet", "-v", "-vv", "--verbose", "-m", "not slow"),
        batch_size=20,
        run=fake_run,
    )

    collect = [call for call in fake_run.calls if "--collect-only" in call][0]
    assert collect.count("-q") == 1
    assert "--quiet" not in collect
    assert "-v" not in collect and "-vv" not in collect and "--verbose" not in collect
    # Selection-affecting arguments must still reach collection, or the batches
    # would run tests the caller deselected.
    assert collect[-2:] == ["-m", "not slow"]
    # The batch command keeps exactly what the caller asked for.
    batch = [call for call in fake_run.calls if "--collect-only" not in call][0]
    assert "-q" in batch and "-vv" in batch
