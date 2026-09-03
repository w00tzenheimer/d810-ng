from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/scripts/run_system_test_batches.py"


def _module():
    spec = importlib.util.spec_from_file_location("run_system_test_batches", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(
                    f"tests/system/test_x.py::test_{index}" for index in range(4)
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout=batch_output, stderr="")

    times = iter([100.0, 101.5, 200.0, 202.0])

    result = module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        run=fake_run,
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
        if "--collect-only" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="\n".join(
                    f"tests/system/test_x.py::test_{index}" for index in range(4)
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(
            command, 0, stdout="2 passed in 0.10s\n", stderr=""
        )

    module.run_batches(
        python="/runtime/python",
        root="tests/system",
        pytest_args=(),
        batch_size=2,
        run=fake_run,
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
