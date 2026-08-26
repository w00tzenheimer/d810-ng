from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess


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
    assert calls[1][3:] == ["-v", "tests/system/test_x.py::test_4"]


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
        ["tests/system/test_x.py::test_0", "tests/system/test_x.py::test_1"],
        ["tests/system/test_x.py::test_2"],
        [oracle],
    ]
