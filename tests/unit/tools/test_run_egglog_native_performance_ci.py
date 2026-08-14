import json
import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
CI_RUNNER = REPO_ROOT / "tools" / "scripts" / "run_egglog_native_performance_ci.sh"
COMPARATOR = (
    REPO_ROOT / "tools" / "scripts" / "compare_egglog_native_performance_receipts.py"
)


def test_ci_runner_archives_two_mode_json_receipts(tmp_path: Path) -> None:
    tools_dir = tmp_path / "tools" / "scripts"
    tools_dir.mkdir(parents=True)
    shutil.copy2(
        REPO_ROOT
        / "tools"
        / "scripts"
        / "compare_egglog_native_performance_receipts.py",
        tools_dir / "compare_egglog_native_performance_receipts.py",
    )
    runner = tools_dir / "run_system_tests_docker.sh"
    runner.write_text(
        """#!/usr/bin/env bash
set -eu
printf '%s|%s\\n' "$D810_NO_CYTHON" "$*" >> "$D810_FAKE_RUNNER_LOG"
if [[ "$*" == *"test_egglog_mba_performance.py"* ]]; then
  echo 'EGGLOG_MBA_CORPUS_PERFORMANCE_RECEIPT={"candidate_count":1,"candidate_names":["add:fixture#1"],"docker_image":"idapro-9.4-speedups:ci","docker_image_id":"sha256:fixture","egglog_version":"13.2.0","stage_timing_ms":{"egglog_extraction":{}},"kind":"corpus"}'
else
  echo 'EGGLOG_MBA_NATIVE_RECEIPT={"corpus":"fixture","execution_count":1,"source_names":[["FixtureRule"]],"stage_sample_counts":{"egglog_extraction":1},"kind":"native"}'
fi
""",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    artifact_dir = tmp_path / "artifacts"
    runner_log = tmp_path / "runner.log"
    env = os.environ | {
        "D810_EGGLOG_PERF_ARTIFACT_DIR": str(artifact_dir),
        "D810_FAKE_RUNNER_LOG": str(runner_log),
        "D810_DOCKER_IMAGE": "idapro-9.4-speedups:ci",
        "D810_REPO_ROOT": str(tmp_path),
    }

    result = subprocess.run(
        ["bash", str(CI_RUNNER)],
        check=False,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Wrote Egglog native performance receipts to" in result.stdout
    assert runner_log.read_text(encoding="utf-8").splitlines() == [
        "1|test -- tests/system/e2e/test_egglog_add_spike.py tests/system/e2e/test_egglog_mba_families_spike.py -q -s",
        "1|test -- tests/system/runtime/backends/test_egglog_mba_performance.py -q -m profile -s",
        "0|test -- tests/system/e2e/test_egglog_add_spike.py tests/system/e2e/test_egglog_mba_families_spike.py -q -s",
        "0|test -- tests/system/runtime/backends/test_egglog_mba_performance.py -q -m profile -s",
    ]
    for mode in ("python", "cython"):
        receipts = [
            json.loads(line)
            for line in (artifact_dir / f"{mode}.receipts.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert [receipt["kind"] for receipt in receipts] == ["native", "corpus"]
    comparison = json.loads(
        (artifact_dir / "comparison.json").read_text(encoding="utf-8")
    )
    assert comparison["comparison"] == {
        "candidate_identities_match": True,
        "egglog_version_match": True,
        "image_digest_match": True,
        "image_match": True,
        "native_stage_coverage_match": True,
    }


def test_comparator_rejects_missing_identity_metadata(tmp_path: Path) -> None:
    receipt = {
        "candidate_count": 1,
        "docker_image": "idapro-9.4-speedups:ci",
        "docker_image_id": "sha256:fixture",
        "egglog_version": "13.2.0",
    }
    python_path = tmp_path / "python.jsonl"
    cython_path = tmp_path / "cython.jsonl"
    python_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    cython_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            str(COMPARATOR),
            "--python",
            str(python_path),
            "--cython",
            str(cython_path),
            "--output",
            str(tmp_path / "comparison.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "candidate_names" in result.stderr
