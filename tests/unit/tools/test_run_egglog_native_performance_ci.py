import copy
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CI_RUNNER = REPO_ROOT / "tools" / "scripts" / "run_egglog_native_performance_ci.sh"
COMPARATOR = (
    REPO_ROOT / "tools" / "scripts" / "compare_egglog_native_performance_receipts.py"
)

_COMPARATOR_SPEC = importlib.util.spec_from_file_location(
    "egglog_receipt_comparator", COMPARATOR
)
assert _COMPARATOR_SPEC is not None and _COMPARATOR_SPEC.loader is not None
_COMPARATOR_MODULE = importlib.util.module_from_spec(_COMPARATOR_SPEC)
_COMPARATOR_SPEC.loader.exec_module(_COMPARATOR_MODULE)
compare_receipts = _COMPARATOR_MODULE.compare_receipts

_STAGES = (
    "root_eligibility",
    "ast_construction",
    "native_preflight",
    "egglog_extraction",
    "native_z3",
    "reconstruction",
)


def _valid_receipts() -> tuple[
    tuple[dict[str, object], ...], tuple[dict[str, object], ...]
]:
    native = {
        "corpus": "fixture",
        "execution_count": 1,
        "outcomes": {"accepted": 1},
        "source_names": [["FixtureRule"]],
        "stage_sample_counts": {stage: 1 for stage in _STAGES},
    }
    corpus = {
        "candidate_count": 1,
        "candidate_names": ["add:fixture#1"],
        "docker_image": "idapro-9.4-speedups:ci",
        "docker_image_id": "sha256:fixture",
        "egglog_version": "13.2.0",
        "stage_timing_ms": {
            stage: {"sample_count": 1, "p50_ms": 1.0, "p95_ms": 1.0, "max_ms": 1.0}
            for stage in _STAGES
        },
    }
    return ((native, corpus), (native.copy(), corpus.copy()))


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
  echo 'EGGLOG_MBA_CORPUS_PERFORMANCE_RECEIPT={"candidate_count":1,"candidate_names":["add:fixture#1"],"docker_image":"idapro-9.4-speedups:ci","docker_image_id":"sha256:fixture","egglog_version":"13.2.0","stage_timing_ms":{"root_eligibility":{"sample_count":1},"ast_construction":{"sample_count":1},"native_preflight":{"sample_count":1},"egglog_extraction":{"sample_count":1},"native_z3":{"sample_count":1},"reconstruction":{"sample_count":1}},"kind":"corpus"}'
else
  echo 'EGGLOG_MBA_NATIVE_RECEIPT={"corpus":"fixture","execution_count":1,"outcomes":{"accepted":1},"source_names":[["FixtureRule"]],"stage_sample_counts":{"root_eligibility":1,"ast_construction":1,"native_preflight":1,"egglog_extraction":1,"native_z3":1,"reconstruction":1},"kind":"native"}'
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
        "candidate_count_match": True,
        "candidate_identities_match": True,
        "egglog_version_match": True,
        "image_digest_match": True,
        "image_match": True,
        "native_outcomes_match": True,
        "native_source_identities_match": True,
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


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda _python, cython: cython[1].update(docker_image="different-image"),
            "image_match",
        ),
        (
            lambda _python, cython: cython[1].update(
                docker_image_id="sha256:different"
            ),
            "image_digest_match",
        ),
        (
            lambda _python, cython: cython[1].update(egglog_version="13.3.0"),
            "egglog_version_match",
        ),
        (
            lambda _python, cython: cython[1].update(
                candidate_count=2,
                candidate_names=["add:fixture#1", "add:fixture#2"],
            ),
            "candidate_count_match",
        ),
        (
            lambda _python, cython: cython[1].update(candidate_names=["add:other#1"]),
            "candidate_identities_match",
        ),
        (
            lambda _python, cython: cython[0]["stage_sample_counts"].update(
                root_eligibility=0
            ),
            "positive stage sample count",
        ),
        (
            lambda _python, cython: cython[0]["stage_sample_counts"].update(
                root_eligibility=2
            ),
            "stage sample counts must equal execution_count",
        ),
        (
            lambda _python, cython: cython[0].update(outcomes={"native_z3_failed": 1}),
            "native_outcomes_match",
        ),
        (
            lambda _python, cython: cython[0].update(source_names=[["OtherRule"]]),
            "native_source_identities_match",
        ),
        (
            lambda _python, cython: cython[0]["stage_sample_counts"].pop(
                "reconstruction"
            ),
            "expected stage set",
        ),
        (
            lambda _python, cython: cython[0].update(corpus="other-fixture"),
            "native_stage_coverage_match",
        ),
    ],
)
def test_comparator_rejects_incomplete_or_mismatched_receipts(
    mutate, message: str
) -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = copy.deepcopy(python_rows)
    cython_rows = copy.deepcopy(cython_rows)
    mutate(python_rows, cython_rows)

    with pytest.raises(ValueError, match=message):
        compare_receipts(python_rows, cython_rows)


def test_ci_runner_removes_stale_comparison_before_a_failed_run(tmp_path: Path) -> None:
    tools_dir = tmp_path / "tools" / "scripts"
    tools_dir.mkdir(parents=True)
    shutil.copy2(
        COMPARATOR,
        tools_dir / "compare_egglog_native_performance_receipts.py",
    )
    runner = tools_dir / "run_system_tests_docker.sh"
    runner.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
    runner.chmod(0o755)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    stale_comparison = artifact_dir / "comparison.json"
    stale_comparison.write_text('{"green": true}\n', encoding="utf-8")

    result = subprocess.run(
        ["bash", str(CI_RUNNER)],
        check=False,
        capture_output=True,
        env=os.environ
        | {
            "D810_EGGLOG_PERF_ARTIFACT_DIR": str(artifact_dir),
            "D810_REPO_ROOT": str(tmp_path),
        },
        text=True,
    )

    assert result.returncode != 0
    assert not stale_comparison.exists()
