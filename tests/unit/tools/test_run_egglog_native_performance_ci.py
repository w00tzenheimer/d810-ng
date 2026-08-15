import copy
import importlib.util
import json
import os
import shutil
import subprocess
from collections import Counter
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


def test_ci_runner_defaults_to_the_cli_image() -> None:
    source = CI_RUNNER.read_text(encoding="utf-8")

    assert 'IMAGE="${D810_DOCKER_IMAGE:-idapro-9.4-speedups:cli}"' in source


def test_ci_runner_profiles_real_idb_only_when_explicitly_requested() -> None:
    source = CI_RUNNER.read_text(encoding="utf-8")

    assert 'CPROFILE="${D810_EGGLOG_CPROFILE:-0}"' in source
    assert 'D810_EGGLOG_CPROFILE_DIR="$CONTAINER_PROFILE_DIR"' in source
    assert 'D810_CYTHON_PROFILE="$CYTHON_TRACE"' in source
    assert "for corpus in egglog-add-spike egglog-mba-families-spike" in source
    assert '"$PROFILE_HOST_DIR/$corpus.prof"' in source


def _real_attempts() -> list[dict[str, object]]:
    applied = [
        {
            "candidate_identity": f"fixture#{index}:matched",
            "status": "applied",
            "refusal_reason": None,
            "source_names": ["FixtureRule"],
            "degree": 1,
            "input_cost": [2, 3],
            "output_cost": [1, 2],
            "stage_timings_ms": {stage: 1.0 for stage in _STAGES},
            "proof_mode": "shadow",
            "template_source_name": "FixtureRule",
            "template_fallback_reason": None,
            "template_proof_verdict": True,
            "legacy_proof_verdict": True,
            "template_proof_elapsed_ms": 1.0,
            "legacy_proof_elapsed_ms": 1.0,
            "native_matcher_backend": "python",
            "native_matcher_comparisons": 4,
            "native_matcher_lazy_swaps": 1,
            "native_fixed_binding_count": 2,
            "native_matcher_elapsed_ms": 1.0,
        }
        for index in range(1, 32)
    ]
    return [
        *applied,
        {
            "candidate_identity": "fixture#32:ineligible",
            "status": "ineligible",
            "refusal_reason": "candidate_budget",
            "source_names": [],
            "degree": None,
            "input_cost": None,
            "output_cost": None,
            "stage_timings_ms": {"root_eligibility": 1.0},
            "proof_mode": None,
            "template_source_name": None,
            "template_fallback_reason": None,
            "template_proof_verdict": None,
            "legacy_proof_verdict": None,
            "template_proof_elapsed_ms": None,
            "legacy_proof_elapsed_ms": None,
            "native_matcher_backend": None,
            "native_matcher_comparisons": None,
            "native_matcher_lazy_swaps": None,
            "native_fixed_binding_count": None,
            "native_matcher_elapsed_ms": None,
        },
    ]


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
    real_attempts = _real_attempts()
    real_native = {
        "schema_version": 3,
        "corpus": "egglog-compiler-shapes",
        "function": "fixture_function",
        "project": "fixture_project",
        "execution_count": len(real_attempts),
        "candidate_identities": [
            attempt["candidate_identity"] for attempt in real_attempts
        ],
        "outcomes": dict(Counter(attempt["status"] for attempt in real_attempts)),
        "source_names": [attempt["source_names"] for attempt in real_attempts],
        "proof_attempt_count": 31,
        "proof_mode_counts": {"shadow": 31},
        "stage_sample_counts": {
            "root_eligibility": len(real_attempts),
            "native_preflight": 31,
            "egglog_extraction": 31,
            "ast_construction": 31,
            "native_z3": 31,
            "reconstruction": 31,
        },
        "attempts": real_attempts,
    }
    corpus = {
        "candidate_count": 1,
        "candidate_names": ["add:fixture#1"],
        "docker_image": "idapro-9.4-speedups:cli",
        "docker_image_id": "sha256:fixture",
        "egglog_version": "13.2.0",
        "cython_enabled": False,
        "stage_attempt_outcomes": {"accepted": 1},
        "stage_timing_ms": {
            stage: {"sample_count": 1, "p50_ms": 1.0, "p95_ms": 1.0, "max_ms": 1.0}
            for stage in _STAGES
        },
    }
    cython_corpus = copy.deepcopy(corpus)
    cython_corpus["cython_enabled"] = True
    cython_real = copy.deepcopy(real_native)
    for attempt in cython_real["attempts"][:-1]:
        attempt["native_matcher_backend"] = "cython"
        attempt["native_matcher_elapsed_ms"] = 0.5
    return (
        (native, real_native, corpus),
        (copy.deepcopy(native), cython_real, cython_corpus),
    )


def _set_synthetic_attempt_count(corpus: dict[str, object], count: int) -> None:
    corpus["stage_attempt_outcomes"] = {"accepted": count}
    for timing in corpus["stage_timing_ms"].values():
        timing["sample_count"] = count


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
  if [[ "$D810_NO_CYTHON" == 0 ]]; then
    printf 'EGGLOG_MBA_CORPUS_PERFORMANCE_RECEIPT=%s\\n' "$D810_FAKE_CYTHON_CORPUS"
  else
    printf 'EGGLOG_MBA_CORPUS_PERFORMANCE_RECEIPT=%s\\n' "$D810_FAKE_PYTHON_CORPUS"
  fi
else
  printf 'EGGLOG_MBA_NATIVE_RECEIPT=%s\\n' "$D810_FAKE_NATIVE"
  if [[ "$D810_NO_CYTHON" == 0 ]]; then
    printf 'EGGLOG_MBA_REAL_CORPUS_RECEIPT=%s\\n' "$D810_FAKE_CYTHON_REAL"
  else
    printf 'EGGLOG_MBA_REAL_CORPUS_RECEIPT=%s\\n' "$D810_FAKE_PYTHON_REAL"
  fi
fi
""",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    artifact_dir = tmp_path / "artifacts"
    runner_log = tmp_path / "runner.log"
    python_rows, cython_rows = _valid_receipts()
    env = os.environ | {
        "D810_EGGLOG_PERF_ARTIFACT_DIR": str(artifact_dir),
        "D810_FAKE_RUNNER_LOG": str(runner_log),
        "D810_DOCKER_IMAGE": "idapro-9.4-speedups:cli",
        "D810_REPO_ROOT": str(tmp_path),
        "D810_FAKE_NATIVE": json.dumps(python_rows[0]),
        "D810_FAKE_PYTHON_REAL": json.dumps(python_rows[1]),
        "D810_FAKE_CYTHON_REAL": json.dumps(cython_rows[1]),
        "D810_FAKE_PYTHON_CORPUS": json.dumps(python_rows[2]),
        "D810_FAKE_CYTHON_CORPUS": json.dumps(cython_rows[2]),
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
        "1|test -- tests/system/e2e/test_egglog_add_spike.py tests/system/e2e/test_egglog_mba_families_spike.py tests/system/e2e/test_egglog_mba_compiler_shape_profile.py -q -s",
        "1|test -- tests/system/runtime/backends/test_egglog_mba_performance.py -q -m profile -s",
        "0|test -- tests/system/e2e/test_egglog_add_spike.py tests/system/e2e/test_egglog_mba_families_spike.py tests/system/e2e/test_egglog_mba_compiler_shape_profile.py -q -s",
        "0|test -- tests/system/runtime/backends/test_egglog_mba_performance.py -q -m profile -s",
    ]
    for mode in ("python", "cython"):
        receipts = [
            json.loads(line)
            for line in (artifact_dir / f"{mode}.receipts.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert len(receipts) == 3
        assert "schema_version" in receipts[1]
        assert "candidate_count" in receipts[2]
    comparison = json.loads(
        (artifact_dir / "comparison.json").read_text(encoding="utf-8")
    )
    assert comparison["comparison"] == {
        "candidate_count_match": True,
        "candidate_identities_match": True,
        "cython_mode_match": True,
        "egglog_version_match": True,
        "image_digest_match": True,
        "image_match": True,
        "native_outcomes_match": True,
        "native_source_identities_match": True,
        "native_stage_coverage_match": True,
        "real_corpus_attempts_match": True,
        "real_corpus_matcher_backend_match": True,
        "real_corpus_matcher_binding_count_match": True,
        "real_corpus_matcher_timing_contract_met": True,
        "real_corpus_outcomes_match": True,
        "real_corpus_proof_paths_match": True,
        "real_corpus_proof_modes_match": True,
        "real_corpus_source_identities_match": True,
        "real_corpus_stage_coverage_match": True,
        "synthetic_stage_sample_counts_match": True,
    }


def test_comparator_rejects_missing_identity_metadata(tmp_path: Path) -> None:
    receipt = {
        "candidate_count": 1,
        "docker_image": "idapro-9.4-speedups:cli",
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
            lambda real: real.update(candidate_identities=["fixture#1:one"]),
            "candidate_identities must match execution_count",
        ),
        (
            lambda real: real["stage_sample_counts"].update(root_eligibility=1),
            "root eligibility count must equal execution_count",
        ),
        (
            lambda real: real.update(source_names=[["OtherRule"]] * 32),
            "sources must equal per-attempt sources",
        ),
        (
            lambda real: real.update(proof_mode_counts={"unknown": 2}),
            "proof modes must equal actual proof attempts",
        ),
    ],
)
def test_comparator_rejects_incomplete_real_corpus_receipts(
    mutate, message: str
) -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    mutate(cython_rows[1])

    with pytest.raises(ValueError, match=message):
        compare_receipts(python_rows, cython_rows)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda _python, cython: cython[2].update(docker_image="different-image"),
            "image_match",
        ),
        (
            lambda _python, cython: cython[2].update(
                docker_image_id="sha256:different"
            ),
            "image_digest_match",
        ),
        (
            lambda _python, cython: cython[2].update(egglog_version="13.3.0"),
            "egglog_version_match",
        ),
        (
            lambda _python, cython: cython[2].update(cython_enabled=False),
            "cython_enabled must be True",
        ),
        (
            lambda _python, cython: cython[2].update(
                candidate_count=2,
                candidate_names=["add:fixture#1", "add:fixture#2"],
            ),
            "candidate_count_match",
        ),
        (
            lambda _python, cython: cython[2].update(candidate_names=["add:other#1"]),
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
        (
            lambda _python, cython: cython[1]["candidate_identities"].__setitem__(
                0, "fixture#1:other"
            ),
            "attempts must preserve candidate identities",
        ),
        (
            lambda _python, cython: cython[1]["stage_sample_counts"].update(
                native_z3=2
            ),
            "stage counts must equal per-attempt coverage",
        ),
        (
            lambda _python, cython: cython[1].update(proof_mode_counts={"shadow": 2}),
            "proof modes must equal actual proof attempts",
        ),
        (
            lambda _python, cython: cython[1]["attempts"][0].update(
                native_matcher_backend="python"
            ),
            "real_corpus_matcher_backend_match",
        ),
        (
            lambda _python, cython: cython[1]["attempts"][0].update(
                native_fixed_binding_count=5
            ),
            "real_corpus_matcher_binding_count_match",
        ),
        (
            lambda _python, cython: cython[2]["stage_timing_ms"][
                "root_eligibility"
            ].update(sample_count=2),
            "synthetic stage sample counts must equal stage_attempt_outcomes",
        ),
        (
            lambda _python, cython: _set_synthetic_attempt_count(cython[2], 2),
            "synthetic_stage_sample_counts_match",
        ),
        (
            lambda python, _cython: python.append({"unexpected": "receipt"}),
            "unrecognized receipt row",
        ),
    ],
)
def test_comparator_rejects_incomplete_or_mismatched_receipts(
    mutate, message: str
) -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    mutate(python_rows, cython_rows)

    with pytest.raises(ValueError, match=message):
        compare_receipts(python_rows, cython_rows)


def test_comparator_publishes_predeclared_paired_proof_contract() -> None:
    python_rows, cython_rows = _valid_receipts()

    comparison = compare_receipts(python_rows, cython_rows)

    assert comparison["performance_contract"] == {
        "schema_version": 1,
        "baseline_kind": "native_pod_matcher",
        "minimum_structural_matcher_pairs_per_mode": 30,
        "minimum_p50_matcher_reduction_fraction": 0.2,
        "minimum_p95_matcher_reduction_fraction": 0.1,
        "requires_exact_semantic_parity": True,
    }
    assert comparison["python"]["real_corpus_matcher_timing"] == {
        "mode": "python",
        "reached_preflight_count": 31,
        "sample_count": 31,
        "p50_ms": 1.0,
        "p95_ms": 1.0,
        "max_ms": 1.0,
    }


def test_comparator_excludes_shared_feasibility_noops_from_matcher_timing() -> None:
    """Zero-comparison rows remain paired evidence but are not matcher work."""

    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    for rows in (python_rows, cython_rows):
        attempt = rows[1]["attempts"][0]
        attempt.update(native_matcher_comparisons=0, native_matcher_lazy_swaps=0)

    comparison = compare_receipts(python_rows, cython_rows)

    assert comparison["python"]["real_corpus_matcher_timing"] == {
        "mode": "python",
        "reached_preflight_count": 31,
        "sample_count": 30,
        "p50_ms": 1.0,
        "p95_ms": 1.0,
        "max_ms": 1.0,
    }


def test_comparator_rejects_missing_live_matcher_timing() -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    cython_rows[1]["attempts"][0]["native_matcher_elapsed_ms"] = None

    with pytest.raises(ValueError, match="matched native matcher attempts require"):
        compare_receipts(python_rows, cython_rows)


def test_comparator_rejects_missing_predeclared_matcher_improvement() -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    for attempt in cython_rows[1]["attempts"]:
        if attempt["native_matcher_backend"] is not None:
            attempt["native_matcher_elapsed_ms"] = 1.0

    with pytest.raises(ValueError, match="real_corpus_matcher_timing_contract_met"):
        compare_receipts(python_rows, cython_rows)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda attempt: attempt.update(
                template_proof_verdict=False,
                legacy_proof_verdict=True,
                template_fallback_reason=None,
            ),
            "shadow verdict disagreement requires shadow_divergence",
        ),
        (
            lambda attempt: attempt.update(template_proof_elapsed_ms=None),
            "template proof verdict requires a template timing",
        ),
        (
            lambda attempt: attempt.update(template_source_name=42),
            "template source must be a non-empty string or null",
        ),
        (
            lambda attempt: attempt.update(degree="one"),
            "degree must be an integer in the supported range or null",
        ),
        (
            lambda attempt: attempt.update(input_cost=[2]),
            "input_cost must contain two non-negative integers or null",
        ),
    ],
)
def test_comparator_rejects_identically_malformed_shadow_attempts(
    mutate, message: str
) -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    mutate(python_rows[1]["attempts"][0])
    mutate(cython_rows[1]["attempts"][0])

    with pytest.raises(ValueError, match=message):
        compare_receipts(python_rows, cython_rows)


def test_comparator_accepts_provenance_bearing_shadow_divergence() -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    for rows in (python_rows, cython_rows):
        real = rows[1]
        attempt = real["attempts"][0]
        attempt.update(
            status="proof_failed",
            refusal_reason="native_z3_failed",
            template_proof_verdict=False,
            legacy_proof_verdict=True,
            template_fallback_reason="shadow_divergence",
        )
        real["outcomes"] = {"applied": 30, "ineligible": 1, "proof_failed": 1}

    assert all(compare_receipts(python_rows, cython_rows)["comparison"].values())


def test_comparator_rejects_provenance_free_proof_failure_and_unreached_proof() -> None:
    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    attempt = cython_rows[1]["attempts"][0]
    attempt.update(
        status="proof_failed",
        refusal_reason="native_z3_failed",
        source_names=[],
        template_proof_verdict=False,
        legacy_proof_verdict=True,
        template_fallback_reason="shadow_divergence",
    )
    cython_rows[1]["outcomes"] = {
        "applied": 30,
        "ineligible": 1,
        "proof_failed": 1,
    }

    with pytest.raises(ValueError, match="proof failure must retain source provenance"):
        compare_receipts(python_rows, cython_rows)

    python_rows, cython_rows = _valid_receipts()
    python_rows = list(copy.deepcopy(python_rows))
    cython_rows = list(copy.deepcopy(cython_rows))
    cython_rows[1]["attempts"][31]["template_source_name"] = "leaked"

    with pytest.raises(
        ValueError, match="unreached proof must leave proof fields null"
    ):
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
