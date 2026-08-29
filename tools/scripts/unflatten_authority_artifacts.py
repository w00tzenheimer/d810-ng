"""Write and compare unflatten semantic-authority timing artifacts.

This script intentionally has no project imports.  It is used before the
runtime environment is available, and its input/output format is an evidence
format rather than an application API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


MAIN_ROOT = Path.cwd()
WORKTREE_NAME = "unflatten-semantic-authority"
IMAGE = "idapro-9.4-speedups:latest"
MARKER = "[UNFLATTEN-AUTHORITY-ORACLE] "
TARGETS: dict[str, dict[str, Any]] = {
    "A": {
        "function": "sub_7FF8569F0540",
        "source": "samples/src/masm/sub_7FF8569F0540.asm",
        "node": (
            "tests/system/e2e/test_unflattening_effect_safety_fixtures.py::"
            "TestUnflatteningEffectSafetyDecompilation::"
            "test_target_a_after_preserves_memcpy_effect_and_commits"
        ),
    },
    "C": {
        "function": "sub_7FF855576B50",
        "source": "samples/src/masm/sub_7FF855576B50.asm",
        "node": (
            "tests/system/e2e/test_unflattening_effect_safety_fixtures.py::"
            "TestUnflatteningEffectSafetyDecompilation::"
            "test_target_c_after_preserves_termination_effects_and_commits"
        ),
    },
    "B": {
        "function": "sub_7FF8568132D0",
        "source": "samples/src/masm/sub_7FF8568132D0.asm",
        "node": (
            "tests/system/e2e/test_unflattening_effect_safety_fixtures.py::"
            "TestUnflatteningEffectSafetyDecompilation::"
            "test_target_b_after_preserves_srw_lock_effect_and_commits"
        ),
    },
}
TARGET_ORDER = ("A", "C", "B")
RUN_MODES = ("pre-cutover", "post-cutover", "rebase")
ARTIFACT_MODES = ("base",) + RUN_MODES
PHASES = ("inventory_ms", "binding_ms", "evaluation_ms", "views_ms")
COUNTERS = (
    "source_inventory_builds",
    "candidate_inventory_builds",
    "index_folds",
    "view_graph_traversals",
)
ORACLE_KEYS = frozenset(
    {"schema", "target", "function", "function_ea", "fixture_sha256", "image", "canonical_pair"}
)
CANONICAL_PAIR_KEYS = frozenset({
    "authority_id", "projected_case_id", "observed_case_id", "source_fingerprint",
    "projected_candidate_fingerprint", "observed_candidate_fingerprint",
    "observed_binding_id", "plan_id", "attempt_id", "session_id",
    "projected_timings", "observed_timings",
})


class ArtifactError(ValueError):
    """Raised when an artifact or command is not evidence-safe."""


def _fail(message: str) -> None:
    raise ArtifactError(message)


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def write_json_atomic(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(_canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _worktree_root(worktree: str) -> Path:
    if worktree != WORKTREE_NAME:
        _fail(f"worktree must be exactly {WORKTREE_NAME!r}")
    candidate = MAIN_ROOT / ".worktrees" / worktree
    if not MAIN_ROOT.is_dir() or not candidate.is_dir() or candidate.resolve() == MAIN_ROOT.resolve():
        _fail("MAIN_ROOT must contain the exact .worktrees/unflatten-semantic-authority checkout")
    return candidate


def _commit(worktree_root: Path) -> str:
    try:
        value = subprocess.check_output(
            ["git", "-C", str(worktree_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        _fail(f"cannot resolve committed HEAD for {worktree_root}")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
        _fail("git HEAD is not a 40-hex commit")
    return value


def _digest(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        _fail(f"cannot read fixture {path}: {exc}")
    return hashlib.sha256(data).hexdigest()


def _bare_log(log: str) -> str:
    if not log or Path(log).name != log or log in {".", ".."}:
        _fail("log must be a bare filename")
    return log


def _normal_digest(value: Any) -> str:
    value = str(value)
    if value.startswith("sha256:"):
        value = value[7:]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        _fail("fixture_sha256 must be a raw 64-hex digest")
    return value.lower()


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{field} must be numeric")
    if not math.isfinite(float(value)):
        _fail(f"{field} must be finite")
    if value < 0:
        _fail(f"{field} must be non-negative")
    return float(value)


def _phase_row(row: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(row, dict):
        _fail(f"{field} must be an object")
    result: dict[str, Any] = {}
    for key in PHASES:
        if key not in row:
            _fail(f"{field}.{key} is required")
        result[key] = _number(row[key], f"{field}.{key}")
    for key in COUNTERS:
        if key not in row:
            _fail(f"{field}.{key} is required")
        value = row[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(f"{field}.{key} must be a non-negative integer")
        result[key] = value
    if "total_authority_ms" not in row:
        _fail(f"{field}.total_authority_ms is required")
    result["total_authority_ms"] = _number(
        row["total_authority_ms"], f"{field}.total_authority_ms"
    )
    if abs(result["total_authority_ms"] - sum(result[key] for key in PHASES)) > 1.0:
        _fail(f"{field}.total_authority_ms is inconsistent with phase sum")
    return result


def _canonical_pair(value: Any) -> tuple[str, str, str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != CANONICAL_PAIR_KEYS:
        _fail("canonical_pair keys are invalid")
    for key in (
        "authority_id", "projected_case_id", "observed_case_id", "source_fingerprint",
        "projected_candidate_fingerprint", "observed_candidate_fingerprint",
        "observed_binding_id", "plan_id", "attempt_id", "session_id",
    ):
        if not isinstance(value[key], str) or not value[key]:
            _fail(f"canonical_pair.{key} is invalid")
    if value["projected_case_id"] == value["observed_case_id"]:
        _fail("canonical_pair case IDs must be distinct")
    projected = _phase_row(value["projected_timings"], field="canonical_pair.projected_timings")
    observed = _phase_row(value["observed_timings"], field="canonical_pair.observed_timings")
    return (
        value["plan_id"], value["attempt_id"], value["session_id"],
        projected, observed, dict(value),
    )


def _oracle(payload: Any, target: str, fixture_sha256: str) -> tuple[str, str, str, int, dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    if not isinstance(payload, dict):
        _fail("oracle marker JSON must be an object")
    schema = payload.get("schema")
    if schema != "unflatten-authority-oracle.v2":
        _fail("oracle schema is invalid")
    if set(payload) != ORACLE_KEYS:
        missing = ", ".join(sorted(ORACLE_KEYS - set(payload)))
        _fail(f"oracle keys are invalid; missing {missing or 'none'}")
    if payload.get("target") != target:
        _fail("oracle target does not match requested target")
    expected = TARGETS[target]
    if payload.get("function") != expected["function"]:
        _fail("oracle function name does not match target")
    function_ea = payload.get("function_ea")
    if isinstance(function_ea, bool) or not isinstance(function_ea, int) or function_ea <= 0:
        _fail("oracle function_ea is invalid")
    marker_digest = payload["fixture_sha256"]
    if not isinstance(marker_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", marker_digest):
        _fail("oracle fixture_sha256 must be a raw 64-hex digest")
    marker_digest = marker_digest.lower()
    if marker_digest != fixture_sha256:
        _fail("oracle fixture identity does not match committed MASM")
    plan_id, attempt_id, session, projected, observed, canonical_pair = _canonical_pair(payload["canonical_pair"])
    if payload["image"] != IMAGE:
        _fail("oracle image is invalid")
    return session, plan_id, attempt_id, function_ea, projected, observed, payload["image"], canonical_pair


def _marker_payload(log_path: Path) -> Any:
    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _fail(f"cannot read child log {log_path}: {exc}")
    markers = [line[len(MARKER) :] for line in lines if line.startswith(MARKER)]
    if len(markers) != 1:
        _fail(f"expected exactly one authority oracle marker, found {len(markers)}")
    try:
        return json.loads(markers[0])
    except json.JSONDecodeError as exc:
        _fail(f"authority oracle marker is not JSON: {exc}")


def _validate_child_argv(argv: Sequence[str], target: str, log: str) -> None:
    expected = TARGETS[target]
    prefix = [
        "./tools/scripts/run_system_tests_docker.sh",
        "test",
        "-w",
        WORKTREE_NAME,
        "-l",
        "-o",
        log,
        "--",
    ]
    expected_argv = prefix + [expected["node"], "-vv", "-s", "-rs"]
    if list(argv) != expected_argv:
        _fail("child argv must be the exact A/C/B system runner command")


def run_target(
    *,
    mode: str,
    target: str,
    worktree: str,
    log: str,
    output: Path,
    argv: Sequence[str],
    retry_of: dict[str, str] | None = None,
) -> dict[str, Any]:
    if mode not in RUN_MODES:
        _fail("run-target mode must be pre-cutover, post-cutover, or rebase")
    if target not in TARGETS:
        _fail("target must be exactly one of A, C, B")
    log = _bare_log(log)
    if not Path(output).is_absolute():
        _fail("output must be an absolute path")
    _validate_child_argv(argv, target, log)
    worktree_root = _worktree_root(worktree)
    source_path = worktree_root / TARGETS[target]["source"]
    fixture_sha256 = _digest(source_path)
    started = time.perf_counter_ns()
    completed = subprocess.run(list(argv), cwd=MAIN_ROOT, check=False)
    ended = time.perf_counter_ns()
    if completed.returncode != 0:
        _fail(f"child exited with status {completed.returncode}")
    payload = _marker_payload(worktree_root / ".tmp" / log)
    session_id, plan_id, attempt_id, runtime_function_ea, projected, observed, image, canonical_pair = _oracle(payload, target, fixture_sha256)
    target_info = TARGETS[target]
    record = {
        "schema": "unflatten-authority-timing.v1",
        "commit": _commit(worktree_root),
        "target": target,
        "function": target_info["function"],
        "function_ea": runtime_function_ea,
        "source_path": target_info["source"],
        "node": target_info["node"],
        "fixture_sha256": fixture_sha256,
        "plan_id": plan_id,
        "attempt_id": attempt_id,
        "mode": mode,
        "end_to_end_ms": (ended - started) / 1_000_000.0,
        "projected": projected,
        "observed": observed,
        "command": list(argv),
        "log": log,
        "exit_code": completed.returncode,
        "image": image,
        "canonical_pair": canonical_pair,
        "output": str(Path(output)),
    }
    record["session_id"] = session_id
    if retry_of is not None:
        if set(retry_of) != {"retry_token", "prior_record_sha256", "prior_plan_id", "prior_attempt_id"}:
            _fail("retry linkage is invalid")
        record["retry_of"] = {
            "retry_token": _retry_token(retry_of["retry_token"]),
            "prior_record_sha256": retry_of["prior_record_sha256"],
            "prior_plan_id": retry_of["prior_plan_id"],
            "prior_attempt_id": retry_of["prior_attempt_id"],
        }
        if not re.fullmatch(r"[0-9a-f]{64}", str(record["retry_of"]["prior_record_sha256"])):
            _fail("retry linkage digest is invalid")
    write_json_atomic(Path(output), record)
    return record


def _read_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read JSON {path}: {exc}")
    if not isinstance(value, dict):
        _fail(f"JSON artifact {path} must be an object")
    return value


def _record_check(record: dict[str, Any], target: str, mode: str) -> None:
    if record.get("schema") != "unflatten-authority-timing.v1":
        _fail("target record schema is invalid")
    if record.get("target") != target or record.get("mode") != mode:
        _fail("target record identity does not match assemble request")
    target_info = TARGETS[target]
    if record.get("source_path") != target_info["source"]:
        _fail("target record source identity is invalid")
    if record.get("function") != target_info["function"]:
        _fail("target record function identity is invalid")
    if record.get("node") != target_info["node"]:
        _fail("target record node identity is invalid")
    runtime_ea = record.get("function_ea")
    if isinstance(runtime_ea, bool) or not isinstance(runtime_ea, int) or runtime_ea < 0:
        _fail("target record function_ea is invalid")
    if mode != "base" and runtime_ea <= 0:
        _fail("non-base target record function_ea must be positive")
    if mode == "base" and runtime_ea != 0:
        _fail("base target record function_ea must be zero")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", str(record.get("commit", ""))):
        _fail("target record commit is invalid")
    _normal_digest(record.get("fixture_sha256", ""))
    _number(record.get("end_to_end_ms"), "end_to_end_ms")
    phase_rows = {
        key: _phase_row(record.get(key), field=key)
        for key in ("projected", "observed")
    }
    command = record.get("command")
    if not isinstance(command, list) or not command:
        _fail("target record command is invalid")
    log = record.get("log")
    _validate_child_argv(command, target, _bare_log(log))
    exit_code = record.get("exit_code")
    if exit_code != 0:
        _fail("target record exit_code must be zero")
    image = record.get("image")
    if image != IMAGE:
        _fail("target record image is invalid")
    if mode != "base":
        for key in ("plan_id", "attempt_id"):
            value = record.get(key)
            if not isinstance(value, str) or not value:
                _fail(f"non-base target record {key} is required")
        session = record.get("session_id")
        if not isinstance(session, str) or not session:
            _fail("non-base target record session_id is required")
        (
            pair_plan_id,
            pair_attempt_id,
            pair_session_id,
            pair_projected,
            pair_observed,
            _,
        ) = _canonical_pair(record.get("canonical_pair"))
        if (record["plan_id"], record["attempt_id"], record["session_id"]) != (
            pair_plan_id,
            pair_attempt_id,
            pair_session_id,
        ):
            _fail("target record correlation must match canonical_pair")
        if (phase_rows["projected"], phase_rows["observed"]) != (pair_projected, pair_observed):
            _fail("target record timings must match canonical_pair")
    else:
        for key in ("plan_id", "attempt_id"):
            if key in record:
                _fail(f"base target record must not contain {key}")
        if "session_id" in record:
            _fail("base target record must not contain session_id")
        if "canonical_pair" in record:
            _fail("base target record must not contain canonical_pair")
        for subject in ("projected", "observed"):
            if any(record[subject][key] != 0 for key in (*PHASES, *COUNTERS, "total_authority_ms")):
                _fail("base target record authority metrics must be zero")


def assemble(*, mode: str, base: str, input_a: Path, input_c: Path, input_b: Path, output: Path) -> dict[str, Any]:
    if mode not in RUN_MODES:
        _fail("assemble mode must be pre-cutover, post-cutover, or rebase")
    if not Path(output).is_absolute():
        _fail("output must be an absolute path")
    base_artifact = None
    if base.lower() != "none":
        base_artifact = _read_json(base)
        _artifact_check(base_artifact, "base")
    paths = (input_a, input_c, input_b)
    records = tuple(_read_json(path) for path in paths)
    for target, record in zip(TARGET_ORDER, records):
        _record_check(record, target, mode)
    if base_artifact is not None:
        for target, record in zip(TARGET_ORDER, records):
            base_hash = _normal_digest(base_artifact[f"fixture_{target.lower()}_sha256"])
            if _normal_digest(record["fixture_sha256"]) != base_hash:
                _fail(f"{target} fixture identity differs from base")
    if len({record["target"] for record in records}) != 3:
        _fail("assembled targets must be distinct")
    result: dict[str, Any] = {
        "schema": "unflatten-authority-timing.v1",
        "mode": mode,
        "fixture_a_sha256": records[0]["fixture_sha256"],
        "fixture_c_sha256": records[1]["fixture_sha256"],
        "fixture_b_sha256": records[2]["fixture_sha256"],
        "targets": list(records),
    }
    if base.lower() != "none":
        result["base"] = str(Path(base).absolute())
    write_json_atomic(Path(output), result)
    return result


def _authority_total(record: dict[str, Any]) -> float:
    return float(record["projected"]["total_authority_ms"]) + float(record["observed"]["total_authority_ms"])


def _record_digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(record)).hexdigest()


def _retry_token(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        _fail("retry token is invalid")
    return value


def _command_from_row(record: dict[str, Any]) -> list[str]:
    command = record.get("command")
    if not isinstance(command, list):
        _fail("target record command is invalid")
    return command


def _relative_reasons(
    record: dict[str, Any],
    base: dict[str, Any],
    shadow: dict[str, Any],
    mode: str,
) -> list[str]:
    if mode == "pre-cutover":
        return []
    reasons: list[str] = []
    if _authority_total(record) > 1.20 * _authority_total(shadow) + 100.0:
        reasons.append("relative_authority")
    if float(record["end_to_end_ms"]) > 1.15 * float(base["end_to_end_ms"]) + 5000.0:
        reasons.append("relative_end_to_end")
    return reasons


def _apply_retry_measurements(
    rows: dict[str, dict[str, Any]],
    retry_file: Path,
    base_rows: dict[str, dict[str, Any]],
    shadow_rows: dict[str, dict[str, Any]],
) -> None:
    if not retry_file.exists():
        return
    retry = _read_json(retry_file)
    if not retry.get("used"):
        return
    prior = retry.get("prior_record")
    target = retry.get("target")
    if not isinstance(prior, dict) or not isinstance(target, str) or target not in rows or prior.get("target") != target:
        _fail("retry record lacks its prior target record")
    mode = str(retry.get("mode"))
    if retry.get("schema") != "unflatten-authority-retry.v1" or retry.get("attempts") != 1:
        _fail("retry record is not exactly one consumed attempt")
    _record_check(prior, target, mode)
    prior_digest = retry.get("prior_record_sha256")
    if prior_digest != _record_digest(prior):
        _fail("retry prior record digest is invalid")
    token = _retry_token(retry.get("retry_token"))
    current = rows[target]
    linkage = current.get("retry_of")
    if not isinstance(linkage, dict) or set(linkage) != {"retry_token", "prior_record_sha256", "prior_plan_id", "prior_attempt_id"}:
        _fail("retry current record linkage is missing")
    if linkage.get("retry_token") != token or linkage.get("prior_record_sha256") != prior_digest:
        _fail("retry current record linkage does not match")
    current_session = current.get("session_id")
    prior_session = prior.get("session_id")
    if not isinstance(current_session, str) or not current_session or current_session == prior_session:
        _fail("retry requires a new nonempty session linkage")
    for key in ("plan_id", "attempt_id"):
        if not isinstance(prior.get(key), str) or not prior[key] or not isinstance(current.get(key), str) or not current[key]:
            _fail(f"retry requires {key} identity")
        if retry.get(f"prior_{key}") != prior[key]:
            _fail(f"retry prior {key} linkage does not match")
        if linkage.get(f"prior_{key}") != prior[key]:
            _fail(f"retry current {key} linkage does not match")
    if current["plan_id"] != prior["plan_id"]:
        _fail("retry plan_id does not match prior record")
    if current["attempt_id"] == prior["attempt_id"]:
        _fail("retry requires a new attempt_id")
    for key in (
        "schema", "mode", "target", "commit", "fixture_sha256", "function",
        "function_ea", "source_path", "node", "command", "log", "output", "image",
    ):
        if current.get(key) != prior.get(key):
            _fail(f"retry {key} identity does not match prior record")
    reason = retry.get("reason")
    if reason not in _relative_reasons(prior, base_rows[target], shadow_rows[target], mode):
        _fail("retry reason is not evidenced by prior record")
    if "retry_record_sha256" in retry and retry["retry_record_sha256"] != _record_digest(current):
        _fail("retry record digest does not match current record")
    current = rows[target]
    merged = json.loads(json.dumps(current))
    merged["end_to_end_ms"] = min(float(current["end_to_end_ms"]), float(prior["end_to_end_ms"]))
    for subject in ("projected", "observed"):
        for key in (*PHASES, "total_authority_ms"):
            merged[subject][key] = min(float(current[subject][key]), float(prior[subject][key]))
    rows[target] = merged


def _absolute_reasons(record: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for subject in ("projected", "observed"):
        row = record[subject]
        if tuple(row[key] for key in COUNTERS) != (1, 1, 1, 0):
            reasons.append(f"{subject}.counters")
        for phase in PHASES:
            if float(row[phase]) > 2000.0:
                reasons.append(f"{subject}.{phase}")
        if float(row["total_authority_ms"]) > 2000.0:
            reasons.append(f"{subject}.total_authority_ms")
    if _authority_total(record) > max(500.0, 0.05 * float(record["end_to_end_ms"])):
        reasons.append("authority_total")
    return reasons


def _rows(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return _artifact_check(artifact, str(artifact.get("mode")))


def _artifact_check(artifact: dict[str, Any], expected_mode: str) -> dict[str, dict[str, Any]]:
    if artifact.get("schema") != "unflatten-authority-timing.v1":
        _fail("assembled artifact schema is invalid")
    if expected_mode not in ARTIFACT_MODES or artifact.get("mode") != expected_mode:
        _fail("assembled artifact mode is invalid")
    if "fixture_sha256" in artifact:
        _fail("assembled artifact must not contain singular fixture_sha256")
    hash_fields = {
        "A": "fixture_a_sha256",
        "C": "fixture_c_sha256",
        "B": "fixture_b_sha256",
    }
    for key in hash_fields.values():
        if key not in artifact:
            _fail(f"assembled artifact missing {key}")
        _normal_digest(artifact[key])
    rows = artifact.get("targets")
    if not isinstance(rows, list) or len(rows) != 3:
        _fail("assembled artifact must contain exactly three targets")
    result: dict[str, dict[str, Any]] = {}
    for target, row in zip(TARGET_ORDER, rows):
        if not isinstance(row, dict):
            _fail("assembled target rows must be objects")
        _record_check(row, target, expected_mode)
        if _normal_digest(row["fixture_sha256"]) != _normal_digest(artifact[hash_fields[target]]):
            _fail(f"{target} fixture identity does not match assembled hash")
        result[target] = row
    if tuple(result) != TARGET_ORDER:
        _fail("assembled rows must be ordered A, C, B")
    return result


def compare(*, base: Path, shadow: Path, candidate: Path, retry_file: Path) -> dict[str, Any]:
    base_artifact, shadow_artifact, candidate_artifact = (
        _read_json(base),
        _read_json(shadow),
        _read_json(candidate),
    )
    base_rows = _artifact_check(base_artifact, "base")
    shadow_rows = _artifact_check(shadow_artifact, "pre-cutover")
    candidate_mode = str(candidate_artifact.get("mode"))
    if candidate_mode not in {"pre-cutover", "post-cutover", "rebase"}:
        _fail("candidate mode is invalid")
    candidate_rows = _artifact_check(candidate_artifact, candidate_mode)
    for target in TARGET_ORDER:
        digest = _normal_digest(base_artifact[f"fixture_{target.lower()}_sha256"])
        for artifact in (shadow_artifact, candidate_artifact):
            if _normal_digest(artifact[f"fixture_{target.lower()}_sha256"]) != digest:
                _fail(f"{target} fixture identity differs across artifacts")
    _apply_retry_measurements(candidate_rows, Path(retry_file), base_rows, shadow_rows)
    failures: list[dict[str, str]] = []
    for target in TARGET_ORDER:
        candidate_row = candidate_rows[target]
        absolute = _absolute_reasons(candidate_row)
        if absolute:
            failures.extend({"target": target, "reason": reason, "kind": "absolute"} for reason in absolute)
            continue
        if candidate_mode != "pre-cutover":
            failures.extend(
                {"target": target, "reason": reason, "kind": "relative"}
                for reason in _relative_reasons(candidate_row, base_rows[target], shadow_rows[target], candidate_mode)
            )
    absolute_failures = [failure for failure in failures if failure["kind"] == "absolute"]
    relative_failures = [failure for failure in failures if failure["kind"] == "relative"]
    if absolute_failures:
        _fail("comparison failed: " + ", ".join(f"{x['target']}:{x['reason']}" for x in absolute_failures))
    if relative_failures:
        if len(relative_failures) != 1:
            _fail("multiple relative target failures cannot be represented by one retry")
        if Path(retry_file).exists():
            prior = _read_json(retry_file)
            if prior.get("used") or int(prior.get("attempts", 0)) >= 1:
                _fail("relative threshold failed after the one allowed retry")
        failure = relative_failures[0]
        row = (candidate_rows if candidate_mode != "pre-cutover" else shadow_rows)[failure["target"]]
        retry = {
            "schema": "unflatten-authority-retry.v1",
            "target": failure["target"],
            "mode": candidate_mode,
            "reason": failure["reason"],
            "prior_command": _command_from_row(row),
            "prior_record": row,
            "prior_record_sha256": _record_digest(row),
            "prior_plan_id": row.get("plan_id"),
            "prior_attempt_id": row.get("attempt_id"),
            "retry_token": secrets.token_hex(16),
            "output": row.get("output"),
            "worktree": WORKTREE_NAME,
            "log": row.get("log"),
            "attempts": 0,
            "used": False,
        }
        write_json_atomic(Path(retry_file), retry)
        return {"ok": False, "retry": retry}
    return {"ok": True, "mode": candidate_mode}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run-target")
    run.add_argument("--mode", choices=RUN_MODES, required=False)
    run.add_argument("--target", choices=TARGETS, required=False)
    run.add_argument("--worktree", default=WORKTREE_NAME)
    run.add_argument("--log")
    run.add_argument("--output")
    run.add_argument("--retry-file")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    assemble_parser = commands.add_parser("assemble")
    assemble_parser.add_argument("--mode", required=True)
    assemble_parser.add_argument("--base", required=True)
    assemble_parser.add_argument("--input-a", type=Path, required=True)
    assemble_parser.add_argument("--input-c", type=Path, required=True)
    assemble_parser.add_argument("--input-b", type=Path, required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--base", type=Path, required=True)
    compare_parser.add_argument("--shadow", type=Path, required=True)
    compare_parser.add_argument("--candidate", type=Path, required=True)
    compare_parser.add_argument("--retry-file", type=Path, required=True)
    return parser


def _run_retry(path: Path) -> dict[str, Any]:
    retry = _read_json(path)
    if retry.get("used") is not False or retry.get("attempts") != 0:
        _fail("retry record has already been consumed")
    command = retry.get("prior_command") or retry.get("command")
    output = retry.get("output")
    log = retry.get("log")
    prior = retry.get("prior_record")
    if retry.get("schema") != "unflatten-authority-retry.v1" or not isinstance(prior, dict):
        _fail("retry record schema or prior record is invalid")
    target = retry.get("target")
    mode = retry.get("mode")
    if target not in TARGETS or mode not in RUN_MODES:
        _fail("retry target or mode is invalid")
    _record_check(prior, target, mode)
    prior_digest = retry.get("prior_record_sha256")
    if prior_digest != _record_digest(prior):
        _fail("retry prior record digest is invalid")
    token = _retry_token(retry.get("retry_token"))
    if not isinstance(command, list) or not isinstance(output, str) or not isinstance(log, str):
        _fail("retry record lacks command, output, or log")
    # Consume the single retry before starting the child.  A failed retry is
    # still an attempt and must not become an accidental second retry.
    retry["attempts"] = 1
    retry["used"] = True
    write_json_atomic(path, retry)
    result = run_target(
        mode=mode,
        target=target,
        worktree=str(retry.get("worktree", WORKTREE_NAME)),
        log=log,
        output=Path(output),
        argv=command,
        retry_of={
            "retry_token": token,
            "prior_record_sha256": prior_digest,
            "prior_plan_id": retry.get("prior_plan_id"),
            "prior_attempt_id": retry.get("prior_attempt_id"),
        },
    )
    retry["retry_record_sha256"] = _record_digest(result)
    write_json_atomic(path, retry)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run-target":
            if args.retry_file:
                _run_retry(Path(args.retry_file))
            else:
                if not all((args.mode, args.target, args.log, args.output)):
                    _fail("run-target requires mode, target, log, and output")
                child = list(args.argv)
                if child and child[0] == "--":
                    child = child[1:]
                run_target(
                    mode=args.mode,
                    target=args.target,
                    worktree=args.worktree,
                    log=args.log,
                    output=Path(args.output),
                    argv=child,
                )
        elif args.command == "assemble":
            assemble(
                mode=args.mode,
                base=args.base,
                input_a=args.input_a,
                input_c=args.input_c,
                input_b=args.input_b,
                output=args.output,
            )
        else:
            result = compare(
                base=args.base,
                shadow=args.shadow,
                candidate=args.candidate,
                retry_file=args.retry_file,
            )
            if not result.get("ok", False):
                return 2
    except ArtifactError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
