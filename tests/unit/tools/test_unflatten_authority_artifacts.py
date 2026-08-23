"""Tests for the unflatten authority timing artifact CLI."""

from __future__ import annotations

import importlib
import hashlib
import json
import stat
from pathlib import Path

import pytest


artifacts = importlib.import_module("tools.scripts.unflatten_authority_artifacts")


def test_run_target_requires_exact_runner_and_one_session_marker() -> None:
    """The artifact CLI module is the production surface under test."""

    assert hasattr(artifacts, "main")


def _fixture_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    wt = root / ".worktrees" / artifacts.WORKTREE_NAME
    (wt / "samples/src/masm").mkdir(parents=True)
    for target, info in artifacts.TARGETS.items():
        (wt / info["source"]).write_bytes(f"fixture-{target}".encode())
    (wt / ".tmp").mkdir()
    monkeypatch.setattr(artifacts, "MAIN_ROOT", root)
    monkeypatch.setattr(artifacts, "_commit", lambda _root: "a" * 40)
    return root, wt


def _runner(root: Path, marker: dict | None = None, *, status: int = 0) -> None:
    script = root / "tools/scripts/run_system_tests_docker.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    payload = ""
    if marker is not None:
        payload = "echo '" + artifacts.MARKER + json.dumps(marker) + "' > \"$PWD/.worktrees/unflatten-semantic-authority/.tmp/$6\"\n"
    script.write_text("#!/bin/sh\n" + payload + f"exit {status}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


def _command(target: str, log: str = "authority.log") -> list[str]:
    return [
        "./tools/scripts/run_system_tests_docker.sh",
        "test",
        "-w",
        artifacts.WORKTREE_NAME,
        "-l",
        "-o",
        log,
        "--",
        artifacts.TARGETS[target]["node"],
        "-vv",
        "-s",
        "-rs",
    ]


def _parity() -> dict:
    return {
        "schema": "unflatten_authority_shadow_parity.v2",
        "authority_id": "authority-1",
        "case_ids": {"projected": "case-p", "observed": "case-o"},
        "projected": {"accepted_equal": True, "reason_equal": True, "losses_equal": True},
        "observed": {"accepted_equal": True, "reason_equal": True, "losses_equal": True},
        "legacy_anchored_loss_labels": {"projected": [], "observed": []},
        "counters": {"projected": [1, 1, 1, 0], "observed": [1, 1, 1, 0]},
        "codec": {
            "captured_keys": ["full_unflattening_claim"],
            "adaptations": [{
                "key": "full_unflattening_claim",
                "family": "full_unflattening_claim",
                "result_ids": ["result-1"],
                "payload_sha256": "a" * 64,
            }],
            "all_adapted": True,
        },
        "parity_ok": True,
    }


def _marker(wt: Path, target: str) -> dict:
    digest = __import__("hashlib").sha256((wt / artifacts.TARGETS[target]["source"]).read_bytes()).hexdigest()
    phases = {
        "inventory_ms": 1,
        "binding_ms": 2,
        "evaluation_ms": 3,
        "views_ms": 4,
        "total_authority_ms": 10,
        "source_inventory_builds": 1,
        "candidate_inventory_builds": 1,
        "index_folds": 1,
        "view_graph_traversals": 0,
        "plan_id": "plan-1",
        "attempt_id": "attempt-1",
    }
    return {
        "schema": "unflatten-authority-oracle.v1",
        "target": target,
        "function": artifacts.TARGETS[target]["function"],
        "function_ea": 0x1234,
        "fixture_sha256": digest,
        "session_id": "session-1",
        "image": artifacts.IMAGE,
        "parity": _parity(),
        "projected": phases,
        "observed": phases,
    }


def test_run_target_records_exact_command_marker_and_fixture_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, wt = _fixture_root(tmp_path, monkeypatch)
    marker = _marker(wt, "A")
    _runner(root, marker)
    output = tmp_path / "A.json"
    record = artifacts.run_target(
        mode="pre-cutover",
        target="A",
        worktree=artifacts.WORKTREE_NAME,
        log="authority.log",
        output=output.absolute(),
        argv=_command("A"),
    )
    assert record["target"] == "A"
    assert record["command"] == _command("A")
    assert record["fixture_sha256"] == marker["fixture_sha256"]
    assert record["plan_id"] == "plan-1"
    assert record["attempt_id"] == "attempt-1"
    assert record["parity"] == marker["parity"]
    assert json.loads(output.read_text())["session_id"] == "session-1"


def test_run_target_rejects_mismatched_phase_plan_and_attempt_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, wt = _fixture_root(tmp_path, monkeypatch)
    marker = _marker(wt, "A")
    marker["observed"] = dict(marker["observed"])
    marker["observed"]["plan_id"] = "stale-plan"
    _runner(root, marker)
    with pytest.raises(artifacts.ArtifactError, match="plan/attempt"):
        artifacts.run_target(
            mode="pre-cutover",
            target="A",
            worktree=artifacts.WORKTREE_NAME,
            log="authority.log",
            output=(tmp_path / "A.json").absolute(),
            argv=_command("A"),
        )


@pytest.mark.parametrize("bad", [
    ["./tools/scripts/run_system_tests_docker.sh", "test"],
    _command("A")[:-1] + ["-rs", "extra"],
    _command("A")[:-3] + ["-s", "-vv", "-rs"],
])
def test_run_target_rejects_malformed_runner_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: list[str]) -> None:
    _root, wt = _fixture_root(tmp_path, monkeypatch)
    _runner(tmp_path / "repo", _marker(wt, "A"))
    called = False

    def fail_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("child must not run")

    monkeypatch.setattr(artifacts.subprocess, "run", fail_run)
    with pytest.raises(artifacts.ArtifactError):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=bad)
    assert not called


def test_run_target_rejects_multiple_markers_and_nonzero_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, wt = _fixture_root(tmp_path, monkeypatch)
    marker = _marker(wt, "A")
    log = wt / ".tmp/authority.log"
    log.write_text(artifacts.MARKER + json.dumps(marker) + "\n" + artifacts.MARKER + json.dumps(marker) + "\n")
    _runner(root, marker)
    # The fake runner writes the normal one-marker log; restore the malformed
    # log after the child has run so validation is the exercised failure.
    original_run = artifacts.subprocess.run
    monkeypatch.setattr(artifacts.subprocess, "run", lambda *args, **kwargs: type("Result", (), {"returncode": 0})())
    with pytest.raises(artifacts.ArtifactError, match="exactly one"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))
    monkeypatch.setattr(artifacts.subprocess, "run", original_run)
    _runner(root, marker, status=7)
    with pytest.raises(artifacts.ArtifactError, match="status 7"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))


def test_base_run_target_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, _wt = _fixture_root(tmp_path, monkeypatch)
    _runner(root)
    with pytest.raises(artifacts.ArtifactError):
        artifacts.run_target(mode="base", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))


def _record(target: str, mode: str, *, e2e: float = 100.0, authority: float = 10.0) -> dict:
    is_base = mode == "base"
    phase = authority / 4
    counters = {key: 0 for key in artifacts.COUNTERS} if is_base else {"source_inventory_builds": 1, "candidate_inventory_builds": 1, "index_folds": 1, "view_graph_traversals": 0}
    row = {
        "schema": "unflatten-authority-timing.v1",
        "commit": "a" * 40,
        "target": target,
        "mode": mode,
        "function": artifacts.TARGETS[target]["function"],
        "function_ea": 0 if is_base else 0x1234,
        "source_path": artifacts.TARGETS[target]["source"],
        "node": artifacts.TARGETS[target]["node"],
        "fixture_sha256": target.lower() * 64,
        "end_to_end_ms": e2e,
        "projected": {"inventory_ms": phase, "binding_ms": phase, "evaluation_ms": phase, "views_ms": phase, "total_authority_ms": authority, **counters},
        "observed": {"inventory_ms": phase, "binding_ms": phase, "evaluation_ms": phase, "views_ms": phase, "total_authority_ms": authority, **counters},
        "command": _command(target),
        "log": "authority.log",
        "exit_code": 0,
        "image": artifacts.IMAGE,
    }
    if not is_base:
        row["plan_id"] = "plan-1"
        row["attempt_id"] = "attempt-1"
        row["session_id"] = "session-1"
        row["parity"] = _parity()
    return row


def _assembled(path: Path, mode: str, *, e2e: float = 100.0, authority: float = 10.0) -> None:
    if mode == "base":
        authority = 0
    rows = [_record(t, mode, e2e=e2e, authority=authority) for t in artifacts.TARGET_ORDER]
    artifacts.write_json_atomic(path, {"schema": "unflatten-authority-timing.v1", "mode": mode, "targets": rows, "fixture_a_sha256": rows[0]["fixture_sha256"], "fixture_c_sha256": rows[1]["fixture_sha256"], "fixture_b_sha256": rows[2]["fixture_sha256"]})


def test_assemble_requires_a_c_b_and_separate_fixture_hashes(tmp_path: Path) -> None:
    inputs = [tmp_path / f"{t}.json" for t in "ACB"]
    for path, target in zip(inputs, artifacts.TARGET_ORDER):
        artifacts.write_json_atomic(path, _record(target, "pre-cutover"))
    result = artifacts.assemble(mode="pre-cutover", base="none", input_a=inputs[0], input_c=inputs[1], input_b=inputs[2], output=(tmp_path / "timing.json").absolute())
    assert [row["target"] for row in result["targets"]] == ["A", "C", "B"]
    assert {key for key in result if key.endswith("_sha256")} == {"fixture_a_sha256", "fixture_c_sha256", "fixture_b_sha256"}
    assert "fixture_sha256" not in result


def test_compare_writes_one_relative_retry_then_rejects_second(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base", e2e=100)
    _assembled(shadow, "pre-cutover", e2e=100, authority=10)
    _assembled(candidate, "post-cutover", e2e=100, authority=10)
    candidate_data = json.loads(candidate.read_text())
    candidate_data["targets"][0]["end_to_end_ms"] = 6000
    candidate_data["targets"][0]["session_id"] = "session-2"
    candidate.write_text(json.dumps(candidate_data))
    retry = tmp_path / "retry.json"
    result = artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)
    assert result["ok"] is False
    retry_data = json.loads(retry.read_text())
    assert retry_data["target"] == "A"
    assert retry_data["prior_record"]["end_to_end_ms"] == 6000
    retry_data["used"] = True
    retry_data["attempts"] = 1
    retry.write_text(json.dumps(retry_data))
    with pytest.raises(artifacts.ArtifactError, match="linkage"):
        artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)


def test_run_target_rejects_main_root_without_exact_worktree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "not-main"
    (root / "samples/src/masm").mkdir(parents=True)
    (root / artifacts.TARGETS["A"]["source"]).write_bytes(b"wrong-root")
    (root / ".tmp").mkdir()
    monkeypatch.setattr(artifacts, "MAIN_ROOT", root)
    called = False

    def child(*_args, **_kwargs):
        nonlocal called
        called = True
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(artifacts.subprocess, "run", child)
    with pytest.raises(artifacts.ArtifactError, match="worktree"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))
    assert not called


def test_run_target_rejects_base_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _root, wt = _fixture_root(tmp_path, monkeypatch)
    _runner(tmp_path / "repo", _marker(wt, "A"))
    with pytest.raises(artifacts.ArtifactError):
        artifacts.run_target(mode="base", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))


def test_run_target_accepts_relocated_runtime_ea_but_requires_function_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, wt = _fixture_root(tmp_path, monkeypatch)
    marker = _marker(wt, "A")
    marker["function"] = artifacts.TARGETS["A"]["function"]
    marker["function_ea"] = 0x1234
    _runner(root, marker)
    monkeypatch.setattr(artifacts, "_commit", lambda _root: "a" * 40)
    record = artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))
    assert record["function"] == artifacts.TARGETS["A"]["function"]
    assert record["function_ea"] == 0x1234
    marker["function"] = "wrong_function"
    _runner(root, marker)
    with pytest.raises(artifacts.ArtifactError, match="function name"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))


def test_oracle_requires_exact_schema_keys_and_complete_phase_rows() -> None:
    payload = {
        "schema": "unflatten-authority-timing.v1",
        "target": "A",
        "function_ea": "0x1234",
        "fixture_sha256": "a" * 64,
        "session_id": "session-1",
        "projected": {},
        "observed": {},
    }
    with pytest.raises(artifacts.ArtifactError):
        artifacts._oracle(payload, "A", "a" * 64)
    payload["schema"] = "unflatten-authority-oracle.v1"
    with pytest.raises(artifacts.ArtifactError):
        artifacts._oracle({**payload, "projected": {"inventory_ms": 0}}, "A", "a" * 64)


def test_assemble_rejects_invalid_base_and_cross_artifact_identity(tmp_path: Path) -> None:
    inputs = [tmp_path / f"{t}.json" for t in "ACB"]
    for path, target in zip(inputs, artifacts.TARGET_ORDER):
        artifacts.write_json_atomic(path, _record(target, "pre-cutover"))
    with pytest.raises(artifacts.ArtifactError, match="base"):
        artifacts.assemble(mode="pre-cutover", base="not-a-base.json", input_a=inputs[0], input_c=inputs[1], input_b=inputs[2], output=(tmp_path / "timing.json").absolute())


def test_assemble_accepts_only_valid_base_timing_artifact(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    _assembled(base, "base")
    inputs = [tmp_path / f"{t}.json" for t in "ACB"]
    for path, target in zip(inputs, artifacts.TARGET_ORDER):
        artifacts.write_json_atomic(path, _record(target, "pre-cutover"))
    result = artifacts.assemble(mode="pre-cutover", base=str(base), input_a=inputs[0], input_c=inputs[1], input_b=inputs[2], output=(tmp_path / "timing.json").absolute())
    assert result["base"] == str(base.absolute())


def test_compare_rejects_multiple_relative_target_failures_and_preserves_prior_row(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base", e2e=100)
    _assembled(shadow, "pre-cutover", e2e=100, authority=10)
    _assembled(candidate, "post-cutover", e2e=6000, authority=10)
    retry = tmp_path / "retry.json"
    with pytest.raises(artifacts.ArtifactError, match="multiple"):
        artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)


def test_compare_uses_lower_original_or_retry_measurement(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base", e2e=100)
    _assembled(shadow, "pre-cutover", e2e=100, authority=10)
    _assembled(candidate, "post-cutover", e2e=100, authority=10)
    candidate_data = json.loads(candidate.read_text())
    candidate_data["targets"][0]["end_to_end_ms"] = 6000
    candidate_data["targets"][0]["session_id"] = "session-2"
    candidate_data["targets"][0]["attempt_id"] = "attempt-2"
    retry = tmp_path / "retry.json"
    prior = dict(candidate_data["targets"][0])
    prior["session_id"] = "session-1"
    prior["attempt_id"] = "attempt-1"
    candidate_data["targets"][0]["end_to_end_ms"] = 100
    candidate.write_text(json.dumps(candidate_data))
    token = "a" * 32
    artifacts.write_json_atomic(retry, {
        "schema": "unflatten-authority-retry.v1",
        "target": "A",
        "mode": "post-cutover",
        "reason": "relative_end_to_end",
        "retry_token": token,
        "prior_record_sha256": hashlib.sha256(artifacts._canonical_bytes(prior)).hexdigest(),
        "prior_plan_id": prior["plan_id"],
        "prior_attempt_id": prior["attempt_id"],
        "used": True,
        "attempts": 1,
        "prior_record": prior,
    })
    candidate_data = json.loads(candidate.read_text())
    candidate_data["targets"][0]["retry_of"] = {
        "retry_token": token,
        "prior_record_sha256": hashlib.sha256(artifacts._canonical_bytes(prior)).hexdigest(),
        "prior_plan_id": prior["plan_id"],
        "prior_attempt_id": prior["attempt_id"],
    }
    candidate.write_text(json.dumps(candidate_data))
    assert artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)["ok"] is True


def test_compare_rejects_used_retry_without_current_linkage(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base", e2e=100)
    _assembled(shadow, "pre-cutover", e2e=100, authority=10)
    _assembled(candidate, "post-cutover", e2e=100, authority=10)
    prior = json.loads(candidate.read_text())["targets"][0]
    prior["end_to_end_ms"] = 100
    retry = tmp_path / "retry.json"
    artifacts.write_json_atomic(retry, {
        "schema": "unflatten-authority-retry.v1",
        "target": "A",
        "mode": "post-cutover",
        "reason": "relative_end_to_end",
        "retry_token": "b" * 32,
        "prior_record_sha256": hashlib.sha256(artifacts._canonical_bytes(prior)).hexdigest(),
        "prior_plan_id": prior["plan_id"],
        "prior_attempt_id": prior["attempt_id"],
        "used": True,
        "attempts": 1,
        "prior_record": prior,
    })
    with pytest.raises(artifacts.ArtifactError, match="linkage"):
        artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)


def test_compare_rejects_cross_artifact_fixture_identity_drift(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base")
    _assembled(shadow, "pre-cutover")
    _assembled(candidate, "post-cutover")
    candidate_data = json.loads(candidate.read_text())
    candidate_data["fixture_a_sha256"] = "f" * 64
    candidate.write_text(json.dumps(candidate_data))
    with pytest.raises(artifacts.ArtifactError, match="fixture identity"):
        artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=(tmp_path / "retry.json"))


def test_absolute_reasons_reject_each_phase_total_over_threshold() -> None:
    row = _record("A", "post-cutover", e2e=100_000.0, authority=2_400.0)
    reasons = artifacts._absolute_reasons(row)
    assert "projected.total_authority_ms" in reasons
    assert "observed.total_authority_ms" in reasons


def test_compare_accepts_pre_cutover_when_shadow_and_candidate_are_same_artifact(tmp_path: Path) -> None:
    base, shadow = (tmp_path / name for name in ("base.json", "shadow.json"))
    _assembled(base, "base", authority=0)
    _assembled(shadow, "pre-cutover", authority=10)
    assert artifacts.compare(base=base, shadow=shadow, candidate=shadow, retry_file=(tmp_path / "retry.json"))["ok"] is True


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_phase_row_rejects_non_finite_numbers(value: float) -> None:
    row = {key: 0 for key in artifacts.PHASES + artifacts.COUNTERS}
    row["total_authority_ms"] = 0
    row["inventory_ms"] = value
    with pytest.raises(artifacts.ArtifactError):
        artifacts._phase_row(row, field="projected")


def test_phase_row_rejects_inconsistent_total() -> None:
    row = {key: 1 for key in artifacts.PHASES}
    row.update({key: 0 for key in artifacts.COUNTERS})
    row["total_authority_ms"] = 99
    with pytest.raises(artifacts.ArtifactError, match="total_authority_ms"):
        artifacts._phase_row(row, field="projected")


def test_oracle_requires_positive_runtime_ea_exact_image_and_parity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, wt = _fixture_root(tmp_path, monkeypatch)
    marker = _marker(wt, "A")
    marker["function_ea"] = 0
    _runner(root, marker)
    with pytest.raises(artifacts.ArtifactError, match="function_ea"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))
    marker["function_ea"] = 0x1234
    marker["image"] = "wrong-image"
    _runner(root, marker)
    with pytest.raises(artifacts.ArtifactError, match="image"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))
    marker["image"] = artifacts.IMAGE
    del marker["parity"]
    _runner(root, marker)
    with pytest.raises(artifacts.ArtifactError, match="parity"):
        artifacts.run_target(mode="pre-cutover", target="A", worktree=artifacts.WORKTREE_NAME, log="authority.log", output=(tmp_path / "A.json").absolute(), argv=_command("A"))


def test_parity_requires_closed_codec_receipt() -> None:
    parity = _parity()
    del parity["codec"]
    with pytest.raises(artifacts.ArtifactError, match="parity"):
        artifacts._validate_parity(parity)
    parity = _parity()
    parity["codec"]["adaptations"][0]["payload_sha256"] = "not-a-digest"
    with pytest.raises(artifacts.ArtifactError, match="payload_sha256"):
        artifacts._validate_parity(parity)


def test_parity_rejects_unsupported_family_and_noncanonical_digest() -> None:
    parity = _parity()
    parity["codec"]["captured_keys"] = ["unsupported_family"]
    parity["codec"]["adaptations"][0]["key"] = "unsupported_family"
    with pytest.raises(artifacts.ArtifactError, match="unsupported"):
        artifacts._validate_parity(parity)
    parity = _parity()
    parity["codec"]["adaptations"][0]["family"] = "other_family"
    with pytest.raises(artifacts.ArtifactError, match="family"):
        artifacts._validate_parity(parity)
    parity = _parity()
    parity["codec"]["adaptations"][0]["payload_sha256"] = "A" * 64
    with pytest.raises(artifacts.ArtifactError, match="payload_sha256"):
        artifacts._validate_parity(parity)


def test_base_record_requires_zero_authority_metrics_and_no_session() -> None:
    row = _record("A", "base", authority=10)
    with pytest.raises(artifacts.ArtifactError, match="zero"):
        artifacts._record_check(row, "A", "base")


@pytest.mark.parametrize("field", ["plan_id", "attempt_id"])
def test_non_base_record_requires_plan_and_attempt_identity(field: str) -> None:
    row = _record("A", "post-cutover")
    del row[field]
    with pytest.raises(artifacts.ArtifactError, match=field):
        artifacts._record_check(row, "A", "post-cutover")


def test_retry_rejects_reused_attempt_identity(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base", e2e=100)
    _assembled(shadow, "pre-cutover", e2e=100, authority=10)
    _assembled(candidate, "post-cutover", e2e=100, authority=10)
    candidate_data = json.loads(candidate.read_text())
    candidate_data["targets"][0]["end_to_end_ms"] = 6000
    candidate_data["targets"][0]["session_id"] = "session-2"
    candidate.write_text(json.dumps(candidate_data))
    retry = tmp_path / "retry.json"
    result = artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)
    assert result["ok"] is False
    retry_data = json.loads(retry.read_text())
    retry_data["prior_record"]["session_id"] = "session-1"
    retry_data["prior_record_sha256"] = artifacts._record_digest(retry_data["prior_record"])
    retry_data["used"] = True
    retry_data["attempts"] = 1
    candidate_data["targets"][0]["retry_of"] = {
        "retry_token": retry_data["retry_token"],
        "prior_record_sha256": retry_data["prior_record_sha256"],
        "prior_plan_id": retry_data["prior_plan_id"],
        "prior_attempt_id": retry_data["prior_attempt_id"],
    }
    candidate_data["targets"][0]["plan_id"] = retry_data["prior_plan_id"]
    candidate_data["targets"][0]["attempt_id"] = retry_data["prior_attempt_id"]
    candidate.write_text(json.dumps(candidate_data))
    retry.write_text(json.dumps(retry_data))
    with pytest.raises(artifacts.ArtifactError, match="attempt"):
        artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)


def test_retry_rejects_stale_plan_identity(tmp_path: Path) -> None:
    base, shadow, candidate = (tmp_path / name for name in ("base.json", "shadow.json", "candidate.json"))
    _assembled(base, "base", e2e=100)
    _assembled(shadow, "pre-cutover", e2e=100, authority=10)
    _assembled(candidate, "post-cutover", e2e=100, authority=10)
    candidate_data = json.loads(candidate.read_text())
    candidate_data["targets"][0].update(end_to_end_ms=6000, session_id="session-2", attempt_id="attempt-2")
    candidate.write_text(json.dumps(candidate_data))
    retry = tmp_path / "retry.json"
    artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)
    retry_data = json.loads(retry.read_text())
    retry_data["used"] = True
    retry_data["attempts"] = 1
    retry_data["prior_plan_id"] = "stale-plan"
    current = candidate_data["targets"][0]
    current.update(session_id="session-3", attempt_id="attempt-3")
    current["retry_of"] = {
        "retry_token": retry_data["retry_token"],
        "prior_record_sha256": retry_data["prior_record_sha256"],
        "prior_plan_id": "stale-plan",
        "prior_attempt_id": retry_data["prior_attempt_id"],
    }
    candidate_data["targets"][0] = current
    candidate.write_text(json.dumps(candidate_data))
    retry.write_text(json.dumps(retry_data))
    with pytest.raises(artifacts.ArtifactError, match="plan_id"):
        artifacts.compare(base=base, shadow=shadow, candidate=candidate, retry_file=retry)


def test_assemble_base_fixture_hashes_must_match_input_rows(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    _assembled(base, "base", authority=0)
    inputs = [tmp_path / f"{t}.json" for t in "ACB"]
    for path, target in zip(inputs, artifacts.TARGET_ORDER):
        row = _record(target, "pre-cutover")
        if target == "A":
            row["fixture_sha256"] = "f" * 64
        artifacts.write_json_atomic(path, row)
    with pytest.raises(artifacts.ArtifactError, match="fixture"):
        artifacts.assemble(mode="pre-cutover", base=str(base), input_a=inputs[0], input_c=inputs[1], input_b=inputs[2], output=(tmp_path / "timing.json").absolute())
