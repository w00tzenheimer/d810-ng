#!/usr/bin/env python3
"""Qualify each collected DSL project and profile every node in a fresh child."""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from tools.bench.canonical_dac_measurement import (
    child_options_log_dir,
    prepare_activation,
    pytest_command,
    render_profile,
)
from tools.bench.canonical_dac_probe import combine_evidence


UNSAFE_LEDGER_FIELDS = (
    "legacy_rule_mismatches",
    "legacy_binding_mismatches",
    "legacy_binding_unknown",
    "new_safe_coverage_pending",
    "unsafe_mutations",
    "unproved_structural_replacements",
)
EXECUTION_HELPER_SOURCES = (
    "tools/bench/canonical_dac_probe.py",
    "tools/bench/canonical_dac_measurement.py",
    "tools/bench/dsl_profile_collection.py",
    "tools/bench/dsl_per_test_profile.py",
    "tools/scripts/mba_structural_matcher_certificate.py",
)


def collection_command(python: str, test_path: str) -> list[str]:
    return [
        python,
        "-u",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "tools.bench.dsl_profile_collection",
        "--collect-only",
        "-q",
        "-o",
        "addopts=",
        test_path,
    ]


def validate_collection_manifest(
    document: object, *, limit: int | None = None
) -> list[dict]:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("invalid collection manifest")
    rows = document.get("nodes")
    if not isinstance(rows, list) or not rows:
        raise ValueError("empty collection manifest")
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError("limit must be a positive integer")
    seen = set()
    normalized = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid collection row")
        nodeid, project = row.get("nodeid"), row.get("project")
        if type(nodeid) is not str or not nodeid:
            raise ValueError("collection row has no nodeid")
        if nodeid in seen:
            raise ValueError(f"duplicate collection nodeid: {nodeid}")
        seen.add(nodeid)
        if (
            type(project) is not str
            or not project
            or Path(project).name != project
            or not project.endswith(".json")
        ):
            raise ValueError(f"unknown project mapping for {nodeid}")
        normalized.append({"nodeid": nodeid, "project": project})
    return normalized if limit is None else normalized[:limit]


def group_nodes_by_project(nodes: list[dict]) -> OrderedDict[str, list[str]]:
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    for row in nodes:
        grouped.setdefault(row["project"], []).append(row["nodeid"])
    return grouped


def _test_status(receipt: dict) -> str:
    if receipt.get("timeout") is True:
        return "timeout"
    if (
        receipt.get("exit") == 0
        and receipt.get("skipped") == 1
        and receipt.get("passed", 0) == 0
        and receipt.get("failed", 0) == 0
    ):
        return "skipped"
    if (
        receipt.get("exit") == 0
        and receipt.get("passed") == 1
        and receipt.get("failed", 0) == 0
        and receipt.get("skipped", 0) == 0
    ):
        return "passed"
    return "failed"


def _validate_generic_run(receipt: dict) -> None:
    if _test_status(receipt) != "passed":
        raise ValueError("qualification node did not pass exactly once")


def _refusal(
    project: str,
    reason: str,
    evidence_nodes: list[str],
    skipped_nodes: list[str],
    **extra,
) -> dict:
    return {
        "project": project,
        "status": "refused",
        "reason": reason,
        "evidence_nodes": list(evidence_nodes),
        "skipped_nodes": list(skipped_nodes),
        **extra,
    }


def assess_qualification(receipts: list[dict], *, project: str, admission) -> dict:
    """Admit the shortest unchanged collection-order prefix with positive evidence."""
    evidence_receipts = []
    evidence_nodes: list[str] = []
    skipped_nodes: list[str] = []
    for raw in receipts:
        nodeid = raw.get("nodeid")
        status = _test_status(raw)
        if status == "skipped":
            skipped_nodes.append(nodeid)
            continue
        if status != "passed":
            return _refusal(
                project,
                "test_failed",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
                test_status=status,
            )
        records = raw.get("records")
        if not isinstance(records, list) or not records:
            return _refusal(
                project,
                "missing_observation",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
            )
        matching = [row for row in records if row.get("project") == project]
        if not matching:
            return _refusal(
                project,
                "wrong_project_capture",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
            )
        latest = matching[-1]
        snapshot, ledger = latest.get("snapshot"), latest.get("ledger")
        if snapshot is None or ledger is None:
            enrollment = latest.get("enrollment", {})
            if enrollment.get("selected_rule_count") == 0:
                return {
                    "project": project,
                    "status": "not_applicable",
                    "reason": "no_selected_catalogue",
                    "evidence_nodes": evidence_nodes,
                    "skipped_nodes": skipped_nodes,
                }
            return _refusal(
                project,
                "missing_authorizable_snapshot",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
            )
        if snapshot.get("structural_authorizable") is not True:
            return _refusal(
                project,
                "snapshot_not_authorizable",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
            )
        if any(
            type(ledger.get(name)) is not int or ledger[name] != 0
            for name in UNSAFE_LEDGER_FIELDS
        ):
            return _refusal(
                project,
                "unsafe_evidence",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
            )
        segment = deepcopy(raw)
        segment["segment_id"] = nodeid
        evidence_receipts.append(segment)
        evidence_nodes.append(nodeid)
        try:
            combined = combine_evidence(
                evidence_receipts, project=project, run_validator=_validate_generic_run
            )
        except (KeyError, TypeError, ValueError) as exc:
            return _refusal(
                project,
                "incompatible_evidence",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
                error=repr(exc),
            )
        if combined["ledger"]["legacy_match_count"] <= 0:
            continue
        combined["adapters"] = deepcopy(latest["adapters"])
        evidence = {
            "schema_version": 1,
            "runtime_mode": combined["toolchain"]["matcher_backend"]["backend"],
            "snapshot": combined["snapshot"],
            "ledger": combined["ledger"],
            "coverage_limit": (
                "bounded collection-order subset; not per-rule empirical coverage"
            ),
            "segments": combined["segments"],
            "enrollment": combined["enrollment"],
            "canonical_status_by_rule_width": combined[
                "canonical_status_by_rule_width"
            ],
            "snapshot_widths": combined["snapshot_widths"],
            "legacy_only_observation_count": combined["legacy_only_observation_count"],
            "legacy_only_match_count": combined["legacy_only_match_count"],
            "adapters": combined["adapters"],
        }
        try:
            certificate = admission(evidence)
        except (KeyError, TypeError, ValueError) as exc:
            return _refusal(
                project,
                "certificate_refused",
                evidence_nodes,
                skipped_nodes,
                failed_node=nodeid,
                error=repr(exc),
            )
        return {
            "project": project,
            "status": "qualified",
            "reason": "admitted",
            "evidence_nodes": evidence_nodes,
            "skipped_nodes": skipped_nodes,
            "coverage_limit": evidence["coverage_limit"],
            "evidence": evidence,
            "certificate": certificate,
        }
    return {
        "project": project,
        "status": "unqualified",
        "reason": "no_positive_evidence",
        "evidence_nodes": evidence_nodes,
        "skipped_nodes": skipped_nodes,
    }


def profile_command(python: str, nodeid: str, profile_path: Path) -> list[str]:
    return pytest_command(python, nodeid, profile_path=profile_path)


def inspect_profile(profile_path: Path, *, test_status: str) -> dict:
    if not profile_path.exists():
        return {
            "raw_profile": str(profile_path),
            "profile_status": "missing",
            "test_status": test_status,
        }
    try:
        metrics = render_profile(profile_path)
    except BaseException as exc:
        return {
            "raw_profile": str(profile_path),
            "profile_status": "unreadable",
            "test_status": test_status,
            "error": repr(exc),
        }
    return {
        "raw_profile": str(profile_path),
        "profile_status": "readable",
        "test_status": test_status,
        "metrics": metrics,
    }


def validate_runtime_partition(
    raw: dict, *, expected_project: str, qualified: dict
) -> None:
    if raw.get("project") != expected_project:
        raise ValueError("generated project was not selected")
    if raw.get("toolchain", {}).get("matcher_backend", {}).get("backend") != "cython":
        raise ValueError("canonical profile requires native Cython backend")
    if any(row.get("project") != expected_project for row in raw.get("records", [])):
        raise ValueError("canonical capture contains an unexpected project record")
    records = [
        row for row in raw.get("records", []) if row.get("project") == expected_project
    ]
    if not records:
        raise ValueError("generated project produced no live partition")
    expected = qualified.get("adapters", [])
    expected_rows = [
        (row.get("rule_id"), row.get("name"), row.get("canonical_eligible"))
        for row in expected
    ]
    required = [
        (eligible is True, eligible is True) for _, _, eligible in expected_rows
    ]
    for record in records:
        if record.get("snapshot") != qualified.get("snapshot"):
            raise ValueError("live canonical snapshot changed from qualification")
        if record.get("enrollment") != qualified.get("enrollment"):
            raise ValueError("live canonical enrollment changed from qualification")
        if record.get("snapshot_widths") != qualified.get("snapshot_widths"):
            raise ValueError(
                "live canonical snapshot widths changed from qualification"
            )
        if record.get("canonical_status_by_rule_width") != qualified.get(
            "canonical_status_by_rule_width"
        ):
            raise ValueError(
                "live canonical width status matrix changed from qualification"
            )
        actual = record.get("adapters", [])
        actual_rows = [
            (row.get("rule_id"), row.get("name"), row.get("canonical_eligible"))
            for row in actual
        ]
        if actual_rows != expected_rows:
            raise ValueError(
                "live canonical catalogue partition changed from qualification"
            )
        active = [
            (
                row.get("canonical_fallback_enabled"),
                row.get("uses_structural_matching"),
            )
            for row in actual
        ]
        if active != required:
            raise ValueError("qualified canonical partition was not active")


def validate_legacy_partition(raw: dict, *, expected_project: str) -> None:
    if raw.get("project") != expected_project:
        raise ValueError("original project was not selected")
    if any(row.get("project") != expected_project for row in raw.get("records", [])):
        raise ValueError(
            "legacy-unqualified capture contains an unexpected project record"
        )
    records = [
        row for row in raw.get("records", []) if row.get("project") == expected_project
    ]
    if not records:
        raise ValueError("legacy profile produced no live project record")
    for record in records:
        if record.get("snapshot") is not None or record.get("ledger") is not None:
            raise ValueError(
                "legacy-unqualified profile unexpectedly admitted a snapshot"
            )
        if any(
            row.get("canonical_fallback_enabled") is True
            or row.get("uses_structural_matching") is True
            for row in record.get("adapters", [])
        ):
            raise ValueError("legacy-unqualified profile activated canonical matching")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_capture(path: Path) -> tuple[dict, str | None]:
    if not path.exists():
        return {}, "missing capture receipt"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"unreadable capture receipt: {exc!r}"
    if not isinstance(value, dict):
        return {}, "capture receipt is not a JSON object"
    return value, None


def _slug(value: str, index: int) -> str:
    stem = "".join(character if character.isalnum() else "-" for character in value)
    stem = "-".join(filter(None, stem.split("-")))[:48] or "node"
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"{index:03d}-{stem}-{digest}"


def _clean_environment(
    *,
    original_project: str,
    target_project: str,
    output: Path,
    idalog: Path,
    tmpdir: Path,
    canonical: bool,
) -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "D810_CANONICAL_MATCH_FALLBACK",
        "D810_STRUCTURAL_DSL_MATCHING",
        "D810_LEGACY_DSL_PERMUTATIONS",
        "D810_SHADOW_DSL_MATCHING",
        "D810_CANONICAL_DAC_WITNESSES",
        "D810_CANONICAL_DAC_SCHEDULE_DIAGNOSTIC",
        "D810_PROFILE_CONTROLLER",
        "D810_CPROFILE",
        "D810_PYINSTRUMENT",
    ):
        env.pop(name, None)
    env.update(
        D810_CANONICAL_DAC_ORIGINAL_PROJECT=original_project,
        D810_CANONICAL_DAC_PROJECT=target_project,
        D810_CANONICAL_DAC_OUT=str(output),
        D810_CANONICAL_DAC_AGGREGATE_ONLY="1",
        IDALOG=str(idalog),
        TMPDIR=str(tmpdir),
    )
    if canonical:
        env["D810_CANONICAL_MATCH_FALLBACK"] = "1"
        env["D810_CANONICAL_DAC_ACTIVATION_PROOF"] = "1"
    else:
        env.pop("D810_CANONICAL_DAC_ACTIVATION_PROOF", None)
    return env


def _execute_child(
    *,
    command: list[str],
    env: dict[str, str],
    run_dir: Path,
    native_dir: Path,
    options: Path,
    timeout: int,
) -> dict:
    run_dir.mkdir(parents=True, exist_ok=False)
    native_dir.mkdir(parents=True, exist_ok=False)
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=False)
    process = {
        "command": command,
        "environment": {
            key: value for key, value in env.items() if key.startswith("D810_")
        },
        "paths": {
            "run_dir": str(run_dir),
            "native_dir": str(native_dir),
            "idalog": env["IDALOG"],
            "tmpdir": env["TMPDIR"],
        },
        "exit": None,
    }
    _write_json(run_dir / "process.json", process)
    started = time.perf_counter()
    try:
        with child_options_log_dir(options, native_dir):
            with (run_dir / "pytest.log").open("w", encoding="utf-8") as log:
                completed = subprocess.run(
                    command,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                )
        process["exit"] = completed.returncode
    except subprocess.TimeoutExpired as exc:
        process.update(exit=-1, timeout=True, error=repr(exc))
    except BaseException as exc:
        process.update(exit=-1, error=repr(exc))
    process["process_seconds"] = time.perf_counter() - started
    _write_json(run_dir / "process.json", process)
    return process


def _collection(
    *, python: str, test_path: str, output: Path, timeout: int
) -> tuple[dict, dict]:
    manifest_path = output / "collection.json"
    command = collection_command(python, test_path)
    env = dict(os.environ)
    env["D810_DSL_PROFILE_COLLECTION_OUT"] = str(manifest_path)
    process = {"command": command, "exit": None}
    _write_json(output / "collection-process.json", process)
    started = time.perf_counter()
    try:
        with (output / "collection.log").open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                command,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
        process["exit"] = completed.returncode
    except subprocess.TimeoutExpired as exc:
        process.update(exit=-1, timeout=True, error=repr(exc))
    except BaseException as exc:
        process.update(exit=-1, error=repr(exc))
    process["process_seconds"] = time.perf_counter() - started
    _write_json(output / "collection-process.json", process)
    if process["exit"] != 0:
        raise RuntimeError(f"pytest collection failed: exit={process['exit']}")
    if not manifest_path.exists():
        raise RuntimeError("pytest collection produced no manifest")
    return json.loads(manifest_path.read_text(encoding="utf-8")), process


def _certificate_builder(root: Path):
    path = root / "tools/scripts/mba_structural_matcher_certificate.py"
    spec = importlib.util.spec_from_file_location("dsl_certificate_builder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load unchanged certificate builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_certificate


def _execution_provenance(root: Path) -> dict:
    image = os.environ.get("D810_TEST_RUNTIME_IMAGE")
    image_id = os.environ.get("D810_TEST_RUNTIME_IMAGE_ID")
    if Path("/app/ida").is_dir() and (
        not image or not image_id or not image_id.startswith("sha256:")
    ):
        raise ValueError(
            "maintained runner did not provide exact runtime image identity"
        )
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--short"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return {
        "runtime_image": image or "local-portable-check",
        "runtime_image_id": image_id or "not-applicable",
        "git_revision": revision,
        "git_dirty": dirty,
        "execution_helper_sources": {
            name: _digest(root / name) for name in EXECUTION_HELPER_SOURCES
        },
    }


def _project_manifest(root: Path, *, project: str, nodes: list[str]) -> dict:
    relative_sources = [
        "samples/bins/libobfuscated.dll",
        f"src/d810/conf/{project}",
        "src/d810/backends/mba/ida.py",
        "src/d810/mba/certified_catalogue.py",
        "src/d810/backends/mba/hexrays_island.py",
        "src/d810/ir/expr/dsl.py",
        "src/d810/ir/expr/constraints.py",
        "src/d810/mba/canonical_pattern.py",
        "src/d810/runtime_semantics_manifest.json",
        "src/d810/hexrays/hooks/optinsn_adapter.py",
        "src/d810/mba/rules/_base.py",
        "src/d810/mba/rules/cst.py",
        "src/d810/mba/rules/predicates.py",
        "src/d810/optimizers/microcode/instructions/pattern_matching/handler.py",
        "src/d810/manager/state.py",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
        *EXECUTION_HELPER_SOURCES,
    ]
    missing = [name for name in relative_sources if not (root / name).is_file()]
    if missing:
        raise ValueError("qualification source missing: " + ", ".join(missing))
    provenance = _execution_provenance(root)
    return {
        "schema_version": 1,
        "scope": "per-project DSL nodes; bounded collection-order qualification subset",
        "project": project,
        "nodes": nodes,
        "sources": {name: _digest(root / name) for name in relative_sources},
        "runtime_image": provenance["runtime_image"],
        "runtime_image_id": provenance["runtime_image_id"],
        "git_revision": provenance["git_revision"],
        "git_dirty": provenance["git_dirty"],
    }


def _shadow_child(
    *,
    python: str,
    nodeid: str,
    project: str,
    run_dir: Path,
    native_dir: Path,
    options: Path,
    timeout: int,
) -> dict:
    raw_path = run_dir / "shadow.json"
    env = _clean_environment(
        original_project=project,
        target_project=project,
        output=raw_path,
        idalog=native_dir / "ida.log",
        tmpdir=native_dir / "tmp",
        canonical=False,
    )
    env.update(D810_LEGACY_DSL_PERMUTATIONS="1", D810_SHADOW_DSL_MATCHING="1")
    process = _execute_child(
        command=pytest_command(python, nodeid),
        env=env,
        run_dir=run_dir,
        native_dir=native_dir,
        options=options,
        timeout=timeout,
    )
    raw, capture_error = _read_capture(raw_path)
    raw.update(nodeid=nodeid, exit=process["exit"])
    if capture_error is not None:
        raw["capture_error"] = capture_error
    if process.get("timeout"):
        raw["timeout"] = True
    _write_json(run_dir / "receipt.json", raw)
    return raw


def _profile_child(
    *,
    python: str,
    nodeid: str,
    original_project: str,
    target_project: str,
    qualified: dict | None,
    run_dir: Path,
    native_dir: Path,
    options: Path,
    timeout: int,
) -> dict:
    raw_path = run_dir / "capture.json"
    profile_path = run_dir / "whole-child.prof"
    canonical = qualified is not None
    env = _clean_environment(
        original_project=original_project,
        target_project=target_project,
        output=raw_path,
        idalog=native_dir / "ida.log",
        tmpdir=native_dir / "tmp",
        canonical=canonical,
    )
    process = _execute_child(
        command=profile_command(python, nodeid, profile_path),
        env=env,
        run_dir=run_dir,
        native_dir=native_dir,
        options=options,
        timeout=timeout,
    )
    raw, capture_error = _read_capture(raw_path)
    raw.update(nodeid=nodeid, exit=process["exit"])
    if capture_error is not None:
        raw["capture_error"] = capture_error
    if process.get("timeout"):
        raw["timeout"] = True
    test_status = _test_status(raw)
    profile = inspect_profile(profile_path, test_status=test_status)
    partition = {"status": "missing", "error": "capture receipt missing"}
    if capture_error is None:
        try:
            if qualified is None:
                validate_legacy_partition(raw, expected_project=target_project)
            else:
                validate_runtime_partition(
                    raw, expected_project=target_project, qualified=qualified
                )
            partition = {"status": "validated"}
        except (KeyError, TypeError, ValueError) as exc:
            partition = {"status": "refused", "error": repr(exc)}
    status = "passed"
    if test_status != "passed":
        status = test_status
    elif profile["profile_status"] != "readable":
        status = "profile_" + profile["profile_status"]
    elif partition["status"] != "validated":
        status = "partition_refused"
    receipt = {
        "nodeid": nodeid,
        "project": original_project,
        "selected_project": target_project,
        "mode": "canonical-qualified" if canonical else "legacy-unqualified",
        "status": status,
        "test_status": test_status,
        "profile": profile,
        "runtime_partition": partition,
        "process": process,
        "capture": raw,
    }
    _write_json(run_dir / "profile-receipt.json", receipt)
    return receipt


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--test-path", default="tests/system/e2e/test_libdeobfuscated_dsl.py"
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--collect-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.timeout <= 0:
        raise ValueError("timeout must be positive")
    root = Path.cwd().resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    progress = {
        "schema_version": 1,
        "status": "collecting",
        "projects": {},
        "profiles": [],
    }
    _write_json(output / "progress.json", progress)
    document, collection_process = _collection(
        python=args.python,
        test_path=args.test_path,
        output=output,
        timeout=args.timeout,
    )
    discovered = validate_collection_manifest(document)
    selected = validate_collection_manifest(document, limit=args.limit)
    groups = group_nodes_by_project(selected)
    provenance_path = output / "provenance.json"
    _write_json(provenance_path, _execution_provenance(root))
    summary = {
        "schema_version": 1,
        "status": "collected" if args.collect_only else "running",
        "discovered_node_count": len(discovered),
        "selected_node_count": len(selected),
        "project_count": len(groups),
        "limit": args.limit,
        "collection_process": collection_process,
        "provenance_sha256": _digest(provenance_path),
    }
    _write_json(output / "summary.json", summary)
    progress.update(status=summary["status"], collection=summary)
    _write_json(output / "progress.json", progress)
    if args.collect_only:
        return 0

    run_id = os.environ.get("D810_RUN_ID", output.name)
    native_root = Path("/work/runs") / run_id / "dsl-per-test-profile"
    native_root.mkdir(parents=True, exist_ok=False)
    options = Path.home() / ".idapro/cfg/d810/options.json"
    build_certificate = _certificate_builder(root)
    qualification_by_project = {}
    generated_configs: list[Path] = []
    try:
        for project_index, (project, nodes) in enumerate(groups.items()):
            project_key = _slug(project, project_index)
            project_dir = output / "qualification" / project_key
            project_dir.mkdir(parents=True)
            manifest = _project_manifest(root, project=project, nodes=nodes)
            manifest_path = project_dir / "workload.json"
            _write_json(manifest_path, manifest)
            receipts = []

            def admission(evidence, *, _project_dir=project_dir):
                evidence_path = _project_dir / "evidence.json"
                toolchain_path = _project_dir / "toolchain.json"
                _write_json(evidence_path, evidence)
                toolchain = receipts[-1]["toolchain"]
                _write_json(toolchain_path, toolchain)
                certificate = build_certificate(
                    evidence, manifest=manifest_path, toolchain=toolchain_path
                )
                _write_json(_project_dir / "certificate.json", certificate)
                return certificate

            decision = {
                "project": project,
                "status": "unqualified",
                "reason": "not_started",
                "evidence_nodes": [],
                "skipped_nodes": [],
            }
            for node_index, nodeid in enumerate(nodes):
                run_dir = project_dir / "children" / _slug(nodeid, node_index)
                native_dir = (
                    native_root
                    / "qualification"
                    / project_key
                    / _slug(nodeid, node_index)
                )
                receipts.append(
                    _shadow_child(
                        python=args.python,
                        nodeid=nodeid,
                        project=project,
                        run_dir=run_dir,
                        native_dir=native_dir,
                        options=options,
                        timeout=args.timeout,
                    )
                )
                decision = assess_qualification(
                    receipts, project=project, admission=admission
                )
                _write_json(project_dir / "admission.json", decision)
                progress["projects"][project] = {
                    "status": decision["status"],
                    "reason": decision["reason"],
                    "completed_children": len(receipts),
                    "total_nodes": len(nodes),
                }
                _write_json(output / "progress.json", progress)
                if decision["status"] in {"qualified", "refused", "not_applicable"}:
                    break
            qualification_by_project[project] = decision
            if decision["status"] == "qualified":
                stamp = (
                    f"dsl-profile-{project_index}-{os.getpid()}-{time.time_ns()}.json"
                )
                generated = Path.home() / ".idapro/cfg/d810" / stamp
                generated.parent.mkdir(parents=True, exist_ok=True)
                try:
                    activation = prepare_activation(
                        profile_path=(root / "src/d810/conf" / project).resolve(),
                        certificate_path=project_dir / "certificate.json",
                        manifest_path=manifest_path,
                        toolchain_path=project_dir / "toolchain.json",
                        evidence_path=project_dir / "evidence.json",
                        output_path=generated,
                    )
                except (OSError, KeyError, TypeError, ValueError) as exc:
                    decision.update(
                        status="refused",
                        reason="activation_config_refused",
                        error=repr(exc),
                    )
                    generated.unlink(missing_ok=True)
                else:
                    activation["evidence_sha256"] = _digest(
                        project_dir / "evidence.json"
                    )
                    decision["activation"] = activation
                    decision["activation_project"] = generated.name
                    generated_configs.append(generated)
                _write_json(project_dir / "admission.json", decision)
                progress["projects"][project].update(
                    status=decision["status"], reason=decision["reason"]
                )
                _write_json(output / "progress.json", progress)

        failures = 0
        for node_index, row in enumerate(selected):
            project, nodeid = row["project"], row["nodeid"]
            qualification = qualification_by_project[project]
            qualified = (
                qualification.get("evidence")
                if (qualification["status"] == "qualified")
                else None
            )
            target = qualification.get("activation_project", project)
            node_key = _slug(nodeid, node_index)
            receipt = _profile_child(
                python=args.python,
                nodeid=nodeid,
                original_project=project,
                target_project=target,
                qualified=qualified,
                run_dir=output / "profiles" / node_key,
                native_dir=native_root / "profiles" / node_key,
                options=options,
                timeout=args.timeout,
            )
            progress["profiles"].append(
                {
                    "nodeid": nodeid,
                    "project": project,
                    "status": receipt["status"],
                    "mode": receipt["mode"],
                }
            )
            failures += receipt["status"] not in {"passed", "skipped"}
            _write_json(output / "progress.json", progress)
        summary.update(
            status="complete" if failures == 0 else "complete_with_failures",
            qualification={
                project: {
                    key: value
                    for key, value in decision.items()
                    if key not in {"evidence", "certificate"}
                }
                for project, decision in qualification_by_project.items()
            },
            profile_status_counts={
                status: sum(row["status"] == status for row in progress["profiles"])
                for status in sorted({row["status"] for row in progress["profiles"]})
            },
        )
        progress["status"] = summary["status"]
        _write_json(output / "summary.json", summary)
        _write_json(output / "progress.json", progress)
        return 0 if failures == 0 else 1
    finally:
        for path in generated_configs:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
