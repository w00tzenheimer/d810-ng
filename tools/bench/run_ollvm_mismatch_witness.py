#!/usr/bin/env python3
"""Run the one authoritative OLLVM mismatch-witness child capture."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from d810.core.typing import NamedTuple

from tools.bench.dsl_per_test_profile import (
    _clean_environment,
    _digest,
    _execute_child,
    _execution_provenance,
    _read_capture,
    _test_status,
    _write_json,
    pytest_command,
)


OLLVM_NODE_ID = (
    "tests/system/e2e/test_libdeobfuscated_dsl.py::TestOLLVMPatterns::"
    "test_ollvm_patterns[test_function_ollvm_fla_bcf_sub]"
)
OLLVM_PROJECT = "default_unflattening_ollvm.json"
REFERENCE_V4_NODE_ID = (
    "tests/system/e2e/test_libdeobfuscated_dsl.py::TestDacMasmFixtures::"
    "test_dac_masm_fixtures[sub_7FF856533A20]"
)
REFERENCE_V4_PROJECT = "eidolon_v4_const_simplify_solve.json"
DEFAULT_OUTPUT_LABEL = "mismatch-witness-r2"
CHILD_TIMEOUT_SECONDS = 900
OUTPUT_ROOT = Path("/work/.tmp")
NATIVE_ROOT = Path("/work/runs")


class Target(NamedTuple):
    nodeid: str
    project: str
    slug: str


TARGETS = {
    "ollvm": Target(OLLVM_NODE_ID, OLLVM_PROJECT, "ollvm"),
    "reference-v4": Target(REFERENCE_V4_NODE_ID, REFERENCE_V4_PROJECT, "reference-v4"),
}
TARGET_SOURCE_FILES = {
    "ollvm": (
        "samples/bins/libobfuscated.dll",
        "src/d810/backends/mba/hexrays_island.py",
        "src/d810/backends/mba/ida.py",
        "src/d810/backends/mba/native_z3.py",
        "src/d810/conf/default_unflattening_ollvm.json",
        "src/d810/hexrays/hooks/optinsn_adapter.py",
        "src/d810/mba/ac_matching.py",
        "src/d810/mba/canonical_pattern.py",
        "src/d810/mba/rules/bnot.py",
        "src/d810/mba/rules/catalogue.py",
        "src/d810/optimizers/microcode/instructions/pattern_matching/handler.py",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
    ),
    "reference-v4": (
        "samples/bins/libobfuscated.dll",
        "src/d810/backends/mba/hexrays_island.py",
        "src/d810/backends/mba/ida.py",
        "src/d810/backends/mba/native_z3.py",
        "src/d810/conf/eidolon_v4_const_simplify_solve.json",
        "src/d810/hexrays/hooks/optinsn_adapter.py",
        "src/d810/mba/ac_matching.py",
        "src/d810/mba/canonical_pattern.py",
        "src/d810/mba/rules/catalogue.py",
        "src/d810/mba/rules/hodur.py",
        "src/d810/optimizers/microcode/instructions/pattern_matching/handler.py",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
    ),
}
# Preserve the original single-target names for callers identifying the default.
NODE_ID = OLLVM_NODE_ID
PROJECT = OLLVM_PROJECT


def _safe_component(value: str, *, name: str) -> str:
    if not value or Path(value).name != value or value in {".", ".."}:
        raise ValueError(f"{name} must be one non-empty path component")
    return value


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output-label", default=DEFAULT_OUTPUT_LABEL)
    parser.add_argument("--target", choices=tuple(TARGETS), default="ollvm")
    return parser.parse_args(argv)


def _read_witnesses(path: Path) -> tuple[list[object], str | None]:
    if not path.exists():
        return [], "missing witness capture"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"unreadable witness capture: {exc!r}"
    if not isinstance(value, list) or not value:
        return [], "empty witness capture"
    return value, None


def _validate_shadow_capture(capture: dict, *, project: str) -> str | None:
    if capture.get("project") != project or capture.get("expected_project") != project:
        return "unexpected project capture"
    activation_calls = capture.get("activation_calls")
    if type(activation_calls) is not list or activation_calls:
        return "activation_calls must be an empty list"
    accepted_enrolled = capture.get("accepted_enrolled")
    if type(accepted_enrolled) is not list or accepted_enrolled:
        return "accepted_enrolled must be an empty list"
    records = capture.get("records")
    if not isinstance(records, list) or not records:
        return "missing shadow records"
    if any(not isinstance(record, dict) for record in records):
        return "shadow records must be JSON objects"
    if any(record.get("project") != project for record in records):
        return "unexpected project record"
    for record in records:
        adapters = record.get("adapters")
        if not isinstance(adapters, list):
            return "shadow adapters must be a list"
        if not adapters:
            return "missing shadow adapters"
        if any(not isinstance(adapter, dict) for adapter in adapters):
            return "shadow adapters must be JSON objects"
        if any(
            adapter.get("canonical_fallback_enabled") is not False
            or adapter.get("uses_structural_matching") is not False
            for adapter in adapters
        ):
            return "canonical adapter flags must be explicitly false"
    return None


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    target = TARGETS[args.target]
    run_id = _safe_component(os.environ.get("D810_RUN_ID", ""), name="D810_RUN_ID")
    output_label = _safe_component(args.output_label, name="output label")
    root = Path.cwd().resolve()
    run_dir = OUTPUT_ROOT / output_label / run_id / target.slug
    native_dir = NATIVE_ROOT / run_id / "mismatch-native" / target.slug
    for path in (run_dir, native_dir):
        if path.exists():
            raise FileExistsError(
                f"refusing to overwrite existing witness directory: {path}"
            )

    raw_path = run_dir / "shadow.json"
    witness_path = raw_path.with_suffix(".witnesses.json")
    provenance = _execution_provenance(root)
    provenance.update(
        nodeid=target.nodeid,
        project=target.project,
        target=args.target,
        output_label=output_label,
        child_timeout_seconds=CHILD_TIMEOUT_SECONDS,
        witness_runner_sha256=_digest(
            root / "tools/bench/run_ollvm_mismatch_witness.py"
        ),
        target_source_sha256={
            path: _digest(root / path) for path in TARGET_SOURCE_FILES[args.target]
        },
    )
    env = _clean_environment(
        original_project=target.project,
        target_project=target.project,
        output=raw_path,
        idalog=native_dir / "ida.log",
        tmpdir=native_dir / "tmp",
        canonical=False,
    )
    # These shadow-only settings intentionally follow environment cleaning.
    env.update(
        D810_LEGACY_DSL_PERMUTATIONS="1",
        D810_SHADOW_DSL_MATCHING="1",
        D810_CANONICAL_DAC_WITNESSES="1",
    )
    process = _execute_child(
        command=pytest_command(args.python, target.nodeid),
        env=env,
        run_dir=run_dir,
        native_dir=native_dir,
        options=Path.home() / ".idapro/cfg/d810/options.json",
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    provenance_path = run_dir / "source-provenance.json"
    _write_json(provenance_path, provenance)

    capture, capture_error = _read_capture(raw_path)
    witnesses, witness_error = _read_witnesses(witness_path)
    test_status = _test_status({**capture, "exit": process.get("exit")})
    reason = None
    if process.get("exit") != 0:
        reason = f"child_exit_{process.get('exit')}"
    elif capture_error is not None:
        reason = capture_error
    elif test_status != "passed":
        reason = f"test_status_{test_status}"
    elif witness_error is not None:
        reason = witness_error
    else:
        reason = _validate_shadow_capture(capture, project=target.project)

    receipt = {
        "schema_version": 1,
        "status": "failed" if reason else "passed",
        "reason": reason,
        "nodeid": target.nodeid,
        "project": target.project,
        "target": args.target,
        "mode": "shadow-legacy",
        "output_label": output_label,
        "test_status": test_status,
        "witness_count": len(witnesses),
        "paths": {
            "process": str(run_dir / "process.json"),
            "capture": str(raw_path),
            "witnesses": str(witness_path),
            "source_provenance": str(provenance_path),
        },
    }
    _write_json(run_dir / "receipt.json", receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 1 if reason else 0


if __name__ == "__main__":
    raise SystemExit(main())
