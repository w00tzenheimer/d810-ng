#!/usr/bin/env python3
"""Build and validate fail-closed fresh-process DAC measurement receipts."""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
from statistics import median
import argparse
import contextlib
import io
import os
import pstats
import subprocess
import sys
import time


EXPECTATION_FIELDS = (
    "corpus_digest", "toolchain_digest", "runtime_semantics_digest",
    "legacy_observation_count", "observation_count",
)
POSITIVE_XOR_BEFORE_SHA256 = "fd1643fcf2109f53ae75bdbd59de35bbf44ce6e01f4468761e52e6a58328b0ec"
POSITIVE_XOR_RETAINED_SHA256 = "10e4c5d329387e4d77ba4bdbcff3ff887bb7b35d8c6ea8b082142f74d5a7c066"
POSITIVE_XOR_ALTERNATIVE_SHA256 = "204f133682ef52bfe65ff799f8d045aaf2736698066dd613905e1301c58f01bd"
XOR_PROOF_SHA256 = "8dca935604c9238c8322ba103f1fea32b75ef6e96cf0c9df8b63774c03aedcd8"


def validate_segment_hashes(segment_id: str, expected: list[str], actual: list[str]) -> None:
    if actual == expected:
        return
    if (segment_id == "positive-xor"
            and expected == [POSITIVE_XOR_BEFORE_SHA256, POSITIVE_XOR_RETAINED_SHA256]
            and actual == [POSITIVE_XOR_BEFORE_SHA256, POSITIVE_XOR_ALTERNATIVE_SHA256]):
        return
    raise ValueError("decompile output differs from retained baseline")


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True,
                         separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def file_digest(path: Path | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def derive_expectation(corpus_digest: str, toolchain: dict, evidence: dict,
                       certificate: dict) -> dict:
    """Derive the activation claim from retained source receipts, then cross-check evidence."""
    toolchain_digest = canonical_digest(toolchain)
    if certificate.get("corpus_digest") != corpus_digest:
        raise ValueError("certificate corpus digest disagrees with retained manifest")
    if certificate.get("toolchain_digest") != toolchain_digest:
        raise ValueError("certificate toolchain digest disagrees with retained toolchain")
    snapshot = evidence.get("snapshot", {})
    ledger = evidence.get("ledger", {})
    expectation = {
        "corpus_digest": corpus_digest,
        "toolchain_digest": toolchain_digest,
        "runtime_semantics_digest": snapshot.get("runtime_semantics_digest"),
        "legacy_observation_count": ledger.get("legacy_match_count"),
        "observation_count": ledger.get("observation_count"),
    }
    if any(value is None for value in expectation.values()):
        raise ValueError("retained evidence is missing an activation expectation field")
    if any(certificate.get(name) != value for name, value in expectation.items()):
        raise ValueError("certificate disagrees with independently derived expectation")
    return expectation


def build_activation_config(base: dict, certificate_path: str, expectation: dict) -> dict:
    if set(expectation) != set(EXPECTATION_FIELDS):
        raise ValueError("activation expectation is incomplete")
    result = deepcopy(base)
    additional = result.setdefault("additional_configuration", {})
    additional["structural_matcher_parity_certificate"] = certificate_path
    additional["structural_matcher_parity_expectation"] = deepcopy(expectation)
    return result


def _positive_decimal(value: object) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("missing or invalid timing") from None
    if not result.is_finite() or result <= 0:
        raise ValueError("missing or invalid timing")
    return result


def _partition(receipt: dict) -> tuple:
    adapters = receipt.get("adapters")
    enrollment = receipt.get("enrollment")
    snapshot = receipt.get("snapshot")
    if not isinstance(adapters, list) or not isinstance(enrollment, dict) or not isinstance(snapshot, dict):
        raise ValueError("missing partition receipt")
    rows = tuple((item.get("rule_id"), item.get("name"), item.get("canonical_eligible"))
                 for item in adapters)
    counts = (enrollment.get("selected_rule_count"),
              enrollment.get("canonical_eligible_rule_count"),
              enrollment.get("legacy_only_rule_count"))
    if counts != (len(rows), sum(row[2] is True for row in rows),
                  sum(row[2] is False for row in rows)):
        raise ValueError("inconsistent partition receipt")
    return snapshot.get("fingerprint"), counts, rows


def validate_measurement_receipt(receipt: dict) -> None:
    if receipt.get("exit") != 0 or receipt.get("passed") != 1 or receipt.get("skipped") != 0:
        raise ValueError("measurement node did not pass exactly once without skips")
    if receipt.get("project") != receipt.get("expected_project"):
        raise ValueError("generated project was not selected")
    if receipt.get("toolchain", {}).get("matcher_backend", {}).get("backend") != "cython":
        raise ValueError("measurement requires the native Cython backend")
    _positive_decimal(receipt.get("process_seconds"))
    decompiles = receipt.get("decompiles")
    if len(decompiles) != 2 or any(item.get("error") or len(item.get("sha256", "")) != 64
                                  or _positive_decimal(item.get("seconds")) <= 0
                                  for item in decompiles):
        raise ValueError("missing successful decompile timing receipts")
    actual_hashes = [item["sha256"] for item in decompiles]
    validate_segment_hashes(receipt.get("segment_id"),
                            receipt.get("expected_decompile_sha256"), actual_hashes)
    _partition(receipt)
    adapters = receipt["adapters"]
    enabled = [item for item in adapters if item.get("canonical_fallback_enabled") is True]
    structural = [item for item in adapters if item.get("uses_structural_matching") is True]
    mode = receipt.get("mode")
    if mode == "canonical":
        if receipt.get("live_snapshot") != receipt.get("snapshot") or receipt.get("live_ledger") is None:
            raise ValueError("live canonical snapshot/admission differs from qualification")
        eligible = [item for item in adapters if item.get("canonical_eligible") is True]
        if not eligible or enabled != eligible or structural != eligible:
            raise ValueError("canonical backend was not active for the exact eligible partition")
        if (receipt.get("segment_id") == "positive-xor"
                and (receipt.get("metrics", {}).get("canonical_call_count", 0) < 1
                     or receipt.get("metrics", {}).get(
                         "enrolled_transformation_count", 0) < 1)):
            raise ValueError("positive companion did not exercise reachable canonical matching and an enrolled transformation")
    elif mode == "legacy":
        if receipt.get("live_snapshot") is not None or receipt.get("live_ledger") is not None:
            raise ValueError("legacy run unexpectedly constructed a snapshot or ledger")
        if enabled or structural:
            raise ValueError("legacy receipt contains canonical activation")
    else:
        raise ValueError("unknown measurement mode")


def compare_matched_runs(
    receipts: list[dict],
    *,
    expected_outputs_by_mode: dict[str, list[str]] | None = None,
) -> dict:
    for receipt in receipts:
        validate_measurement_receipt(receipt)
    groups: list[tuple[str, list[dict]]] = []
    for receipt in receipts:
        if receipt.get("segment_id") != "dac":
            continue
        mode = receipt["mode"]
        if not groups or groups[-1][0] != mode:
            groups.append((mode, []))
        groups[-1][1].append(receipt)
    if [mode for mode, _ in groups] != ["legacy", "canonical", "legacy"]:
        raise ValueError("matched sequence must be legacy/canonical/legacy")
    if any(len(items) < 3 for _, items in groups):
        raise ValueError("each DAC arm requires at least three fresh processes")
    partitions = {_partition(item) for _, items in groups for item in items}
    toolchains = {canonical_digest(item["toolchain"]) for _, items in groups for item in items}
    if len(partitions) != 1:
        raise ValueError("partition changed across matched runs")
    if len(toolchains) != 1:
        raise ValueError("toolchain changed across matched runs")
    if expected_outputs_by_mode is None:
        outputs = {tuple(item["expected_decompile_sha256"])
                   for _, items in groups for item in items}
        actual_outputs = {tuple(entry["sha256"] for entry in item["decompiles"])
                          for _, items in groups for item in items}
        if len(outputs) != 1 or outputs != actual_outputs:
            raise ValueError("output hashes changed across matched runs")
        actual_output_sha256_by_mode = None
    else:
        if set(expected_outputs_by_mode) != {"legacy", "canonical"}:
            raise ValueError("per-mode outputs require exact legacy and canonical keys")
        expected = {}
        for mode, hashes in expected_outputs_by_mode.items():
            if (not isinstance(hashes, (list, tuple)) or len(hashes) != 2
                    or any(type(value) is not str or len(value) != 64
                           for value in hashes)):
                raise ValueError(f"invalid declared {mode} output hashes")
            expected[mode] = tuple(hashes)
        observed = {"legacy": set(), "canonical": set()}
        for mode, items in groups:
            for item in items:
                declared = tuple(item["expected_decompile_sha256"])
                actual = tuple(entry["sha256"] for entry in item["decompiles"])
                if declared != expected[mode] or actual != expected[mode]:
                    raise ValueError(f"{mode} output hashes changed from exact policy")
                observed[mode].add(actual)
        if any(len(values) != 1 for values in observed.values()):
            raise ValueError("output hashes changed within a matched mode")
        actual_output_sha256_by_mode = {
            mode: list(next(iter(values))) for mode, values in observed.items()
        }
    legacy_values = [_positive_decimal(item["process_seconds"])
                     for mode, items in groups if mode == "legacy" for item in items]
    canonical_values = [_positive_decimal(item["process_seconds"])
                        for mode, items in groups if mode == "canonical" for item in items]
    legacy_median = median(legacy_values)
    canonical_median = median(canonical_values)
    ratio = canonical_median / legacy_median
    result = {"sequence": [mode for mode, _ in groups],
            "legacy_before_median_seconds": str(median(
                [_positive_decimal(item["process_seconds"]) for item in groups[0][1]])),
            "legacy_after_median_seconds": str(median(
                [_positive_decimal(item["process_seconds"]) for item in groups[2][1]])),
            "legacy_median_seconds": str(legacy_median),
            "canonical_median_seconds": str(canonical_median),
            "canonical_over_legacy": str(ratio), "timing_win": ratio < 1}
    if actual_output_sha256_by_mode is not None:
        result["actual_output_sha256_by_mode"] = actual_output_sha256_by_mode
    return result


def prepare_activation(*, profile_path: Path, certificate_path: Path,
                       manifest_path: Path, toolchain_path: Path, evidence_path: Path,
                       output_path: Path) -> dict:
    """Write a unique-basename activation document and return its provenance receipt."""
    certificate = json.loads(certificate_path.read_text())
    toolchain = json.loads(toolchain_path.read_text())
    evidence = json.loads(evidence_path.read_text())
    expectation = derive_expectation(file_digest(manifest_path), toolchain, evidence, certificate)
    config = build_activation_config(json.loads(profile_path.read_text()),
                                     str(certificate_path.resolve()), expectation)
    output_path.write_text(json.dumps(config, allow_nan=False, ensure_ascii=True,
                                      indent=2, sort_keys=True) + "\n")
    return {"project": output_path.name, "profile_sha256": file_digest(profile_path),
            "activation_sha256": file_digest(output_path),
            "certificate_sha256": file_digest(certificate_path),
            "manifest_sha256": file_digest(manifest_path),
            "toolchain_sha256": file_digest(toolchain_path), "expectation": expectation}


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, allow_nan=False, ensure_ascii=True,
                               indent=2, sort_keys=True) + "\n")


@contextlib.contextmanager
def child_options_log_dir(options: Path, native_run: Path):
    """Select one cold child log/database root and restore exact prior bytes."""
    initial = options.read_bytes() if options.exists() else None
    document = json.loads(initial) if initial else {}
    resolved = str(native_run.resolve())
    document["log_dir"] = resolved
    options.parent.mkdir(parents=True, exist_ok=True)
    _write_json(options, document)
    try:
        yield resolved
    finally:
        if initial is None:
            options.unlink(missing_ok=True)
        else:
            options.write_bytes(initial)


def run_sequence(*, activation_only: bool, profile_only: bool,
                 repetitions: int) -> list[tuple[str, str, int]]:
    if activation_only and profile_only:
        raise ValueError("activation-only and profile-only are mutually exclusive")
    if profile_only:
        return [("legacy", "dac", 1), ("canonical", "dac", 1)]
    if activation_only:
        return [("canonical", "dac", 1), ("canonical", "positive-xor", 1)]
    return [("legacy", "dac", repetitions),
            ("canonical", "dac", repetitions),
            ("legacy", "dac", repetitions)]


def pytest_command(python: str, node: str, *, profile_path: Path | None = None) -> list[str]:
    prefix = ([python, "-u", "-m", "pytest"] if profile_path is None else
              [python, "-u", "-m", "cProfile", "-o", str(profile_path), "-m", "pytest"])
    return [*prefix, "-p", "no:cacheprovider", "-p", "tools.bench.canonical_dac_probe",
            "-q", "-s", "-o", "addopts=", node]


def render_profile(profile_path: Path) -> dict:
    """Save independent self/cumulative views; never sum inclusive frames."""
    stats = pstats.Stats(str(profile_path))
    outputs = {}
    for label, sort_key in (("self", "tottime"), ("cumulative", "cumulative")):
        stream = io.StringIO()
        stats.stream = stream
        stats.sort_stats(sort_key).print_stats(75)
        path = profile_path.with_suffix(f".{label}.txt")
        path.write_text(stream.getvalue())
        outputs[label] = str(path)
    metrics = {"whole_child_profile": "measured", "registration_seconds": "missing",
               "admission_seconds": "missing", "fallback_totals": "missing",
               "total_calls": stats.total_calls, "primitive_calls": stats.prim_calls,
               "profile_total_seconds": str(stats.total_tt), "views": outputs}
    _write_json(profile_path.with_suffix(".metrics.json"), metrics)
    return metrics


def _source_provenance(root: Path, qualification: Path) -> dict:
    workload = json.loads((qualification / "workload.json").read_text())
    checked = {}
    for name, expected in workload["sources"].items():
        if name.startswith("tools/bench/"):
            continue
        actual = file_digest(root / name)
        if actual != expected:
            raise ValueError(f"retained production source changed: {name}")
        checked[name] = actual
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                              capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--short"], cwd=root, check=True,
                           capture_output=True, text=True).stdout.splitlines()
    proof_path = root / "tools/bench/xor-commutation-proof.md"
    if file_digest(proof_path) != XOR_PROOF_SHA256:
        raise ValueError("positive-XOR proof receipt changed or is missing")
    image = os.environ.get("D810_TEST_RUNTIME_IMAGE")
    image_id = os.environ.get("D810_TEST_RUNTIME_IMAGE_ID")
    if Path("/app/ida").is_dir() and (not image or not image_id or not image_id.startswith("sha256:")):
        raise ValueError("maintained runner did not provide exact runtime image identity")
    return {"revision": revision, "dirty": dirty, "retained_production_sources": checked,
            "intentional_probe_delta": {
                "retained": workload["sources"].get("tools/bench/canonical_dac_probe.py"),
                "current": file_digest(root / "tools/bench/canonical_dac_probe.py")},
            "measurement_harness_sha256": file_digest(
                root / "tools/bench/canonical_dac_measurement.py"),
            "positive_xor_equivalence": {
                "function": "test_xor", "proof_width": 32,
                "solver": "Z3 4.13.0", "result": "UNSAT",
                "claim": "((a2-3) ^ (a3*a1)) != ((a3*a1) ^ (a2-3))",
                "proof_path": str(proof_path), "proof_sha256": XOR_PROOF_SHA256,
                "retained_hashes": [POSITIVE_XOR_BEFORE_SHA256,
                                    POSITIVE_XOR_RETAINED_SHA256],
                "allowed_hashes": [POSITIVE_XOR_BEFORE_SHA256,
                                   POSITIVE_XOR_ALTERNATIVE_SHA256]},
            "runtime_image": image or "local-portable-check",
            "runtime_image_id": image_id or "not-applicable"}


def _qualified_partition(evidence: dict) -> tuple[list[dict], dict, dict]:
    adapters = evidence.get("adapters")
    if adapters is None:
        # Qualification evidence stores adapters in the selected segment records.
        raise ValueError("qualification evidence lacks adapter partition; use segment capture")
    return adapters, evidence["enrollment"], evidence["snapshot"]


def _normalize_receipt(raw: dict, process: dict, *, mode: str,
                       expected_adapters: list[dict], enrollment: dict,
                       snapshot: dict, expected_hashes: list[str]) -> dict:
    records = [item for item in raw.get("records", []) if item.get("project") == raw.get("project")]
    if not records:
        raise ValueError("measurement captured no selected project record")
    latest = records[-1]
    runtime_paths = latest.get("runtime_paths", {})
    expected_log_dir = process.get("paths", {}).get("expected_state_log_dir")
    if runtime_paths.get("state_log_dir") != expected_log_dir:
        raise ValueError("live D810 state did not use the child-native log root")
    actual = latest.get("adapters", [])
    if [item.get("name") for item in actual] != [item.get("name") for item in expected_adapters]:
        raise ValueError("selected rule identity/order changed from qualification")
    if mode == "canonical":
        live_rows = [(item.get("rule_id"), item.get("canonical_eligible")) for item in actual]
        expected_rows = [(item.get("rule_id"), item.get("canonical_eligible"))
                         for item in expected_adapters]
        if (latest.get("snapshot") != snapshot or latest.get("enrollment") != enrollment
                or live_rows != expected_rows):
            raise ValueError("live canonical snapshot/partition changed from qualification")
    elif latest.get("snapshot") is not None or latest.get("ledger") is not None:
        raise ValueError("legacy run unexpectedly constructed snapshot/ledger")
    adapters = []
    for expected, observed in zip(expected_adapters, actual):
        adapters.append({**observed, "rule_id": expected["rule_id"],
                         "canonical_eligible": expected["canonical_eligible"]})
    accepted_enrolled = raw.get("accepted_enrolled", [])
    valid_enrolled = [item for item in accepted_enrolled
                      if item.get("route") in {"raw_base", "canonical_fallback"}
                      and item.get("outcome_status") == "applied"
                      and item.get("candidate_count") == 1]
    receipt = {**raw, "mode": mode, "segment_id": process["segment_id"],
               "exit": process["exit"], "process_seconds": str(process["process_seconds"]),
               "toolchain": raw["toolchain"], "snapshot": snapshot,
               "live_snapshot": latest.get("snapshot"),
               "live_ledger": latest.get("ledger"),
               "runtime_paths": runtime_paths,
               "diagnostic_profile": process.get("diagnostic_profile"),
               "enrollment": enrollment, "adapters": adapters,
               "expected_decompile_sha256": expected_hashes,
               "metrics": {"registration_seconds": None,
                           "candidate_count": sum(item.get("candidate_count") or 0 for item in actual),
                           "canonical_match_count": sum(
                               call.get("matched") is True
                               for call in raw.get("activation_calls", [])),
                           "canonical_call_count": len(raw.get("activation_calls", [])),
                           "enrolled_transformation_count": len(
                               valid_enrolled),
                           "accepted_enrolled": accepted_enrolled,
                           "fallback_count": None}}
    validate_measurement_receipt(receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualification-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--activation-only", action="store_true")
    modes.add_argument("--profile-only", action="store_true")
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args(argv)
    root = Path.cwd()
    qualification = args.qualification_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    run_id = os.environ.get("D810_RUN_ID", output.name)
    native = Path("/work/runs") / run_id / "canonical-dac-measurement"
    native.mkdir(parents=True, exist_ok=False)
    options = Path.home() / ".idapro/cfg/d810/options.json"
    evidence = json.loads((qualification / "evidence.json").read_text())
    _write_json(output / "provenance.json", _source_provenance(root, qualification))
    # Partition identity comes from the actual retained DAC segment, not a legacy
    # run where snapshot creation is intentionally absent.
    capture = json.loads((qualification / "dac/shadow.json").read_text())
    selected = [item for item in capture["records"] if item.get("snapshot")]
    expected_adapters = selected[-1]["adapters"]
    expected_hashes_by_segment = {
        name: [item["sha256"] for item in json.loads(
            (qualification / name / "shadow.json").read_text())["decompiles"]]
        for name in ("dac", "positive-xor")
    }
    enrollment, snapshot = evidence["enrollment"], evidence["snapshot"]
    stamp = f"canonical-dac-{os.getpid()}-{time.time_ns()}"
    user_dir = Path.home() / ".idapro/cfg/d810"
    user_dir.mkdir(parents=True, exist_ok=True)
    canonical_path = user_dir / f"{stamp}-canonical.json"
    legacy_path = user_dir / f"{stamp}-legacy.json"
    profile = root / "src/d810/conf/eidolon_v4_const_simplify_solve.json"
    activation_receipt = prepare_activation(
        profile_path=profile, certificate_path=qualification / "certificate.json",
        manifest_path=qualification / "workload.json",
        toolchain_path=qualification / "toolchain.json",
        evidence_path=qualification / "evidence.json", output_path=canonical_path)
    legacy_path.write_bytes(profile.read_bytes())
    _write_json(output / "activation-config.json", activation_receipt)
    sequence = run_sequence(activation_only=args.activation_only,
                            profile_only=args.profile_only,
                            repetitions=args.repetitions)
    receipts = []
    try:
        probe = __import__("tools.bench.canonical_dac_probe", fromlist=["NODE"])
        for arm_index, (mode, segment_id, repetitions) in enumerate(sequence):
            project = canonical_path if mode == "canonical" else legacy_path
            for repetition in range(repetitions):
                run_dir = output / f"{arm_index:02d}-{mode}-{segment_id}-{repetition:02d}"
                run_dir.mkdir()
                raw_path = run_dir / "probe.json"
                native_run = native / run_dir.name
                native_run.mkdir()
                env = dict(os.environ)
                for name in ("D810_CANONICAL_MATCH_FALLBACK", "D810_STRUCTURAL_DSL_MATCHING",
                             "D810_LEGACY_DSL_PERMUTATIONS", "D810_SHADOW_DSL_MATCHING",
                             "D810_CANONICAL_DAC_WITNESSES", "D810_PROFILE_CONTROLLER",
                             "D810_CPROFILE", "D810_PYINSTRUMENT"):
                    env.pop(name, None)
                if mode == "canonical":
                    env["D810_CANONICAL_MATCH_FALLBACK"] = "1"
                if args.activation_only or args.profile_only:
                    env["D810_CANONICAL_DAC_ACTIVATION_PROOF"] = "1"
                env.update(D810_CANONICAL_DAC_PROJECT=project.name,
                           D810_CANONICAL_DAC_OUT=str(raw_path),
                           IDALOG=str(native_run / "ida.log"),
                           TMPDIR=str(native_run / "tmp"))
                Path(env["TMPDIR"]).mkdir()
                profile_path = run_dir / "whole-child.prof" if args.profile_only else None
                command = pytest_command(sys.executable,
                    probe.POSITIVE_NODE if segment_id == "positive-xor" else probe.NODE,
                    profile_path=profile_path)
                process = {"segment_id": segment_id, "mode": mode, "command": command,
                           "environment": {key: value for key, value in env.items()
                                           if key.startswith("D810_")},
                           "paths": {"idalog": env["IDALOG"], "tmpdir": env["TMPDIR"],
                                     "configured_child_root": str(native_run.resolve()),
                                     "expected_state_log_dir": str(
                                         (native_run / "d810_logs").resolve())},
                           "exit": None}
                started = time.perf_counter()
                try:
                    with child_options_log_dir(options, native_run):
                        with (run_dir / "pytest.log").open("w") as log:
                            result = subprocess.run(command, env=env, stdout=log,
                                                    stderr=subprocess.STDOUT, timeout=900)
                    process["exit"] = result.returncode
                except BaseException as exc:
                    process["error"] = repr(exc)
                    process["exit"] = -1
                process["process_seconds"] = time.perf_counter() - started
                if profile_path is not None:
                    process["diagnostic_profile"] = (
                        render_profile(profile_path) if profile_path.exists()
                        else {"whole_child_profile": "missing",
                              "registration_seconds": "missing",
                              "admission_seconds": "missing",
                              "fallback_totals": "missing"})
                _write_json(run_dir / "process.json", process)
                if raw_path.exists():
                    raw = json.loads(raw_path.read_text())
                    try:
                        receipt = _normalize_receipt(raw, process, mode=mode,
                            expected_adapters=expected_adapters, enrollment=enrollment,
                            snapshot=snapshot,
                            expected_hashes=expected_hashes_by_segment[segment_id])
                    except BaseException as exc:
                        _write_json(run_dir / "invalid.json", {"error": repr(exc),
                                                               "process": process, "raw": raw})
                        raise
                    _write_json(run_dir / "receipt.json", receipt)
                    receipts.append(receipt)
                else:
                    _write_json(run_dir / "invalid.json", {
                        "error": f"missing probe receipt: {raw_path}", "process": process})
                    raise RuntimeError(f"missing probe receipt: {raw_path}")
        _write_json(output / "receipts.json", receipts)
        if not args.activation_only and not args.profile_only:
            _write_json(output / "comparison.json", compare_matched_runs(receipts))
        return 0
    finally:
        canonical_path.unlink(missing_ok=True)
        legacy_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
