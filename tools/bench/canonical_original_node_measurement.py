#!/usr/bin/env python3
"""Admit retained shadow receipts and measure their exact original test node."""

from __future__ import annotations

from copy import deepcopy
import argparse
from decimal import Decimal
import json
import math
import os
from pathlib import Path
import sys
import time

from d810.core.typing import Callable

from tools.bench.canonical_dac_measurement import (
    _normalize_receipt,
    build_activation_config,
    canonical_digest,
    compare_matched_runs,
    derive_expectation,
    file_digest,
    prepare_activation,
    pytest_command,
    validate_measurement_receipt,
)
from tools.bench.dsl_per_test_profile import (
    _certificate_builder,
    _clean_environment,
    _execute_child,
    assess_qualification,
)
from tools.bench.run_ollvm_mismatch_witness import (
    TARGETS,
    TARGET_SOURCE_FILES,
    _validate_shadow_capture,
)


COMPARISON_BUDGET = 256
FILTER_FLAG = "D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER"
FILTER_COUNTER_KEYS = (
    "candidate_fact_constructions",
    "candidate_fact_operands",
    "template_fact_constructions",
    "template_fact_requirements",
    "predicate_comparisons",
    "rejected_candidates",
    "surviving_candidates",
    "unknown_candidates",
)
REPETITIONS = 3
NATIVE_ROOT = Path("/work/runs")
ADMISSION_ARTIFACTS = (
    "admission.json",
    "certificate.json",
    "evidence.json",
    "source-provenance.json",
    "target.json",
    "toolchain.json",
    "workload.json",
)
OUTPUT_POLICY_ARTIFACTS = ("output-proof.json", "output-policy.json")
REFERENCE_OUTPUT_PROOF_SHA256 = (
    "3614ddf7ccef2cb78625c4b54b57df627d68dbaca96bf7611bda36e5d8e42306"
)
REFERENCE_NODEID = (
    "tests/system/e2e/test_libdeobfuscated_dsl.py::"
    "TestDacMasmFixtures::test_dac_masm_fixtures[sub_7FF856533A20]"
)
REFERENCE_PROJECT = "eidolon_v4_const_simplify_solve.json"
REFERENCE_PE_SHA256 = (
    "87720f6347b39b30792d871e8c69ba46a0d7fed1b65a6441488316de1be7532e"
)
REFERENCE_COMMON_OUTPUT_SHA256 = (
    "4614e64fb63cc6f1d77101dceac6196f53eb648874901fa0a62e16a60ae5870b"
)
REFERENCE_LEGACY_OUTPUT_SHA256 = (
    "05eac5b9156f272e41ab9232c730511467e5145af53753b501e4306512a15342"
)
REFERENCE_CANONICAL_OUTPUT_SHA256 = (
    "6c22013d6d1fe0e57b14bc37646298a04938680e90bc07e59cf4ab6990cadcbb"
)
REFERENCE_CAPTURE_PLUGIN_SHA256 = (
    "91151f6bb085a4b6ebacedd8154cee4ed6753fc293de6517e97a3b08eb1aeb6c"
)
REFERENCE_PROOF_ASSIGNMENTS = (
    ("case 0x1C:", "v2"),
    ("case 0x20:", "v2"),
    ("case 0x27:", "v17"),
    ("LABEL_xC055:", "v29"),
)


def _read_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"missing retained {label}: {path}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid retained {label}: {exc!r}") from None
    if not isinstance(value, dict):
        raise ValueError(f"retained {label} must be a JSON object")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def _validate_exact_output_proof(proof_path: Path, bundle: dict) -> dict:
    proof_path = Path(proof_path).resolve()
    if file_digest(proof_path) != REFERENCE_OUTPUT_PROOF_SHA256:
        raise ValueError("output proof receipt hash is not the reviewed Reference proof")
    proof = _read_json(proof_path, "output proof")
    target = bundle.get("target")
    expected_target = {
        "nodeid": REFERENCE_NODEID,
        "project": REFERENCE_PROJECT,
        "slug": "reference-v4",
    }
    if target != expected_target:
        raise ValueError("exact output policy target is not the reviewed Reference node")
    checked_sources = bundle.get("checked_sources")
    if (
        not isinstance(checked_sources, dict)
        or checked_sources.get("samples/bins/libobfuscated.dll")
        != REFERENCE_PE_SHA256
    ):
        raise ValueError("exact output policy fixture differs from the reviewed PE")
    legacy_outputs = bundle.get("expected_decompile_sha256")
    if legacy_outputs != [
        REFERENCE_COMMON_OUTPUT_SHA256,
        REFERENCE_LEGACY_OUTPUT_SHA256,
    ]:
        raise ValueError("exact output policy legacy output pair changed")
    function = proof.get("function")
    inputs = proof.get("inputs")
    expression_proofs = proof.get("expression_proofs")
    proof_claim = proof.get("claim")
    proof_limitations = proof.get("limitations")
    if (
        proof.get("schema_version") != 1
        or proof.get("status") != "passed"
        or proof.get("passed") is not True
        or proof.get("surrounding_text_byte_identical") is not True
        or proof.get("bitvector_width") != 64
        or proof.get("assumptions_on_input_values") != []
        or type(proof_claim) is not str
        or not proof_claim
        or not isinstance(proof_limitations, list)
        or len(proof_limitations) != 4
        or any(type(item) is not str or not item for item in proof_limitations)
        or not isinstance(function, dict)
        or function.get("nodeid") != REFERENCE_NODEID
        or function.get("function_ea") != 0x18001AE24
        or function.get("function_ea_hex") != "0x18001ae24"
        or function.get("function_name") != "_sub_7FF856533A20"
        or not isinstance(inputs, dict)
        or inputs.get("legacy_capture", {}).get("sha256")
        != REFERENCE_LEGACY_OUTPUT_SHA256
        or inputs.get("canonical_capture", {}).get("sha256")
        != REFERENCE_CANONICAL_OUTPUT_SHA256
        or inputs.get("capture_plugin_sha256") != REFERENCE_CAPTURE_PLUGIN_SHA256
        or not isinstance(expression_proofs, list)
        or len(expression_proofs) != len(REFERENCE_PROOF_ASSIGNMENTS)
    ):
        raise ValueError("output proof receipt does not carry the reviewed proof claim")
    observed_assignments = []
    for item in expression_proofs:
        if not isinstance(item, dict):
            raise ValueError("output proof expression is malformed")
        observed_assignments.append((item.get("anchor"), item.get("target")))
        if (
            item.get("solver_result") != "unsat"
            or item.get("inequality_satisfiable") is not False
            or item.get("counterexample") is not None
        ):
            raise ValueError("output proof expression is not proved equivalent")
    if tuple(observed_assignments) != REFERENCE_PROOF_ASSIGNMENTS:
        raise ValueError("output proof assignments differ from the reviewed four")
    return proof


def build_exact_output_policy(
    bundle: dict, proof_path: Path, admission_dir: Path
) -> dict:
    """Build the one reviewed Reference output policy, bound to this admission."""
    proof = _validate_exact_output_proof(proof_path, bundle)
    admission_dir = Path(admission_dir).resolve()
    binding_names = (
        "workload.json",
        "evidence.json",
        "certificate.json",
        "toolchain.json",
        "admission.json",
    )
    bindings = {
        name.removesuffix(".json") + "_sha256": file_digest(admission_dir / name)
        for name in binding_names
    }
    evidence = _read_json(admission_dir / "evidence.json", "admission evidence")
    bindings.update(
        {
            "profile_sha256": bundle["checked_sources"][
                f"src/d810/conf/{REFERENCE_PROJECT}"
            ],
            "source_sha256": deepcopy(bundle["checked_sources"]),
            "snapshot": deepcopy(evidence.get("snapshot")),
            "toolchain_digest": canonical_digest(bundle["toolchain"]),
            "runtime_image": bundle["runtime_image"],
            "runtime_image_id": bundle["runtime_image_id"],
            "controller_sha256": file_digest(Path(__file__)),
        }
    )
    return {
        "schema_version": 1,
        "kind": "exact-reference-v4-captured-output-equivalence",
        "target": deepcopy(bundle["target"]),
        "function_ea": proof["function"]["function_ea"],
        "fixture_sha256": REFERENCE_PE_SHA256,
        "proof_receipt_sha256": REFERENCE_OUTPUT_PROOF_SHA256,
        "proof_program_sha256": proof.get("proof_program_sha256"),
        "proof_tests_sha256": proof.get("proof_tests_sha256"),
        "proof_claim": proof["claim"],
        "proof_limitations": deepcopy(proof["limitations"]),
        "outputs": {
            "legacy": [
                REFERENCE_COMMON_OUTPUT_SHA256,
                REFERENCE_LEGACY_OUTPUT_SHA256,
            ],
            "canonical": [
                REFERENCE_COMMON_OUTPUT_SHA256,
                REFERENCE_CANONICAL_OUTPUT_SHA256,
            ],
        },
        "admission_bindings": bindings,
    }


def store_exact_output_policy(
    bundle: dict, proof_path: Path, admission_dir: Path
) -> dict:
    admission_dir = Path(admission_dir).resolve()
    proof_copy = admission_dir / "output-proof.json"
    policy_path = admission_dir / "output-policy.json"
    if proof_copy.exists() or policy_path.exists():
        raise FileExistsError("exact output policy artifacts already exist")
    _validate_exact_output_proof(proof_path, bundle)
    proof_copy.write_bytes(Path(proof_path).resolve().read_bytes())
    policy = build_exact_output_policy(bundle, proof_copy, admission_dir)
    _write_json(policy_path, policy)
    return {
        "policy": policy_path.name,
        "policy_sha256": file_digest(policy_path),
        "proof": proof_copy.name,
        "proof_sha256": file_digest(proof_copy),
    }


def load_exact_output_policy(
    reference: object, bundle: dict, admission_dir: Path
) -> dict | None:
    admission_dir = Path(admission_dir).resolve()
    policy_path = admission_dir / "output-policy.json"
    proof_path = admission_dir / "output-proof.json"
    if reference is None:
        if policy_path.exists() or proof_path.exists():
            raise ValueError("unreferenced exact output policy artifacts")
        return None
    if reference != {
        "policy": "output-policy.json",
        "policy_sha256": file_digest(policy_path),
        "proof": "output-proof.json",
        "proof_sha256": file_digest(proof_path),
    }:
        raise ValueError("exact output policy artifact digest changed")
    policy = _read_json(policy_path, "exact output policy")
    expected = build_exact_output_policy(bundle, proof_path, admission_dir)
    if policy != expected:
        raise ValueError("exact output policy differs from current admission")
    return policy


def expected_output_hashes(admission: dict, mode: str) -> list[str]:
    if mode not in {"legacy", "canonical"}:
        raise ValueError(f"unknown output policy mode: {mode}")
    policy = admission.get("output_policy")
    if policy is None:
        return list(admission["target"]["expected_decompile_sha256"])
    outputs = policy.get("outputs")
    if not isinstance(outputs, dict) or set(outputs) != {"legacy", "canonical"}:
        raise ValueError("exact output policy lacks per-mode output hashes")
    hashes = outputs.get(mode)
    if (
        not isinstance(hashes, list)
        or len(hashes) != 2
        or any(type(value) is not str or len(value) != 64 for value in hashes)
    ):
        raise ValueError(f"exact output policy has invalid {mode} hashes")
    return list(hashes)


def _source_path(root: Path, name: object) -> Path:
    if type(name) is not str or not name:
        raise ValueError("source provenance contains an invalid path")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"source provenance escapes the source root: {name}")
    return root / relative


def _safe_component(value: str, *, name: str) -> str:
    if not value or Path(value).name != value or value in {".", ".."}:
        raise ValueError(f"{name} must be one non-empty path component")
    return value


def _validate_recorded_sources(
    root: Path, provenance: dict, *, project: str, target_slug: str
) -> dict:
    checked: dict[str, str] = {}
    maps = (
        ("target_source_sha256", provenance.get("target_source_sha256")),
        ("execution_helper_sources", provenance.get("execution_helper_sources")),
    )
    for label, entries in maps:
        if not isinstance(entries, dict) or not entries:
            raise ValueError(f"source provenance lacks {label}")
        for name, expected in entries.items():
            path = _source_path(root, name)
            if not path.is_file():
                raise FileNotFoundError(f"missing retained source: {name}")
            actual = file_digest(path)
            if type(expected) is not str or len(expected) != 64 or actual != expected:
                raise ValueError(f"retained source changed: {name}")
            checked[name] = actual
    profile_name = f"src/d810/conf/{project}"
    if profile_name not in provenance["target_source_sha256"]:
        raise ValueError(
            "native fixture configuration is absent from source provenance"
        )
    expected_target_sources = set(TARGET_SOURCE_FILES.get(target_slug, ()))
    missing_target_sources = sorted(
        expected_target_sources - provenance["target_source_sha256"].keys()
    )
    if missing_target_sources:
        raise ValueError(
            "source provenance lacks required target sources: "
            + ", ".join(missing_target_sources)
        )
    required_helpers = {
        "tools/bench/canonical_dac_probe.py",
        "tools/bench/canonical_dac_measurement.py",
        "tools/bench/dsl_per_test_profile.py",
        "tools/scripts/mba_structural_matcher_certificate.py",
    }
    missing = sorted(required_helpers - provenance["execution_helper_sources"].keys())
    if missing:
        raise ValueError(
            "source provenance lacks required helpers: " + ", ".join(missing)
        )
    return checked


def import_shadow_bundle(run_dir: Path, *, target, root: Path) -> dict:
    """Import one completed native shadow run without rerunning its evidence node."""
    run_dir = Path(run_dir).resolve()
    root = Path(root).resolve()
    receipt = _read_json(run_dir / "receipt.json", "receipt")
    process = _read_json(run_dir / "process.json", "process")
    capture = _read_json(run_dir / "shadow.json", "shadow capture")
    provenance = _read_json(run_dir / "source-provenance.json", "source provenance")

    identity = (target.nodeid, target.project, target.slug)
    for label, document in (("receipt", receipt), ("source provenance", provenance)):
        actual = (
            document.get("nodeid"),
            document.get("project"),
            document.get("target"),
        )
        if actual != identity:
            raise ValueError(f"{label} target identity mismatch")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("status") != "passed"
        or receipt.get("reason") is not None
        or receipt.get("test_status") != "passed"
        or receipt.get("mode") != "shadow-legacy"
    ):
        raise ValueError("retained receipt is not a successful shadow run")
    if process.get("exit") != 0:
        raise ValueError("retained process did not exit successfully")
    seconds = process.get("process_seconds")
    if (
        type(seconds) not in {int, float}
        or not math.isfinite(seconds)
        or seconds <= 0
        or process.get("timeout") is not None
        or process.get("error") is not None
    ):
        raise ValueError("retained process has an invalid terminal receipt")
    command = process.get("command")
    if (
        not isinstance(command, list)
        or not command
        or command != pytest_command(command[0], target.nodeid)
    ):
        raise ValueError(
            "retained process command is not the exact target pytest command"
        )
    shadow_error = _validate_shadow_capture(capture, project=target.project)
    if shadow_error is not None:
        raise ValueError(f"invalid retained shadow capture: {shadow_error}")
    if (
        capture.get("passed") != 1
        or capture.get("failed", 0) != 0
        or capture.get("skipped", 0) != 0
    ):
        raise ValueError("retained shadow node did not pass exactly once")
    decompiles = capture.get("decompiles")
    if (
        not isinstance(decompiles, list)
        or len(decompiles) != 2
        or any(
            not isinstance(item, dict)
            or item.get("error")
            or type(item.get("sha256")) is not str
            or len(item["sha256"]) != 64
            for item in decompiles
        )
    ):
        raise ValueError("retained shadow capture lacks two successful output hashes")

    toolchain = capture.get("toolchain")
    if not isinstance(toolchain, dict):
        raise ValueError("retained shadow capture lacks a toolchain")
    if toolchain.get("ida_sdk") != 940:
        raise ValueError("retained toolchain is not the required IDA SDK 940")
    if toolchain.get("matcher_backend", {}).get("backend") != "cython":
        raise ValueError("retained evidence requires the native Cython backend")

    image = provenance.get("runtime_image")
    image_id = provenance.get("runtime_image_id")
    environment = process.get("environment")
    if (
        type(image) is not str
        or type(image_id) is not str
        or not image.startswith("sha256:")
        or image != image_id
        or not isinstance(environment, dict)
        or environment.get("D810_TEST_RUNTIME_IMAGE") != image
        or environment.get("D810_TEST_RUNTIME_IMAGE_ID") != image_id
    ):
        raise ValueError("runtime image identity differs across retained evidence")
    expected_shadow_environment = {
        "D810_CANONICAL_DAC_AGGREGATE_ONLY": "1",
        "D810_CANONICAL_DAC_ORIGINAL_PROJECT": target.project,
        "D810_CANONICAL_DAC_PROJECT": target.project,
        "D810_CANONICAL_DAC_WITNESSES": "1",
        "D810_LEGACY_DSL_PERMUTATIONS": "1",
        "D810_SHADOW_DSL_MATCHING": "1",
    }
    if any(
        environment.get(name) != value
        for name, value in expected_shadow_environment.items()
    ):
        raise ValueError("retained process environment is not the exact shadow mode")
    if any(
        environment.get(name) is not None
        for name in (
            "D810_CANONICAL_MATCH_FALLBACK",
            "D810_STRUCTURAL_DSL_MATCHING",
            "D810_CANONICAL_DAC_ACTIVATION_PROOF",
            "D810_CANONICAL_DAC_SCHEDULE_DIAGNOSTIC",
        )
    ):
        raise ValueError(
            "retained process environment is not the exact shadow mode: "
            "canonical/proof diagnostics enabled"
        )
    if receipt.get("output_label") != provenance.get("output_label"):
        raise ValueError("retained output label differs across receipt and provenance")

    checked_sources = _validate_recorded_sources(
        root, provenance, project=target.project, target_slug=target.slug
    )
    runner = root / "tools/bench/run_ollvm_mismatch_witness.py"
    expected_runner = provenance.get("witness_runner_sha256")
    if (
        type(expected_runner) is not str
        or len(expected_runner) != 64
        or not runner.is_file()
        or file_digest(runner) != expected_runner
    ):
        raise ValueError("retained witness runner source changed")
    checked_sources["tools/bench/run_ollvm_mismatch_witness.py"] = expected_runner
    normalized = deepcopy(capture)
    normalized["nodeid"] = receipt["nodeid"]
    normalized["exit"] = process["exit"]
    return {
        "root": root,
        "run_dir": run_dir,
        "target": {
            "nodeid": target.nodeid,
            "project": target.project,
            "slug": target.slug,
        },
        "receipt": receipt,
        "process": process,
        "capture": capture,
        "provenance": provenance,
        "normalized_receipt": normalized,
        "toolchain": deepcopy(toolchain),
        "runtime_image": image,
        "runtime_image_id": image_id,
        "checked_sources": checked_sources,
        "expected_decompile_sha256": [item["sha256"] for item in decompiles],
    }


def _admission_manifest(bundle: dict) -> dict:
    target = bundle["target"]
    provenance = bundle["provenance"]
    return {
        "schema_version": 1,
        "scope": "retained-original-node-shadow-prefix",
        "project": target["project"],
        "nodeid": target["nodeid"],
        "target": target["slug"],
        "nodes": [target["nodeid"]],
        "sources": deepcopy(bundle["checked_sources"]),
        "retained_artifacts": {
            name: file_digest(bundle["run_dir"] / name)
            for name in (
                "receipt.json",
                "process.json",
                "shadow.json",
                "source-provenance.json",
            )
        },
        "runtime_image": bundle["runtime_image"],
        "runtime_image_id": bundle["runtime_image_id"],
        "git_revision": provenance.get("git_revision"),
        "git_dirty": deepcopy(provenance.get("git_dirty")),
    }


def admit_shadow_bundle(
    bundle: dict,
    output_dir: Path,
    *,
    certificate_builder: Callable | None = None,
    output_equivalence_proof: Path | None = None,
) -> dict:
    """Build an unchanged certificate from one validated retained native receipt."""
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    retained_dir = output_dir / "retained-shadow"
    retained_dir.mkdir()
    for name in (
        "receipt.json",
        "process.json",
        "shadow.json",
        "source-provenance.json",
    ):
        (retained_dir / name).write_bytes((bundle["run_dir"] / name).read_bytes())
    manifest_path = output_dir / "workload.json"
    toolchain_path = output_dir / "toolchain.json"
    _write_json(manifest_path, _admission_manifest(bundle))
    _write_json(toolchain_path, bundle["toolchain"])
    builder = certificate_builder or _certificate_builder(bundle["root"])

    def admission(evidence: dict) -> dict:
        evidence_path = output_dir / "evidence.json"
        certificate_path = output_dir / "certificate.json"
        _write_json(evidence_path, evidence)
        certificate = builder(
            evidence, manifest=manifest_path, toolchain=toolchain_path
        )
        _write_json(certificate_path, certificate)
        return certificate

    decision = assess_qualification(
        [bundle["normalized_receipt"]],
        project=bundle["target"]["project"],
        admission=admission,
    )
    _write_json(output_dir / "admission.json", decision)
    output_policy_reference = None
    if decision.get("status") == "qualified" and output_equivalence_proof is not None:
        output_policy_reference = store_exact_output_policy(
            bundle, output_equivalence_proof, output_dir
        )
    target = {
        **bundle["target"],
        "profile": f"src/d810/conf/{bundle['target']['project']}",
        "profile_sha256": bundle["checked_sources"][
            f"src/d810/conf/{bundle['target']['project']}"
        ],
        "expected_decompile_sha256": bundle["expected_decompile_sha256"],
        "runtime_image": bundle["runtime_image"],
        "runtime_image_id": bundle["runtime_image_id"],
        "toolchain_digest": canonical_digest(bundle["toolchain"]),
        "source_provenance": "source-provenance.json",
        "retained_bundle": "retained-shadow",
        "retained_artifacts": {
            name: file_digest(retained_dir / name)
            for name in (
                "receipt.json",
                "process.json",
                "shadow.json",
                "source-provenance.json",
            )
        },
        "controller_sha256": file_digest(Path(__file__)),
        "cache_policy": cache_policy_for_target(bundle["target"]["slug"]),
    }
    if output_policy_reference is not None:
        target["output_policy"] = output_policy_reference
    _write_json(output_dir / "target.json", target)
    _write_json(output_dir / "source-provenance.json", bundle["provenance"])
    if decision.get("status") != "qualified":
        _write_json(
            output_dir / "failure.json",
            {"stage": "admission", "decision": decision},
        )
        raise ValueError(
            f"retained original-node evidence was not qualified: {decision.get('reason')}"
        )
    return decision


def _activation_groups(calls: list[dict]) -> list[list[dict]]:
    groups: list[list[dict]] = []
    for call in calls:
        if not isinstance(call, dict):
            raise ValueError("activation call must be an object")
        count = call.get("attempted_rule_count")
        bucket_size = call.get("bucket_size")
        if type(count) is not int or count <= 0:
            raise ValueError("activation call lacks attempted_rule_count")
        if type(bucket_size) is not int or bucket_size <= 0 or count > bucket_size:
            raise ValueError("activation call has an invalid bucket size")
        if count == 1:
            groups.append([])
        if not groups or count != len(groups[-1]) + 1:
            raise ValueError("activation attempted_rule_count is not contiguous")
        groups[-1].append(call)
    return groups


def validate_original_activation(receipt: dict) -> dict:
    """Require a real eligible rewrite and observed per-attempt budget accounting."""
    if receipt.get("mode") != "canonical":
        raise ValueError("activation receipt is not canonical")
    calls = receipt.get("activation_calls")
    if not isinstance(calls, list) or not calls:
        raise ValueError("activation receipt has no canonical calls")
    groups = _activation_groups(calls)
    matched = 0
    comparisons = 0
    for group in groups:
        bucket_size = group[0].get("bucket_size")
        if len(group) > bucket_size:
            raise ValueError("activation call count exceeds its bucket")
        remaining = COMPARISON_BUDGET
        for call in group:
            if call.get("bucket_size") != bucket_size:
                raise ValueError("activation bucket size changed within one attempt")
            requested = call.get("requested_comparison_budget")
            consumed = call.get("comparisons")
            if requested != remaining:
                raise ValueError("activation did not begin at and preserve budget 256")
            if type(consumed) is not int or consumed < 0 or consumed > requested:
                raise ValueError("invalid activation comparison count")
            remaining -= consumed
            comparisons += consumed
            matched += call.get("matched") is True
            if call.get("stop_reason") == "comparison_budget":
                raise ValueError("activation comparison budget was exhausted")

    summary = receipt.get("activation_summary")
    if not isinstance(summary, dict):
        raise ValueError("activation summary is missing")
    if (
        summary.get("call_count") != len(calls)
        or summary.get("match_count") != matched
        or summary.get("comparison_count") != comparisons
        or summary.get("exhaustion_count") != 0
    ):
        raise ValueError("activation summary is inconsistent or exhausted")
    if matched < 1:
        raise ValueError("activation observed no matched canonical call")

    adapters = receipt.get("adapters")
    if not isinstance(adapters, list):
        raise ValueError("activation receipt lacks the live partition")
    eligible_ids = {
        row.get("rule_id")
        for row in adapters
        if isinstance(row, dict) and row.get("canonical_eligible") is True
    }
    if not eligible_ids:
        raise ValueError("activation receipt has no canonical-eligible rules")
    accepted = receipt.get("accepted_enrolled")
    if not isinstance(accepted, list):
        raise ValueError("activation receipt lacks applied enrolled rows")
    valid = [
        row
        for row in accepted
        if isinstance(row, dict)
        and row.get("rule_id") in eligible_ids
        and row.get("route") in {"raw_base", "canonical_fallback"}
        and row.get("outcome_status") == "applied"
        and row.get("candidate_count") == 1
    ]
    if not valid:
        raise ValueError("activation has no applied eligible one-candidate route")
    route_counts = {"raw_base": 0, "canonical_fallback": 0}
    for row in valid:
        route_counts[row["route"]] += 1
    return {
        "status": "passed",
        "comparison_budget": COMPARISON_BUDGET,
        "attempt_count": len(groups),
        "call_count": len(calls),
        "match_count": matched,
        "comparison_count": comparisons,
        "exhaustion_count": 0,
        "applied_route_counts": route_counts,
    }


def phase_plan(mode: str, *, repetitions: int = REPETITIONS) -> list[dict]:
    if repetitions != REPETITIONS:
        raise ValueError("matched timing requires exactly three repetitions per arm")
    if mode == "admit-only":
        return []
    if mode == "activation-only":
        return [{"arm": "canonical-proof", "mode": "canonical", "proof": True}]
    if mode == "filter-activation-only":
        return [
            {
                "arm": "filter-off-proof",
                "mode": "canonical",
                "proof": True,
                "filter_enabled": False,
            },
            {
                "arm": "filter-on-proof",
                "mode": "canonical",
                "proof": True,
                "filter_enabled": True,
            },
        ]
    if mode == "timing-only":
        return [
            {"arm": arm, "mode": arm.split("-")[0], "proof": False}
            for arm in ("legacy-before", "canonical", "legacy-after")
            for _ in range(REPETITIONS)
        ]
    if mode == "filter-timing-only":
        return [
            {
                "arm": arm,
                "mode": "canonical",
                "proof": False,
                "filter_enabled": arm == "filter-on",
            }
            for arm in ("filter-off-before", "filter-on", "filter-off-after")
            for _ in range(REPETITIONS)
        ]
    raise ValueError(f"unknown controller mode: {mode}")


def configure_filter_environment(env: dict[str, str], spec: dict) -> dict[str, str]:
    """Apply one explicit filter arm after the maintained environment cleaner."""
    enabled = spec.get("filter_enabled")
    if type(enabled) is not bool or spec.get("mode") != "canonical":
        raise ValueError("filter arm must explicitly select canonical OFF or ON")
    env.pop(FILTER_FLAG, None)
    if enabled:
        env[FILTER_FLAG] = "1"
    return env


def validate_filter_process(spec: dict, process: dict, *, expected_image: str) -> None:
    """Reconcile declared arm metadata with the environment actually executed."""
    environment = process.get("environment")
    enabled = spec.get("filter_enabled")
    expected_flag = "1" if enabled else None
    if (
        not isinstance(environment, dict)
        or process.get("mode") != "canonical"
        or process.get("filter_enabled") is not enabled
        or environment.get("D810_CANONICAL_MATCH_FALLBACK") != "1"
        or environment.get(FILTER_FLAG) != expected_flag
    ):
        raise ValueError("filter environment does not match the declared arm")
    required = {
        "D810_CODE_ANALYSIS_CACHE": "1",
        "D810_PRODUCER_STRUCTURAL_VALIDATION": "1",
        "D810_AUTHORITY_TRUST_SEALED": "0",
        "D810_NO_CYTHON": "0",
        "D810_TEST_RUNTIME_IMAGE": expected_image,
        "D810_TEST_RUNTIME_IMAGE_ID": expected_image,
    }
    if any(environment.get(name) != value for name, value in required.items()):
        raise ValueError("filter environment lacks an exact common runtime setting")
    if spec.get("proof") is True:
        if (
            environment.get("D810_CANONICAL_DAC_ACTIVATION_PROOF") != "1"
            or environment.get("D810_CANONICAL_DAC_AGGREGATE_ONLY") is not None
        ):
            raise ValueError("filter proof arm did not run with detailed proof capture")
    elif (
        environment.get("D810_CANONICAL_DAC_ACTIVATION_PROOF") is not None
        or environment.get("D810_CANONICAL_DAC_AGGREGATE_ONLY") != "1"
    ):
        raise ValueError("filter timing arm carried proof-mode settings")
    forbidden = (
        "D810_LEGACY_DSL_PERMUTATIONS",
        "D810_SHADOW_DSL_MATCHING",
        "D810_CANONICAL_DAC_WITNESSES",
        "D810_CANONICAL_DAC_SCHEDULE_DIAGNOSTIC",
        "D810_PROFILE_CONTROLLER",
        "D810_CPROFILE",
        "D810_PYINSTRUMENT",
        "D810_STRUCTURAL_DSL_MATCHING",
        "D810_STRUCTURAL_MATCHING_RESET",
    )
    if any(environment.get(name) is not None for name in forbidden):
        raise ValueError("filter environment contains a forbidden diagnostic selector")


def validate_retained_filter_processes(
    phase_dir: Path,
    *,
    plan: list[dict],
    receipts: list[dict],
    expected_image: str,
) -> None:
    if len(plan) != len(receipts):
        raise ValueError("filter process receipt count differs from the phase plan")
    for index, (spec, receipt) in enumerate(zip(plan, receipts)):
        process = _read_json(
            Path(phase_dir) / f"{index:02d}-{spec['arm']}" / "process.json",
            "filter child process",
        )
        validate_filter_process(spec, process, expected_image=expected_image)
        if (
            receipt.get("arm") != spec["arm"]
            or receipt.get("filter_enabled") is not spec["filter_enabled"]
            or receipt.get("process_environment") != process.get("environment")
            or receipt.get("process_digest") != canonical_digest(process)
        ):
            raise ValueError("filter receipt does not match its retained process")


def normalize_filter_counters(records: list[dict], *, filter_enabled: bool) -> dict:
    """Allow rebuilt zero baselines, then retain one cumulative work epoch."""
    snapshots = [record.get("canonical_fallback_feasibility") for record in records]
    if not snapshots or any(
        not isinstance(snapshot, dict) or snapshot.get("status") != "available"
        for snapshot in snapshots
    ):
        raise ValueError("filter counter snapshot is unavailable")
    validated = []
    for snapshot in snapshots:
        occurrence = snapshot.get("optimizer_occurrence")
        generation = snapshot.get("optimizer_generation")
        if type(occurrence) is not str or not occurrence:
            raise ValueError("filter counter optimizer occurrence is malformed")
        if type(generation) is not int or generation < 0:
            raise ValueError("filter counter optimizer generation is malformed")
        counts = snapshot.get("counts")
        if (
            not isinstance(counts, dict)
            or set(counts) != set(FILTER_COUNTER_KEYS)
            or any(type(counts[name]) is not int or counts[name] < 0 for name in FILTER_COUNTER_KEYS)
        ):
            raise ValueError("filter counters do not have the fixed non-negative schema")
        validated.append((occurrence, generation, dict(counts)))

    work_occurrence = None
    work_generation = None
    previous = None
    for occurrence, generation, counts in validated:
        if previous is None and not any(counts.values()):
            continue
        if previous is None:
            work_occurrence = occurrence
            work_generation = generation
        elif occurrence != work_occurrence:
            raise ValueError("filter counter optimizer occurrence changed after work")
        elif generation != work_generation:
            raise ValueError("filter counter optimizer generation changed after work")
        if previous is not None and any(
            counts[name] < previous[name] for name in FILTER_COUNTER_KEYS
        ):
            raise ValueError("filter cumulative counters decreased within one occurrence")
        previous = counts
    result = dict(validated[-1][2] if previous is None else previous)
    validate_filter_counters(result, filter_enabled=filter_enabled)
    return result


def attach_filter_receipt(
    receipt: dict,
    *,
    raw: dict,
    process: dict,
    spec: dict,
    expected_image: str,
) -> dict:
    validate_filter_process(spec, process, expected_image=expected_image)
    enriched = dict(receipt)
    enriched.update(
        arm=spec["arm"],
        filter_enabled=spec["filter_enabled"],
        filter_counters=normalize_filter_counters(
            raw.get("records", ()), filter_enabled=spec["filter_enabled"]
        ),
        process_environment=deepcopy(process["environment"]),
        process_digest=canonical_digest(process),
    )
    return enriched


def validate_filter_counters(counts: dict, *, filter_enabled: bool) -> dict:
    if not isinstance(counts, dict) or set(counts) != set(FILTER_COUNTER_KEYS):
        raise ValueError("filter counters have an invalid key set")
    if any(type(counts[name]) is not int or counts[name] < 0 for name in FILTER_COUNTER_KEYS):
        raise ValueError("filter counters must be non-negative integers")
    if not filter_enabled:
        if any(counts.values()):
            raise ValueError("filter OFF constructed facts or rejected a candidate")
        return {"attempted_candidates": 0, "rejected_fraction": "0"}
    rejected = counts["rejected_candidates"]
    surviving = counts["surviving_candidates"]
    attempted = rejected + surviving
    if (
        attempted <= 0
        or counts["unknown_candidates"] > surviving
        or counts["candidate_fact_constructions"] > attempted
    ):
        raise ValueError("filter ON counters do not reconcile")
    return {
        "attempted_candidates": attempted,
        "rejected_fraction": str(Decimal(rejected) / Decimal(attempted)),
    }


def _full_match_identities(receipt: dict) -> list[list[object]]:
    identities = []
    for row in receipt.get("activation_calls", ()):
        if not isinstance(row, dict) or row.get("matched") is not True:
            continue
        identity = [
            row.get("rule"),
            row.get("input_ea"),
        ]
        if type(identity[0]) is not str or type(identity[1]) is not int:
            raise ValueError("filter activation full-match identity is incomplete")
        identities.append(identity)
    return identities


def _applied_outcome_identities(receipt: dict) -> list[list[object]]:
    identities = []
    for row in receipt.get("accepted_enrolled", ()):
        if (
            not isinstance(row, dict)
            or row.get("outcome_status") != "applied"
            or row.get("candidate_count") != 1
        ):
            continue
        identity = [
            row.get("rule"),
            row.get("input_ea"),
            row.get("route"),
        ]
        if (
            type(identity[0]) is not str
            or type(identity[1]) is not int
            or identity[2] not in {"canonical_fallback", "raw_base"}
        ):
            raise ValueError("filter activation applied-outcome identity is incomplete")
        identities.append(identity)
    return identities


def _ordered_identity_difference(
    required: list[list[object]], observed: list[list[object]]
) -> list[list[object]]:
    retained_index = 0
    additional = []
    for identity in observed:
        if retained_index < len(required) and identity == required[retained_index]:
            retained_index += 1
        else:
            additional.append(identity)
    if retained_index != len(required):
        raise ValueError("filter activation retained identities changed or were lost")
    return additional


def _provider_fingerprint_diagnostics(receipt: dict) -> dict[str, list[object]]:
    return {
        "full": [
            row.get("provider_fingerprint")
            for row in receipt.get("activation_calls", ())
            if isinstance(row, dict) and row.get("matched") is True
        ],
        "applied": [
            row.get("provider_fingerprint")
            for row in receipt.get("accepted_enrolled", ())
            if isinstance(row, dict)
            and row.get("outcome_status") == "applied"
            and row.get("candidate_count") == 1
        ],
    }


def validate_filter_activation_pair(
    receipts: list[dict],
    *,
    expected_match_count: int = 18,
    expected_applied_route_counts: dict[str, int] | None = None,
) -> dict:
    if (
        not isinstance(receipts, list)
        or len(receipts) != 2
        or [receipt.get("arm") for receipt in receipts]
        != ["filter-off-proof", "filter-on-proof"]
        or [receipt.get("filter_enabled") for receipt in receipts] != [False, True]
    ):
        raise ValueError("filter activation must contain exact canonical OFF then ON arms")
    validations = [validate_original_activation(receipt) for receipt in receipts]
    full_match_identities = [_full_match_identities(receipt) for receipt in receipts]
    if len(full_match_identities[0]) != expected_match_count:
        raise ValueError("filter activation known full-match identity count changed")
    additional_full_matches = _ordered_identity_difference(
        full_match_identities[0], full_match_identities[1]
    )
    expected_routes = (
        {"canonical_fallback": 16, "raw_base": 11}
        if expected_applied_route_counts is None
        else expected_applied_route_counts
    )
    if validations[0]["applied_route_counts"] != expected_routes:
        raise ValueError("filter activation applied route counts changed")
    applied_identities = [
        _applied_outcome_identities(receipt) for receipt in receipts
    ]
    if len(applied_identities[0]) != sum(expected_routes.values()):
        raise ValueError("filter activation applied-outcome count changed")
    additional_applied = _ordered_identity_difference(
        applied_identities[0], applied_identities[1]
    )
    counter_results = [
        validate_filter_counters(
            receipt.get("filter_counters"), filter_enabled=enabled
        )
        for receipt, enabled in zip(receipts, (False, True))
    ]
    if receipts[1]["activation_summary"].get("call_count") != receipts[1][
        "filter_counters"
    ]["surviving_candidates"]:
        raise ValueError("filter activation surviving candidates do not match calls")
    return {
        "status": (
            "investigation_required"
            if additional_full_matches or additional_applied
            else "passed"
        ),
        "known_full_match_identities": full_match_identities[0],
        "additional_on_full_match_identities": additional_full_matches,
        "provider_fingerprint_diagnostics": {
            "full": {
                "off": _provider_fingerprint_diagnostics(receipts[0])["full"],
                "on": _provider_fingerprint_diagnostics(receipts[1])["full"],
            },
            "applied": {
                "off": _provider_fingerprint_diagnostics(receipts[0])["applied"],
                "on": _provider_fingerprint_diagnostics(receipts[1])["applied"],
            },
        },
        "applied_outcomes": {
            "off": applied_identities[0],
            "on": applied_identities[1],
            "off_route_counts": validations[0]["applied_route_counts"],
            "on_route_counts": validations[1]["applied_route_counts"],
            "additional_on": additional_applied,
        },
        "off": {"activation": validations[0], "filter_counters": counter_results[0]},
        "on": {"activation": validations[1], "filter_counters": counter_results[1]},
    }


def cache_policy_for_target(target_slug: str) -> str:
    if target_slug == "ollvm":
        return "OLLVM selected pipeline has no solver consumer; no proof-cache reuse applies"
    if target_slug == "reference-v4":
        return "each Reference-v4 child creates a cold child-local proof database"
    raise ValueError(f"unknown target for cache policy: {target_slug}")


def _median(values: list[Decimal]) -> Decimal:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / Decimal(2)


def filter_timing_comparison(receipts: list[dict]) -> dict:
    expected = [
        *(["filter-off-before"] * REPETITIONS),
        *(["filter-on"] * REPETITIONS),
        *(["filter-off-after"] * REPETITIONS),
    ]
    expected_enabled = [False] * 3 + [True] * 3 + [False] * 3
    if (
        [receipt.get("arm") for receipt in receipts] != expected
        or [receipt.get("filter_enabled") for receipt in receipts]
        != expected_enabled
        or any(receipt.get("mode") != "canonical" for receipt in receipts)
    ):
        raise ValueError("filter timing sequence is not OFF/ON/OFF with three samples")
    samples = []
    for receipt in receipts:
        process = Decimal(receipt["process_seconds"])
        decompiles = [Decimal(item["seconds"]) for item in receipt["decompiles"]]
        samples.append(
            {
                "arm": receipt["arm"],
                "filter_enabled": receipt.get("filter_enabled"),
                "process_seconds": str(process),
                "second_decompile_seconds": str(decompiles[1]),
                "process_minus_both_decompiles": str(process - sum(decompiles)),
            }
        )
    before = [Decimal(item["process_seconds"]) for item in samples[:3]]
    on = [Decimal(item["process_seconds"]) for item in samples[3:6]]
    after = [Decimal(item["process_seconds"]) for item in samples[6:]]
    off = before + after
    before_median = _median(before)
    after_median = _median(after)
    off_median = _median(off)
    on_median = _median(on)
    return {
        "sequence": ["filter-off-before", "filter-on", "filter-off-after"],
        "off_before_median_seconds": str(before_median),
        "off_after_median_seconds": str(after_median),
        "off_before_after_drift_seconds": str(after_median - before_median),
        "off_median_seconds": str(off_median),
        "on_median_seconds": str(on_median),
        "on_over_off": str(on_median / off_median),
        "samples": samples,
    }


def run_phase_children(
    plan: list[dict], *, nodeid: str, child_runner: Callable
) -> list[dict]:
    return [
        child_runner(spec=deepcopy(spec), nodeid=nodeid, index=index)
        for index, spec in enumerate(plan)
    ]


def timing_outcome(
    receipts: list[dict],
    *,
    failure: str | None = None,
    output_policy: dict | None = None,
) -> dict:
    if failure is not None:
        return {"status": "failed", "error": failure, "comparison": None}
    return {
        "status": "passed",
        "error": None,
        "comparison": compare_matched_runs(
            receipts,
            expected_outputs_by_mode=(
                output_policy["outputs"] if output_policy is not None else None
            ),
        ),
    }


def admission_artifact_digests(admission_dir: Path) -> dict[str, str]:
    admission_dir = Path(admission_dir).resolve()
    optional = [name for name in OUTPUT_POLICY_ARTIFACTS if (admission_dir / name).exists()]
    if optional and len(optional) != len(OUTPUT_POLICY_ARTIFACTS):
        raise ValueError("exact output policy admission artifacts are incomplete")
    names = (*ADMISSION_ARTIFACTS, *optional)
    return {name: file_digest(admission_dir / name) for name in names}


def validate_activation_preflight(
    activation_dir: Path,
    *,
    admission_dir: Path,
    admission: dict,
    target,
    root: Path,
    expected_mode: str = "activation-only",
) -> dict:
    """Revalidate the retained activation receipt before any timed child runs."""
    activation_dir = Path(activation_dir).resolve()
    result = _read_json(activation_dir / "result.json", "activation result")
    provenance = _read_json(activation_dir / "provenance.json", "activation provenance")
    receipts_path = activation_dir / "receipts.json"
    try:
        receipts = json.loads(receipts_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(
            f"missing retained activation receipts: {receipts_path}"
        ) from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid retained activation receipts: {exc!r}") from None
    expected_count = 2 if expected_mode == "filter-activation-only" else 1
    if not isinstance(receipts, list) or len(receipts) != expected_count:
        raise ValueError(
            f"activation preflight must contain exactly {expected_count} receipt(s)"
        )
    receipt = receipts[0]
    if any(not isinstance(item, dict) for item in receipts):
        raise ValueError("activation receipt must be a JSON object")
    for item in receipts:
        validate_measurement_receipt(item)
    validation = (
        validate_filter_activation_pair(receipts)
        if expected_mode == "filter-activation-only"
        else validate_original_activation(receipt)
    )
    expected_digests = [canonical_digest(item) for item in receipts]
    if (
        result.get("status") != "passed"
        or result.get("phase") != expected_mode
        or result.get("activation") != validation
        or (
            result.get("receipt_digests") != expected_digests
            if expected_mode == "filter-activation-only"
            else result.get("receipt_digest") != expected_digests[0]
        )
    ):
        raise ValueError("activation result does not match its revalidated receipt")
    expected_identity = (target.nodeid, target.project, target.slug)
    actual_identity = (
        provenance.get("nodeid"),
        provenance.get("project"),
        provenance.get("target"),
    )
    if (
        actual_identity != expected_identity
        or provenance.get("mode") != expected_mode
    ):
        raise ValueError("activation target identity mismatch")
    admitted = admission["target"]
    if (
        provenance.get("controller_sha256") != file_digest(Path(__file__))
        or provenance.get("runtime_image") != admitted.get("runtime_image")
        or provenance.get("runtime_image_id") != admitted.get("runtime_image_id")
        or provenance.get("toolchain_digest") != admitted.get("toolchain_digest")
    ):
        raise ValueError("activation source/runtime/toolchain binding changed")
    evidence = admission["evidence"]
    expected_partition = [
        (row.get("rule_id"), row.get("name"), row.get("canonical_eligible"))
        for row in evidence.get("adapters", ())
    ]
    actual_partition = [
        (row.get("rule_id"), row.get("name"), row.get("canonical_eligible"))
        for row in receipt.get("adapters", ())
    ]
    if (
        receipt.get("toolchain") != admission.get("toolchain")
        or receipt.get("snapshot") != evidence.get("snapshot")
        or receipt.get("enrollment") != evidence.get("enrollment")
        or actual_partition != expected_partition
        or receipt.get("expected_decompile_sha256")
        != expected_output_hashes(admission, "canonical")
    ):
        raise ValueError(
            "activation receipt differs from the admitted native partition"
        )
    activation = provenance.get("activation")
    if not isinstance(activation, dict):
        raise ValueError("activation preparation receipt is missing")
    if receipt.get("project") != activation.get("project") or receipt.get(
        "expected_project"
    ) != activation.get("project"):
        raise ValueError(
            "activation receipt project differs from generated configuration"
        )
    profile = Path(root) / admitted.get("profile", "")
    certificate_path = Path(admission_dir) / "certificate.json"
    manifest_path = Path(admission_dir) / "workload.json"
    toolchain_path = Path(admission_dir) / "toolchain.json"
    certificate = _read_json(certificate_path, "admission certificate")
    expected_expectation = derive_expectation(
        file_digest(manifest_path),
        admission["toolchain"],
        evidence,
        certificate,
    )
    config = activation_dir / "canonical-config.json"
    expected_activation = {
        "project": activation.get("project"),
        "profile_sha256": file_digest(profile),
        "activation_sha256": file_digest(config),
        "certificate_sha256": file_digest(certificate_path),
        "manifest_sha256": file_digest(manifest_path),
        "toolchain_sha256": file_digest(toolchain_path),
        "expectation": expected_expectation,
    }
    if activation != expected_activation:
        raise ValueError("activation preparation receipt or expectation changed")
    expected_config = build_activation_config(
        _read_json(profile, "admitted base profile"),
        str(certificate_path.resolve()),
        expected_expectation,
    )
    if _read_json(config, "retained activation configuration") != expected_config:
        raise ValueError("retained activation configuration content changed")
    if provenance.get("admission_artifacts") != admission_artifact_digests(
        admission_dir
    ):
        raise ValueError("activation admission artifact binding changed")
    if provenance.get("generated_config_sha256") != file_digest(config):
        raise ValueError("activation generated configuration changed")
    output_policy_reference = admitted.get("output_policy")
    if (
        receipt.get("output_policy") != output_policy_reference
        or provenance.get("output_policy") != output_policy_reference
    ):
        raise ValueError("activation exact output policy binding changed")
    if expected_mode == "filter-activation-only":
        expected_partition = [
            (row.get("rule_id"), row.get("name"), row.get("canonical_eligible"))
            for row in evidence.get("adapters", ())
        ]
        for item in receipts[1:]:
            actual_partition = [
                (row.get("rule_id"), row.get("name"), row.get("canonical_eligible"))
                for row in item.get("adapters", ())
            ]
            if (
                item.get("toolchain") != admission.get("toolchain")
                or item.get("snapshot") != evidence.get("snapshot")
                or item.get("enrollment") != evidence.get("enrollment")
                or actual_partition != expected_partition
                or item.get("expected_decompile_sha256")
                != expected_output_hashes(admission, "canonical")
                or item.get("project") != activation.get("project")
                or item.get("expected_project") != activation.get("project")
                or item.get("output_policy") != output_policy_reference
            ):
                raise ValueError(
                    "filter activation receipt differs from admission/config/output gates"
                )
        validate_retained_filter_processes(
            activation_dir,
            plan=phase_plan(expected_mode),
            receipts=receipts,
            expected_image=admitted["runtime_image"],
        )
    result = {
        "status": "passed",
        "activation": validation,
        "admission_artifacts": provenance["admission_artifacts"],
        "generated_config_sha256": provenance["generated_config_sha256"],
    }
    if expected_mode == "filter-activation-only":
        result["receipt_digests"] = expected_digests
    else:
        result["receipt_digest"] = expected_digests[0]
    if output_policy_reference is not None:
        result["output_policy_sha256"] = output_policy_reference["policy_sha256"]
    return result


def require_same_activation_config(preflight: dict, generated_config: Path) -> None:
    if preflight.get("generated_config_sha256") != file_digest(generated_config):
        raise ValueError(
            "timing canonical config differs from accepted activation config"
        )


def _load_admission(admission_dir: Path, *, root: Path, target) -> dict:
    admission_dir = admission_dir.resolve()
    target_receipt = _read_json(admission_dir / "target.json", "admission target")
    expected = (target.nodeid, target.project, target.slug)
    actual = (
        target_receipt.get("nodeid"),
        target_receipt.get("project"),
        target_receipt.get("slug"),
    )
    if actual != expected:
        raise ValueError("admission target identity mismatch")
    if target_receipt.get("controller_sha256") != file_digest(Path(__file__)):
        raise ValueError("admission controller source changed")
    provenance = _read_json(
        admission_dir / target_receipt["source_provenance"], "admission provenance"
    )
    _validate_recorded_sources(
        root, provenance, project=target.project, target_slug=target.slug
    )
    retained_dir = admission_dir / target_receipt.get("retained_bundle", "")
    retained_hashes = target_receipt.get("retained_artifacts")
    if not isinstance(retained_hashes, dict) or any(
        retained_hashes.get(name) != file_digest(retained_dir / name)
        for name in (
            "receipt.json",
            "process.json",
            "shadow.json",
            "source-provenance.json",
        )
    ):
        raise ValueError("admission retained shadow artifacts changed")
    imported = import_shadow_bundle(retained_dir, target=target, root=root)
    if provenance != imported["provenance"]:
        raise ValueError("admission source provenance differs from retained evidence")
    if (
        target_receipt.get("runtime_image") != imported["runtime_image"]
        or target_receipt.get("runtime_image_id") != imported["runtime_image_id"]
        or target_receipt.get("profile_sha256")
        != imported["checked_sources"].get(f"src/d810/conf/{target.project}")
    ):
        raise ValueError("admission target provenance differs from retained evidence")
    toolchain = _read_json(admission_dir / "toolchain.json", "admission toolchain")
    if canonical_digest(toolchain) != target_receipt.get("toolchain_digest"):
        raise ValueError("admission toolchain digest changed")
    if toolchain != imported["toolchain"]:
        raise ValueError("admission toolchain differs from retained shadow evidence")
    image = os.environ.get("D810_TEST_RUNTIME_IMAGE")
    image_id = os.environ.get("D810_TEST_RUNTIME_IMAGE_ID")
    if image != target_receipt.get("runtime_image") or image_id != target_receipt.get(
        "runtime_image_id"
    ):
        raise ValueError("current runtime image differs from retained admission")
    decision = _read_json(admission_dir / "admission.json", "admission decision")
    if decision.get("status") != "qualified":
        raise ValueError("admission is not qualified")
    evidence = _read_json(admission_dir / "evidence.json", "admission evidence")
    certificate = _read_json(
        admission_dir / "certificate.json", "admission certificate"
    )
    workload = _read_json(admission_dir / "workload.json", "admission workload")
    if workload != _admission_manifest(imported):
        raise ValueError("admission workload differs from retained shadow evidence")
    if (
        decision.get("evidence") != evidence
        or decision.get("certificate") != certificate
    ):
        raise ValueError("admission decision is not linked to evidence and certificate")
    rebuilt = _certificate_builder(root)(
        evidence,
        manifest=admission_dir / "workload.json",
        toolchain=admission_dir / "toolchain.json",
    )
    if rebuilt != certificate:
        raise ValueError("admission certificate does not match the unchanged builder")
    if target_receipt.get("expected_decompile_sha256") != imported.get(
        "expected_decompile_sha256"
    ):
        raise ValueError("admission output expectations changed")
    output_policy = load_exact_output_policy(
        target_receipt.get("output_policy"), imported, admission_dir
    )
    return {
        "dir": admission_dir,
        "target": target_receipt,
        "decision": decision,
        "evidence": evidence,
        "toolchain": toolchain,
        "output_policy": output_policy,
    }


def _run_runtime_phase(
    *,
    mode: str,
    admission_dir: Path,
    activation_dir: Path | None,
    output_dir: Path,
    target,
    root: Path,
    python: str,
    timeout: int,
    repetitions: int,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=False)
    canonical_path: Path | None = None
    legacy_path: Path | None = None
    try:
        admission_dir = admission_dir.resolve()
        admission = _load_admission(admission_dir, root=root, target=target)
        if mode in {"timing-only", "filter-timing-only"}:
            if activation_dir is None:
                raise ValueError(f"{mode} requires a retained activation preflight")
            preflight = validate_activation_preflight(
                activation_dir,
                admission_dir=admission_dir,
                admission=admission,
                target=target,
                root=root,
                expected_mode=(
                    "filter-activation-only"
                    if mode == "filter-timing-only"
                    else "activation-only"
                ),
            )
        else:
            preflight = None
        run_id = _safe_component(
            os.environ.get("D810_RUN_ID", output_dir.name), name="D810_RUN_ID"
        )
        native_root = NATIVE_ROOT / run_id / f"canonical-original-{target.slug}-{mode}"
        native_root.mkdir(parents=True, exist_ok=False)
        options = Path.home() / ".idapro/cfg/d810/options.json"
        stamp = f"canonical-original-{target.slug}-{os.getpid()}-{time.time_ns()}"
        user_dir = Path.home() / ".idapro/cfg/d810"
        user_dir.mkdir(parents=True, exist_ok=True)
        canonical_path = user_dir / f"{stamp}-canonical.json"
        legacy_path = user_dir / f"{stamp}-legacy.json"
        profile = root / admission["target"]["profile"]
        if file_digest(profile) != admission["target"].get("profile_sha256"):
            raise ValueError("native fixture configuration changed after admission")
        activation = prepare_activation(
            profile_path=profile,
            certificate_path=admission_dir / "certificate.json",
            manifest_path=admission_dir / "workload.json",
            toolchain_path=admission_dir / "toolchain.json",
            evidence_path=admission_dir / "evidence.json",
            output_path=canonical_path,
        )
        legacy_path.write_bytes(profile.read_bytes())
        (output_dir / "canonical-config.json").write_bytes(canonical_path.read_bytes())
        if preflight is not None:
            require_same_activation_config(
                preflight, output_dir / "canonical-config.json"
            )
        _write_json(output_dir / "activation-config.json", activation)
        provenance = {
            "nodeid": target.nodeid,
            "project": target.project,
            "target": target.slug,
            "mode": mode,
            "controller_sha256": file_digest(Path(__file__)),
            "runtime_image": admission["target"]["runtime_image"],
            "runtime_image_id": admission["target"]["runtime_image_id"],
            "toolchain_digest": admission["target"]["toolchain_digest"],
            "base_profile_sha256": file_digest(profile),
            "generated_config_sha256": file_digest(
                output_dir / "canonical-config.json"
            ),
            "admission_artifacts": admission_artifact_digests(admission_dir),
            "activation": activation,
            "activation_preflight": preflight,
            "cache_policy": admission["target"]["cache_policy"],
        }
        output_policy_reference = admission["target"].get("output_policy")
        if output_policy_reference is not None:
            provenance["output_policy"] = deepcopy(output_policy_reference)
        _write_json(output_dir / "provenance.json", provenance)
        plan = phase_plan(mode, repetitions=repetitions)
        expected_adapters = admission["evidence"]["adapters"]
        enrollment = admission["evidence"]["enrollment"]
        snapshot = admission["evidence"]["snapshot"]

        def child_runner(*, spec: dict, nodeid: str, index: int) -> dict:
            run_dir = output_dir / f"{index:02d}-{spec['arm']}"
            native_dir = native_root / run_dir.name
            raw_path = run_dir / "probe.json"
            selected = canonical_path if spec["mode"] == "canonical" else legacy_path
            env = _clean_environment(
                original_project=target.project,
                target_project=selected.name,
                output=raw_path,
                idalog=native_dir / "ida.log",
                tmpdir=native_dir / "tmp",
                canonical=spec["mode"] == "canonical",
            )
            if mode.startswith("filter-"):
                configure_filter_environment(env, spec)
            if spec["proof"]:
                env.pop("D810_CANONICAL_DAC_AGGREGATE_ONLY", None)
            else:
                env.pop("D810_CANONICAL_DAC_ACTIVATION_PROOF", None)
            process = _execute_child(
                command=pytest_command(python, nodeid),
                env=env,
                run_dir=run_dir,
                native_dir=native_dir,
                options=options,
                timeout=timeout,
            )
            process["segment_id"] = "dac"
            process["mode"] = spec["mode"]
            if mode.startswith("filter-"):
                process["filter_enabled"] = spec["filter_enabled"]
            process["paths"]["expected_state_log_dir"] = str(
                (native_dir / "d810_logs").resolve()
            )
            _write_json(run_dir / "process.json", process)
            if not raw_path.exists():
                raise RuntimeError(f"child produced no probe receipt: {raw_path}")
            raw = _read_json(raw_path, "child probe receipt")
            if (
                canonical_digest(raw.get("toolchain"))
                != admission["target"]["toolchain_digest"]
            ):
                raise ValueError("child toolchain differs from retained admission")
            receipt = _normalize_receipt(
                raw,
                process,
                mode=spec["mode"],
                expected_adapters=expected_adapters,
                enrollment=enrollment,
                snapshot=snapshot,
                expected_hashes=expected_output_hashes(admission, spec["mode"]),
            )
            if mode.startswith("filter-"):
                receipt = attach_filter_receipt(
                    receipt,
                    raw=raw,
                    process=process,
                    spec=spec,
                    expected_image=admission["target"]["runtime_image"],
                )
            if output_policy_reference is not None:
                receipt["output_policy"] = deepcopy(output_policy_reference)
            _write_json(run_dir / "receipt.json", receipt)
            return receipt

        receipts = run_phase_children(
            plan, nodeid=target.nodeid, child_runner=child_runner
        )
        _write_json(output_dir / "receipts.json", receipts)
        if mode in {"activation-only", "filter-activation-only"}:
            validation = (
                validate_filter_activation_pair(receipts)
                if mode == "filter-activation-only"
                else validate_original_activation(receipts[0])
            )
            result = {
                "status": validation.get("status", "passed"),
                "phase": mode,
                "activation": validation,
            }
            if mode == "filter-activation-only":
                result["receipt_digests"] = [
                    canonical_digest(receipt) for receipt in receipts
                ]
            else:
                result["receipt_digest"] = canonical_digest(receipts[0])
        elif mode == "filter-timing-only":
            result = {
                "status": "passed",
                "error": None,
                "phase": mode,
                "comparison": filter_timing_comparison(receipts),
            }
        else:
            result = {
                "phase": mode,
                **timing_outcome(
                    receipts, output_policy=admission.get("output_policy")
                ),
            }
        _write_json(output_dir / "result.json", result)
        if result.get("status") == "investigation_required":
            raise ValueError(
                "filter activation found additional ON identities requiring investigation"
            )
        return 0
    except BaseException as exc:
        _write_json(
            output_dir / "failure.json",
            {"phase": mode, "error": repr(exc), "timing_claim": None},
        )
        raise
    finally:
        if canonical_path is not None:
            canonical_path.unlink(missing_ok=True)
        if legacy_path is not None:
            legacy_path.unlink(missing_ok=True)


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--admit-only", action="store_true")
    modes.add_argument("--activation-only", action="store_true")
    modes.add_argument("--timing-only", action="store_true")
    modes.add_argument("--filter-activation-only", action="store_true")
    modes.add_argument("--filter-timing-only", action="store_true")
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--shadow-run-dir", type=Path)
    parser.add_argument("--admission-dir", type=Path)
    parser.add_argument("--activation-dir", type=Path)
    parser.add_argument("--output-equivalence-proof", type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--repetitions", type=int, default=REPETITIONS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    root = Path.cwd().resolve()
    target = TARGETS[args.target]
    output = args.output_dir.resolve()
    output_preexisted = output.exists()
    mode = (
        "admit-only"
        if args.admit_only
        else "activation-only"
        if args.activation_only
        else "filter-activation-only"
        if args.filter_activation_only
        else "filter-timing-only"
        if args.filter_timing_only
        else "timing-only"
    )
    try:
        if args.admit_only:
            if args.shadow_run_dir is None:
                raise ValueError("--admit-only requires --shadow-run-dir")
            bundle = import_shadow_bundle(args.shadow_run_dir, target=target, root=root)
            admit_shadow_bundle(
                bundle,
                output,
                output_equivalence_proof=args.output_equivalence_proof,
            )
            return 0
        if args.output_equivalence_proof is not None:
            raise ValueError("--output-equivalence-proof is admit-only")
        if mode.startswith("filter-") and target.slug != "ollvm":
            raise ValueError("filter comparison modes are OLLVM-only")
        if args.admission_dir is None:
            raise ValueError("activation/timing phases require --admission-dir")
        if mode in {"timing-only", "filter-timing-only"} and args.activation_dir is None:
            raise ValueError(f"--{mode.removesuffix('-only')} requires --activation-dir")
        return _run_runtime_phase(
            mode=mode,
            admission_dir=args.admission_dir,
            activation_dir=args.activation_dir,
            output_dir=output,
            target=target,
            root=root,
            python=args.python,
            timeout=args.timeout,
            repetitions=args.repetitions,
        )
    except BaseException as exc:
        if not output_preexisted:
            output.mkdir(parents=True, exist_ok=True)
            failure = output / "failure.json"
            if not failure.exists():
                _write_json(
                    failure,
                    {"phase": mode, "error": repr(exc), "timing_claim": None},
                )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
