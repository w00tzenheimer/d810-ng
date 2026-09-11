"""Pure contracts for importing and measuring retained original-node evidence."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_controller():
    path = ROOT / "tools/bench/canonical_original_node_measurement.py"
    assert path.exists(), "original-node measurement controller not implemented"
    spec = importlib.util.spec_from_file_location(
        "canonical_original_node_measurement", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def retained_shadow(tmp_path: Path):
    root = tmp_path / "root"
    run = tmp_path / "retained"
    target = SimpleNamespace(
        nodeid="tests/system/e2e/test_original.py::test_original[node]",
        project="default_unflattening_ollvm.json",
        slug="ollvm",
    )
    sources = {
        "samples/bins/libobfuscated.dll": b"binary",
        "src/d810/backends/mba/hexrays_island.py": b"island\n",
        "src/d810/backends/mba/ida.py": b"ida-adapter\n",
        "src/d810/backends/mba/native_z3.py": b"native-z3\n",
        "src/d810/conf/default_unflattening_ollvm.json": b'{"profile":true}\n',
        "src/d810/hexrays/hooks/optinsn_adapter.py": b"optinsn-adapter\n",
        "src/d810/mba/ac_matching.py": b"ac-matching\n",
        "src/d810/mba/canonical_pattern.py": b"canonical\n",
        "src/d810/mba/rules/bnot.py": b"bnot\n",
        "src/d810/mba/rules/catalogue.py": b"catalogue\n",
        "src/d810/optimizers/microcode/instructions/pattern_matching/handler.py": b"handler\n",
        "tests/system/e2e/test_libdeobfuscated_dsl.py": b"fixture\n",
    }
    helpers = {
        "tools/bench/canonical_dac_probe.py": b"probe\n",
        "tools/bench/canonical_dac_measurement.py": b"measurement\n",
        "tools/bench/dsl_per_test_profile.py": b"per-test\n",
        "tools/scripts/mba_structural_matcher_certificate.py": b"builder\n",
    }
    runner = root / "tools/bench/run_ollvm_mismatch_witness.py"
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.write_bytes(b"runner\n")
    for name, content in (sources | helpers).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    snapshot = {
        "fingerprint": "a" * 64,
        "structural_authorizable": True,
        "canonicalizer_schema_version": 1,
        "runtime_semantics_digest": "b" * 64,
    }
    ledger = {
        "observation_count": 4207,
        "legacy_match_count": 25,
        "legacy_rule_mismatches": 0,
        "legacy_binding_mismatches": 0,
        "legacy_binding_unknown": 0,
        "new_safe_coverage_pending": 0,
        "new_safe_coverage_proved": 7,
        "unsafe_mutations": 0,
        "unproved_structural_replacements": 0,
    }
    enrollment = {
        "selected_rule_count": 2,
        "canonical_eligible_rule_count": 1,
        "legacy_only_rule_count": 1,
        "snapshot_fingerprint": snapshot["fingerprint"],
    }
    adapters = [
        {
            "rule_id": 0,
            "name": "eligible",
            "canonical_eligible": True,
            "canonical_fallback_enabled": False,
            "uses_structural_matching": False,
            "legacy_only_observation_count": 0,
            "legacy_only_match_count": 0,
        },
        {
            "rule_id": 1,
            "name": "legacy",
            "canonical_eligible": False,
            "canonical_fallback_enabled": False,
            "uses_structural_matching": False,
            "legacy_only_observation_count": 3,
            "legacy_only_match_count": 1,
        },
    ]
    toolchain = {
        "ida_sdk": 940,
        "matcher_backend": {"backend": "cython"},
        "python": "recorded-native-python",
    }
    capture = {
        "project": target.project,
        "expected_project": target.project,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "decompiles": [
            {"seconds": 1.0, "sha256": "1" * 64},
            {"seconds": 2.0, "sha256": "2" * 64},
        ],
        "toolchain": toolchain,
        "activation_calls": [],
        "accepted_enrolled": [],
        "records": [
            {
                "project": target.project,
                "snapshot": snapshot,
                "ledger": ledger,
                "ledger_occurrence": "fake-native-occurrence",
                "enrollment": enrollment,
                "snapshot_widths": [8, 16, 32, 64],
                "canonical_status_by_rule_width": [
                    {"rule_id": rule_id, "width": width, "status": status}
                    for rule_id, status in ((0, "eligible"), (1, "unsupported"))
                    for width in (8, 16, 32, 64)
                ],
                "adapters": adapters,
            }
        ],
    }
    process = {
        "command": [
            "recorded-native-python",
            "-u",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "tools.bench.canonical_dac_probe",
            "-q",
            "-s",
            "-o",
            "addopts=",
            target.nodeid,
        ],
        "exit": 0,
        "process_seconds": 3.5,
        "environment": {
            "D810_CANONICAL_DAC_AGGREGATE_ONLY": "1",
            "D810_CANONICAL_DAC_ORIGINAL_PROJECT": target.project,
            "D810_CANONICAL_DAC_PROJECT": target.project,
            "D810_CANONICAL_DAC_WITNESSES": "1",
            "D810_LEGACY_DSL_PERMUTATIONS": "1",
            "D810_SHADOW_DSL_MATCHING": "1",
            "D810_TEST_RUNTIME_IMAGE": "sha256:" + "c" * 64,
            "D810_TEST_RUNTIME_IMAGE_ID": "sha256:" + "c" * 64,
        },
    }
    receipt = {
        "schema_version": 1,
        "status": "passed",
        "reason": None,
        "test_status": "passed",
        "mode": "shadow-legacy",
        "nodeid": target.nodeid,
        "project": target.project,
        "target": target.slug,
        "output_label": "retained-r7",
    }
    provenance = {
        "nodeid": target.nodeid,
        "project": target.project,
        "target": target.slug,
        "output_label": "retained-r7",
        "runtime_image": "sha256:" + "c" * 64,
        "runtime_image_id": "sha256:" + "c" * 64,
        "git_revision": "d" * 40,
        "git_dirty": [],
        "target_source_sha256": {name: _digest(root / name) for name in sources},
        "execution_helper_sources": {name: _digest(root / name) for name in helpers},
        "witness_runner_sha256": _digest(runner),
    }
    _write(run / "receipt.json", receipt)
    _write(run / "process.json", process)
    _write(run / "shadow.json", capture)
    _write(run / "source-provenance.json", provenance)
    return root, run, target, capture, provenance


def test_import_uses_terminal_receipt_process_and_recorded_native_toolchain(tmp_path):
    module = load_controller()
    root, run, target, capture, provenance = retained_shadow(tmp_path)

    bundle = module.import_shadow_bundle(run, target=target, root=root)

    assert bundle["normalized_receipt"]["nodeid"] == target.nodeid
    assert bundle["normalized_receipt"]["exit"] == 0
    assert bundle["toolchain"] == capture["toolchain"]
    assert bundle["toolchain"]["python"] == "recorded-native-python"
    assert bundle["expected_decompile_sha256"] == ["1" * 64, "2" * 64]
    assert bundle["runtime_image_id"] == provenance["runtime_image_id"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda run, root: (run / "receipt.json").unlink(), "receipt"),
        (
            lambda run, root: _write(
                run / "process.json", {"exit": 1, "environment": {}}
            ),
            "process",
        ),
        (
            lambda run, root: (root / "samples/bins/libobfuscated.dll").write_bytes(
                b"changed"
            ),
            "source",
        ),
        (
            lambda run, root: _mutate_json(
                run / "shadow.json",
                lambda value: value["toolchain"].update(
                    matcher_backend={"backend": "python"}
                ),
            ),
            "Cython",
        ),
        (
            lambda run, root: _mutate_json(
                run / "process.json",
                lambda value: value["command"].append("unexpected"),
            ),
            "command",
        ),
        (
            lambda run, root: (
                root / "tools/bench/run_ollvm_mismatch_witness.py"
            ).write_bytes(b"changed\n"),
            "witness runner",
        ),
        (
            lambda run, root: _mutate_json(
                run / "source-provenance.json",
                lambda value: value["target_source_sha256"].pop(
                    "src/d810/backends/mba/hexrays_island.py"
                ),
            ),
            "target sources",
        ),
        (
            lambda run, root: _mutate_json(
                run / "process.json",
                lambda value: value["environment"].update(
                    D810_CANONICAL_DAC_ACTIVATION_PROOF="1"
                ),
            ),
            "shadow mode",
        ),
    ],
)
def test_import_refuses_missing_failed_changed_or_non_native_evidence(
    tmp_path, mutation, message
):
    module = load_controller()
    root, run, target, *_ = retained_shadow(tmp_path)
    mutation(run, root)
    with pytest.raises((FileNotFoundError, ValueError), match=message):
        module.import_shadow_bundle(run, target=target, root=root)


def _mutate_json(path: Path, mutation) -> None:
    value = json.loads(path.read_text())
    mutation(value)
    _write(path, value)


def test_admission_reuses_unchanged_assessor_builder_and_recorded_toolchain(tmp_path):
    module = load_controller()
    root, run, target, capture, _ = retained_shadow(tmp_path)
    bundle = module.import_shadow_bundle(run, target=target, root=root)
    calls = []

    def builder(evidence, *, manifest, toolchain):
        calls.append(
            {
                "evidence": deepcopy(evidence),
                "manifest": json.loads(manifest.read_text()),
                "toolchain": json.loads(toolchain.read_text()),
            }
        )
        return {
            "schema_version": 3,
            "snapshot_fingerprint": evidence["snapshot"]["fingerprint"],
        }

    output = tmp_path / "admission"
    decision = module.admit_shadow_bundle(bundle, output, certificate_builder=builder)

    assert decision["status"] == "qualified"
    assert calls[0]["toolchain"] == capture["toolchain"]
    assert calls[0]["evidence"]["ledger"]["legacy_match_count"] == 25
    assert calls[0]["manifest"]["nodeid"] == target.nodeid
    assert (output / "certificate.json").exists()
    with pytest.raises(FileExistsError):
        module.admit_shadow_bundle(bundle, output, certificate_builder=builder)


def test_admission_persists_only_explicit_validated_output_policy(
    tmp_path, monkeypatch
):
    module = load_controller()
    root, run, target, *_ = retained_shadow(tmp_path)
    bundle = module.import_shadow_bundle(run, target=target, root=root)
    proof = tmp_path / "reviewed-proof.json"
    _write(proof, {"proof": True})
    seen = []

    def store(candidate, proof_path, output_dir):
        seen.append((candidate, proof_path, output_dir))
        return {
            "policy": "output-policy.json",
            "policy_sha256": "a" * 64,
            "proof": "output-proof.json",
            "proof_sha256": "b" * 64,
        }

    monkeypatch.setattr(module, "store_exact_output_policy", store)

    def builder(evidence, *, manifest, toolchain):
        return {
            "schema_version": 3,
            "snapshot_fingerprint": evidence["snapshot"]["fingerprint"],
        }

    output = tmp_path / "policy-admission"
    module.admit_shadow_bundle(
        bundle,
        output,
        certificate_builder=builder,
        output_equivalence_proof=proof,
    )

    target_receipt = json.loads((output / "target.json").read_text())
    assert target_receipt["output_policy"]["policy_sha256"] == "a" * 64
    assert seen == [(bundle, proof, output.resolve())]


def activation_receipt(*, route="canonical_fallback", budget=256, exhausted=0):
    return {
        "mode": "canonical",
        "adapters": [
            {"rule_id": 7, "canonical_eligible": True},
            {"rule_id": 8, "canonical_eligible": False},
        ],
        "activation_calls": [
            {
                "attempted_rule_count": 1,
                "bucket_size": 2,
                "matched": True,
                "requested_comparison_budget": budget,
                "comparisons": 7,
                "stop_reason": "matched",
            }
        ],
        "activation_summary": {
            "call_count": 1,
            "match_count": 1,
            "comparison_count": 7,
            "exhaustion_count": exhausted,
        },
        "accepted_enrolled": [
            {
                "rule_id": 7,
                "route": route,
                "outcome_status": "applied",
                "candidate_count": 1,
            }
        ],
    }


def test_original_activation_requires_applied_canonical_route_and_budget_256():
    module = load_controller()
    module.validate_original_activation(activation_receipt())
    module.validate_original_activation(activation_receipt(route="raw_base"))
    for broken, message in [
        (activation_receipt(route="unknown"), "route"),
        (activation_receipt(budget=255), "256"),
        (activation_receipt(exhausted=1), "exhaust"),
    ]:
        with pytest.raises(ValueError, match=message):
            module.validate_original_activation(broken)
    invalid_bucket = activation_receipt()
    invalid_bucket["activation_calls"][0]["bucket_size"] = 0
    with pytest.raises(ValueError, match="bucket"):
        module.validate_original_activation(invalid_bucket)


def test_phase_plans_use_original_node_without_requalifying_or_claiming_failed_timing():
    module = load_controller()
    assert module.phase_plan("admit-only", repetitions=3) == []
    assert module.phase_plan("activation-only", repetitions=3) == [
        {"arm": "canonical-proof", "mode": "canonical", "proof": True}
    ]
    timing = module.phase_plan("timing-only", repetitions=3)
    assert [item["mode"] for item in timing] == [
        "legacy",
        "legacy",
        "legacy",
        "canonical",
        "canonical",
        "canonical",
        "legacy",
        "legacy",
        "legacy",
    ]
    assert all(item["proof"] is False for item in timing)
    assert module.phase_plan("filter-activation-only", repetitions=3) == [
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
    filter_timing = module.phase_plan("filter-timing-only", repetitions=3)
    assert [item["arm"] for item in filter_timing] == [
        *(["filter-off-before"] * 3),
        *(["filter-on"] * 3),
        *(["filter-off-after"] * 3),
    ]
    assert [item["filter_enabled"] for item in filter_timing] == [
        *([False] * 3),
        *([True] * 3),
        *([False] * 3),
    ]
    assert all(item["mode"] == "canonical" for item in filter_timing)
    assert all(item["proof"] is False for item in filter_timing)
    with pytest.raises(ValueError, match="three"):
        module.phase_plan("timing-only", repetitions=2)
    assert module.timing_outcome([], failure="child failed") == {
        "status": "failed",
        "error": "child failed",
        "comparison": None,
    }


def _filter_counts(**updates):
    counts = {
        "candidate_fact_constructions": 0,
        "candidate_fact_operands": 0,
        "template_fact_constructions": 0,
        "template_fact_requirements": 0,
        "predicate_comparisons": 0,
        "rejected_candidates": 0,
        "surviving_candidates": 0,
        "unknown_candidates": 0,
    }
    counts.update(updates)
    return counts


def _filter_counter_record(occurrence, generation, counts):
    return {
        "canonical_fallback_feasibility": {
            "status": "available",
            "optimizer_occurrence": occurrence,
            "optimizer_generation": generation,
            "counts": counts,
        }
    }


def test_filter_environment_removes_inherited_flag_and_receipt_matches_actual_env():
    module = load_controller()
    base = {
        "D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER": "inherited",
        "D810_CANONICAL_MATCH_FALLBACK": "1",
        "D810_CODE_ANALYSIS_CACHE": "1",
        "D810_PRODUCER_STRUCTURAL_VALIDATION": "1",
        "D810_AUTHORITY_TRUST_SEALED": "0",
        "D810_NO_CYTHON": "0",
        "D810_CANONICAL_DAC_ACTIVATION_PROOF": "1",
        "D810_TEST_RUNTIME_IMAGE": "sha256:" + "a" * 64,
        "D810_TEST_RUNTIME_IMAGE_ID": "sha256:" + "a" * 64,
    }
    off_spec = module.phase_plan("filter-activation-only")[0]
    on_spec = module.phase_plan("filter-activation-only")[1]

    off = module.configure_filter_environment(dict(base), off_spec)
    on = module.configure_filter_environment(dict(base), on_spec)

    assert "D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER" not in off
    assert on["D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER"] == "1"
    process = {"environment": on, "mode": "canonical", "filter_enabled": True}
    module.validate_filter_process(on_spec, process, expected_image=base["D810_TEST_RUNTIME_IMAGE"])
    process["environment"].pop("D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER")
    with pytest.raises(ValueError, match="filter environment"):
        module.validate_filter_process(on_spec, process, expected_image=base["D810_TEST_RUNTIME_IMAGE"])
    process["environment"]["D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER"] = "1"
    process["environment"].pop("D810_CANONICAL_DAC_ACTIVATION_PROOF")
    with pytest.raises(ValueError, match="proof"):
        module.validate_filter_process(on_spec, process, expected_image=base["D810_TEST_RUNTIME_IMAGE"])


def test_filter_counter_normalization_uses_final_monotonic_same_occurrence_snapshot():
    module = load_controller()
    first = _filter_counts(rejected_candidates=2, surviving_candidates=1)
    final = _filter_counts(
        candidate_fact_constructions=2,
        candidate_fact_operands=5,
        template_fact_constructions=1,
        template_fact_requirements=2,
        predicate_comparisons=7,
        rejected_candidates=4,
        surviving_candidates=2,
        unknown_candidates=1,
    )
    records = [
        {"canonical_fallback_feasibility": {"status": "available", "optimizer_occurrence": "pattern-optimizer-1", "optimizer_generation": 7, "counts": first}},
        {"canonical_fallback_feasibility": {"status": "available", "optimizer_occurrence": "pattern-optimizer-1", "optimizer_generation": 7, "counts": final}},
    ]

    assert module.normalize_filter_counters(records, filter_enabled=True) == final
    broken = deepcopy(records)
    broken[1]["canonical_fallback_feasibility"]["optimizer_occurrence"] = "pattern-optimizer-2"
    with pytest.raises(ValueError, match="occurrence"):
        module.normalize_filter_counters(broken, filter_enabled=True)
    broken = deepcopy(records)
    broken[1]["canonical_fallback_feasibility"]["counts"]["rejected_candidates"] = 1
    with pytest.raises(ValueError, match="cumulative"):
        module.normalize_filter_counters(broken, filter_enabled=True)


def test_filter_counter_normalization_rejects_reset_overtake_and_replacement():
    module = load_controller()
    first = _filter_counts(rejected_candidates=4, surviving_candidates=2)
    overtaken = _filter_counts(rejected_candidates=8, surviving_candidates=3)
    records = [
        {"canonical_fallback_feasibility": {"status": "available", "optimizer_occurrence": "pattern-optimizer-1", "optimizer_generation": 7, "counts": first}},
        {"canonical_fallback_feasibility": {"status": "available", "optimizer_occurrence": "pattern-optimizer-1", "optimizer_generation": 8, "counts": overtaken}},
    ]
    with pytest.raises(ValueError, match="generation"):
        module.normalize_filter_counters(records, filter_enabled=True)
    records[1]["canonical_fallback_feasibility"].update(
        optimizer_occurrence="pattern-optimizer-2", optimizer_generation=7
    )
    with pytest.raises(ValueError, match="occurrence"):
        module.normalize_filter_counters(records, filter_enabled=True)


def test_filter_counter_normalization_accepts_actual_all_zero_rebuilt_baseline():
    module = load_controller()
    records = [
        _filter_counter_record("pattern-optimizer-1", 172, _filter_counts()),
        _filter_counter_record("pattern-optimizer-2", 169, _filter_counts()),
    ]

    assert module.normalize_filter_counters(records, filter_enabled=False) == _filter_counts()
    with pytest.raises(ValueError, match="filter ON"):
        module.normalize_filter_counters(records, filter_enabled=True)


def test_filter_counter_normalization_allows_zero_prefix_before_work_epoch():
    module = load_controller()
    work = _filter_counts(rejected_candidates=3, surviving_candidates=18)
    records = [
        _filter_counter_record("pattern-optimizer-1", 172, _filter_counts()),
        _filter_counter_record("pattern-optimizer-2", 169, work),
    ]

    assert module.normalize_filter_counters(records, filter_enabled=True) == work


def test_filter_counter_normalization_never_treats_missing_baseline_as_zero():
    module = load_controller()
    records = [
        {},
        _filter_counter_record(
            "pattern-optimizer-2",
            169,
            _filter_counts(rejected_candidates=3, surviving_candidates=18),
        ),
    ]

    with pytest.raises(ValueError, match="unavailable"):
        module.normalize_filter_counters(records, filter_enabled=True)


@pytest.mark.parametrize(
    ("later", "message"),
    [
        (
            _filter_counter_record(
                "pattern-optimizer-2",
                7,
                _filter_counts(rejected_candidates=8, surviving_candidates=3),
            ),
            "occurrence",
        ),
        (
            _filter_counter_record(
                "pattern-optimizer-1",
                8,
                _filter_counts(rejected_candidates=8, surviving_candidates=3),
            ),
            "generation",
        ),
        (
            _filter_counter_record("pattern-optimizer-1", 7, _filter_counts()),
            "cumulative",
        ),
    ],
)
def test_filter_counter_normalization_rejects_changes_after_work(later, message):
    module = load_controller()
    first = _filter_counter_record(
        "pattern-optimizer-1",
        7,
        _filter_counts(rejected_candidates=4, surviving_candidates=2),
    )

    with pytest.raises(ValueError, match=message):
        module.normalize_filter_counters([first, later], filter_enabled=True)


def test_filter_counter_normalization_treats_construction_only_as_work():
    module = load_controller()
    records = [
        _filter_counter_record(
            "pattern-optimizer-1",
            7,
            _filter_counts(candidate_fact_constructions=1),
        ),
        _filter_counter_record("pattern-optimizer-2", 7, _filter_counts()),
    ]

    with pytest.raises(ValueError, match="occurrence"):
        module.normalize_filter_counters(records, filter_enabled=True)


def test_filter_counter_normalization_does_not_sum_duplicate_work_snapshot():
    module = load_controller()
    work = _filter_counts(rejected_candidates=3, surviving_candidates=18)
    record = _filter_counter_record("pattern-optimizer-2", 169, work)

    assert module.normalize_filter_counters(
        [deepcopy(record), deepcopy(record)], filter_enabled=True
    ) == work


def test_filter_counter_gates_distinguish_off_zero_from_on_actual_work():
    module = load_controller()
    assert module.validate_filter_counters(_filter_counts(), filter_enabled=False) == {
        "attempted_candidates": 0,
        "rejected_fraction": "0",
    }
    on = _filter_counts(
        candidate_fact_constructions=2,
        predicate_comparisons=7,
        rejected_candidates=4,
        surviving_candidates=2,
        unknown_candidates=1,
    )
    assert module.validate_filter_counters(on, filter_enabled=True) == {
        "attempted_candidates": 6,
        "rejected_fraction": "0.6666666666666666666666666667",
    }
    for updates in (
        {},
        {"surviving_candidates": 1, "unknown_candidates": 2},
        {"candidate_fact_constructions": 2, "surviving_candidates": 1},
    ):
        with pytest.raises(ValueError, match="filter"):
            module.validate_filter_counters(
                _filter_counts(**updates), filter_enabled=True
            )


def _filter_activation_receipt(enabled):
    receipt = activation_receipt()
    receipt["arm"] = "filter-on-proof" if enabled else "filter-off-proof"
    receipt["filter_enabled"] = enabled
    receipt["filter_counters"] = (
        _filter_counts(
            candidate_fact_constructions=1,
            predicate_comparisons=2,
            rejected_candidates=3,
            surviving_candidates=1,
        )
        if enabled
        else _filter_counts()
    )
    receipt["accepted_enrolled"][0].update(
        rule="eligible",
        input_ea=0x401000,
        provider_fingerprint="provider-fingerprint",
    )
    receipt["activation_calls"][0].update(
        rule="eligible",
        input_ea=0x401000,
        provider_fingerprint="provider-fingerprint",
    )
    return receipt


def test_filter_activation_pair_requires_ordered_actual_arms_and_match_identity():
    module = load_controller()
    off = _filter_activation_receipt(False)
    on = _filter_activation_receipt(True)

    result = module.validate_filter_activation_pair(
        [off, on],
        expected_match_count=1,
        expected_applied_route_counts={"canonical_fallback": 1, "raw_base": 0},
    )

    assert result["status"] == "passed"
    assert result["known_full_match_identities"] == [
        ["eligible", 0x401000]
    ]
    assert result["off"]["filter_counters"]["attempted_candidates"] == 0
    assert result["on"]["filter_counters"]["attempted_candidates"] == 4
    for broken in (
        [on, off],
        [off],
        [off, deepcopy(off)],
    ):
        with pytest.raises(ValueError, match="filter activation"):
            module.validate_filter_activation_pair(
                broken,
                expected_match_count=1,
                expected_applied_route_counts={"canonical_fallback": 1, "raw_base": 0},
            )
    changed = deepcopy(on)
    changed["activation_calls"][0]["input_ea"] += 1
    with pytest.raises(ValueError, match="identit"):
        module.validate_filter_activation_pair(
            [off, changed],
            expected_match_count=1,
            expected_applied_route_counts={"canonical_fallback": 1, "raw_base": 0},
        )


def _retained_filter_activation_receipt(enabled):
    receipt = _filter_activation_receipt(enabled)
    receipt["activation_calls"] = [
        {
            "rule": f"full-match-{0 if index == 1 else index}",
            "input_ea": 0x401000 + (0 if index == 1 else index),
            "provider_fingerprint": f"full-provider-{index}",
            "attempted_rule_count": 1,
            "bucket_size": 1,
            "matched": True,
            "requested_comparison_budget": 256,
            "comparisons": 1,
            "stop_reason": "matched",
        }
        for index in range(18)
    ]
    receipt["activation_summary"] = {
        "call_count": 18,
        "match_count": 18,
        "comparison_count": 18,
        "exhaustion_count": 0,
    }
    receipt["accepted_enrolled"] = [
        {
            "rule_id": 7,
            "rule": f"applied-{0 if index == 1 else index}",
            "input_ea": 0x501000 + (0 if index == 1 else index),
            "provider_fingerprint": f"applied-provider-{index}",
            "route": "canonical_fallback" if index < 16 else "raw_base",
            "outcome_status": "applied",
            "candidate_count": 1,
        }
        for index in range(27)
    ]
    if enabled:
        receipt["filter_counters"].update(
            rejected_candidates=3, surviving_candidates=18
        )
    return receipt


def test_filter_activation_retains_18_full_matches_separate_from_27_applied():
    module = load_controller()
    result = module.validate_filter_activation_pair(
        [
            _retained_filter_activation_receipt(False),
            _retained_filter_activation_receipt(True),
        ]
    )

    assert result["status"] == "passed"
    assert len(result["known_full_match_identities"]) == 18
    assert result["known_full_match_identities"].count(
        ["full-match-0", 0x401000]
    ) == 2
    assert len(result["applied_outcomes"]["off"]) == 27
    assert result["applied_outcomes"]["off_route_counts"] == {
        "canonical_fallback": 16,
        "raw_base": 11,
    }


def test_filter_activation_accepts_opaque_fingerprint_only_difference_as_diagnostic():
    module = load_controller()
    off = _retained_filter_activation_receipt(False)
    on = _retained_filter_activation_receipt(True)
    on["activation_calls"][4]["provider_fingerprint"] = "process-local-full-hash"
    on["accepted_enrolled"][9]["provider_fingerprint"] = "process-local-applied-hash"

    result = module.validate_filter_activation_pair([off, on])

    assert result["status"] == "passed"
    assert result["provider_fingerprint_diagnostics"]["full"]["off"][4] == "full-provider-4"
    assert result["provider_fingerprint_diagnostics"]["full"]["on"][4] == "process-local-full-hash"
    assert result["provider_fingerprint_diagnostics"]["applied"]["on"][9] == "process-local-applied-hash"


@pytest.mark.parametrize("field", ["rule", "input_ea"])
def test_filter_activation_rejects_equal_count_full_identity_substitution(field):
    module = load_controller()
    off = _retained_filter_activation_receipt(False)
    on = _retained_filter_activation_receipt(True)
    on["activation_calls"][4][field] = (
        "replacement-rule" if field == "rule" else 0x409999
    )

    with pytest.raises(ValueError, match="identit"):
        module.validate_filter_activation_pair([off, on])


def test_filter_activation_rejects_lost_and_reordered_full_matches():
    module = load_controller()
    off = _retained_filter_activation_receipt(False)

    lost = _retained_filter_activation_receipt(True)
    lost["activation_calls"].pop()
    lost["activation_summary"].update(
        call_count=17, match_count=17, comparison_count=17
    )
    lost["filter_counters"]["surviving_candidates"] = 17
    with pytest.raises(ValueError, match="identit"):
        module.validate_filter_activation_pair([off, lost])

    reordered = _retained_filter_activation_receipt(True)
    reordered["activation_calls"][4], reordered["activation_calls"][5] = (
        reordered["activation_calls"][5],
        reordered["activation_calls"][4],
    )
    with pytest.raises(ValueError, match="identit"):
        module.validate_filter_activation_pair([off, reordered])


@pytest.mark.parametrize("mutation", ["route", "order"])
def test_filter_activation_rejects_applied_route_or_order_change(mutation):
    module = load_controller()
    off = _retained_filter_activation_receipt(False)
    on = _retained_filter_activation_receipt(True)
    if mutation == "route":
        on["accepted_enrolled"][0]["route"] = "raw_base"
    else:
        on["accepted_enrolled"][4], on["accepted_enrolled"][5] = (
            on["accepted_enrolled"][5],
            on["accepted_enrolled"][4],
        )

    with pytest.raises(ValueError, match="identit"):
        module.validate_filter_activation_pair([off, on])


def test_filter_activation_labels_additional_on_match_for_investigation():
    module = load_controller()
    off = _retained_filter_activation_receipt(False)
    on = _retained_filter_activation_receipt(True)
    extra = deepcopy(on["activation_calls"][-1])
    extra.update(
        rule="new-full-match",
        input_ea=0x409999,
        provider_fingerprint="new-provider",
    )
    on["activation_calls"].append(extra)
    on["activation_summary"].update(
        call_count=19, match_count=19, comparison_count=19
    )
    on["filter_counters"]["surviving_candidates"] = 19

    result = module.validate_filter_activation_pair([off, on])

    assert result["status"] == "investigation_required"
    assert result["additional_on_full_match_identities"] == [
        ["new-full-match", 0x409999]
    ]


def test_retained_filter_processes_reconcile_actual_environment_and_receipt(tmp_path):
    module = load_controller()
    image = "sha256:" + "a" * 64
    plan = module.phase_plan("filter-activation-only")
    receipts = []
    for index, spec in enumerate(plan):
        environment = {
            "D810_CANONICAL_MATCH_FALLBACK": "1",
            "D810_CODE_ANALYSIS_CACHE": "1",
            "D810_PRODUCER_STRUCTURAL_VALIDATION": "1",
            "D810_AUTHORITY_TRUST_SEALED": "0",
            "D810_NO_CYTHON": "0",
            "D810_TEST_RUNTIME_IMAGE": image,
            "D810_TEST_RUNTIME_IMAGE_ID": image,
            "D810_CANONICAL_DAC_ACTIVATION_PROOF": "1",
        }
        module.configure_filter_environment(environment, spec)
        process = {
            "environment": environment,
            "mode": "canonical",
            "filter_enabled": spec["filter_enabled"],
        }
        run_dir = tmp_path / f"{index:02d}-{spec['arm']}"
        _write(run_dir / "process.json", process)
        receipts.append(
            {
                "arm": spec["arm"],
                "filter_enabled": spec["filter_enabled"],
                "process_environment": environment,
                "process_digest": module.canonical_digest(process),
            }
        )

    module.validate_retained_filter_processes(
        tmp_path, plan=plan, receipts=receipts, expected_image=image
    )
    receipts[0]["filter_enabled"] = True
    with pytest.raises(ValueError, match="receipt"):
        module.validate_retained_filter_processes(
            tmp_path, plan=plan, receipts=receipts, expected_image=image
        )


def test_filter_receipt_is_bound_to_actual_process_and_final_counter_snapshot():
    module = load_controller()
    image = "sha256:" + "a" * 64
    spec = module.phase_plan("filter-activation-only")[1]
    environment = {
        "D810_CANONICAL_MATCH_FALLBACK": "1",
        "D810_CANONICAL_FALLBACK_FEASIBILITY_FILTER": "1",
        "D810_CODE_ANALYSIS_CACHE": "1",
        "D810_PRODUCER_STRUCTURAL_VALIDATION": "1",
        "D810_AUTHORITY_TRUST_SEALED": "0",
        "D810_NO_CYTHON": "0",
        "D810_TEST_RUNTIME_IMAGE": image,
        "D810_TEST_RUNTIME_IMAGE_ID": image,
        "D810_CANONICAL_DAC_ACTIVATION_PROOF": "1",
    }
    process = {
        "environment": environment,
        "mode": "canonical",
        "filter_enabled": True,
    }
    final = _filter_counts(
        candidate_fact_constructions=1,
        rejected_candidates=2,
        surviving_candidates=1,
    )
    raw = {
        "records": [
            {
                "canonical_fallback_feasibility": {
                    "status": "available",
                    "optimizer_occurrence": "pattern-optimizer-1",
                    "optimizer_generation": 7,
                    "counts": final,
                }
            }
        ]
    }

    receipt = module.attach_filter_receipt(
        {}, raw=raw, process=process, spec=spec, expected_image=image
    )

    assert receipt["arm"] == "filter-on-proof"
    assert receipt["filter_enabled"] is True
    assert receipt["filter_counters"] == final
    assert receipt["process_environment"] == environment
    assert receipt["process_digest"] == module.canonical_digest(process)


def test_cache_policy_metadata_is_fixture_specific_and_does_not_claim_reuse():
    module = load_controller()
    assert module.cache_policy_for_target("ollvm") == (
        "OLLVM selected pipeline has no solver consumer; no proof-cache reuse applies"
    )
    assert module.cache_policy_for_target("reference-v4") == (
        "each Reference-v4 child creates a cold child-local proof database"
    )
    with pytest.raises(ValueError, match="target"):
        module.cache_policy_for_target("unknown")


def test_filter_cli_modes_are_ollvm_only_and_timing_requires_dual_activation(tmp_path, monkeypatch):
    module = load_controller()
    ollvm = SimpleNamespace(nodeid="node", project="project", slug="ollvm")
    reference = SimpleNamespace(nodeid="node", project="project", slug="reference-v4")
    monkeypatch.setitem(module.TARGETS, "ollvm", ollvm)
    monkeypatch.setitem(module.TARGETS, "reference-v4", reference)
    seen = []
    monkeypatch.setattr(module, "_run_runtime_phase", lambda **kwargs: seen.append(kwargs) or 0)

    assert module.main([
        "--filter-activation-only", "--target", "ollvm",
        "--output-dir", str(tmp_path / "activation"),
        "--admission-dir", str(tmp_path / "admission"),
    ]) == 0
    assert seen[-1]["mode"] == "filter-activation-only"
    with pytest.raises(ValueError, match="OLLVM"):
        module.main([
            "--filter-activation-only", "--target", "reference-v4",
            "--output-dir", str(tmp_path / "reference"),
            "--admission-dir", str(tmp_path / "admission"),
        ])
    with pytest.raises(ValueError, match="activation-dir"):
        module.main([
            "--filter-timing-only", "--target", "ollvm",
            "--output-dir", str(tmp_path / "timing"),
            "--admission-dir", str(tmp_path / "admission"),
        ])


def _filter_timing_receipt(arm, enabled, seconds):
    return {
        "arm": arm,
        "mode": "canonical",
        "filter_enabled": enabled,
        "process_seconds": str(seconds),
        "decompiles": [
            {"seconds": "1", "sha256": "a" * 64},
            {"seconds": "2", "sha256": "b" * 64},
        ],
    }


def test_filter_timing_uses_pooled_off_decimal_median_and_reports_drift_and_samples():
    module = load_controller()
    receipts = [
        *[_filter_timing_receipt("filter-off-before", False, value) for value in ("10", "12", "11")],
        *[_filter_timing_receipt("filter-on", True, value) for value in ("7", "8", "9")],
        *[_filter_timing_receipt("filter-off-after", False, value) for value in ("13", "14", "15")],
    ]

    result = module.filter_timing_comparison(receipts)

    assert result["sequence"] == ["filter-off-before", "filter-on", "filter-off-after"]
    assert result["off_median_seconds"] == "12.5"
    assert result["on_median_seconds"] == "8"
    assert result["on_over_off"] == "0.64"
    assert result["off_before_median_seconds"] == "11"
    assert result["off_after_median_seconds"] == "14"
    assert result["off_before_after_drift_seconds"] == "3"
    assert result["samples"][0]["process_minus_both_decompiles"] == "7"
    reordered = deepcopy(receipts)
    reordered[0], reordered[3] = reordered[3], reordered[0]
    with pytest.raises(ValueError, match="sequence"):
        module.filter_timing_comparison(reordered)
    mislabeled = deepcopy(receipts)
    mislabeled[3]["filter_enabled"] = False
    with pytest.raises(ValueError, match="sequence"):
        module.filter_timing_comparison(mislabeled)


def test_phase_child_sequence_preserves_exact_original_node():
    module = load_controller()
    nodeid = "tests/system/e2e/test_original.py::test_original[node]"
    seen = []

    def child(*, spec, nodeid, index):
        seen.append((spec, nodeid, index))
        return {"mode": spec["mode"], "index": index}

    activation = module.run_phase_children(
        module.phase_plan("activation-only", repetitions=3),
        nodeid=nodeid,
        child_runner=child,
    )
    timing = module.run_phase_children(
        module.phase_plan("timing-only", repetitions=3),
        nodeid=nodeid,
        child_runner=child,
    )

    assert activation == [{"mode": "canonical", "index": 0}]
    assert [row[1] for row in seen] == [nodeid] * 10
    assert [item["mode"] for item in timing] == [
        "legacy",
        "legacy",
        "legacy",
        "canonical",
        "canonical",
        "canonical",
        "legacy",
        "legacy",
        "legacy",
    ]


def test_timing_preflight_is_bound_to_receipt_admission_and_config(tmp_path):
    module = load_controller()
    target = SimpleNamespace(nodeid="node::id", project="project.json", slug="p")
    admission_dir = tmp_path / "admission"
    activation_dir = tmp_path / "activation"
    profile = tmp_path / "src/d810/conf/project.json"
    admission_dir.mkdir()
    activation_dir.mkdir()
    _write(profile, {"profile": "original"})
    toolchain = {"matcher_backend": {"backend": "cython"}}
    snapshot = {"fingerprint": "a" * 64, "runtime_semantics_digest": "b" * 64}
    ledger = {"observation_count": 9, "legacy_match_count": 2}
    _write(admission_dir / "workload.json", {"scope": "test"})
    _write(admission_dir / "toolchain.json", toolchain)
    _write(admission_dir / "evidence.json", {"snapshot": snapshot, "ledger": ledger})
    certificate = {
        "corpus_digest": _digest(admission_dir / "workload.json"),
        "toolchain_digest": module.canonical_digest(toolchain),
        "runtime_semantics_digest": snapshot["runtime_semantics_digest"],
        "legacy_observation_count": ledger["legacy_match_count"],
        "observation_count": ledger["observation_count"],
    }
    _write(admission_dir / "certificate.json", certificate)
    for name in ("admission.json", "source-provenance.json", "target.json"):
        _write(admission_dir / name, {"name": name})
    expectation = module.derive_expectation(
        _digest(admission_dir / "workload.json"),
        toolchain,
        {"snapshot": snapshot, "ledger": ledger},
        certificate,
    )
    config = activation_dir / "canonical-config.json"
    _write(
        config,
        module.build_activation_config(
            {"profile": "original"},
            str((admission_dir / "certificate.json").resolve()),
            expectation,
        ),
    )
    receipt = activation_receipt(route="raw_base")
    enrollment = {
        "selected_rule_count": 2,
        "canonical_eligible_rule_count": 1,
        "legacy_only_rule_count": 1,
    }
    expected_hashes = ["1" * 64, "2" * 64]
    receipt.update(
        exit=0,
        passed=1,
        skipped=0,
        project="generated-canonical.json",
        expected_project="generated-canonical.json",
        process_seconds="3.5",
        decompiles=[
            {"seconds": 1, "sha256": expected_hashes[0]},
            {"seconds": 2, "sha256": expected_hashes[1]},
        ],
        expected_decompile_sha256=expected_hashes,
        segment_id="dac",
        toolchain=toolchain,
        snapshot=snapshot,
        live_snapshot=snapshot,
        live_ledger={},
        enrollment=enrollment,
        metrics={"canonical_call_count": 1, "enrolled_transformation_count": 1},
    )
    receipt["adapters"] = [
        {
            "rule_id": 7,
            "name": "eligible",
            "canonical_eligible": True,
            "canonical_fallback_enabled": True,
            "uses_structural_matching": True,
        },
        {
            "rule_id": 8,
            "name": "legacy",
            "canonical_eligible": False,
            "canonical_fallback_enabled": False,
            "uses_structural_matching": False,
        },
    ]
    _write(activation_dir / "receipts.json", [receipt])
    binding = module.admission_artifact_digests(admission_dir)
    provenance = {
        "nodeid": target.nodeid,
        "project": target.project,
        "target": target.slug,
        "mode": "activation-only",
        "controller_sha256": _digest(
            ROOT / "tools/bench/canonical_original_node_measurement.py"
        ),
        "runtime_image": "sha256:" + "c" * 64,
        "runtime_image_id": "sha256:" + "c" * 64,
        "toolchain_digest": module.canonical_digest(toolchain),
        "admission_artifacts": binding,
        "generated_config_sha256": _digest(config),
        "activation": {
            "project": receipt["project"],
            "profile_sha256": _digest(profile),
            "activation_sha256": _digest(config),
            "certificate_sha256": _digest(admission_dir / "certificate.json"),
            "manifest_sha256": _digest(admission_dir / "workload.json"),
            "toolchain_sha256": _digest(admission_dir / "toolchain.json"),
            "expectation": expectation,
        },
    }
    _write(activation_dir / "provenance.json", provenance)
    validation = module.validate_original_activation(receipt)
    _write(
        activation_dir / "result.json",
        {
            "status": "passed",
            "phase": "activation-only",
            "activation": validation,
            "receipt_digest": module.canonical_digest(receipt),
        },
    )
    admission = {
        "target": {
            "runtime_image": provenance["runtime_image"],
            "runtime_image_id": provenance["runtime_image_id"],
            "toolchain_digest": provenance["toolchain_digest"],
            "expected_decompile_sha256": expected_hashes,
            "profile": "src/d810/conf/project.json",
            "profile_sha256": _digest(profile),
        },
        "toolchain": toolchain,
        "evidence": {
            "snapshot": snapshot,
            "ledger": ledger,
            "enrollment": enrollment,
            "adapters": receipt["adapters"],
        },
    }

    module.validate_activation_preflight(
        activation_dir,
        admission_dir=admission_dir,
        admission=admission,
        target=target,
        root=tmp_path,
    )
    unexpected_policy = deepcopy(receipt)
    unexpected_policy["output_policy"] = {
        "policy": "substituted.json",
        "policy_sha256": "f" * 64,
    }
    _write(activation_dir / "receipts.json", [unexpected_policy])
    result = json.loads((activation_dir / "result.json").read_text())
    result["receipt_digest"] = module.canonical_digest(unexpected_policy)
    _write(activation_dir / "result.json", result)
    with pytest.raises(ValueError, match="output policy"):
        module.validate_activation_preflight(
            activation_dir,
            admission_dir=admission_dir,
            admission=admission,
            target=target,
            root=tmp_path,
        )
    _write(activation_dir / "receipts.json", [receipt])
    result["receipt_digest"] = module.canonical_digest(receipt)
    _write(activation_dir / "result.json", result)
    wrong_project = deepcopy(receipt)
    wrong_project["project"] = wrong_project["expected_project"] = "other.json"
    _write(activation_dir / "receipts.json", [wrong_project])
    result = json.loads((activation_dir / "result.json").read_text())
    result["receipt_digest"] = module.canonical_digest(wrong_project)
    _write(activation_dir / "result.json", result)
    with pytest.raises(ValueError, match="project"):
        module.validate_activation_preflight(
            activation_dir,
            admission_dir=admission_dir,
            admission=admission,
            target=target,
            root=tmp_path,
        )
    _write(activation_dir / "receipts.json", [receipt])
    result["receipt_digest"] = module.canonical_digest(receipt)
    _write(activation_dir / "result.json", result)

    altered_provenance = deepcopy(provenance)
    altered_provenance["activation"]["expectation"]["observation_count"] += 1
    _write(activation_dir / "provenance.json", altered_provenance)
    with pytest.raises(ValueError, match="expectation"):
        module.validate_activation_preflight(
            activation_dir,
            admission_dir=admission_dir,
            admission=admission,
            target=target,
            root=tmp_path,
        )
    _write(activation_dir / "provenance.json", provenance)

    accepted = module.validate_activation_preflight(
        activation_dir,
        admission_dir=admission_dir,
        admission=admission,
        target=target,
        root=tmp_path,
    )
    module.require_same_activation_config(accepted, config)
    config.write_text("changed\n")
    with pytest.raises(ValueError, match="config"):
        module.require_same_activation_config(accepted, config)
    _write(
        config,
        module.build_activation_config(
            {"profile": "original"},
            str((admission_dir / "certificate.json").resolve()),
            expectation,
        ),
    )
    (admission_dir / "certificate.json").write_text("changed\n")
    with pytest.raises(ValueError, match="admission"):
        module.validate_activation_preflight(
            activation_dir,
            admission_dir=admission_dir,
            admission=admission,
            target=target,
            root=tmp_path,
        )

    _write(admission_dir / "certificate.json", certificate)
    broken = deepcopy(receipt)
    broken["exit"] = 1
    _write(activation_dir / "receipts.json", [broken])
    result = json.loads((activation_dir / "result.json").read_text())
    result["receipt_digest"] = module.canonical_digest(broken)
    _write(activation_dir / "result.json", result)
    with pytest.raises(ValueError, match="pass exactly once"):
        module.validate_activation_preflight(
            activation_dir,
            admission_dir=admission_dir,
            admission=admission,
            target=target,
            root=tmp_path,
        )


def test_runtime_setup_failure_is_retained_before_any_child(tmp_path):
    module = load_controller()
    output = tmp_path / "failed-phase"
    target = SimpleNamespace(nodeid="node::id", project="project.json", slug="p")

    with pytest.raises(FileNotFoundError, match="admission target"):
        module._run_runtime_phase(
            mode="activation-only",
            admission_dir=tmp_path / "missing-admission",
            activation_dir=None,
            output_dir=output,
            target=target,
            root=tmp_path,
            python="recorded-native-python",
            timeout=1,
            repetitions=3,
        )

    failure = json.loads((output / "failure.json").read_text())
    assert failure["phase"] == "activation-only"
    assert failure["timing_claim"] is None


REFERENCE_NODE = (
    "tests/system/e2e/test_libdeobfuscated_dsl.py::"
    "TestDacMasmFixtures::test_dac_masm_fixtures[sub_7FF856533A20]"
)
REFERENCE_PROJECT = "eidolon_v4_const_simplify_solve.json"
REFERENCE_PE_SHA256 = "87720f6347b39b30792d871e8c69ba46a0d7fed1b65a6441488316de1be7532e"
COMMON_OUTPUT = "4614e64fb63cc6f1d77101dceac6196f53eb648874901fa0a62e16a60ae5870b"
LEGACY_OUTPUT = "05eac5b9156f272e41ab9232c730511467e5145af53753b501e4306512a15342"
CANONICAL_OUTPUT = "6c22013d6d1fe0e57b14bc37646298a04938680e90bc07e59cf4ab6990cadcbb"


def _exact_proof_receipt():
    return {
        "schema_version": 1,
        "status": "passed",
        "passed": True,
        "surrounding_text_byte_identical": True,
        "bitvector_width": 64,
        "assumptions_on_input_values": [],
        "claim": "exact reviewed captured-expression claim",
        "limitations": [
            "This is not an independent proof of full native-function equivalence.",
            "This does not prove ISO-C undefined-behavior semantics.",
            "The captured pseudocode reported a local-variable-allocation warning.",
            "Opaque loads and addresses are equal atoms only for shared spellings.",
        ],
        "function": {
            "function_ea": 0x18001AE24,
            "function_ea_hex": "0x18001ae24",
            "function_name": "_sub_7FF856533A20",
            "nodeid": REFERENCE_NODE,
        },
        "inputs": {
            "legacy_capture": {"sha256": LEGACY_OUTPUT},
            "canonical_capture": {"sha256": CANONICAL_OUTPUT},
            "capture_plugin_sha256": (
                "91151f6bb085a4b6ebacedd8154cee4ed6753fc293de6517e97a3b08eb1aeb6c"
            ),
        },
        "expression_proofs": [
            {
                "anchor": anchor,
                "target": target,
                "solver_result": "unsat",
                "inequality_satisfiable": False,
                "counterexample": None,
            }
            for anchor, target in (
                ("case 0x1C:", "v2"),
                ("case 0x20:", "v2"),
                ("case 0x27:", "v17"),
                ("LABEL_xC055:", "v29"),
            )
        ],
    }


def _exact_policy_inputs(module, tmp_path, monkeypatch):
    proof = tmp_path / "proof.json"
    _write(proof, _exact_proof_receipt())
    monkeypatch.setattr(module, "REFERENCE_OUTPUT_PROOF_SHA256", _digest(proof))
    admission = tmp_path / "admission"
    admission.mkdir()
    for name, value in (
        ("workload.json", {"scope": "exact-reference"}),
        ("evidence.json", {"snapshot": {"fingerprint": "a" * 64}}),
        ("certificate.json", {"snapshot_fingerprint": "a" * 64}),
        ("toolchain.json", {"matcher_backend": {"backend": "cython"}}),
        ("admission.json", {"status": "qualified"}),
    ):
        _write(admission / name, value)
    bundle = {
        "target": {
            "slug": "reference-v4",
            "project": REFERENCE_PROJECT,
            "nodeid": REFERENCE_NODE,
        },
        "checked_sources": {
            "samples/bins/libobfuscated.dll": REFERENCE_PE_SHA256,
            f"src/d810/conf/{REFERENCE_PROJECT}": "b" * 64,
            "tests/system/e2e/test_libdeobfuscated_dsl.py": "c" * 64,
        },
        "expected_decompile_sha256": [COMMON_OUTPUT, LEGACY_OUTPUT],
        "runtime_image": "sha256:" + "d" * 64,
        "runtime_image_id": "sha256:" + "d" * 64,
        "toolchain": {"matcher_backend": {"backend": "cython"}},
    }
    return bundle, proof, admission


def test_exact_output_policy_is_bound_to_reviewed_proof_target_fixture_and_admission(
    tmp_path, monkeypatch
):
    module = load_controller()
    bundle, proof, admission = _exact_policy_inputs(module, tmp_path, monkeypatch)

    policy = module.build_exact_output_policy(bundle, proof, admission)

    assert policy["target"] == bundle["target"]
    assert policy["fixture_sha256"] == REFERENCE_PE_SHA256
    assert policy["outputs"] == {
        "legacy": [COMMON_OUTPUT, LEGACY_OUTPUT],
        "canonical": [COMMON_OUTPUT, CANONICAL_OUTPUT],
    }
    assert policy["proof_receipt_sha256"] == _digest(proof)
    assert policy["proof_claim"] == _exact_proof_receipt()["claim"]
    assert policy["proof_limitations"] == _exact_proof_receipt()["limitations"]
    assert len(policy["proof_limitations"]) == 4
    assert policy["admission_bindings"]["certificate_sha256"] == _digest(
        admission / "certificate.json"
    )

    changed = deepcopy(bundle)
    changed["checked_sources"]["samples/bins/libobfuscated.dll"] = "f" * 64
    with pytest.raises(ValueError, match="fixture"):
        module.build_exact_output_policy(changed, proof, admission)
    changed = deepcopy(bundle)
    changed["target"]["nodeid"] = "other::node"
    with pytest.raises(ValueError, match="target"):
        module.build_exact_output_policy(changed, proof, admission)
    changed = deepcopy(bundle)
    changed["expected_decompile_sha256"][1] = "f" * 64
    with pytest.raises(ValueError, match="legacy output"):
        module.build_exact_output_policy(changed, proof, admission)
    _mutate_json(proof, lambda value: value.update(status="failed"))
    monkeypatch.setattr(module, "REFERENCE_OUTPUT_PROOF_SHA256", _digest(proof))
    with pytest.raises(ValueError, match="proof"):
        module.build_exact_output_policy(bundle, proof, admission)


def test_output_policy_selects_exact_mode_tuple_and_absence_stays_strict(
    tmp_path, monkeypatch
):
    module = load_controller()
    bundle, proof, admission = _exact_policy_inputs(module, tmp_path, monkeypatch)
    policy = module.build_exact_output_policy(bundle, proof, admission)
    strict = {"target": {"expected_decompile_sha256": ["1" * 64, "2" * 64]}}

    assert module.expected_output_hashes(strict, "legacy") == ["1" * 64, "2" * 64]
    assert module.expected_output_hashes(strict, "canonical") == ["1" * 64, "2" * 64]
    admitted = {
        "target": {"expected_decompile_sha256": [COMMON_OUTPUT, LEGACY_OUTPUT]},
        "output_policy": policy,
    }
    assert module.expected_output_hashes(admitted, "legacy") == policy["outputs"]["legacy"]
    assert (
        module.expected_output_hashes(admitted, "canonical")
        == policy["outputs"]["canonical"]
    )
    with pytest.raises(ValueError, match="mode"):
        module.expected_output_hashes(admitted, "shadow")


def test_output_policy_copy_and_reload_are_digest_and_admission_bound(
    tmp_path, monkeypatch
):
    module = load_controller()
    bundle, proof, admission = _exact_policy_inputs(module, tmp_path, monkeypatch)

    reference = module.store_exact_output_policy(bundle, proof, admission)
    loaded = module.load_exact_output_policy(reference, bundle, admission)

    assert loaded["outputs"]["canonical"] == [COMMON_OUTPUT, CANONICAL_OUTPUT]
    assert reference == {
        "policy": "output-policy.json",
        "policy_sha256": _digest(admission / "output-policy.json"),
        "proof": "output-proof.json",
        "proof_sha256": _digest(admission / "output-proof.json"),
    }
    changed = deepcopy(reference)
    changed["policy_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="digest"):
        module.load_exact_output_policy(changed, bundle, admission)
    changed_bundle = deepcopy(bundle)
    changed_bundle["checked_sources"][
        "tests/system/e2e/test_libdeobfuscated_dsl.py"
    ] = "f" * 64
    with pytest.raises(ValueError, match="policy"):
        module.load_exact_output_policy(reference, changed_bundle, admission)
    original_certificate = (admission / "certificate.json").read_bytes()
    _write(admission / "certificate.json", {"changed": True})
    with pytest.raises(ValueError, match="policy"):
        module.load_exact_output_policy(reference, bundle, admission)
    (admission / "certificate.json").write_bytes(original_certificate)
    original_proof = (admission / "output-proof.json").read_bytes()
    _write(admission / "output-proof.json", {"changed": True})
    changed = deepcopy(reference)
    changed["proof_sha256"] = _digest(admission / "output-proof.json")
    with pytest.raises(ValueError, match="proof"):
        module.load_exact_output_policy(changed, bundle, admission)
    (admission / "output-proof.json").write_bytes(original_proof)
    _mutate_json(
        admission / "output-policy.json",
        lambda value: value["outputs"]["canonical"].__setitem__(1, "f" * 64),
    )
    changed = deepcopy(reference)
    changed["policy_sha256"] = _digest(admission / "output-policy.json")
    with pytest.raises(ValueError, match="policy"):
        module.load_exact_output_policy(changed, bundle, admission)


def test_policy_absence_rejects_unreferenced_policy_artifacts(tmp_path):
    module = load_controller()
    admission = tmp_path / "admission"
    admission.mkdir()
    _write(admission / "output-policy.json", {})

    with pytest.raises(ValueError, match="unreferenced"):
        module.load_exact_output_policy(None, {}, admission)


def test_output_equivalence_proof_cli_is_admission_only(tmp_path, monkeypatch):
    module = load_controller()
    target = SimpleNamespace(nodeid="node", project="project", slug="reference-v4")
    monkeypatch.setitem(module.TARGETS, "reference-v4", target)
    seen = []
    monkeypatch.setattr(
        module,
        "import_shadow_bundle",
        lambda run, *, target, root: {"run": run, "target": target, "root": root},
    )
    monkeypatch.setattr(
        module,
        "admit_shadow_bundle",
        lambda bundle, output, *, output_equivalence_proof: seen.append(
            (bundle, output, output_equivalence_proof)
        ),
    )
    proof = tmp_path / "proof.json"
    shadow = tmp_path / "shadow"
    output = tmp_path / "output"
    module.main(
        [
            "--admit-only",
            "--target",
            "reference-v4",
            "--output-dir",
            str(output),
            "--shadow-run-dir",
            str(shadow),
            "--output-equivalence-proof",
            str(proof),
        ]
    )
    assert seen[0][2] == proof

    with pytest.raises(ValueError, match="admit-only"):
        module.main(
            [
                "--activation-only",
                "--target",
                "reference-v4",
                "--output-dir",
                str(tmp_path / "activation"),
                "--admission-dir",
                str(tmp_path / "admission"),
                "--output-equivalence-proof",
                str(proof),
            ]
        )


def _timing_receipts_for_exact_policy(module, policy):
    receipts = []
    for mode, values in (
        ("legacy", ("5", "4", "6")),
        ("canonical", ("3", "2", "4")),
        ("legacy", ("5.5", "4.5", "6.5")),
    ):
        for value in values:
            active = mode == "canonical"
            item = {
                "mode": mode,
                "segment_id": "dac",
                "exit": 0,
                "passed": 1,
                "skipped": 0,
                "project": "generated.json",
                "expected_project": "generated.json",
                "process_seconds": value,
                "decompiles": [
                    {"seconds": "1", "sha256": digest}
                    for digest in policy["outputs"][mode]
                ],
                "expected_decompile_sha256": list(policy["outputs"][mode]),
                "toolchain": {"matcher_backend": {"backend": "cython"}},
                "snapshot": {"fingerprint": "a" * 64},
                "live_snapshot": {"fingerprint": "a" * 64} if active else None,
                "live_ledger": {} if active else None,
                "enrollment": {
                    "selected_rule_count": 1,
                    "canonical_eligible_rule_count": 1,
                    "legacy_only_rule_count": 0,
                },
                "adapters": [
                    {
                        "rule_id": 1,
                        "name": "eligible",
                        "canonical_eligible": True,
                        "canonical_fallback_enabled": active,
                        "uses_structural_matching": active,
                    }
                ],
                "metrics": {
                    "canonical_call_count": 1,
                    "enrolled_transformation_count": 1,
                },
            }
            receipts.append(item)
    return receipts


def test_timing_outcome_reports_both_actual_tuples_without_normalizing(
    tmp_path, monkeypatch
):
    module = load_controller()
    bundle, proof, admission = _exact_policy_inputs(module, tmp_path, monkeypatch)
    policy = module.build_exact_output_policy(bundle, proof, admission)
    receipts = _timing_receipts_for_exact_policy(module, policy)

    outcome = module.timing_outcome(receipts, output_policy=policy)

    assert outcome["status"] == "passed"
    assert outcome["comparison"]["actual_output_sha256_by_mode"] == policy["outputs"]
    changed = deepcopy(receipts)
    changed[4]["decompiles"][1]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="output"):
        module.timing_outcome(changed, output_policy=policy)
