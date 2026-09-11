"""Portable contracts for the bounded native DAC activation harness."""
import importlib.util
from copy import deepcopy
from decimal import Decimal
from pathlib import Path

import pytest


def helpers():
    path = Path(__file__).resolve().parents[2] / "tools/bench/canonical_dac_measurement.py"
    assert path.exists(), "measurement harness not implemented"
    spec = importlib.util.spec_from_file_location("canonical_dac_measurement", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CERTIFICATE = {
    "schema_version": 3,
    "snapshot_fingerprint": "a" * 64,
    "runtime_mode": "cython",
    "corpus_digest": "b" * 64,
    "toolchain_digest": "c" * 64,
    "runtime_semantics_digest": "d" * 64,
    "legacy_observation_count": 2,
    "observation_count": 146,
}


def test_activation_config_uses_independent_expectation_and_preserves_profile():
    base = {"description": "real profile", "additional_configuration": {"pipeline_v2": [1]}}
    expectation = {key: CERTIFICATE[key] for key in (
        "corpus_digest", "toolchain_digest", "runtime_semantics_digest",
        "legacy_observation_count", "observation_count")}
    result = helpers().build_activation_config(base, "evidence/certificate.json", expectation)
    assert result == {"description": "real profile", "additional_configuration": {
        "pipeline_v2": [1],
        "structural_matcher_parity_certificate": "evidence/certificate.json",
        "structural_matcher_parity_expectation": expectation,
    }}
    assert base == {"description": "real profile", "additional_configuration": {"pipeline_v2": [1]}}


def test_expectation_is_derived_from_manifest_and_toolchain_not_certificate_counts():
    corpus_digest = "b" * 64
    toolchain = {"matcher_backend": {"backend": "cython"}, "ida_sdk": 940}
    certificate = dict(CERTIFICATE, corpus_digest=corpus_digest,
                       toolchain_digest=helpers().canonical_digest(toolchain))
    evidence = {"snapshot": {"runtime_semantics_digest": "d" * 64},
                "ledger": {"legacy_match_count": 2, "observation_count": 146}}
    expectation = helpers().derive_expectation(corpus_digest, toolchain, evidence, certificate)
    assert expectation == {
        "corpus_digest": corpus_digest,
        "toolchain_digest": helpers().canonical_digest(toolchain),
        "runtime_semantics_digest": "d" * 64,
        "legacy_observation_count": 2,
        "observation_count": 146,
    }
    bad = dict(certificate, corpus_digest="e" * 64)
    with pytest.raises(ValueError, match="corpus"):
        helpers().derive_expectation(corpus_digest, toolchain, evidence, bad)
    lied = dict(certificate, observation_count=147)
    with pytest.raises(ValueError, match="certificate"):
        helpers().derive_expectation(corpus_digest, toolchain, evidence, lied)


def receipt(*, mode="canonical", seconds="4.25", active=True, segment="dac"):
    adapters = [
        {"rule_id": 0, "name": "eligible", "canonical_eligible": True,
         "canonical_fallback_enabled": active, "uses_structural_matching": active,
         "candidate_count": 1},
        {"rule_id": 1, "name": "legacy", "canonical_eligible": False,
         "canonical_fallback_enabled": False, "uses_structural_matching": False,
         "candidate_count": 4},
    ]
    return {
        "mode": mode, "segment_id": segment, "exit": 0, "passed": 1, "skipped": 0,
        "project": "generated-activation-123.json", "expected_project": "generated-activation-123.json",
        "process_seconds": seconds,
        "decompiles": [{"seconds": "1.0", "sha256": "1" * 64},
                       {"seconds": "2.0", "sha256": "2" * 64}],
        "toolchain": {"matcher_backend": {"backend": "cython"}, "ida_sdk": 940},
        "snapshot": {"fingerprint": "a" * 64},
        "live_snapshot": ({"fingerprint": "a" * 64} if mode == "canonical" else None),
        "live_ledger": ({} if mode == "canonical" else None),
        "enrollment": {"selected_rule_count": 2, "canonical_eligible_rule_count": 1,
                       "legacy_only_rule_count": 1},
        "adapters": adapters,
        "metrics": {"registration_seconds": None, "candidate_count": 5,
                    "canonical_match_count": None, "canonical_call_count": 1,
                    "enrolled_transformation_count": 1, "fallback_count": None},
        "expected_decompile_sha256": ["1" * 64, "2" * 64],
    }


def test_canonical_receipt_requires_fresh_active_backend_and_exact_project():
    helpers().validate_measurement_receipt(receipt())
    for mutation, message in [
        (("exit", 1), "pass"), (("skipped", 1), "pass"),
        (("project", "bundled.json"), "project"),
        (("toolchain", {"matcher_backend": {"backend": "python"}}), "Cython"),
    ]:
        broken = receipt()
        broken[mutation[0]] = mutation[1]
        with pytest.raises(ValueError, match=message):
            helpers().validate_measurement_receipt(broken)
    broken = receipt()
    broken["adapters"][0]["canonical_fallback_enabled"] = False
    with pytest.raises(ValueError, match="active"):
        helpers().validate_measurement_receipt(broken)


def test_positive_activation_requires_observed_canonical_matcher_work():
    positive = receipt(segment="positive-xor")
    helpers().validate_measurement_receipt(positive)
    positive["metrics"]["enrolled_transformation_count"] = 0
    with pytest.raises(ValueError, match="exercise"):
        helpers().validate_measurement_receipt(positive)


def test_only_known_positive_hash_pair_may_differ_from_retained_output():
    module = helpers()
    expected = [module.POSITIVE_XOR_BEFORE_SHA256, module.POSITIVE_XOR_RETAINED_SHA256]
    alternative = [module.POSITIVE_XOR_BEFORE_SHA256, module.POSITIVE_XOR_ALTERNATIVE_SHA256]
    module.validate_segment_hashes("positive-xor", expected, alternative)
    with pytest.raises(ValueError, match="output"):
        module.validate_segment_hashes("dac", expected, alternative)
    changed = list(alternative)
    changed[0] = "f" * 64
    with pytest.raises(ValueError, match="output"):
        module.validate_segment_hashes("positive-xor", expected, changed)


def test_legacy_receipt_rejects_any_canonical_activation():
    legacy = receipt(mode="legacy", active=False)
    helpers().validate_measurement_receipt(legacy)
    legacy["adapters"][0]["uses_structural_matching"] = True
    with pytest.raises(ValueError, match="legacy"):
        helpers().validate_measurement_receipt(legacy)
    legacy = receipt(mode="legacy", active=False)
    legacy["live_snapshot"] = {"fingerprint": "a" * 64}
    with pytest.raises(ValueError, match="snapshot"):
        helpers().validate_measurement_receipt(legacy)


@pytest.mark.parametrize("field,value", [
    ("process_seconds", None), ("process_seconds", "NaN"), ("process_seconds", "0"),
])
def test_missing_or_nonfinite_timing_is_invalid(field, value):
    item = receipt()
    item[field] = value
    with pytest.raises(ValueError, match="timing"):
        helpers().validate_measurement_receipt(item)


def test_matched_comparison_needs_three_dac_repetitions_per_arm_and_unchanged_partition():
    runs = []
    for mode, values in (("legacy", ("5", "4", "6")),
                         ("canonical", ("3", "2", "4")),
                         ("legacy", ("5.5", "4.5", "6.5"))):
        runs.extend(receipt(mode=mode, seconds=value, active=mode == "canonical") for value in values)
    result = helpers().compare_matched_runs(runs)
    assert result["sequence"] == ["legacy", "canonical", "legacy"]
    assert result["legacy_median_seconds"] == "5.25"
    assert result["canonical_median_seconds"] == "3"
    assert result["legacy_before_median_seconds"] == "5"
    assert result["legacy_after_median_seconds"] == "5.5"
    assert result["canonical_over_legacy"] == str(Decimal("3") / Decimal("5.25"))
    assert result["timing_win"] is True
    with pytest.raises(ValueError, match="three"):
        helpers().compare_matched_runs(runs[:-1])
    changed = deepcopy(runs)
    changed[4]["enrollment"]["legacy_only_rule_count"] = 0
    with pytest.raises(ValueError, match="partition"):
        helpers().compare_matched_runs(changed)
    changed = deepcopy(runs)
    changed[4]["decompiles"][1]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="output"):
        helpers().compare_matched_runs(changed)


def test_matched_comparison_accepts_only_declared_per_mode_exact_output_tuples():
    module = helpers()
    legacy_hashes = ["1" * 64, "2" * 64]
    canonical_hashes = ["1" * 64, "3" * 64]
    expected_by_mode = {
        "legacy": legacy_hashes,
        "canonical": canonical_hashes,
    }
    runs = []
    for mode, values in (
        ("legacy", ("5", "4", "6")),
        ("canonical", ("3", "2", "4")),
        ("legacy", ("5.5", "4.5", "6.5")),
    ):
        for value in values:
            item = receipt(mode=mode, seconds=value, active=mode == "canonical")
            hashes = expected_by_mode[mode]
            item["expected_decompile_sha256"] = list(hashes)
            item["decompiles"] = [
                {"seconds": "1.0", "sha256": output_hash}
                for output_hash in hashes
            ]
            runs.append(item)

    with pytest.raises(ValueError, match="output"):
        module.compare_matched_runs(runs)
    result = module.compare_matched_runs(
        runs,
        expected_outputs_by_mode=expected_by_mode,
    )
    assert result["actual_output_sha256_by_mode"] == expected_by_mode

    changed_actual = deepcopy(runs)
    changed_actual[4]["decompiles"][1]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="output"):
        module.compare_matched_runs(
            changed_actual,
            expected_outputs_by_mode=expected_by_mode,
        )
    changed_declared = deepcopy(runs)
    changed_declared[4]["expected_decompile_sha256"][1] = "f" * 64
    with pytest.raises(ValueError, match="output"):
        module.compare_matched_runs(
            changed_declared,
            expected_outputs_by_mode=expected_by_mode,
        )
    with pytest.raises(ValueError, match="legacy.*canonical"):
        module.compare_matched_runs(
            runs,
            expected_outputs_by_mode={"legacy": legacy_hashes},
        )


def test_each_child_gets_distinct_native_log_dir_and_options_restore_on_failure(tmp_path):
    options = tmp_path / "cfg" / "options.json"
    options.parent.mkdir()
    original = b'{"log_dir":"original","other":7}\n'
    options.write_bytes(original)
    seen = []
    for child in (tmp_path / "native" / "child-0", tmp_path / "native" / "child-1"):
        child.mkdir(parents=True)
        with pytest.raises(RuntimeError, match="child failed"):
            with helpers().child_options_log_dir(options, child) as resolved:
                seen.append(resolved)
                assert Path(__import__('json').loads(options.read_text())["log_dir"]) == child.resolve()
                raise RuntimeError("child failed")
        assert options.read_bytes() == original
    assert seen == [str((tmp_path / "native" / "child-0").resolve()),
                    str((tmp_path / "native" / "child-1").resolve())]


def test_normalization_distinguishes_configured_root_from_live_d810_suffix(tmp_path):
    base = receipt()
    configured = str((tmp_path / "child").resolve())
    live = str((tmp_path / "child" / "d810_logs").resolve())
    raw = {key: deepcopy(base[key]) for key in (
        "exit", "passed", "skipped", "project", "expected_project",
        "decompiles", "toolchain")}
    raw["activation_calls"] = []
    raw["records"] = [{"project": base["project"], "snapshot": base["snapshot"],
        "ledger": {}, "enrollment": base["enrollment"],
        "adapters": deepcopy(base["adapters"]),
        "runtime_paths": {"state_log_dir": live}}]
    process = {"segment_id": "dac", "exit": 0, "process_seconds": "4.25",
               "paths": {"configured_child_root": configured,
                         "expected_state_log_dir": live}}
    result = helpers()._normalize_receipt(raw, process, mode="canonical",
        expected_adapters=deepcopy(base["adapters"]),
        enrollment=base["enrollment"], snapshot=base["snapshot"],
        expected_hashes=base["expected_decompile_sha256"])
    assert result["runtime_paths"]["state_log_dir"] == live
    raw["records"][0]["runtime_paths"]["state_log_dir"] = configured
    with pytest.raises(ValueError, match="child-native"):
        helpers()._normalize_receipt(raw, process, mode="canonical",
            expected_adapters=deepcopy(base["adapters"]),
            enrollment=base["enrollment"], snapshot=base["snapshot"],
            expected_hashes=base["expected_decompile_sha256"])


def test_profile_mode_is_two_dac_legs_and_never_a_matched_timing_sequence():
    module = helpers()
    assert module.run_sequence(activation_only=False, profile_only=True, repetitions=9) == [
        ("legacy", "dac", 1), ("canonical", "dac", 1)]
    assert module.run_sequence(activation_only=True, profile_only=False, repetitions=3) == [
        ("canonical", "dac", 1), ("canonical", "positive-xor", 1)]
    with pytest.raises(ValueError, match="exclusive"):
        module.run_sequence(activation_only=True, profile_only=True, repetitions=3)


def test_profile_child_command_wraps_whole_pytest_and_normal_command_is_unchanged(tmp_path):
    module = helpers()
    node = "tests/system/example.py::test_case"
    normal = module.pytest_command("/python", node)
    assert normal[:4] == ["/python", "-u", "-m", "pytest"]
    assert "cProfile" not in normal
    profile = module.pytest_command("/python", node, profile_path=tmp_path / "leg.prof")
    assert profile[:7] == ["/python", "-u", "-m", "cProfile", "-o",
                           str(tmp_path / "leg.prof"), "-m"]
    assert profile[7] == "pytest"


def test_profile_render_saves_separate_self_and_cumulative_views(tmp_path):
    import cProfile
    module = helpers()
    path = tmp_path / "leg.prof"
    profiler = cProfile.Profile()
    profiler.runcall(sum, [1, 2, 3])
    profiler.dump_stats(path)
    metrics = module.render_profile(path)
    assert metrics["whole_child_profile"] == "measured"
    assert metrics["registration_seconds"] == "missing"
    assert metrics["total_calls"] >= 1
    assert Path(metrics["views"]["self"]).exists()
    assert Path(metrics["views"]["cumulative"]).exists()


def test_invalid_mode_combination_creates_no_output_or_config(tmp_path):
    output = tmp_path / "must-not-exist"
    with pytest.raises(SystemExit):
        helpers().main(["--qualification-dir", str(tmp_path / "missing"),
                        "--output-dir", str(output),
                        "--activation-only", "--profile-only"])
    assert not output.exists()
