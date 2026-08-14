"""Contract for the independently-authored compiler-shaped MBA corpus."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[3]
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_SAMPLE = _ROOT / "samples/src/c/mba_compiler_shapes.c"

_EXPECTED_STRATA = {
    "chain": 8,
    "catalogue": 10,
    "reassociation": 8,
    "degree2": 10,
    "coefficient": 10,
    "nonlinear": 8,
    "unsafe": 10,
    "matcher_refusal": 6,
}


def _llvm_definition(ir: str, function_name: str) -> str:
    match = re.search(
        rf"^define [^\n{{]* @{re.escape(function_name)}\([^\n]*\) #[0-9]+ \{{\n.*?^\}}",
        ir,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"missing LLVM definition for {function_name}"
    return match.group(0)


def _cases() -> list[dict[str, object]]:
    payload = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["fixture_kind"] == "post_lowering_semantic_shapes"
    assert payload["authorship"] == "independently_authored"
    return payload["cases"]


def _payload() -> dict[str, object]:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def test_manifest_has_the_planned_independently_authored_strata() -> None:
    cases = _cases()

    assert len(cases) == 70
    assert Counter(case["stratum"] for case in cases) == _EXPECTED_STRATA
    assert {case["width"] for case in cases} == {8, 16, 32, 64}
    assert all(case["authorship"] == "independently_authored" for case in cases)


def test_manifest_declares_the_complete_native_provider_matrix() -> None:
    assert _payload()["provider_matrix"] == [
        "structural_chain",
        "catalogue",
        "egglog",
        "coefficient_solver",
    ]


def test_manifest_declares_a_pinned_lowering_shape_contract() -> None:
    contract = _payload()["lowering_contract"]
    assert contract["compiler"] == "clang"
    assert contract["flags"] == [
        "-S",
        "-emit-llvm",
        "-O0",
        "-fno-inline",
        "-fno-builtin",
        "-fno-vectorize",
        "-fno-slp-vectorize",
        "-fno-omit-frame-pointer",
        "-I samples/include",
    ]
    assert contract["provider_eligible_strata"] == [
        "catalogue",
        "reassociation",
        "degree2",
        "coefficient",
    ]
    assert contract["forbidden_ir_instructions"] == ["zext", "sext", "trunc"]


def test_manifest_has_unique_exported_ground_truth_pairs_without_host_paths() -> None:
    cases = _cases()
    case_ids = [case["case_id"] for case in cases]
    functions = [case["function"] for case in cases]
    truths = [case["ground_truth_function"] for case in cases]

    assert len(case_ids) == len(set(case_ids))
    assert len(functions) == len(set(functions))
    assert len(truths) == len(set(truths))
    assert all(name.startswith("mba_shape_") for name in functions)
    assert all(name.startswith("mba_truth_") for name in truths)
    assert all(
        not Path(value).is_absolute()
        for case in cases
        for value in case.values()
        if isinstance(value, str)
    )


def test_cases_declare_routes_degree_and_stable_refusal_semantics() -> None:
    cases = _cases()
    expected_unsafe_blockers = {
        "unsafe_01": "cast",
        "unsafe_02": "cast",
        "unsafe_03": "cast",
        "unsafe_04": "cast",
        "unsafe_05": "load",
        "unsafe_06": "load",
        "unsafe_07": "call",
        "unsafe_08": "call",
        "unsafe_09": "ambiguous_shift",
        "unsafe_10": "ambiguous_shift",
    }
    for case in cases:
        assert "refusal" not in case["expected_route"]
        assert isinstance(case["semantic_seed"], int)
        if case["stratum"] == "degree2":
            assert case["expected_minimum_degree"] == 2
            assert "egglog" in case["expected_route"]
        if case["stratum"] == "coefficient":
            assert case["expected_route"] == ["coefficient_solver"]
        if case["stratum"] == "nonlinear":
            assert case["expected_route"] == []
            assert case["expected_omission_reason"] == "nonlinear_solver_disabled"
        if case["stratum"] == "unsafe":
            assert case["expected_route"] == []
            assert case["expected_blocker"] == expected_unsafe_blockers[case["case_id"]]
        if case["stratum"] == "matcher_refusal":
            assert case["expected_route"] == []
            assert case["coverage_status"] == "pending_shadow_matcher"
            assert case["expected_shadow_stop_reason"] in {
                "cardinality_mismatch",
                "ambiguous_group_capture",
                "comparison_budget",
                "unsupported_heterogeneous_chain",
            }


def test_every_manifest_pair_is_an_export_in_the_compiler_shape_sample() -> None:
    source = _SAMPLE.read_text(encoding="utf-8")
    assert "#define DEFINE_PAIR" in source
    assert "EXPORT T SHAPE" in source
    assert "EXPORT T TRUTH" in source
    for case in _cases():
        assert case["function"] in source
        assert case["ground_truth_function"] in source


def test_coefficient_shapes_are_mixed_mba_residuals_with_shorter_truths() -> None:
    """Coefficient routing must not be benchmarked on ordinary arithmetic."""

    source = _SAMPLE.read_text(encoding="utf-8")
    for case in (case for case in _cases() if case["stratum"] == "coefficient"):
        match = re.search(
            rf"^DEFINE_PAIR\([^\n]*{re.escape(str(case['function']))}[^\n]*\)$",
            source,
            flags=re.MULTILINE,
        )
        assert match is not None, case["case_id"]
        line = match.group(0)
        assert any(operator in line for operator in (" ^ ", " & ", " | ")), line
        assert any(operator in line for operator in (" + ", " - ", " * ")), line
        shape_expression, truth_expression = line.rsplit(",", 2)[-2:]
        assert len(shape_expression) > len(truth_expression.rstrip(")")), line


def test_lowering_contract_includes_mixed_coefficient_mba_residuals() -> None:
    contract = _payload()["lowering_contract"]
    assert "coefficient" in contract["provider_eligible_strata"]


def test_pending_shadow_matcher_shapes_are_not_simplification_proxies() -> None:
    """Shadow labels describe future matching work, not current rewrites."""

    source = _SAMPLE.read_text(encoding="utf-8")
    for case in (case for case in _cases() if case["stratum"] == "matcher_refusal"):
        match = re.search(
            rf"^DEFINE_PAIR\([^\n]*{re.escape(str(case['function']))}[^\n]*\)$",
            source,
            flags=re.MULTILINE,
        )
        assert match is not None, case["case_id"]
        _prefix, shape_expression, truth_expression = match.group(0).rsplit(",", 2)
        assert shape_expression.strip() == truth_expression.strip()[:-1], case["case_id"]


def test_provider_eligible_shapes_have_homogeneous_lowered_llvm_ir(
    tmp_path: Path,
) -> None:
    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("compiler-shape LLVM contract requires clang")
    contract = _payload()["lowering_contract"]
    ir_path = tmp_path / "mba_compiler_shapes.ll"
    subprocess.run(
        [
            compiler,
            "-S",
            "-emit-llvm",
            "-O0",
            "-fno-inline",
            "-fno-builtin",
            "-fno-vectorize",
            "-fno-slp-vectorize",
            "-fno-omit-frame-pointer",
            "-I",
            str(_ROOT / "samples/include"),
            "-o",
            str(ir_path),
            str(_SAMPLE),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    compiler_version = subprocess.run(
        [compiler, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]
    print(
        "MBA_COMPILER_SHAPE_LOWERING_EVIDENCE="
        + json.dumps(
            {
                "compiler": compiler,
                "version": compiler_version,
                "flags": contract["flags"],
            },
            sort_keys=True,
        )
    )
    ir = ir_path.read_text(encoding="utf-8")
    eligible_strata = set(contract["provider_eligible_strata"])
    forbidden = tuple(contract["forbidden_ir_instructions"])
    for case in _cases():
        if case["stratum"] not in eligible_strata:
            continue
        definition = _llvm_definition(ir, str(case["function"]))
        assert not any(f" {instruction} " in definition for instruction in forbidden), (
            case["case_id"],
            definition,
        )
