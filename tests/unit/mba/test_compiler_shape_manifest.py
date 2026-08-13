"""Contract for the independently-authored compiler-shaped MBA corpus."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


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


def _cases() -> list[dict[str, object]]:
    payload = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["fixture_kind"] == "post_lowering_semantic_shapes"
    assert payload["authorship"] == "independently_authored"
    return payload["cases"]


def test_manifest_has_the_planned_independently_authored_strata() -> None:
    cases = _cases()

    assert len(cases) == 70
    assert Counter(case["stratum"] for case in cases) == _EXPECTED_STRATA
    assert {case["width"] for case in cases} == {8, 16, 32, 64}
    assert all(case["authorship"] == "independently_authored" for case in cases)


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
    for case in cases:
        assert case["expected_route"]
        assert isinstance(case["semantic_seed"], int)
        if case["stratum"] == "degree2":
            assert case["expected_minimum_degree"] == 2
            assert "egglog" in case["expected_route"]
        if case["stratum"] == "matcher_refusal":
            assert case["expected_stop_reason"] in {
                "cardinality_mismatch",
                "ambiguous_group_capture",
                "comparison_budget",
                "unsupported_heterogeneous_chain",
            }
            assert "egglog" not in case["expected_route"]
            assert "catalogue" not in case["expected_route"]


def test_every_manifest_pair_is_an_export_in_the_compiler_shape_sample() -> None:
    source = _SAMPLE.read_text(encoding="utf-8")
    assert "#define DEFINE_PAIR" in source
    assert "EXPORT T SHAPE" in source
    assert "EXPORT T TRUTH" in source
    for case in _cases():
        assert case["function"] in source
        assert case["ground_truth_function"] in source
