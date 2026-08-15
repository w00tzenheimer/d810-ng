"""Diagnostic performance receipt for the certified Egglog MBA path."""

from __future__ import annotations

import json
from importlib.metadata import version
import os
import statistics
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba import egglog_add_rule_compiler as catalogue_compiler  # noqa: E402
from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    compiled_rules_for_families,
)
from d810.backends.mba.egglog_saturation import (  # noqa: E402
    EgglogExtractionReceipt,
    ExtractionSkipReason,
)
from d810.backends.mba.hexrays_island import lower_hexrays_island  # noqa: E402
from d810.backends.mba.native_mba_term_view import (  # noqa: E402
    NativeMbaTermView,
    NativeMbaViewResult,
)
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.dsl import SymbolicExpressionProtocol  # noqa: E402
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (  # noqa: E402
    EgglogOptimizer,
)


_CLOSED_FAMILIES = ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")
_BASELINE_PATH = Path(__file__).with_name("egglog_mba_performance_baseline.json")
_CANDIDATE_CORPUS = (
    ("add", "Add_HackersDelightRule_2"),
    ("add", "Add_HackersDelightRule_3"),
    ("add", "Add_OllvmRule_1"),
    ("xor", "Xor_HackersDelightRule_3"),
    ("sub", "Sub_HackersDelightRule_2"),
)
_REPETITIONS = 4
_PIPELINE_STAGE_ORDER = (
    "root_eligibility",
    "native_preflight",
    "egglog_extraction",
    "ast_construction",
    "native_z3",
    "reconstruction",
)
_SYNTHETIC_STAGE_PROFILE_NOTE = (
    "injected active AST plus real handler/extraction/native-Z3; "
    "native_preflight and ast_construction use that injected AST and "
    "reconstruction uses a test materializer"
)


def test_synthetic_stage_profile_note_names_both_mocked_boundaries() -> None:
    assert "ast_construction" in _SYNTHETIC_STAGE_PROFILE_NOTE
    assert "native_preflight" in _SYNTHETIC_STAGE_PROFILE_NOTE
    assert "injected active AST" in _SYNTHETIC_STAGE_PROFILE_NOTE
    assert "reconstruction" in _SYNTHETIC_STAGE_PROFILE_NOTE
    assert "test materializer" in _SYNTHETIC_STAGE_PROFILE_NOTE


_CAP_SKIP_REASONS = frozenset(
    {
        ExtractionSkipReason.CANDIDATE_BUDGET.value,
        ExtractionSkipReason.TIME_BUDGET.value,
        ExtractionSkipReason.ECLASS_BUDGET.value,
        ExtractionSkipReason.ENODE_BUDGET.value,
        ExtractionSkipReason.RULE_FIRING_BUDGET.value,
    }
)
_OPCODE_BY_OPERATION = {
    "add": ida_hexrays.m_add,
    "and": ida_hexrays.m_and,
    "bnot": ida_hexrays.m_bnot,
    "mul": ida_hexrays.m_mul,
    "neg": ida_hexrays.m_neg,
    "or": ida_hexrays.m_or,
    "sub": ida_hexrays.m_sub,
    "xor": ida_hexrays.m_xor,
}


def _candidate_from_pattern(expression: SymbolicExpressionProtocol):
    """Materialize through the active AST dispatcher in both Cython modes."""

    leaves: dict[str, object] = {}

    def materialize(item: SymbolicExpressionProtocol):
        if item.operation is None:
            if item.value is not None:
                constant = ast_dispatcher.AstConstant(str(item.value), item.value, 4)
                constant.mop = MopSnapshot(
                    t=ida_hexrays.mop_n,
                    size=4,
                    value=item.value,
                )
                constant.dest_size = 4
                return constant
            assert item.name is not None
            leaf = leaves.get(item.name)
            if leaf is None:
                leaf = ast_dispatcher.AstLeaf(item.name)
                leaf.mop = MopSnapshot(
                    t=ida_hexrays.mop_r,
                    size=4,
                    reg=len(leaves) + 1,
                )
                leaf.dest_size = 4
                leaves[item.name] = leaf
            return leaf.clone()

        assert item.left is not None
        node = ast_dispatcher.AstNode(
            _OPCODE_BY_OPERATION[item.operation],
            materialize(item.left),
            materialize(item.right) if item.right is not None else None,
        )
        node.dest_size = 4
        return node

    return materialize(expression)


def _native_view_from_typed_term(term):
    if term.operation is None:
        if term.value is not None:
            return NativeMbaTermView(None, term.width, constant_value=term.value)
        return NativeMbaTermView(None, term.width, leaf_key=term.leaf_key)
    return NativeMbaTermView(
        term.operation,
        term.width,
        children=tuple(_native_view_from_typed_term(child) for child in term.children),
    )


def _stage_native_view(candidate, destination_size: int) -> NativeMbaViewResult:
    lowering = lower_hexrays_island(candidate, destination_size=destination_size)
    return NativeMbaViewResult(
        view=(
            None
            if lowering.term is None
            else _native_view_from_typed_term(lowering.term)
        ),
        profile=lowering.profile,
    )


def _stage_profile_handler() -> EgglogOptimizer:
    """Build the explicitly non-production handler used by the profile corpus."""

    handler = EgglogOptimizer()
    handler.configure(
        {
            "families": list(_CLOSED_FAMILIES),
            # Pattern materialization clones repeated Python leaves. The live
            # micro-AST shares its identity, while this stage-only profile must
            # permit the conservative synthetic representation.
            "max_leaves": 8,
            "max_operator_nodes": 10,
            "max_degree": 1,
            "saturation_rounds": 2,
            "max_eclasses": 64,
            "max_enodes": 128,
            "max_rule_firings": 32,
            # This profile measures an admitted pipeline; production remains 3 ms.
            "time_budget_ms": 1000,
            "execution_mode": "noninteractive",
            "require_proof": True,
            "collect_stage_timings": True,
        }
    )
    return handler


def _percentile(values: tuple[float, ...], percentile: int) -> float:
    if not values:
        raise ValueError("candidate receipt corpus must not be empty")
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[percentile - 1]


def _build_receipt_report(
    candidate_names: tuple[str, ...],
    receipts: tuple[EgglogExtractionReceipt, ...],
) -> dict[str, object]:
    if len(candidate_names) != len(receipts):
        raise ValueError("candidate identity count must equal receipt count")
    elapsed = tuple(receipt.elapsed_ms for receipt in receipts)
    eclasses = [
        receipt.eclass_count for receipt in receipts if receipt.eclass_count is not None
    ]
    enodes = [
        receipt.enode_count for receipt in receipts if receipt.enode_count is not None
    ]
    degrees = Counter(
        "none" if receipt.degree is None else str(receipt.degree)
        for receipt in receipts
    )
    skips = Counter(
        "success" if receipt.skip_reason is None else receipt.skip_reason.value
        for receipt in receipts
    )
    cap_skips = {
        reason: count
        for reason, count in sorted(skips.items())
        if reason in _CAP_SKIP_REASONS
    }
    return {
        "candidate_names": list(candidate_names),
        "candidate_count": len(receipts),
        "candidate_elapsed_ms": list(elapsed),
        "p50_ms": _percentile(elapsed, 50),
        "p95_ms": _percentile(elapsed, 95),
        "eclass_counts": eclasses,
        "enode_counts": enodes,
        "degree_distribution": dict(sorted(degrees.items())),
        "skip_distribution": dict(sorted(skips.items())),
        "cap_skip_distribution": cap_skips,
        "cap_skip_count": sum(cap_skips.values()),
    }


def _build_stage_timing_report(
    timing_records: tuple[dict[str, float], ...],
) -> dict[str, dict[str, float | int]]:
    """Summarize one ordered stage-timing record per handler attempt."""

    if not timing_records:
        raise ValueError("stage timing records must not be empty")
    if not timing_records[0]:
        raise ValueError("stage timing records must contain stages")
    for record in timing_records:
        names = tuple(record)
        if names != _PIPELINE_STAGE_ORDER[: len(names)]:
            raise ValueError("stage timing records must be ordered pipeline prefixes")

    report: dict[str, dict[str, float | int]] = {}
    for name in _PIPELINE_STAGE_ORDER:
        samples = tuple(record[name] for record in timing_records if name in record)
        if not samples:
            continue
        if any(type(value) is not float or value < 0.0 for value in samples):
            raise ValueError("stage timing values must be non-negative floats")
        report[name] = {
            "sample_count": len(samples),
            "p50_ms": _percentile(samples, 50),
            "p95_ms": _percentile(samples, 95),
            "max_ms": max(samples),
        }
    return report


def _build_stage_attempt_outcome_report(
    receipts: tuple[EgglogExtractionReceipt, ...],
) -> dict[str, int]:
    """Count accepted and refused timed attempts without conflating them."""

    if not receipts:
        raise ValueError("stage attempt receipts must not be empty")
    return dict(
        sorted(
            Counter(
                "accepted" if receipt.skip_reason is None else receipt.skip_reason.value
                for receipt in receipts
            ).items()
        )
    )


def _measure_catalogue_selection(select, *, clock=time.perf_counter):
    """Measure the configured immutable selection once cold and once warm."""

    cold_started = clock()
    selected = select()
    cold_seconds = clock() - cold_started
    warm_started = clock()
    select()
    warm_seconds = clock() - warm_started
    return selected, {"cold_seconds": cold_seconds, "warm_seconds": warm_seconds}


def _measure_handler_configuration(handler, config, *, clock=time.perf_counter):
    """Measure configuration after the selected immutable catalogue is warm."""

    started = clock()
    handler.configure(config)
    return handler, clock() - started


def _assert_comparable_baseline(
    baseline: dict[str, object], report: dict[str, object]
) -> None:
    baseline_names = baseline.get("candidate_names")
    report_names = report.get("candidate_names")
    baseline_count = baseline.get("candidate_count")
    report_count = report.get("candidate_count")
    if not baseline_names or not report_names or not baseline_count or not report_count:
        pytest.skip("empty candidate corpus invalidates the performance comparison")
    if baseline_count != report_count:
        pytest.skip("candidate corpus count differs from the committed baseline")
    if baseline_names != report_names:
        pytest.skip("candidate corpus identity differs from the committed baseline")
    baseline_p95 = baseline.get("baseline_p95_ms")
    report_p95 = report.get("p95_ms")
    if not isinstance(baseline_p95, (int, float)) or baseline_p95 <= 0:
        pytest.skip("baseline p95 must be a positive number")
    if not isinstance(report_p95, (int, float)):
        pytest.skip("report p95 must be a number")
    assert report_p95 <= baseline_p95 * 100, (
        f"candidate p95 {report_p95:.6f} ms exceeds the comparable "
        f"baseline {baseline_p95:.6f} ms by more than 100x"
    )


def test_controlled_receipts_report_quantiles_distributions_and_skips() -> None:
    receipts = (
        EgglogExtractionReceipt(
            elapsed_ms=1.0,
            degree=1,
            eclass_count=10,
            enode_count=20,
        ),
        EgglogExtractionReceipt(
            elapsed_ms=2.0,
            degree=1,
            eclass_count=12,
            enode_count=24,
        ),
        EgglogExtractionReceipt(
            elapsed_ms=4.0,
            eclass_count=14,
            enode_count=28,
            skip_reason=ExtractionSkipReason.TIME_BUDGET,
        ),
        EgglogExtractionReceipt(
            elapsed_ms=8.0,
            skip_reason=ExtractionSkipReason.CANDIDATE_BUDGET,
        ),
    )

    report = _build_receipt_report(("a", "b", "c", "d"), receipts)

    assert report["candidate_count"] == 4
    assert report["p50_ms"] == 3.0
    assert report["p95_ms"] == pytest.approx(7.4)
    assert report["eclass_counts"] == [10, 12, 14]
    assert report["enode_counts"] == [20, 24, 28]
    assert report["degree_distribution"] == {"1": 2, "none": 2}
    assert report["skip_distribution"] == {
        "candidate_budget": 1,
        "success": 2,
        "time_budget": 1,
    }
    assert report["cap_skip_count"] == 2


def test_stage_attempt_outcomes_keep_acceptance_and_refusals_separate() -> None:
    report = _build_stage_attempt_outcome_report(
        (
            EgglogExtractionReceipt(),
            EgglogExtractionReceipt(skip_reason=ExtractionSkipReason.NATIVE_Z3_FAILED),
            EgglogExtractionReceipt(skip_reason=ExtractionSkipReason.TIME_BUDGET),
        )
    )

    assert report == {
        "accepted": 1,
        "native_z3_failed": 1,
        "time_budget": 1,
    }


def test_catalogue_selection_measurement_separates_cold_and_warm_calls() -> None:
    ticks = iter((10.0, 12.5, 13.0, 13.25))
    calls: list[str] = []

    selected, report = _measure_catalogue_selection(
        lambda: calls.append("select") or ("rule",),
        clock=lambda: next(ticks),
    )

    assert selected == ("rule",)
    assert calls == ["select", "select"]
    assert report == {"cold_seconds": 2.5, "warm_seconds": 0.25}


def test_handler_configuration_measurement_is_separate_from_selection() -> None:
    ticks = iter((10.0, 10.125))
    configured: list[dict[str, object]] = []

    class Handler:
        def configure(self, config: dict[str, object]) -> None:
            configured.append(config)

    handler, elapsed_seconds = _measure_handler_configuration(
        Handler(),
        {"families": ["add"]},
        clock=lambda: next(ticks),
    )

    assert isinstance(handler, Handler)
    assert configured == [{"families": ["add"]}]
    assert elapsed_seconds == 0.125


def test_stage_timing_report_requires_consistent_ordered_stages() -> None:
    report = _build_stage_timing_report(
        (
            {
                "root_eligibility": 1.0,
                "ast_construction": 2.0,
                "native_preflight": 3.0,
            },
            {"root_eligibility": 3.0, "ast_construction": 6.0},
        )
    )

    assert report == {
        "root_eligibility": {
            "sample_count": 2,
            "p50_ms": 2.0,
            "p95_ms": pytest.approx(2.9),
            "max_ms": 3.0,
        },
        "ast_construction": {
            "sample_count": 2,
            "p50_ms": 4.0,
            "p95_ms": pytest.approx(5.8),
            "max_ms": 6.0,
        },
        "native_preflight": {
            "sample_count": 1,
            "p50_ms": 3.0,
            "p95_ms": 3.0,
            "max_ms": 3.0,
        },
    }
    with pytest.raises(ValueError, match="ordered pipeline prefixes"):
        _build_stage_timing_report(
            (
                {"root_eligibility": 1.0, "ast_construction": 2.0},
                {"root_eligibility": 3.0, "native_preflight": 4.0},
            )
        )


@pytest.mark.parametrize(
    ("baseline", "report", "reason"),
    [
        (
            {
                "candidate_names": [],
                "candidate_count": 0,
                "baseline_p95_ms": 1.0,
            },
            {"candidate_names": [], "candidate_count": 0, "p95_ms": 1.0},
            "empty",
        ),
        (
            {
                "candidate_names": ["a"],
                "candidate_count": 1,
                "baseline_p95_ms": 1.0,
            },
            {"candidate_names": ["b"], "candidate_count": 1, "p95_ms": 1.0},
            "identity",
        ),
        (
            {
                "candidate_names": ["a"],
                "candidate_count": 1,
                "baseline_p95_ms": 1.0,
            },
            {"candidate_names": ["a", "a"], "candidate_count": 2, "p95_ms": 1.0},
            "count",
        ),
    ],
)
def test_incomparable_baseline_is_invalidated(
    baseline: dict[str, object],
    report: dict[str, object],
    reason: str,
) -> None:
    with pytest.raises(pytest.skip.Exception, match=reason):
        _assert_comparable_baseline(baseline, report)


def test_comparable_baseline_rejects_only_over_100x() -> None:
    baseline = {
        "candidate_names": ["a"],
        "candidate_count": 1,
        "baseline_p95_ms": 2.0,
    }
    _assert_comparable_baseline(
        baseline,
        {"candidate_names": ["a"], "candidate_count": 1, "p95_ms": 200.0},
    )
    with pytest.raises(AssertionError, match="100x"):
        _assert_comparable_baseline(
            baseline,
            {"candidate_names": ["a"], "candidate_count": 1, "p95_ms": 200.01},
        )


@pytest.mark.profile
def test_corpus_receipt_reports_quantiles_and_rejects_100x_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import d810.optimizers.microcode.instructions.egraph.egglog_handler as handler_module

    # Start from no immutable certificate cache, then measure exactly the
    # configured selection that a live handler requests. This deliberately
    # does not benchmark the unrelated receipt-only rule inventory.
    catalogue_compiler._compile_selected_rule_catalogue.cache_clear()
    compiled_rules, catalogue_selection = _measure_catalogue_selection(
        lambda: compiled_rules_for_families(_CLOSED_FAMILIES)
    )
    extraction_handler, handler_configuration_seconds = _measure_handler_configuration(
        EgglogOptimizer(),
        {
            "families": [family for family in _CLOSED_FAMILIES],
            "max_leaves": 2,
            "max_operator_nodes": 10,
            "max_degree": 1,
            "saturation_rounds": 2,
            "max_eclasses": 64,
            "max_enodes": 128,
            "max_rule_firings": 32,
            "time_budget_ms": 3,
            "require_proof": True,
        },
    )
    rules_by_key = {(rule.family, rule.source_name): rule for rule in compiled_rules}
    corpus_names: list[str] = []
    receipts: list[EgglogExtractionReceipt] = []
    for repetition in range(_REPETITIONS):
        for family, source_name in _CANDIDATE_CORPUS:
            rule = rules_by_key[(family, source_name)]
            candidate = _candidate_from_pattern(rule.pattern)
            assert isinstance(candidate, ast_dispatcher.AstNode)
            result = extraction_handler._select_extraction(
                candidate, destination_size=4
            )
            extraction_handler._record_extraction_receipt(result.receipt)
            assert extraction_handler.last_extraction_receipt is result.receipt
            receipts.append(extraction_handler.last_extraction_receipt)
            corpus_names.append(f"{family}:{source_name}#{repetition + 1}")

    report = _build_receipt_report(tuple(corpus_names), tuple(receipts))
    stage_handler = _stage_profile_handler()
    current_candidate: list[object] = []
    monkeypatch.setattr(
        handler_module,
        "minsn_to_ast",
        lambda _ins: current_candidate[0],
    )
    monkeypatch.setattr(
        stage_handler,
        "_read_native_view",
        lambda _ins, destination_size: _stage_native_view(
            current_candidate[0], destination_size
        ),
    )
    # The profile is a real handler/proof path over active AST terms. Without
    # a live microcode block, both minsn_to_ast() and final materialization
    # are synthetic boundaries; their stages remain visible but ungated.
    monkeypatch.setattr(stage_handler, "_create_instruction", lambda *_args: object())
    stage_records: list[dict[str, float]] = []
    stage_receipts: list[EgglogExtractionReceipt] = []
    for family, source_name in _CANDIDATE_CORPUS:
        rule = rules_by_key[(family, source_name)]
        candidate = _candidate_from_pattern(rule.pattern)
        current_candidate[:] = [candidate]
        instruction = SimpleNamespace(
            opcode=int(candidate.opcode),
            d=SimpleNamespace(size=4),
            ea=0,
        )
        stage_handler.check_and_replace(None, instruction)
        stage_timings = stage_handler.execution_metadata().get("stage_timings_ms")
        assert isinstance(stage_timings, dict)
        stage_records.append(stage_timings)
        assert stage_handler.last_extraction_receipt is not None
        stage_receipts.append(stage_handler.last_extraction_receipt)

    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    baseline_stage_profiles = baseline["phase0_stage_profiles"]
    mode = "cython" if ast_dispatcher._USING_CYTHON else "python"
    baseline_stage_profile = baseline_stage_profiles[mode]
    report.update(
        {
            "baseline_fixture": str(_BASELINE_PATH.relative_to(Path.cwd())),
            "baseline_p95_ms": baseline["baseline_p95_ms"],
            "catalogue_selection_seconds": catalogue_selection,
            "handler_configuration_seconds": handler_configuration_seconds,
            "selected_compiled_rule_count": len(compiled_rules),
            "production_time_budget_ms": extraction_handler.time_budget_ms,
            "stage_profile_time_budget_ms": stage_handler.time_budget_ms,
            "stage_timing_ms": _build_stage_timing_report(tuple(stage_records)),
            "stage_attempt_outcomes": _build_stage_attempt_outcome_report(
                tuple(stage_receipts)
            ),
            "stage_profile_note": _SYNTHETIC_STAGE_PROFILE_NOTE,
            "docker_image": os.environ.get("D810_TEST_RUNTIME_IMAGE", "unknown"),
            "docker_image_id": os.environ.get("D810_TEST_RUNTIME_IMAGE_ID", "unknown"),
            "cython_enabled": bool(ast_dispatcher._USING_CYTHON),
            "egglog_version": version("egglog"),
        }
    )
    print(
        "\nEGGLOG_MBA_CORPUS_PERFORMANCE_RECEIPT=" + json.dumps(report, sort_keys=True)
    )
    _assert_comparable_baseline(baseline, report)

    # The Phase 0 snapshot is provenance, not a performance threshold. It
    # prevents a report from silently mixing the two dispatcher modes/images.
    assert baseline_stage_profiles["image"] == report["docker_image"]
    assert baseline_stage_profiles["image_id"] == report["docker_image_id"]
    assert baseline_stage_profiles["egglog_version"] == report["egglog_version"]
    assert baseline_stage_profile["cython_enabled"] is report["cython_enabled"]

    # cfg-recon-mainline admits the certified Hodur complement-mask rule in
    # addition to the Phase 3 catalogue baseline.
    assert len(compiled_rules) == 109
    assert extraction_handler.max_degree == 1
    assert extraction_handler.time_budget_ms == 3
    assert stage_handler.time_budget_ms == 1000
    assert tuple(report["stage_timing_ms"]) == _PIPELINE_STAGE_ORDER
    assert report["candidate_count"] == len(_CANDIDATE_CORPUS) * _REPETITIONS
    assert report["candidate_names"] == corpus_names
    assert set(report["degree_distribution"]) <= {"1", "none"}
    assert all(
        count <= extraction_handler.max_eclasses for count in report["eclass_counts"]
    )
    assert all(
        count <= extraction_handler.max_enodes for count in report["enode_counts"]
    )
    assert report["p95_ms"] <= report["baseline_p95_ms"] * 100
