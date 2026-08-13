"""Diagnostic performance receipt for the certified Egglog MBA path."""

from __future__ import annotations

import json
import statistics
import time
from collections import Counter
from pathlib import Path

import pytest

egglog = pytest.importorskip("egglog")
ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba.egglog_add_rule_compiler import (  # noqa: E402
    compile_mba_rule_catalogue,
)
from d810.backends.mba.egglog_saturation import (  # noqa: E402
    EgglogExtractionReceipt,
    ExtractionSkipReason,
)
from d810.hexrays.expr.p_ast import AstBase, AstConstant, AstLeaf, AstNode  # noqa: E402
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


def _candidate_from_pattern(expression: SymbolicExpressionProtocol) -> AstBase:
    leaves: dict[str, AstLeaf] = {}

    def materialize(item: SymbolicExpressionProtocol) -> AstBase:
        if item.operation is None:
            if item.value is not None:
                constant = AstConstant(str(item.value), item.value, 4)
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
                leaf = AstLeaf(item.name)
                leaf.mop = MopSnapshot(
                    t=ida_hexrays.mop_r,
                    size=4,
                    reg=len(leaves) + 1,
                )
                leaf.dest_size = 4
                leaves[item.name] = leaf
            return leaf.clone()

        assert item.left is not None
        node = AstNode(
            _OPCODE_BY_OPERATION[item.operation],
            materialize(item.left),
            materialize(item.right) if item.right is not None else None,
        )
        node.dest_size = 4
        return node

    return materialize(expression)


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
        receipt.eclass_count
        for receipt in receipts
        if receipt.eclass_count is not None
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
def test_corpus_receipt_reports_quantiles_and_rejects_100x_regression() -> None:
    cold_started = time.perf_counter()
    catalogue = compile_mba_rule_catalogue()
    cold_seconds = time.perf_counter() - cold_started
    handler = EgglogOptimizer()
    handler.configure(
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
        }
    )
    rules_by_key = {
        (rule.family, rule.source_name): rule for rule in catalogue.compiled_rules
    }
    corpus_names: list[str] = []
    receipts: list[EgglogExtractionReceipt] = []
    for repetition in range(_REPETITIONS):
        for family, source_name in _CANDIDATE_CORPUS:
            rule = rules_by_key[(family, source_name)]
            candidate = _candidate_from_pattern(rule.pattern)
            assert isinstance(candidate, AstNode)
            result = handler._select_extraction(candidate, destination_size=4)
            handler._record_extraction_receipt(result.receipt)
            assert handler.last_extraction_receipt is result.receipt
            receipts.append(handler.last_extraction_receipt)
            corpus_names.append(f"{family}:{source_name}#{repetition + 1}")

    report = _build_receipt_report(tuple(corpus_names), tuple(receipts))
    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    report.update(
        {
            "baseline_fixture": str(_BASELINE_PATH.relative_to(Path.cwd())),
            "baseline_p95_ms": baseline["baseline_p95_ms"],
            "cold_catalogue_seconds": cold_seconds,
            "compiled_rule_count": len(catalogue.compiled_rules),
            "production_time_budget_ms": handler.time_budget_ms,
        }
    )
    print(
        "\nEGGLOG_MBA_CORPUS_PERFORMANCE_RECEIPT="
        + json.dumps(report, sort_keys=True)
    )
    _assert_comparable_baseline(baseline, report)

    assert len(catalogue.receipts) == 188
    assert len(catalogue.compiled_rules) == 108
    assert handler.max_degree == 1
    assert handler.time_budget_ms == 3
    assert report["candidate_count"] == len(_CANDIDATE_CORPUS) * _REPETITIONS
    assert report["candidate_names"] == corpus_names
    assert set(report["degree_distribution"]) <= {"1", "none"}
    assert all(count <= handler.max_eclasses for count in report["eclass_counts"])
    assert all(count <= handler.max_enodes for count in report["enode_counts"])
    assert report["p95_ms"] <= report["baseline_p95_ms"] * 100
