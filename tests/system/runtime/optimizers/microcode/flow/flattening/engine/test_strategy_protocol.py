"""Unit tests for the shared engine strategy protocol types."""
from __future__ import annotations

import importlib.util

import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine import strategy as engine_strategy
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
    VerificationGate,
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
)


def _empty_scope() -> OwnershipScope:
    return OwnershipScope(
        blocks=frozenset(),
        edges=frozenset(),
        transitions=frozenset(),
    )


def _scope(
    blocks: set[int] | None = None,
    edges: set[tuple[int, int]] | None = None,
    transitions: set[tuple[int, int]] | None = None,
) -> OwnershipScope:
    return OwnershipScope(
        blocks=frozenset(blocks or set()),
        edges=frozenset(edges or set()),
        transitions=frozenset(transitions or set()),
    )


def _zero_benefit() -> BenefitMetrics:
    return BenefitMetrics(0, 0, 0, 0.0)


def _make_flow_graph() -> FlowGraph:
    blk0 = BlockSnapshot(
        serial=0,
        block_type=1,
        succs=(1,),
        preds=(),
        flags=0,
        start_ea=0x1000,
        insn_snapshots=(),
    )
    blk1 = BlockSnapshot(
        serial=1,
        block_type=2,
        succs=(),
        preds=(0,),
        flags=0,
        start_ea=0x2000,
        insn_snapshots=(),
    )
    return FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)


class TestEnginePackageApi:
    @staticmethod
    def _ida_runtime_available() -> bool:
        return importlib.util.find_spec("ida_hexrays") is not None

    def test_engine_package_re_exports_strategy_types(self) -> None:
        assert engine.PlanFragment is PlanFragment
        assert engine.VerificationGate is VerificationGate

    def test_engine_strategy_star_import_omits_semantic_gate(self) -> None:
        namespace: dict[str, object] = {}
        exec(
            "from d810.optimizers.microcode.flow.flattening.engine.strategy import *",
            namespace,
        )
        assert "PlanFragment" in namespace
        assert "SemanticGate" not in namespace

    def test_semantic_gate_availability_matches_runtime(self) -> None:
        if self._ida_runtime_available():
            assert engine_strategy.SemanticGate is not None
            return

        with pytest.raises(AttributeError, match="unavailable without IDA"):
            _ = engine_strategy.SemanticGate

    def test_transactional_executor_availability_matches_runtime(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur import (
            executor as hodur_executor,
        )

        if self._ida_runtime_available():
            assert engine.TransactionalExecutor is not None
            assert issubclass(
                hodur_executor.TransactionalExecutor,
                engine.TransactionalExecutor,
            )
            return

        with pytest.raises(AttributeError, match="unavailable without IDA"):
            _ = engine.TransactionalExecutor

        with pytest.raises(AttributeError, match="unavailable without IDA"):
            _ = hodur_executor.TransactionalExecutor


class TestOwnershipScope:
    def test_disjoint_true(self) -> None:
        assert _scope(blocks={1, 2}).is_disjoint(_scope(blocks={3, 4}))

    def test_disjoint_false_blocks(self) -> None:
        assert not _scope(blocks={1, 2}).is_disjoint(_scope(blocks={2, 3}))

    def test_union(self) -> None:
        union = _scope(blocks={1}, edges={(1, 2)}, transitions={(0, 1)}).union(
            _scope(blocks={3}, edges={(3, 4)}, transitions={(2, 3)})
        )
        assert union.blocks == frozenset({1, 3})
        assert union.edges == frozenset({(1, 2), (3, 4)})
        assert union.transitions == frozenset({(0, 1), (2, 3)})

    def test_overlap_helpers(self) -> None:
        assert _scope(blocks={1, 2, 3}).overlap_blocks(
            _scope(blocks={2, 4})
        ) == frozenset({2})
        assert _scope(edges={(1, 2), (3, 4)}).overlap_edges(
            _scope(edges={(1, 2)})
        ) == frozenset({(1, 2)})


class TestBenefitMetrics:
    def test_composite_score_all_zero(self) -> None:
        assert BenefitMetrics(0, 0, 0, 0.0).composite_score() == pytest.approx(0.0)

    def test_composite_score_with_conflict(self) -> None:
        assert BenefitMetrics(1, 1, 1, 1.0).composite_score() == pytest.approx(1.0)


class TestPlanFragment:
    def test_empty_fragment(self) -> None:
        frag = PlanFragment(
            strategy_name="test",
            family=FAMILY_DIRECT,
            modifications=[],
            ownership=_empty_scope(),
            prerequisites=[],
            expected_benefit=_zero_benefit(),
            risk_score=0.0,
        )
        assert frag.is_empty()

    def test_non_empty_fragment(self) -> None:
        frag = PlanFragment(
            strategy_name="mods_only",
            family=FAMILY_DIRECT,
            modifications=[RedirectGoto(from_serial=1, old_target=2, new_target=3)],
            ownership=_empty_scope(),
            prerequisites=[],
            expected_benefit=_zero_benefit(),
            risk_score=0.0,
        )
        assert not frag.is_empty()

    def test_family_constants_are_distinct(self) -> None:
        assert len({FAMILY_DIRECT, FAMILY_FALLBACK, FAMILY_CLEANUP}) == 3


class TestStageResult:
    def test_default_values(self) -> None:
        result = StageResult(strategy_name="my_strategy")
        assert result.edits_applied == 0
        assert result.reachability_after == pytest.approx(1.0)
        assert result.success is True
        assert result.quarantine is False

    def test_mutable_fields(self) -> None:
        result = StageResult(strategy_name="s")
        result.edits_applied = 42
        result.success = False
        assert result.edits_applied == 42
        assert result.success is False


class TestVerificationGate:
    def test_check_passes_when_above_thresholds(self) -> None:
        gate = VerificationGate(min_reachability=0.7, max_conflict_count=10)
        result = StageResult(
            strategy_name="ok",
            reachability_after=0.9,
            handler_reachability=0.95,
            conflict_count_after=5,
        )
        assert gate.check(result) is True

    def test_check_fails_on_handler_reachability(self) -> None:
        gate = VerificationGate(min_handler_reachability=0.9)
        result = StageResult(
            strategy_name="bad_handlers",
            reachability_after=0.95,
            handler_reachability=0.75,
        )
        assert gate.check(result) is False

    def test_check_flow_graph_uses_snapshot_reachability(self) -> None:
        gate = VerificationGate(
            min_reachability=1.0,
            min_handler_reachability=1.0,
        )
        assert (
            gate.check_flow_graph(_make_flow_graph(), handler_entry_serials={1})
            is True
        )
