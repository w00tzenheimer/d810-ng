"""Tests for the generic non-Hodur cleanup family pilot."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening import (
    cleanup_backend as backend_module,
    unflattener_cleanup_family as shell_module,
)
from d810.optimizers.microcode.flow.flattening.cleanup_backend import (
    LiveSimpleFlatteningCleanupBackend,
)
from d810.optimizers.microcode.flow.flattening.cleanup_family import (
    CLEANUP_FAMILY_METADATA_KEY,
    LEGACY_CLEANUP_RULE_NAMES,
    SimpleFlatteningCleanupDetection,
    SimpleFlatteningCleanupFamily,
    SimpleFlatteningCleanupMetadata,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    PlannedPipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    extract_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    SingleIterationPredFix,
    extract_single_iteration_fixes,
)
from d810.optimizers.microcode.flow.flattening.unflattener_cleanup_family import (
    SimpleFlatteningCleanupUnflattener,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 1,
    start_ea: int | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=serial if start_ea is None else start_ea,
        insn_snapshots=(),
    )


def _cleanup_flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (5,), (), start_ea=0x401000),
            2: _block(2, (10, 20), (5,), block_type=4),
            5: _block(5, (2,), (0,), start_ea=0x401005),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2,), block_type=2),
            29: _block(29, (30,), (), start_ea=0x401029),
            30: _block(30, (31, 32), (29, 31), block_type=4),
            31: _block(31, (30,), (30,), start_ea=0x401031),
            32: _block(32, (), (30,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


class _FakeTranslator:
    def __init__(self, flow_graph: FlowGraph) -> None:
        self.flow_graph = flow_graph

    def lift(self, _mba: object) -> FlowGraph:
        return self.flow_graph


class _FakeBackend:
    def __init__(self, detection: SimpleFlatteningCleanupDetection) -> None:
        self.detection = detection
        self.calls: list[tuple[object, object | None]] = []

    def collect(
        self,
        mba: object,
        *,
        logger: object | None = None,
    ) -> SimpleFlatteningCleanupDetection:
        self.calls.append((mba, logger))
        return self.detection


def _fake_mba() -> SimpleNamespace:
    return SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        qty=0,
        get_mblock=lambda _serial: None,
    )


def test_simple_cleanup_family_registers_first_pilot_strategies_only() -> None:
    empty_graph = FlowGraph(blocks={}, entry_serial=0, func_ea=0)
    family = SimpleFlatteningCleanupFamily(
        cfg_translator=_FakeTranslator(empty_graph)
    )

    assert family.name == "simple_flattening_cleanup"
    assert [strategy.name for strategy in family.strategies] == [
        "fake_jump",
        "single_iteration",
    ]


def test_live_cleanup_backend_wraps_existing_collectors(monkeypatch) -> None:
    fake_jump_fix = FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10)
    single_iteration_fix = SingleIterationPredFix(
        loop_header=30,
        pred_block=29,
        new_target=31,
    )
    calls: dict[str, object] = {}

    def _collect_fake_jump(mba, **kwargs):
        calls["fake_jump"] = (mba, kwargs)
        return (fake_jump_fix,)

    def _collect_single_iteration(mba, **kwargs):
        calls["single_iteration"] = (mba, kwargs)
        return (single_iteration_fix,)

    monkeypatch.setattr(
        backend_module,
        "collect_live_fake_jump_fixes",
        _collect_fake_jump,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_single_iteration,
    )

    backend = LiveSimpleFlatteningCleanupBackend()
    mba = _fake_mba()
    detection = backend.collect(mba, logger=None)

    assert detection.fake_jump_fixes == (fake_jump_fix,)
    assert detection.single_iteration_fixes == (single_iteration_fix,)
    assert detection.collection_errors == ()
    assert calls["fake_jump"][0] is mba
    assert calls["fake_jump"][1]["max_nb_block"] == 100
    assert calls["fake_jump"][1]["max_path"] == 100
    assert calls["single_iteration"][0] is mba


def test_simple_cleanup_family_uses_backend_evidence_for_metadata() -> None:
    fake_jump_fix = FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10)
    single_iteration_fixes = (
        SingleIterationPredFix(loop_header=30, pred_block=29, new_target=31),
        SingleIterationPredFix(loop_header=30, pred_block=31, new_target=32),
    )
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            fake_jump_fixes=(fake_jump_fix,),
            single_iteration_fixes=single_iteration_fixes,
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph())
    )

    mba = _fake_mba()
    detection = family.detect(mba)
    snapshot = family.build_snapshot(mba, detection)

    assert backend.calls and backend.calls[0][0] is mba
    assert detection.detected is True
    assert extract_fake_jump_fixes(snapshot.flow_graph) == (fake_jump_fix,)
    assert extract_single_iteration_fixes(snapshot.flow_graph) == single_iteration_fixes
    assert snapshot.state_machine is None
    assert snapshot.state_summary == StateModelSummary(
        state_constants=frozenset(),
        handler_count=0,
        transition_count=0,
    )

    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]
    assert isinstance(metadata, SimpleFlatteningCleanupMetadata)
    assert metadata.strategy_names == ("fake_jump", "single_iteration")
    assert metadata.legacy_rule_names == LEGACY_CLEANUP_RULE_NAMES
    assert metadata.collected_fake_jump_fixes == 1
    assert metadata.selected_fake_jump_fixes == 1
    assert metadata.collected_single_iteration_fixes == 2
    assert metadata.selected_single_iteration_fixes == 2
    assert metadata.planning_ready is True


def test_simple_cleanup_family_records_backend_errors() -> None:
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            collection_errors=("fake_jump:RuntimeError",),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph())
    )

    detection = family.detect(_fake_mba())
    snapshot = family.build_snapshot(_fake_mba(), detection)

    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]
    assert detection.detected is False
    assert detection.collection_errors == ("fake_jump:RuntimeError",)
    assert metadata.collection_errors == ("fake_jump:RuntimeError",)
    assert metadata.planning_ready is False
    assert snapshot.flow_graph.metadata[FAKE_JUMP_FIXES_METADATA_KEY] == {}
    assert snapshot.flow_graph.metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] == {}


def test_cleanup_unflattener_uses_shared_runtime(monkeypatch) -> None:
    mba = _fake_mba()
    metadata = SimpleFlatteningCleanupMetadata(
        family_name="simple_flattening_cleanup",
        strategy_names=("fake_jump", "single_iteration"),
        legacy_rule_names=LEGACY_CLEANUP_RULE_NAMES,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        func_ea=0x401000,
        collected_fake_jump_fixes=1,
        selected_fake_jump_fixes=1,
        collected_single_iteration_fixes=0,
        selected_single_iteration_fixes=0,
        planning_ready=True,
    )
    flow_graph = FlowGraph(
        blocks={},
        entry_serial=0,
        func_ea=0x401000,
        metadata={CLEANUP_FAMILY_METADATA_KEY: metadata},
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        flow_graph=flow_graph,
        state_summary=StateModelSummary(),
    )
    fragment = PlanFragment(
        strategy_name="fake_jump",
        family=FAMILY_CLEANUP,
        ownership=OwnershipScope(
            blocks=frozenset({5}),
            edges=frozenset({(5, 2)}),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=1,
            conflict_density=0.0,
        ),
        risk_score=0.1,
        modifications=[RedirectGoto(from_serial=5, old_target=2, new_target=10)],
    )
    provenance = PipelineProvenance(rows=())
    calls: dict[str, object] = {}

    class _FakeFamily:
        def detect(self, _mba: object) -> SimpleFlatteningCleanupDetection:
            calls["detect"] = True
            return SimpleFlatteningCleanupDetection(
                fake_jump_fixes=(FakeJumpPredFix(2, 5, 10),),
                maturity=ida_hexrays.MMAT_GLBOPT1,
                func_ea=0x401000,
            )

        def build_snapshot(
            self,
            _mba: object,
            _detection: SimpleFlatteningCleanupDetection,
        ) -> AnalysisSnapshot:
            calls["snapshot"] = True
            return snapshot

        def strategies_for_maturity(self, maturity: int) -> list:
            calls["maturity"] = maturity
            return []

        def post_execute_cleanup(
            self,
            _mba: object,
            *,
            snapshot: AnalysisSnapshot,
            total_changes: int,
        ) -> int:
            calls["cleanup"] = (snapshot, total_changes)
            return 1

    def _plan_family_pipeline(snapshot_arg, strategies, *, planner, inputs):
        calls["plan"] = (snapshot_arg, strategies, inputs.total_handlers)
        return PlannedPipeline(pipeline=[fragment], provenance=provenance)

    def _execute_family_pipeline(
        snapshot_arg,
        planned,
        *,
        executor_factory,
        flow_context,
    ):
        calls["execute"] = (snapshot_arg, planned, executor_factory, flow_context)
        return ExecutedPipeline(
            pipeline=planned.pipeline,
            results=[],
            provenance=provenance,
            total_changes=2,
            executor=None,
        )

    monkeypatch.setattr(shell_module, "plan_family_pipeline", _plan_family_pipeline)
    monkeypatch.setattr(shell_module, "execute_family_pipeline", _execute_family_pipeline)

    rule = SimpleFlatteningCleanupUnflattener()
    rule._family = _FakeFamily()

    assert rule.optimize(SimpleNamespace(mba=mba)) == 3
    assert calls["detect"] is True
    assert calls["snapshot"] is True
    assert calls["plan"] == (snapshot, [], 0)
    assert calls["cleanup"] == (snapshot, 2)
    assert calls["execute"][0] is snapshot

    observation = rule.get_last_observation()
    assert observation["snapshot"]["legacy_rule_names"] == LEGACY_CLEANUP_RULE_NAMES
    assert observation["total_changes"] == 3
