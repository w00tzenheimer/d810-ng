from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import CreateConditionalRedirect, RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DecisionPhase,
    DecisionReasonCode,
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
from d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family import (
    EmulatedDispatcherDetection,
    EmulatedDispatcherStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherStrategy,
    extract_emulated_dispatcher_metadata,
    extract_emulated_dispatcher_modifications,
)
from d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine import (
    EmulatedDispatcherUnflattener,
)


def _fake_mba():
    blk = SimpleNamespace(nsucc=lambda: 0)
    return SimpleNamespace(
        qty=1,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        get_mblock=lambda _serial: blk,
        for_all_topinsns=lambda collector: None,
    )


def _flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _flow_graph_with_edge() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _flow_graph_with_conditional_shape() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(2, 3),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401020,
                insn_snapshots=(),
            ),
            3: BlockSnapshot(
                serial=3,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401030,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def test_emulated_dispatcher_family_detect_reports_dispatcher_cache_collector_gap(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    analysis = SimpleNamespace(
        dispatchers=[7, 9],
        state_constants={0xF6A1E, 0xF6A1F},
        dispatcher_type=SimpleNamespace(name="UNKNOWN"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)

    class _Collector:
        def __init__(self):
            self._items = ()

        def get_dispatcher_list(self):
            return list(self._items)

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.OllvmDispatcherCollector",
        _Collector,
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        )
    )
    detection = family.detect(mba)

    assert detection.detected is True
    assert detection.analysis_dispatchers == (7, 9)
    assert detection.collector_dispatcher_entries == ()
    assert detection.dispatcher_shape == "unknown"
    assert detection.state_transport == "father_history_emulation"
    assert detection.lowering_mode == "generic_graph_modifications"
    assert detection.provenance_hints == ()
    assert detection.planning_blocker == "dispatcher_cache_detected_but_collector_found_none"


def test_emulated_dispatcher_family_build_snapshot_attaches_observation_metadata(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: _flow_graph_with_edge())
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3, 5),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E, 0xF6A1F),
        collector_dispatcher_entries=(),
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)

    assert snapshot.dispatcher_cache is cache
    assert snapshot.state_summary == StateModelSummary(
        state_constants=frozenset({0xF6A1E, 0xF6A1F}),
        handler_count=2,
        transition_count=0,
    )
    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3, 5),
        state_constants=(0xF6A1E, 0xF6A1F),
        collector_dispatchers=(),
        planning_ready=False,
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
        candidate_count=0,
        rejected_fathers=0,
        candidate_kinds=(),
        rejection_reasons=(),
    )


def test_emulated_dispatcher_family_build_snapshot_attaches_lowering_candidates(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: _flow_graph_with_edge())
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda _mba, _det: (
            (RedirectGoto(from_serial=0, old_target=1, new_target=1),),
            ("dispatcher_source_shape_not_lowered",),
        ),
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E,),
        collector_dispatcher_entries=(2,),
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3,),
        state_constants=(0xF6A1E,),
        collector_dispatchers=(2,),
        planning_ready=False,
        planning_blocker="dispatcher_source_shape_not_lowered",
        candidate_count=1,
        rejected_fathers=1,
        candidate_kinds=("RedirectGoto",),
        rejection_reasons=("dispatcher_source_shape_not_lowered",),
    )
    assert modifications == (
        RedirectGoto(from_serial=0, old_target=1, new_target=1),
    )
    assert snapshot.flow_graph.metadata[EMULATED_DISPATCHER_MODIFICATIONS_KEY] == modifications


def test_emulated_dispatcher_family_build_snapshot_keeps_safe_conditional_target_candidate(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        )
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda _mba, _det: (
            (
                CreateConditionalRedirect(
                    source_block=0,
                    ref_block=1,
                    conditional_target=2,
                    fallthrough_target=3,
                ),
            ),
            (),
        ),
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E,),
        collector_dispatcher_entries=(2,),
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)

    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3,),
        state_constants=(0xF6A1E,),
        collector_dispatchers=(2,),
        planning_ready=True,
        planning_blocker=None,
        candidate_count=1,
        rejected_fathers=0,
        candidate_kinds=("CreateConditionalRedirect",),
        rejection_reasons=(),
    )
    assert modifications == (
        CreateConditionalRedirect(
            source_block=0,
            ref_block=1,
            conditional_target=2,
            fallthrough_target=3,
        ),
    )


def test_emulated_dispatcher_unflattener_records_no_plan_provenance(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    outcomes: list[object] = []
    rule.set_flow_context(
        SimpleNamespace(report_outcome=lambda provenance, source: outcomes.append((provenance, source)))
    )

    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(7,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(),
                    planning_ready=False,
                    planning_blocker="dispatcher_cache_detected_but_collector_found_none",
                    candidate_count=0,
                    rejected_fathers=0,
                    candidate_kinds=(),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(rule._family, "detect", lambda _mba: detection)
    monkeypatch.setattr(rule._family, "build_snapshot", lambda _mba, _det: snapshot)

    assert rule.optimize(blk) == 0
    assert rule._last_provenance is not None
    assert len(rule._last_provenance.rows) == 1
    row = rule._last_provenance.rows[0]
    assert row.strategy_name == "emulated_dispatcher"
    assert row.phase == DecisionPhase.INAPPLICABLE
    assert row.reason_code == DecisionReasonCode.REJECTED_INAPPLICABLE
    assert outcomes == [(rule._last_provenance, "planner")]
    assert rule.get_last_observation()["snapshot"] == {
        "dispatcher_shape": "unknown",
        "state_transport": "father_history_emulation",
        "lowering_mode": "generic_graph_modifications",
        "provenance_hints": (),
        "analysis_dispatchers": (7,),
        "state_constants": (),
        "collector_dispatchers": (),
        "planning_ready": False,
        "planning_blocker": "dispatcher_cache_detected_but_collector_found_none",
        "candidate_count": 0,
        "rejected_fathers": 0,
        "candidate_kinds": (),
        "rejection_reasons": (),
    }


def test_emulated_dispatcher_strategy_plans_validated_snapshot_modifications() -> None:
    strategy = EmulatedDispatcherStrategy()
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1, entry_ea=0x401000),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("RedirectGoto",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    RedirectGoto(from_serial=0, old_target=1, new_target=1),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert fragment.strategy_name == "emulated_dispatcher"
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.modifications == [
        RedirectGoto(from_serial=0, old_target=1, new_target=1),
    ]


def test_emulated_dispatcher_strategy_rejects_partial_lowering_when_blockers_exist() -> None:
    graph = FlowGraph(
        blocks=_flow_graph_with_edge().blocks,
        entry_serial=0,
        func_ea=0x401000,
        metadata={
            EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                dispatcher_shape="unknown",
                state_transport="father_history_emulation",
                lowering_mode="generic_graph_modifications",
                provenance_hints=(),
                analysis_dispatchers=(7,),
                collector_dispatchers=(2,),
                planning_ready=False,
                planning_blocker="dispatcher_history_missing_values",
                candidate_count=1,
                rejected_fathers=1,
                candidate_kinds=("RedirectGoto",),
                rejection_reasons=("dispatcher_history_missing_values",),
            ),
            EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                RedirectGoto(from_serial=0, old_target=1, new_target=1),
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=graph,
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    strategy = EmulatedDispatcherStrategy()
    assert strategy.is_applicable(snapshot) is False
    assert strategy.plan(snapshot) is None


def test_emulated_dispatcher_unflattener_counts_family_post_execute_cleanup(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("RedirectGoto",),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        rule._family,
        "detect",
        lambda _mba: EmulatedDispatcherDetection(
            analysis_dispatchers=(7,),
            dispatcher_shape="unknown",
            state_transport="father_history_emulation",
            lowering_mode="generic_graph_modifications",
            provenance_hints=(),
        ),
    )
    monkeypatch.setattr(rule._family, "build_snapshot", lambda _mba, _det: snapshot)
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine.plan_family_pipeline",
        lambda *args, **kwargs: PlannedPipeline(
            pipeline=[object()],
            provenance=PipelineProvenance(),
        ),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine.execute_family_pipeline",
        lambda *args, **kwargs: ExecutedPipeline(
            pipeline=[object()],
            results=[],
            provenance=PipelineProvenance(),
            total_changes=2,
            executor=None,
        ),
    )
    monkeypatch.setattr(
        rule._family,
        "post_execute_cleanup",
        lambda _mba, *, snapshot, total_changes: 3,
    )

    assert rule.optimize(blk) == 5


def test_emulated_dispatcher_unflattener_builds_snapshot_from_detection(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    initial_detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(2,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        collector_dispatcher_entries=(2,),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(2, 3),
                    collector_dispatchers=(2,),
                    planning_ready=False,
                    planning_blocker="dispatcher_cache_detected_but_collector_found_none",
                    candidate_count=0,
                    rejected_fathers=0,
                    candidate_kinds=(),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=2,
            transition_count=0,
        ),
    )
    build_inputs = []

    monkeypatch.setattr(rule._family, "detect", lambda _mba: initial_detection)
    monkeypatch.setattr(
        rule._family,
        "build_snapshot",
        lambda _mba, detection: build_inputs.append(detection) or snapshot,
    )

    assert rule.optimize(blk) == 0
    assert build_inputs == [initial_detection]
