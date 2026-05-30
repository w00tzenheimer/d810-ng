from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.graph_modification import RedirectGoto, ZeroStateWrite
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.residual_target_resolution import is_structured_conditional_path_feeder
from d810.ir.state_variable import StateVariableRef
from d810.optimizers.microcode.flow.flattening.hodur.residual_handoff_backend import (
    ResidualEffectiveTargetEvidence,
    ResidualStateWriteEvidence,
)
from d810.optimizers.microcode.flow.flattening.hodur.family import HodurStrategyFamily
from d810.optimizers.microcode.flow.flattening.hodur.post_apply_runtime import (
    collect_live_residual_dispatcher_preds,
    collect_post_apply_bst_cleanup_blockers,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_node_frontier_bypass import (
    ExactNodeFrontierBypassStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    exact_node_frontier_bypass as exact_node_frontier_bypass_module,
)


class _FakeResidualFrontierEvidenceBackend:
    def __init__(
        self,
        *,
        state_values: dict[int, int] | None = None,
        effective_targets: dict[tuple[int, int], int | None] | None = None,
        state_variable: StateVariableRef | None = StateVariableRef(0x10, 4),
    ) -> None:
        self.state_values = dict(state_values or {})
        self.effective_targets = dict(effective_targets or {})
        self.state_variable = state_variable
        self.state_write_calls: list[tuple[object, int, StateVariableRef]] = []
        self.effective_target_calls: list[tuple[int, int, StateVariableRef | None]] = []

    def resolve_state_variable(
        self,
        *,
        state_machine: object | None,
    ) -> StateVariableRef | None:
        return self.state_variable

    def resolve_singleton_state_write(
        self,
        mba: object,
        block_serial: int,
        *,
        state_variable: StateVariableRef,
    ) -> ResidualStateWriteEvidence | None:
        self.state_write_calls.append((mba, int(block_serial), state_variable))
        value = self.state_values.get(int(block_serial))
        if value is None:
            return None
        return ResidualStateWriteEvidence(
            block_serial=int(block_serial),
            state_value=int(value),
            reason="fake_singleton_state_write",
        )

    def resolve_residual_effective_target(
        self,
        dag: object,
        *,
        pred_serial: int,
        state_value: int,
        dispatcher_model: object | None,
        bst_node_blocks: set[int] | frozenset[int],
        state_variable: StateVariableRef | None,
        mba: object | None,
    ) -> ResidualEffectiveTargetEvidence:
        self.effective_target_calls.append(
            (int(pred_serial), int(state_value) & 0xFFFFFFFF, state_variable)
        )
        target = self.effective_targets.get(
            (int(pred_serial), int(state_value) & 0xFFFFFFFF)
        )
        return ResidualEffectiveTargetEvidence(
            source_block=int(pred_serial),
            state_value=int(state_value) & 0xFFFFFFFF,
            target_entry=target,
            reason="fake_effective_target",
        )


def _install_residual_frontier_backend(
    monkeypatch,
    *,
    state_values: dict[int, int],
    effective_targets: dict[tuple[int, int], int | None] | None = None,
    state_variable: StateVariableRef | None = StateVariableRef(0x10, 4),
) -> _FakeResidualFrontierEvidenceBackend:
    backend = _FakeResidualFrontierEvidenceBackend(
        state_values=state_values,
        effective_targets=effective_targets,
        state_variable=state_variable,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module,
        "_RESIDUAL_FRONTIER_EVIDENCE_BACKEND",
        backend,
    )
    return backend


def test_collect_post_apply_bst_cleanup_blockers_uses_group_live_preds() -> None:
    fragment = PlanFragment(
        strategy_name="exact_conditional_alias_lowering",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        metadata={
            "allow_post_apply_bst_cleanup": False,
            "post_apply_bst_cleanup_group": "exact_nodes",
            "residual_dispatcher_preds": (10, 11),
        },
        modifications=[],
    )
    blockers = collect_post_apply_bst_cleanup_blockers(
        [fragment],
        [
            StageResult(
                strategy_name="exact_conditional_alias_lowering",
                success=True,
                edits_applied=1,
            )
        ],
        live_residual_dispatcher_preds_by_strategy={"group:exact_nodes": ()},
    )
    assert blockers == {}


def test_collect_live_residual_dispatcher_preds_falls_back_to_generic_collector() -> None:
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (50,), 0, 0, ()),
            50: BlockSnapshot(50, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=50,
        func_ea=0x180012B60,
    )
    family = HodurStrategyFamily(strategy_classes=())
    family._cfg_translator = SimpleNamespace(lift=lambda _mba: flow_graph)
    snapshot = SimpleNamespace(
        bst_result=SimpleNamespace(bst_node_blocks={}),
        bst_dispatcher_serial=2,
    )

    residual = collect_live_residual_dispatcher_preds(
        SimpleNamespace(),
        snapshot,
        strategies=family.strategies,
        strategy_name="semantic_exact_node_all_plannable_edges",
        cfg_translator=family.cfg_translator,
    )

    assert residual == (50,)


def test_exact_node_frontier_bypass_redirects_residual_pred_to_supported_entry(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (81,), (), 0, 0, ()),
            50: BlockSnapshot(50, 0, (2,), (), 0, 0, ()),
            81: BlockSnapshot(81, 0, (82, 83), (2,), 0, 0, ()),
            82: BlockSnapshot(82, 0, (63,), (81,), 0, 0, ()),
            83: BlockSnapshot(83, 0, (117,), (81,), 0, 0, ()),
        },
        entry_serial=50,
        func_ea=0x180012B60,
    )
    edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x5FE86821),
        source_anchor=SimpleNamespace(block_serial=81, branch_arm=0),
        target_state=0x02760C0D,
        target_entry_anchor=117,
        ordered_path=(81, 83, 117),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge,), nodes=()),
        plannable_edges=(SimpleNamespace(edge=edge),),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (50,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={50: 0x5FE86821},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 81,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=50),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["allow_post_apply_bst_cleanup"] is True
    assert fragment.metadata["post_apply_bst_cleanup_group"] == "exact_nodes"
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 50 and mod.new_target == 81
        for mod in fragment.modifications
    )


def test_exact_node_frontier_bypass_redirects_semantic_supplemental_feeder(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (45,), 0, 0, ()),
            45: BlockSnapshot(45, 0, (2,), (), 0, 0, ()),
            122: BlockSnapshot(122, 0, (), (), 0, 0, ()),
        },
        entry_serial=45,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(), nodes=()),
        plannable_edges=(),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (45,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={45: 0x00C0C59F},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 122,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: True,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=45),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_bypasses"] == ()
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((45, 0x00C0C59F, 122),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 45 and mod.new_target == 122
        for mod in fragment.modifications
    )


def test_exact_node_frontier_bypass_redirects_return_reachable_supplemental_feeder(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (33,), 0, 0, ()),
            33: BlockSnapshot(33, 0, (2,), (), 0, 0, ()),
            34: BlockSnapshot(34, 0, (35,), (33,), 0, 0, ()),
            35: BlockSnapshot(35, 0, (), (34,), 0, 0, ()),
        },
        entry_serial=33,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(), nodes=()),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (33,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={33: 0x27EEEA11},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 34,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "dispatcher_exact_state_target",
        lambda *_args, **_kwargs: 24,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: False,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=33),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_bypasses"] == ()
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((33, 0x27EEEA11, 34),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 33 and mod.new_target == 34
        for mod in fragment.modifications
    )


def test_exact_node_frontier_bypass_uses_supplemental_selected_entry_when_direct_entry_missing(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (33,), 0, 0, ()),
            33: BlockSnapshot(33, 0, (2,), (), 0, 0, ()),
            34: BlockSnapshot(34, 0, (), (), 0, 0, ()),
        },
        entry_serial=33,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(), nodes=(), supplemental_selected_entries=((0x27EEEA11, 34),)),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (33,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={33: 0x27EEEA11},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "dispatcher_exact_state_target",
        lambda *_args, **_kwargs: 24,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: False,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=33),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((33, 0x27EEEA11, 34),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 33 and mod.new_target == 34
        for mod in fragment.modifications
    )


def test_exact_node_frontier_bypass_skips_terminal_owned_supplemental_feeder(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (208,), 0, 0, ()),
            132: BlockSnapshot(132, 0, (), (), 0, 0, ()),
            208: BlockSnapshot(208, 0, (2,), (), 0, 0, ()),
        },
        entry_serial=208,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(), nodes=()),
        plannable_edges=(),
        terminal_source_owned_blocks=(208,),
        terminal_protected_blocks=(),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (208,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={208: 0x09EB3382},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 132,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: True,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=208),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is None


def test_exact_node_frontier_bypass_prefers_normalized_alias_entry_over_raw_exact_row(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (16,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
            72: BlockSnapshot(72, 0, (), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(), nodes=()),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (16,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={16: 0x4C77464F},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 72,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_normalized_alias_entry_for_state",
        lambda *_args, **_kwargs: 14,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "dispatcher_exact_state_target",
        lambda *_args, **_kwargs: 72,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: True,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=16),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((16, 0x4C77464F, 14),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 16 and mod.new_target == 14
        for mod in fragment.modifications
    )


def test_is_structured_conditional_path_feeder_detects_immediate_conditional_feeder():
    dag = SimpleNamespace(
        edges=(
            SimpleNamespace(
                target_state=0x4C77464F,
                source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
                ordered_path=(15, 16),
            ),
        )
    )

    assert is_structured_conditional_path_feeder(
        dag,
        pred_serial=16,
        state_value=0x4C77464F,
    )


def test_exact_node_frontier_bypass_skips_structured_conditional_feeder(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (16,), 0, 0, ()),
            15: BlockSnapshot(15, 0, (), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
            66: BlockSnapshot(66, 0, (), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(
            edges=(
                SimpleNamespace(
                    target_state=0x4C77464F,
                    source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
                    ordered_path=(15, 16),
                ),
            ),
            nodes=(),
        ),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (16,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={16: 0x4C77464F},
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=16),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is None


def test_exact_node_frontier_bypass_uses_semantic_reference_alias_entry(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (16,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
            72: BlockSnapshot(72, 0, (), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )
    alias_edge = SimpleNamespace(
        target_state=0x4C77464F,
        ordered_path=(15, 16),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
    )
    sibling_edge = SimpleNamespace(
        target_state=0x296F2452,
        ordered_path=(15, 17),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(alias_edge, sibling_edge), nodes=()),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
        semantic_reference_program=SimpleNamespace(
            nodes=(
                SimpleNamespace(
                    label_text="0x474EEEBB_fallback",
                    entry_anchor=14,
                    line_start=1,
                    line_end=2,
                ),
                SimpleNamespace(
                    label_text="STATE_6107F8EC",
                    entry_anchor=15,
                    line_start=3,
                    line_end=5,
                ),
            ),
            lines=(
                SimpleNamespace(line_no=4, target_label="STATE_474EEEBB_fallback"),
                SimpleNamespace(line_no=5, target_label="STATE_296F2452"),
            ),
        ),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (16,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={16: 0x4C77464F},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 72,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_normalized_alias_entry_for_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "dispatcher_exact_state_target",
        lambda *_args, **_kwargs: 72,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: True,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=16),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((16, 0x4C77464F, 14),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 16 and mod.new_target == 14
        for mod in fragment.modifications
    )


def test_exact_node_frontier_bypass_scopes_semantic_alias_matching_to_local_source(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (16,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
            72: BlockSnapshot(72, 0, (), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )
    alias_edge = SimpleNamespace(
        target_state=0x4C77464F,
        ordered_path=(15, 16),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15),
    )
    sibling_edge = SimpleNamespace(
        target_state=0x296F2452,
        ordered_path=(15, 17),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15),
    )
    extra_other_source_edge = SimpleNamespace(
        target_state=0x57BE6FD0,
        ordered_path=(99, 100),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=99),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(alias_edge, sibling_edge, extra_other_source_edge), nodes=()),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
        semantic_reference_program=SimpleNamespace(
            nodes=(
                SimpleNamespace(
                    label_text="0x474EEEBB_fallback",
                    entry_anchor=14,
                    line_start=1,
                    line_end=2,
                ),
                SimpleNamespace(
                    label_text="STATE_6107F8EC",
                    entry_anchor=15,
                    line_start=3,
                    line_end=5,
                ),
            ),
            lines=(
                SimpleNamespace(line_no=4, target_label="STATE_474EEEBB_fallback"),
                SimpleNamespace(line_no=5, target_label="STATE_296F2452"),
            ),
        ),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (16,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={16: 0x4C77464F},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 72,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_normalized_alias_entry_for_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "dispatcher_exact_state_target",
        lambda *_args, **_kwargs: 72,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: True,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=16),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((16, 0x4C77464F, 14),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 16 and mod.new_target == 14
        for mod in fragment.modifications
    )


def test_exact_node_frontier_bypass_prefers_direct_semantic_state_entry(monkeypatch):
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (16,), 0, 0, ()),
            16: BlockSnapshot(16, 0, (2,), (), 0, 0, ()),
            66: BlockSnapshot(66, 0, (), (), 0, 0, ()),
            71: BlockSnapshot(71, 0, (), (), 0, 0, ()),
        },
        entry_serial=16,
        func_ea=0x180012B60,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(), nodes=()),
        plannable_edges=(),
        terminal_source_owned_blocks=(),
        terminal_protected_blocks=(),
        semantic_reference_program=SimpleNamespace(
            nodes=(
                SimpleNamespace(
                    label_text="STATE_4C77464F",
                    entry_anchor=66,
                    line_start=1,
                    line_end=1,
                ),
            ),
            lines=(SimpleNamespace(line_no=1, target_label=None),),
        ),
    )
    setup = SimpleNamespace(
        builder=ModificationBuilder.from_snapshot(
            SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
        ),
        bst_node_blocks=(2,),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "collect_residual_dispatcher_predecessors",
        lambda *_args, **_kwargs: (16,),
    )
    _install_residual_frontier_backend(
        monkeypatch,
        state_values={16: 0x4C77464F},
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_dag_entry_for_state",
        lambda *_args, **_kwargs: 71,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "resolve_normalized_alias_entry_for_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "dispatcher_exact_state_target",
        lambda *_args, **_kwargs: 71,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "state_has_semantic_support",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        exact_node_frontier_bypass_module, "find_last_state_write_site_snapshot",
        lambda *_args, **_kwargs: SimpleNamespace(
            state_value=0x4C77464F,
            insn_ea=0x4010,
            trailing_insn_eas=(0x4014,),
            unsafe_trailing_insn_eas=(),
        ),
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x10))
        ),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=16),
    )

    fragment = ExactNodeFrontierBypassStrategy().plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["accepted_supplemental_bypasses"] == ((16, 0x4C77464F, 66),)
    assert fragment.metadata["accepted_zero_state_write_cleanups"] == ((16, 0x4C77464F, 66),)
    assert any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 16 and mod.new_target == 66
        for mod in fragment.modifications
    )
    assert any(
        isinstance(mod, ZeroStateWrite) and mod.block_serial == 16 and mod.insn_ea == 0x4010
        for mod in fragment.modifications
    )
