from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.residual_target_resolution import (
    BstConditionalTail,
    BstGotoTail,
    collect_owned_exact_sources,
    collect_supported_exact_entries,
    is_structured_conditional_path_feeder,
    is_supplemental_feeder_bypass,
    resolve_dispatcher_trampoline_skip_candidate,
    resolve_frontier_target_entry,
    walk_bst_dispatcher,
)


def test_resolve_frontier_target_entry_prefers_residual_effective_target() -> None:
    exact_dispatch_target, target_entry = resolve_frontier_target_entry(
        SimpleNamespace(nodes=(), edges=()),
        pred_serial=16,
        state_value=0x4C77464F,
        dispatcher_model=SimpleNamespace(lookup=None),
        bst_blocks={2},
        semantic_reference_program=None,
        residual_effective_target=14,
        dispatcher_exact_state_target_fn=lambda *_args, **_kwargs: None,
        supplemental_selected_entry_for_state_fn=lambda *_args, **_kwargs: 14,
        resolve_exact_dag_entry_for_state_fn=lambda *_args, **_kwargs: 66,
        resolve_semantic_reference_entry_for_state_fn=lambda *_args, **_kwargs: 66,
        resolve_dag_entry_for_state_fn=lambda *_args, **_kwargs: 66,
        resolve_normalized_alias_entry_for_state_fn=lambda *_args, **_kwargs: 66,
        resolve_semantic_reference_alias_entry_fn=lambda *_args, **_kwargs: None,
    )

    assert exact_dispatch_target is None
    assert target_entry == 14


def test_collect_supported_exact_entries_includes_straight_line_targets() -> None:
    edge = SimpleNamespace(
        kind=SimpleNamespace(name="TRANSITION"),
        source_key=SimpleNamespace(state_const=0x606DC166),
        target_state=0x139F2922,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge,)),
        plannable_edges=(SimpleNamespace(edge=edge),),
    )

    supported = collect_supported_exact_entries(
        round_summary,
        exact_source_blocks={28},
        bst_blocks={2},
        is_straight_line_handoff_fn=lambda _edge: True,
        resolve_dag_entry_for_state_fn=lambda *_args, **_kwargs: 136,
    )

    assert supported == {28, 136}


def test_collect_owned_exact_sources_includes_straight_line_source_block() -> None:
    edge = SimpleNamespace(
        kind=SimpleNamespace(name="TRANSITION"),
        source_key=SimpleNamespace(state_const=0x606DC166),
        source_anchor=SimpleNamespace(block_serial=14),
        target_state=0x139F2922,
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge,)),
        plannable_edges=(SimpleNamespace(edge=edge),),
    )

    owned = collect_owned_exact_sources(
        round_summary,
        exact_source_blocks={28},
        is_straight_line_handoff_fn=lambda _edge: True,
    )

    assert owned == {14, 28}


def test_is_structured_conditional_path_feeder_detects_immediate_conditional_feeder() -> None:
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


def test_is_supplemental_feeder_bypass_requires_semantic_or_return_support() -> None:
    flow_graph = FlowGraph(
        blocks={
            33: BlockSnapshot(33, 0, (2,), (), 0, 0, ()),
            34: BlockSnapshot(34, 0, (), (), 0, 0, ()),
        },
        entry_serial=33,
        func_ea=0x180012B60,
    )
    pred_block = flow_graph.get_block(33)
    assert pred_block is not None

    assert is_supplemental_feeder_bypass(
        flow_graph=flow_graph,
        pred_serial=33,
        pred_block=pred_block,
        state_value=0x27EEEA11,
        exact_dispatch_target=None,
        target_entry=34,
        bst_blocks={2},
        supported_entries=set(),
        owned_exact_sources=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        dag=SimpleNamespace(edges=()),
        state_has_semantic_support_fn=lambda *_args, **_kwargs: False,
        can_reach_return_fn=lambda *_args, **_kwargs: True,
    )


def test_walk_bst_dispatcher_follows_goto_to_non_bst_target() -> None:
    tails = {
        2: BstGotoTail(target=3),
        3: BstGotoTail(target=20),
    }

    assert walk_bst_dispatcher(
        root=2,
        bst_blocks={2, 3},
        state_value=0x42,
        tail_for_block_fn=tails.get,
        is_conditional_taken_fn=lambda *_args: None,
    ) == 20


def test_walk_bst_dispatcher_follows_taken_conditional_target() -> None:
    tails = {
        2: BstConditionalTail(
            opcode=100,
            rhs_value=0x10,
            rhs_size=4,
            taken_target=7,
            successors=(3, 7),
        ),
        7: BstGotoTail(target=30),
    }

    assert walk_bst_dispatcher(
        root=2,
        bst_blocks={2, 7},
        state_value=0x10,
        tail_for_block_fn=tails.get,
        is_conditional_taken_fn=lambda opcode, state, rhs, size: (
            opcode == 100 and state == rhs and size == 4
        ),
    ) == 30


def test_walk_bst_dispatcher_prefers_structural_fallthrough_successor() -> None:
    tails = {
        2: BstConditionalTail(
            opcode=100,
            rhs_value=0x10,
            rhs_size=4,
            taken_target=7,
            successors=(3, 7),
        ),
        3: BstGotoTail(target=40),
    }

    assert walk_bst_dispatcher(
        root=2,
        bst_blocks={2, 3},
        state_value=0x11,
        tail_for_block_fn=tails.get,
        is_conditional_taken_fn=lambda *_args: False,
    ) == 40


def test_walk_bst_dispatcher_returns_none_on_cycle() -> None:
    tails = {
        2: BstGotoTail(target=3),
        3: BstGotoTail(target=2),
    }

    assert walk_bst_dispatcher(
        root=2,
        bst_blocks={2, 3},
        state_value=0x42,
        tail_for_block_fn=tails.get,
        is_conditional_taken_fn=lambda *_args: None,
    ) is None


def test_walk_bst_dispatcher_returns_none_when_conditional_unknown() -> None:
    tails = {
        2: BstConditionalTail(
            opcode=100,
            rhs_value=0x10,
            rhs_size=4,
            taken_target=7,
            successors=(3, 7),
        ),
    }

    assert walk_bst_dispatcher(
        root=2,
        bst_blocks={2},
        state_value=0x10,
        tail_for_block_fn=tails.get,
        is_conditional_taken_fn=lambda *_args: None,
    ) is None


def test_resolve_dispatcher_trampoline_skip_candidate_accepts_bst_resolved_target() -> None:
    decision = resolve_dispatcher_trampoline_skip_candidate(
        source_block=10,
        bst_root=2,
        bst_blocks={2, 3},
        nsucc=1,
        goto_target=2,
        direct_use_def_veto=False,
        state_value_fn=lambda: 0x1234,
        target_for_state_fn=lambda state: 50 if state == 0x1234 else None,
        target_exists_fn=lambda target: target == 50,
        block_count=100,
    )

    assert decision.is_admitted
    assert decision.source_block == 10
    assert decision.old_target == 2
    assert decision.target_block == 50
    assert decision.state_value == 0x1234
    assert decision.rejection_reason is None


def test_resolve_dispatcher_trampoline_skip_candidate_rejects_direct_veto_before_callbacks() -> None:
    callback_calls: list[str] = []

    decision = resolve_dispatcher_trampoline_skip_candidate(
        source_block=10,
        bst_root=2,
        bst_blocks={2, 3},
        nsucc=1,
        goto_target=2,
        direct_use_def_veto=True,
        state_value_fn=lambda: callback_calls.append("state") or 0x1234,
        target_for_state_fn=lambda _state: callback_calls.append("target") or 50,
        target_exists_fn=lambda _target: callback_calls.append("exists") or True,
        block_count=100,
    )

    assert not decision.is_admitted
    assert decision.rejection_reason == "direct_use_def_veto"
    assert callback_calls == []


def test_resolve_dispatcher_trampoline_skip_candidate_requires_one_way_goto_to_bst() -> None:
    decision = resolve_dispatcher_trampoline_skip_candidate(
        source_block=10,
        bst_root=2,
        bst_blocks={2, 3},
        nsucc=2,
        goto_target=2,
        direct_use_def_veto=False,
        state_value_fn=lambda: 0x1234,
        target_for_state_fn=lambda _state: 50,
        target_exists_fn=lambda _target: True,
        block_count=100,
    )
    assert decision.rejection_reason == "source_not_1way"

    decision = resolve_dispatcher_trampoline_skip_candidate(
        source_block=10,
        bst_root=2,
        bst_blocks={2, 3},
        nsucc=1,
        goto_target=4,
        direct_use_def_veto=False,
        state_value_fn=lambda: 0x1234,
        target_for_state_fn=lambda _state: 50,
        target_exists_fn=lambda _target: True,
        block_count=100,
    )
    assert decision.rejection_reason == "goto_not_bst_root"


def test_resolve_dispatcher_trampoline_skip_candidate_rejects_unsafe_targets() -> None:
    common = dict(
        source_block=10,
        bst_root=2,
        bst_blocks={2, 3},
        nsucc=1,
        goto_target=2,
        direct_use_def_veto=False,
        state_value_fn=lambda: 0x1234,
        block_count=100,
    )

    decision = resolve_dispatcher_trampoline_skip_candidate(
        **common,
        target_for_state_fn=lambda _state: 3,
        target_exists_fn=lambda _target: True,
    )
    assert decision.rejection_reason == "target_is_bst"

    decision = resolve_dispatcher_trampoline_skip_candidate(
        **common,
        target_for_state_fn=lambda _state: 10,
        target_exists_fn=lambda _target: True,
    )
    assert decision.rejection_reason == "target_is_source"

    decision = resolve_dispatcher_trampoline_skip_candidate(
        **common,
        target_for_state_fn=lambda _state: 150,
        target_exists_fn=lambda _target: True,
    )
    assert decision.rejection_reason == "target_out_of_range"

    decision = resolve_dispatcher_trampoline_skip_candidate(
        **common,
        target_for_state_fn=lambda _state: 50,
        target_exists_fn=lambda _target: False,
    )
    assert decision.rejection_reason == "target_missing"
