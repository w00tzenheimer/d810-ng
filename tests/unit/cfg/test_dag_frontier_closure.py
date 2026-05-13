from __future__ import annotations

from types import SimpleNamespace

import d810.cfg.dag_frontier_closure as dag_frontier_closure
from d810.cfg.dag_frontier_closure import (
    _build_indexes,
    _choices_for_observed_edge,
    plan_dag_authoritative_frontier_closure,
)
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    DuplicateBlock,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.state_dag_key import StateDagNodeKey


def _block(serial: int, succs: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=(),
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(),
    )


def _flow(succs_by_block: dict[int, tuple[int, ...]]) -> FlowGraph:
    pred_map: dict[int, list[int]] = {serial: [] for serial in succs_by_block}
    for serial, succs in succs_by_block.items():
        for succ in succs:
            pred_map.setdefault(succ, []).append(serial)
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=1,
            succs=succs,
            preds=tuple(sorted(pred_map.get(serial, ()))),
            flags=0,
            start_ea=0x1000 + serial,
            insn_snapshots=(),
        )
        for serial, succs in succs_by_block.items()
    }
    return FlowGraph(blocks=blocks, entry_serial=10, func_ea=0x1000)


def _flow_with_instructions(
    succs_by_block: dict[int, tuple[int, ...]],
    insns_by_block: dict[int, tuple[InsnSnapshot, ...]],
) -> FlowGraph:
    pred_map: dict[int, list[int]] = {serial: [] for serial in succs_by_block}
    for serial, succs in succs_by_block.items():
        for succ in succs:
            pred_map.setdefault(succ, []).append(serial)
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=2 if len(succs) == 2 else 1,
            succs=succs,
            preds=tuple(sorted(pred_map.get(serial, ()))),
            flags=0,
            start_ea=0x1000 + serial,
            insn_snapshots=insns_by_block.get(serial, ()),
        )
        for serial, succs in succs_by_block.items()
    }
    return FlowGraph(blocks=blocks, entry_serial=129, func_ea=0x1800134E0)


def _state_jz(state_const: int, target: int) -> InsnSnapshot:
    try:
        import ida_hexrays  # type: ignore

        opcode = int(ida_hexrays.m_jz)
    except Exception:
        opcode = 5
    state_var = MopSnapshot(t=3, size=4, stkoff=0x7BC)
    const = MopSnapshot(t=2, size=4, value=state_const)
    dest = MopSnapshot(t=5, size=0, block_ref=target)
    return InsnSnapshot(
        opcode=opcode,
        ea=0x180000000 + target,
        operands=(state_var, const, dest),
        operand_slots=(("l", state_var), ("r", const), ("d", dest)),
        l=state_var,
        r=const,
        d=dest,
    )


def _state_jbe(state_const: int, target: int) -> InsnSnapshot:
    try:
        import ida_hexrays  # type: ignore

        opcode = int(ida_hexrays.m_jbe)
    except Exception:
        opcode = 48
    state_var = MopSnapshot(t=3, size=4, stkoff=0x7BC)
    const = MopSnapshot(t=2, size=4, value=state_const)
    dest = MopSnapshot(t=5, size=0, block_ref=target)
    return InsnSnapshot(
        opcode=opcode,
        ea=0x180000000 + target,
        operands=(state_var, const, dest),
        operand_slots=(("l", state_var), ("r", const), ("d", dest)),
        l=state_var,
        r=const,
        d=dest,
    )


def _state_mov(state_const: int) -> InsnSnapshot:
    try:
        import ida_hexrays  # type: ignore

        opcode = int(ida_hexrays.m_mov)
    except Exception:
        opcode = 4
    const = MopSnapshot(t=2, size=4, value=state_const)
    state_var = MopSnapshot(t=3, size=4, stkoff=0x7BC)
    return InsnSnapshot(
        opcode=opcode,
        ea=0x180000000 + state_const,
        operands=(const, state_var),
        operand_slots=(("l", const), ("d", state_var)),
        l=const,
        d=state_var,
    )


def _node(key: StateDagNodeKey, entry: int):
    return SimpleNamespace(
        key=key,
        handler_serial=entry,
        entry_anchor=entry,
        owned_blocks=(entry,),
        exclusive_blocks=(entry,),
        shared_suffix_blocks=(),
        local_segments=(),
    )


def _node_with_blocks(key: StateDagNodeKey, entry: int, *blocks: int):
    owned = tuple(dict.fromkeys((entry, *blocks)))
    return SimpleNamespace(
        key=key,
        handler_serial=entry,
        entry_anchor=entry,
        owned_blocks=owned,
        exclusive_blocks=owned,
        shared_suffix_blocks=(),
        local_segments=(),
    )


def _edge(
    source_key: StateDagNodeKey,
    target_key: StateDagNodeKey | None,
    *,
    source_block: int,
    target_entry: int | None,
    ordered_path: tuple[int, ...],
    kind: str = "TRANSITION",
    branch_arm: int | None = None,
):
    return SimpleNamespace(
        kind=SimpleNamespace(name=kind),
        source_key=source_key,
        target_key=target_key,
        target_entry_anchor=target_entry,
        source_anchor=SimpleNamespace(
            block_serial=source_block,
            branch_arm=branch_arm,
        ),
        ordered_path=ordered_path,
    )


def _scc(scc_id: int, *keys: StateDagNodeKey, is_cyclic: bool = False):
    return SimpleNamespace(
        scc_id=scc_id,
        nodes=frozenset(keys),
        is_cyclic=is_cyclic,
    )


def _dag():
    chunk = StateDagNodeKey(handler_serial=20, state_const=0xC)
    tail = StateDagNodeKey(handler_serial=10, state_const=0xD)
    exit_key = StateDagNodeKey(handler_serial=30, state_const=0xE)
    return SimpleNamespace(
        nodes=(
            _node(chunk, 20),
            _node(tail, 10),
            _node(exit_key, 30),
        ),
        edges=(
            _edge(chunk, tail, source_block=20, target_entry=10, ordered_path=(20,)),
            _edge(tail, exit_key, source_block=10, target_entry=30, ordered_path=(10,)),
        ),
        sccs=(
            _scc(0, chunk, is_cyclic=True),
            _scc(1, tail, is_cyclic=True),
            _scc(2, exit_key),
        ),
    )


def test_emits_dag_redirect_for_illegal_tail_to_chunk_backpath() -> None:
    flow = _flow({
        0: (20,),
        10: (0,),
        20: (10,),
        30: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=_dag(),
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.leaks_after == ()
    assert result.unresolved_frontiers == ()
    assert result.emitted_modifications == (
        RedirectGoto(from_serial=10, old_target=0, new_target=30),
    )


def test_closes_ordered_path_tail_instead_of_rewriting_internal_step() -> None:
    chunk = StateDagNodeKey(handler_serial=20, state_const=0xC)
    tail = StateDagNodeKey(handler_serial=10, state_const=0xD)
    exit_key = StateDagNodeKey(handler_serial=30, state_const=0xE)
    dag = SimpleNamespace(
        nodes=(
            _node(chunk, 20),
            _node(tail, 10),
            _node(exit_key, 30),
        ),
        edges=(
            _edge(chunk, tail, source_block=20, target_entry=10, ordered_path=(20,)),
            _edge(
                tail,
                exit_key,
                source_block=10,
                target_entry=30,
                ordered_path=(10, 11),
            ),
        ),
        sccs=(
            _scc(0, chunk, is_cyclic=True),
            _scc(1, tail, is_cyclic=True),
            _scc(2, exit_key),
        ),
    )
    flow = _flow({
        0: (20,),
        10: (11,),
        11: (0,),
        20: (10,),
        30: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.leaks_after == ()
    assert result.unresolved_frontiers == ()
    assert result.emitted_modifications == (
        RedirectGoto(from_serial=11, old_target=0, new_target=30),
    )


def test_prefers_ordered_path_step_over_target_entry_shortcut() -> None:
    source = StateDagNodeKey(handler_serial=10, state_const=0xA)
    target = StateDagNodeKey(handler_serial=30, state_const=0xB)
    dag = SimpleNamespace(
        nodes=(
            _node(source, 10),
            _node(target, 30),
        ),
        edges=(
            _edge(
                source,
                target,
                source_block=10,
                target_entry=30,
                ordered_path=(10, 11),
            ),
        ),
        sccs=(
            _scc(0, source, is_cyclic=True),
            _scc(1, target, is_cyclic=True),
        ),
    )

    choices = _choices_for_observed_edge(
        _build_indexes(dag),
        source=10,
        arm=None,
        observed_target=30,
        frontier_blocks=set(),
    )

    assert tuple(choice.target_block for choice in choices) == (11,)


def test_preserves_existing_target_entry_shortcut_without_destructive_drop() -> None:
    tail = StateDagNodeKey(handler_serial=129, state_const=0xA)
    chunk = StateDagNodeKey(handler_serial=171, state_const=0xB)
    dag = SimpleNamespace(
        nodes=(
            _node_with_blocks(tail, 129, 130, 155, 156),
            _node(chunk, 171),
        ),
        edges=(
            _edge(
                chunk,
                tail,
                source_block=155,
                target_entry=171,
                ordered_path=(155, 156),
            ),
        ),
        sccs=(
            _scc(11, tail, is_cyclic=True),
            _scc(19, chunk, is_cyclic=True),
        ),
    )
    flow = _flow({
        10: (129,),
        129: (130,),
        130: (155,),
        155: (156,),
        156: (129,),
        171: (129,),
    })
    bad_redirect = RedirectGoto(from_serial=155, old_target=156, new_target=171)

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[bad_redirect],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.dropped_modifications == ()
    assert result.emitted_modifications == ()
    assert result.modifications == (bad_redirect,)
    assert result.leaks_after


def test_stale_hazard_overrides_are_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("D810_DAG_FRONTIER_STALE_OVERRIDES", raising=False)
    flow = _flow({
        0: (20,),
        10: (0,),
        20: (10,),
        30: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=_dag(),
        flow_graph=flow,
        modifications=[RedirectGoto(from_serial=10, old_target=0, new_target=30)],
        dispatcher_serial=0,
    )

    assert result.leaks_before == ()
    assert result.stale_hazard_override_keys == frozenset()


def test_marks_existing_dag_redirect_as_stale_hazard_override(monkeypatch) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_STALE_OVERRIDES", "1")
    flow = _flow({
        0: (20,),
        10: (0,),
        20: (10,),
        30: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=_dag(),
        flow_graph=flow,
        modifications=[RedirectGoto(from_serial=10, old_target=0, new_target=30)],
        dispatcher_serial=0,
    )

    assert result.leaks_before == ()
    assert result.stale_hazard_override_keys == frozenset({(10, 0, 30)})


def test_preserves_existing_redirect_that_reopens_dispatcher_backpath() -> None:
    flow = _flow({
        0: (20,),
        10: (30,),
        20: (10,),
        30: (),
    })
    bad_redirect = RedirectGoto(from_serial=10, old_target=30, new_target=0)

    result = plan_dag_authoritative_frontier_closure(
        dag=_dag(),
        flow_graph=flow,
        modifications=[bad_redirect],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.leaks_after
    assert result.dropped_modifications == ()
    assert result.modifications == (bad_redirect,)


def test_preserves_dispatcher_insert_block_that_reopens_semantic_backpath() -> None:
    chunk = StateDagNodeKey(handler_serial=20, state_const=0xC)
    tail = StateDagNodeKey(handler_serial=10, state_const=0xD)
    exit_key = StateDagNodeKey(handler_serial=40, state_const=0xE)
    dag = SimpleNamespace(
        nodes=(
            _node(chunk, 20),
            _node(tail, 10),
            _node(exit_key, 40),
        ),
        edges=(
            _edge(chunk, tail, source_block=20, target_entry=10, ordered_path=(20,)),
            _edge(tail, exit_key, source_block=10, target_entry=40, ordered_path=(10,)),
        ),
        sccs=(
            _scc(0, chunk, is_cyclic=True),
            _scc(1, tail, is_cyclic=True),
            _scc(2, exit_key),
        ),
    )
    flow = _flow({
        0: (20,),
        10: (0,),
        20: (10,),
        40: (),
        41: (),
    })
    bad_insert = InsertBlock(
        pred_serial=10,
        old_target_serial=0,
        succ_serial=20,
        instructions=(),
    )

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[bad_insert],
        dispatcher_serial=0,
    )

    assert result.dropped_modifications == ()
    assert result.emitted_modifications == ()
    assert result.modifications == (bad_insert,)
    assert result.leaks_after


def test_does_not_close_same_dag_scc_alternate_successor_by_default(
    monkeypatch,
) -> None:
    monkeypatch.delenv("D810_DAG_FRONTIER_SAME_SCC_ALTERNATE", raising=False)
    tail = StateDagNodeKey(handler_serial=10, state_const=0xA)
    chunk = StateDagNodeKey(handler_serial=20, state_const=0xB)
    dag = SimpleNamespace(
        nodes=(
            _node_with_blocks(tail, 10, 11),
            _node(chunk, 20),
        ),
        edges=(
            _edge(chunk, tail, source_block=20, target_entry=10, ordered_path=(20,)),
        ),
        sccs=(
            _scc(0, tail, is_cyclic=True),
            _scc(1, chunk, is_cyclic=True),
        ),
    )
    flow = _flow({
        10: (20, 11),
        11: (10,),
        20: (10,),
        99: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.leaks_after
    assert result.emitted_modifications == ()
    assert len(result.unresolved_frontiers) == 1
    assert result.unresolved_frontiers[0].reason == "same_scc_alternate_disabled"
    assert result.unresolved_frontiers[0].source_block == 10
    assert result.unresolved_frontiers[0].observed_target == 20
    assert result.unresolved_frontiers[0].candidate_targets == (11,)
    unresolved_rows = [
        row for row in result.diagnostic_rows if row.kind == "unresolved"
    ]
    assert len(unresolved_rows) == 1
    assert unresolved_rows[0].reason == "same_scc_alternate_disabled"
    assert unresolved_rows[0].source_block == 10
    assert unresolved_rows[0].observed_target == 20
    assert unresolved_rows[0].branch_arm == 0
    assert unresolved_rows[0].candidate_targets == (11,)
    assert unresolved_rows[0].path == (10, 20)


def _bst_interval_frontier_dag():
    tail = StateDagNodeKey(handler_serial=131, state_const=0x0ACD0BD5)
    chunk = StateDagNodeKey(handler_serial=171, state_const=0x0D64F20F)
    return SimpleNamespace(
        nodes=(
            _node_with_blocks(tail, 131, 129, 174),
            _node(chunk, 171),
        ),
        edges=(
            _edge(chunk, tail, source_block=171, target_entry=131, ordered_path=(171,)),
        ),
        sccs=(
            _scc(11, tail, is_cyclic=True),
            _scc(19, chunk, is_cyclic=True),
        ),
    )


def _bst_interval_frontier_flow(
    *,
    candidate_succ: int = 131,
    observed_succ: int = 130,
    state_const: int = 0x0ACD0BD5,
) -> FlowGraph:
    return _flow_with_instructions(
        {
            129: (observed_succ, candidate_succ),
            observed_succ: (143,),
            143: (145,),
            145: (155,),
            155: (171,),
            171: (129,),
            candidate_succ: (174,),
            174: (129,),
        },
        {129: (_state_jz(state_const, candidate_succ),)},
    )


def _bst_interval_rows(
    *,
    singleton_hi: int = 0x0ACD0BD6,
    singleton_target: int = 131,
    observed_target: int = 130,
):
    return (
        SimpleNamespace(
            snapshot_id=5,
            row_index=0,
            lo=0x09EB3383,
            hi=0x0ACD0BD5,
            target_block=observed_target,
        ),
        SimpleNamespace(
            snapshot_id=5,
            row_index=1,
            lo=0x0ACD0BD5,
            hi=singleton_hi,
            target_block=singleton_target,
        ),
        SimpleNamespace(
            snapshot_id=5,
            row_index=2,
            lo=0x0ACD0BD6,
            hi=0x0D64F20F,
            target_block=observed_target,
        ),
    )


def test_closes_same_scc_frontier_with_bst_interval_singleton_proof(
    monkeypatch,
) -> None:
    monkeypatch.delenv("D810_DAG_FRONTIER_SAME_SCC_ALTERNATE", raising=False)

    result = plan_dag_authoritative_frontier_closure(
        dag=_bst_interval_frontier_dag(),
        flow_graph=_bst_interval_frontier_flow(),
        modifications=[],
        dispatcher_serial=0,
        bst_interval_rows=_bst_interval_rows(),
    )

    assert result.leaks_before
    assert result.leaks_after == ()
    assert result.unresolved_frontiers == ()
    assert result.emitted_modifications == (
        InsertBlock(
            pred_serial=129,
            old_target_serial=130,
            succ_serial=131,
            instructions=(),
        ),
    )
    assert len(result.resolved_frontiers) == 1
    assert result.resolved_frontiers[0].reason == "bst_interval_proven_frontier"
    resolved_rows = [
        row for row in result.diagnostic_rows if row.kind == "resolved"
    ]
    assert len(resolved_rows) == 1
    assert resolved_rows[0].reason == "bst_interval_proven_frontier"
    assert resolved_rows[0].source_block == 129
    assert resolved_rows[0].observed_target == 130
    assert resolved_rows[0].branch_arm == 0
    assert resolved_rows[0].candidate_targets == (131,)
    assert resolved_rows[0].payload["proof"] == "BST_INTERVAL_PROVEN_FRONTIER"
    assert resolved_rows[0].payload["state"] == "0x0ACD0BD5"


def test_explicit_bst_interval_rows_do_not_use_db_fallback(monkeypatch) -> None:
    def fail_db_fallback(_flow_graph):
        raise AssertionError("DB fallback should not run with explicit rows")

    monkeypatch.setattr(
        dag_frontier_closure,
        "_load_latest_bst_interval_rows",
        fail_db_fallback,
    )

    result = plan_dag_authoritative_frontier_closure(
        dag=_bst_interval_frontier_dag(),
        flow_graph=_bst_interval_frontier_flow(),
        modifications=[],
        dispatcher_serial=0,
        bst_interval_rows=_bst_interval_rows(),
    )

    assert result.unresolved_frontiers == ()
    assert result.resolved_frontiers[0].reason == "bst_interval_proven_frontier"


def test_rejects_bst_frontier_when_singleton_interval_is_not_singleton() -> None:
    result = plan_dag_authoritative_frontier_closure(
        dag=_bst_interval_frontier_dag(),
        flow_graph=_bst_interval_frontier_flow(),
        modifications=[],
        dispatcher_serial=0,
        bst_interval_rows=_bst_interval_rows(singleton_hi=0x0ACD0BD7),
    )

    assert result.emitted_modifications == ()
    assert result.leaks_after
    assert result.unresolved_frontiers[0].reason == "same_scc_alternate_disabled"


def test_rejects_bst_frontier_when_candidate_is_not_dag_entry() -> None:
    result = plan_dag_authoritative_frontier_closure(
        dag=_bst_interval_frontier_dag(),
        flow_graph=_bst_interval_frontier_flow(candidate_succ=132),
        modifications=[],
        dispatcher_serial=0,
        bst_interval_rows=_bst_interval_rows(singleton_target=132),
    )

    assert result.emitted_modifications == ()
    assert result.leaks_after
    assert result.unresolved_frontiers[0].reason == "no_dag_choice_for_source"


def test_rejects_bst_frontier_when_candidate_is_not_source_successor() -> None:
    result = plan_dag_authoritative_frontier_closure(
        dag=_bst_interval_frontier_dag(),
        flow_graph=_bst_interval_frontier_flow(candidate_succ=132),
        modifications=[],
        dispatcher_serial=0,
        bst_interval_rows=_bst_interval_rows(),
    )

    assert result.emitted_modifications == ()
    assert result.leaks_after
    assert result.unresolved_frontiers[0].reason == "no_dag_choice_for_source"


def test_rejects_bst_frontier_without_observed_range_sibling() -> None:
    result = plan_dag_authoritative_frontier_closure(
        dag=_bst_interval_frontier_dag(),
        flow_graph=_bst_interval_frontier_flow(),
        modifications=[],
        dispatcher_serial=0,
        bst_interval_rows=_bst_interval_rows(observed_target=140),
    )

    assert result.emitted_modifications == ()
    assert result.leaks_after
    assert result.unresolved_frontiers[0].reason == "same_scc_alternate_disabled"


def test_closes_dispatcher_state_residue_with_dag_chain_and_bst_interval() -> None:
    source_key = StateDagNodeKey(handler_serial=136, state_const=0x139F2922)
    target_key = StateDagNodeKey(handler_serial=20, state_const=0x6465D164)
    dag = SimpleNamespace(
        nodes=(
            _node_with_blocks(source_key, 136, 139, 140),
            _node(target_key, 20),
        ),
        edges=(
            _edge(
                source_key,
                target_key,
                source_block=139,
                target_entry=20,
                ordered_path=(136, 137, 139, 140),
                kind="CONDITIONAL_TRANSITION",
                branch_arm=0,
            ),
        ),
        sccs=(
            _scc(0, source_key),
            _scc(1, target_key),
        ),
    )
    flow = _flow_with_instructions(
        {
            129: (136,),
            2: (3, 112),
            3: (),
            20: (),
            112: (),
            136: (137,),
            137: (139,),
            139: (140, 141),
            140: (2,),
            141: (),
        },
        {
            2: (_state_jbe(0x37B42A3F, 112),),
            140: (_state_mov(0x63F502FA),),
        },
    )

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(
            SimpleNamespace(
                snapshot_id=5,
                row_index=75,
                lo=0x63D54756,
                hi=0x6465D165,
                target_block=20,
            ),
        ),
    )

    assert result.leaks_before == ()
    assert result.emitted_modifications == (
        RedirectGoto(from_serial=140, old_target=2, new_target=20),
    )
    assert len(result.resolved_frontiers) == 1
    assert (
        result.resolved_frontiers[0].reason
        == "dag_bst_interval_dispatcher_residue"
    )
    resolved_rows = [
        row for row in result.diagnostic_rows if row.kind == "resolved"
    ]
    assert len(resolved_rows) == 1
    assert (
        resolved_rows[0].reason
        == "dag_bst_interval_dispatcher_residue"
    )
    assert resolved_rows[0].source_block == 140
    assert resolved_rows[0].observed_target == 2
    assert resolved_rows[0].candidate_targets == (20,)
    assert resolved_rows[0].payload["proof"] == (
        "DAG_BST_INTERVAL_DISPATCHER_RESIDUE"
    )
    assert resolved_rows[0].payload["state"] == "0x63F502FA"


def test_rejects_dispatcher_state_residue_without_matching_bst_interval() -> None:
    source_key = StateDagNodeKey(handler_serial=136, state_const=0x139F2922)
    target_key = StateDagNodeKey(handler_serial=20, state_const=0x6465D164)
    dag = SimpleNamespace(
        nodes=(
            _node_with_blocks(source_key, 136, 139, 140),
            _node(target_key, 20),
        ),
        edges=(
            _edge(
                source_key,
                target_key,
                source_block=139,
                target_entry=20,
                ordered_path=(136, 137, 139, 140),
                kind="CONDITIONAL_TRANSITION",
                branch_arm=0,
            ),
        ),
        sccs=(
            _scc(0, source_key),
            _scc(1, target_key),
        ),
    )
    flow = _flow_with_instructions(
        {
            129: (136,),
            2: (3, 112),
            3: (),
            20: (),
            112: (),
            136: (137,),
            137: (139,),
            139: (140, 141),
            140: (2,),
            141: (),
        },
        {
            2: (_state_jbe(0x37B42A3F, 112),),
            140: (_state_mov(0x63F502FA),),
        },
    )

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(
            SimpleNamespace(
                snapshot_id=5,
                row_index=75,
                lo=0x63D54756,
                hi=0x6465D165,
                target_block=21,
            ),
        ),
    )

    assert result.emitted_modifications == ()
    assert result.resolved_frontiers == ()


def test_closes_direct_dag_bst_dispatcher_residue_without_scc_leak() -> None:
    source_key = StateDagNodeKey(handler_serial=56, state_const=0x7D9C16EC)
    target_key = StateDagNodeKey(handler_serial=42, state_const=0x72AFE1BC)
    dag = SimpleNamespace(
        nodes=(
            _node(source_key, 56),
            _node(target_key, 42),
        ),
        edges=(
            _edge(
                source_key,
                target_key,
                source_block=56,
                target_entry=42,
                ordered_path=(56,),
                kind="TRANSITION",
            ),
        ),
        sccs=(
            _scc(0, source_key),
            _scc(1, target_key),
        ),
    )
    flow = _flow_with_instructions(
        {
            129: (56,),
            2: (3, 62),
            3: (),
            42: (),
            56: (2,),
            62: (),
        },
        {
            2: (_state_jbe(0x37B42A3F, 62),),
            56: (_state_mov(0x72AFE1BC),),
        },
    )

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(
            SimpleNamespace(
                snapshot_id=5,
                row_index=40,
                lo=0x72AFE1BC,
                hi=0x72AFE1BD,
                target_block=42,
            ),
        ),
    )

    assert result.leaks_before == ()
    assert result.emitted_modifications == (
        RedirectGoto(from_serial=56, old_target=2, new_target=42),
    )
    assert len(result.resolved_frontiers) == 1
    assert (
        result.resolved_frontiers[0].reason
        == "dag_bst_interval_dispatcher_residue"
    )
    resolved_rows = [
        row for row in result.diagnostic_rows if row.kind == "resolved"
    ]
    assert len(resolved_rows) == 1
    assert (
        resolved_rows[0].reason
        == "dag_bst_interval_dispatcher_residue"
    )
    assert resolved_rows[0].source_block == 56
    assert resolved_rows[0].observed_target == 2
    assert resolved_rows[0].candidate_targets == (42,)
    assert resolved_rows[0].payload["proof"] == (
        "DAG_BST_INTERVAL_DISPATCHER_RESIDUE"
    )
    assert resolved_rows[0].payload["state"] == "0x72AFE1BC"


def test_rejects_direct_dag_bst_residue_when_only_path_step_is_proven() -> None:
    source_key = StateDagNodeKey(handler_serial=56, state_const=0x7D9C16EC)
    target_key = StateDagNodeKey(handler_serial=42, state_const=0x72AFE1BC)
    dag = SimpleNamespace(
        nodes=(
            _node(source_key, 56),
            _node(target_key, 42),
        ),
        edges=(
            _edge(
                source_key,
                target_key,
                source_block=56,
                target_entry=42,
                ordered_path=(56, 57),
                kind="TRANSITION",
            ),
        ),
        sccs=(
            _scc(0, source_key),
            _scc(1, target_key),
        ),
    )
    flow = _flow_with_instructions(
        {
            129: (56,),
            2: (3, 62),
            3: (),
            42: (),
            56: (2,),
            57: (42,),
            62: (),
        },
        {
            2: (_state_jbe(0x37B42A3F, 62),),
            56: (_state_mov(0x72AFE1BC),),
        },
    )

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(
            SimpleNamespace(
                snapshot_id=5,
                row_index=40,
                lo=0x72AFE1BC,
                hi=0x72AFE1BD,
                target_block=42,
            ),
        ),
    )

    assert result.emitted_modifications == ()
    assert result.resolved_frontiers == ()


def _shared_condition_clone_dag(
    *,
    include_entry_edge: bool = True,
    include_arm_edges: bool = True,
):
    entry_key = StateDagNodeKey(handler_serial=52, state_const=0x737189D5)
    condition_key = StateDagNodeKey(handler_serial=81, state_const=0x5FE86821)
    false_key = StateDagNodeKey(handler_serial=63, state_const=0x45B18E82)
    true_key = StateDagNodeKey(handler_serial=117, state_const=0x02760C0D)
    edges = []
    if include_entry_edge:
        edges.append(
            _edge(
                entry_key,
                condition_key,
                source_block=52,
                target_entry=81,
                ordered_path=(52,),
                kind="TRANSITION",
            )
        )
    if include_arm_edges:
        edges.extend(
            (
                _edge(
                    condition_key,
                    false_key,
                    source_block=81,
                    branch_arm=0,
                    target_entry=63,
                    ordered_path=(81, 82),
                    kind="CONDITIONAL_TRANSITION",
                ),
                _edge(
                    condition_key,
                    true_key,
                    source_block=81,
                    branch_arm=1,
                    target_entry=117,
                    ordered_path=(81, 83),
                    kind="CONDITIONAL_TRANSITION",
                ),
            )
        )
    return SimpleNamespace(
        nodes=(
            _node(entry_key, 52),
            _node_with_blocks(condition_key, 81, 82, 83),
            _node(false_key, 63),
            _node(true_key, 117),
        ),
        edges=tuple(edges),
        sccs=(
            _scc(0, entry_key),
            _scc(1, condition_key, is_cyclic=True),
            _scc(2, false_key),
            _scc(3, true_key),
        ),
    )


def _shared_condition_clone_flow(*, base_pred_targets_condition: bool = True) -> FlowGraph:
    pred_succ = (81,) if base_pred_targets_condition else (2,)
    return _flow_with_instructions(
        {
            129: (2,),
            2: (3, 112),
            3: (),
            50: (52,),
            52: pred_succ,
            79: (80, 81),
            80: (),
            81: (82, 83),
            82: (),
            83: (),
            112: (),
            117: (),
            239: (81,),
        },
        {
            2: (_state_jbe(0x37B42A3F, 112),),
            81: (_state_mov(0x5FE86821), _state_jz(0x1234, 83)),
        },
    )


def test_clones_dag_backed_shared_condition_entry(monkeypatch) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_SHARED_CONDITION_CLONE", "1")

    result = plan_dag_authoritative_frontier_closure(
        dag=_shared_condition_clone_dag(),
        flow_graph=_shared_condition_clone_flow(),
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(),
    )

    assert result.emitted_modifications == (
        DuplicateBlock(
            source_block=81,
            target_block=None,
            pred_serial=52,
            patch_kind="dag_entry_shared_condition_clone",
        ),
    )
    assert len(result.resolved_frontiers) == 1
    assert result.resolved_frontiers[0].reason == "dag_entry_shared_condition_clone"
    assert result.resolved_frontiers[0].source_block == 52
    assert result.resolved_frontiers[0].target_block == 81

    resolved_rows = [
        row for row in result.diagnostic_rows if row.kind == "resolved"
    ]
    assert len(resolved_rows) == 1
    assert resolved_rows[0].reason == "dag_entry_shared_condition_clone"
    assert resolved_rows[0].payload["proof"] == "DAG_ENTRY_SHARED_CONDITION_CLONE"


def test_shared_condition_clone_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_SHARED_CONDITION_CLONE", "0")

    result = plan_dag_authoritative_frontier_closure(
        dag=_shared_condition_clone_dag(),
        flow_graph=_shared_condition_clone_flow(),
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(),
    )

    assert result.emitted_modifications == ()
    assert result.resolved_frontiers == ()


def test_replaces_dag_redirect_with_shared_condition_clone(monkeypatch) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_SHARED_CONDITION_CLONE", "1")
    existing = RedirectGoto(from_serial=52, old_target=2, new_target=81)

    result = plan_dag_authoritative_frontier_closure(
        dag=_shared_condition_clone_dag(),
        flow_graph=_shared_condition_clone_flow(base_pred_targets_condition=False),
        modifications=[existing],
        dispatcher_serial=2,
        bst_interval_rows=(),
    )

    assert result.dropped_modifications == (existing,)
    assert result.emitted_modifications == (
        CreateConditionalRedirect(
            source_block=52,
            ref_block=81,
            conditional_target=83,
            fallthrough_target=82,
        ),
    )
    assert result.resolved_frontiers[0].reason == "dag_entry_shared_condition_clone"


def test_rejects_shared_condition_clone_without_dag_entry_edge(monkeypatch) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_SHARED_CONDITION_CLONE", "1")

    result = plan_dag_authoritative_frontier_closure(
        dag=_shared_condition_clone_dag(include_entry_edge=False),
        flow_graph=_shared_condition_clone_flow(),
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(),
    )

    assert result.emitted_modifications == ()
    assert result.resolved_frontiers == ()


def test_rejects_shared_condition_clone_without_dag_arm_edges(monkeypatch) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_SHARED_CONDITION_CLONE", "1")

    result = plan_dag_authoritative_frontier_closure(
        dag=_shared_condition_clone_dag(include_arm_edges=False),
        flow_graph=_shared_condition_clone_flow(),
        modifications=[],
        dispatcher_serial=2,
        bst_interval_rows=(),
    )

    assert result.emitted_modifications == ()
    assert result.resolved_frontiers == ()


def test_can_close_dispatch_frontier_to_same_dag_scc_alternate_successor(
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_DAG_FRONTIER_SAME_SCC_ALTERNATE", "1")
    tail = StateDagNodeKey(handler_serial=10, state_const=0xA)
    chunk = StateDagNodeKey(handler_serial=20, state_const=0xB)
    dag = SimpleNamespace(
        nodes=(
            _node_with_blocks(tail, 10, 11),
            _node(chunk, 20),
        ),
        edges=(
            _edge(chunk, tail, source_block=20, target_entry=10, ordered_path=(20,)),
        ),
        sccs=(
            _scc(0, tail, is_cyclic=True),
            _scc(1, chunk, is_cyclic=True),
        ),
    )
    flow = _flow({
        10: (20, 11),
        11: (10,),
        20: (10,),
        99: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.leaks_after == ()
    assert result.unresolved_frontiers == ()
    assert result.emitted_modifications == (
        InsertBlock(
            pred_serial=10,
            old_target_serial=20,
            succ_serial=11,
            instructions=(),
        ),
    )


def test_does_not_close_dispatch_frontier_without_same_dag_scc_alternate() -> None:
    tail = StateDagNodeKey(handler_serial=10, state_const=0xA)
    chunk = StateDagNodeKey(handler_serial=20, state_const=0xB)
    other = StateDagNodeKey(handler_serial=11, state_const=0xC)
    dag = SimpleNamespace(
        nodes=(
            _node(tail, 10),
            _node(chunk, 20),
            _node(other, 11),
        ),
        edges=(
            _edge(chunk, tail, source_block=20, target_entry=10, ordered_path=(20,)),
        ),
        sccs=(
            _scc(0, tail, is_cyclic=True),
            _scc(1, chunk, is_cyclic=True),
            _scc(2, other),
        ),
    )
    flow = _flow({
        10: (20, 11),
        11: (10,),
        20: (10,),
        99: (),
    })

    result = plan_dag_authoritative_frontier_closure(
        dag=dag,
        flow_graph=flow,
        modifications=[],
        dispatcher_serial=0,
    )

    assert result.leaks_before
    assert result.leaks_after
    assert result.emitted_modifications == ()
    assert len(result.unresolved_frontiers) == 1
    assert result.unresolved_frontiers[0].reason == "no_dag_choice_for_source"
