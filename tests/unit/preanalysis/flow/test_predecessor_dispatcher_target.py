from dataclasses import replace
from types import SimpleNamespace

from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainAnalysisResult,
)
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    collect_predecessor_dispatcher_target_facts,
    project_predecessor_dispatcher_target_observations,
    resolve_predecessor_dispatcher_target,
)
from d810.analyses.control_flow.dispatcher_discovery_facts import (
    predecessor_dispatcher_target_observation,
)
from d810.analyses.control_flow import (
    predecessor_dispatcher_target as predecessor_target_module,
)
from d810.analyses.control_flow.transition_builder import (
    StateTransition,
    TransitionResult,
)
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)


_NATIVE_ENTRY_STATE = 0x16AA65E9
_NATIVE_LATER_STATE = 0x079323F9
_NATIVE_DECOY_STATE = 0x1
_NATIVE_ENTRY_EA = 0x180014E30
_NATIVE_LATER_EA = 0x180015115


def _native_identity_dispatcher_fixture():
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=_NATIVE_ENTRY_STATE,
                target_block=2,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
                row_kind="dispatcher_self_loop",
            ),
            StateDispatcherRow(
                state_const=_NATIVE_LATER_STATE,
                target_block=2,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
                row_kind="dispatcher_self_loop",
            ),
            StateDispatcherRow(
                state_const=_NATIVE_DECOY_STATE,
                target_block=2,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2, 3}),
        state_var_stkoff=52,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    range_evidence = ConditionChainAnalysisResult(
        dispatcher=IntervalDispatcher(
            [
                IntervalRow(lo=0x1000, hi=0x1001, target=7),
                IntervalRow(lo=0x2000, hi=0x2001, target=8),
                IntervalRow(
                    lo=_NATIVE_ENTRY_STATE, hi=_NATIVE_ENTRY_STATE + 1, target=7
                ),
                IntervalRow(
                    lo=_NATIVE_LATER_STATE, hi=_NATIVE_LATER_STATE + 1, target=8
                ),
                IntervalRow(
                    lo=_NATIVE_DECOY_STATE, hi=_NATIVE_DECOY_STATE + 1, target=9
                ),
            ]
        )
    )
    return dispatch_map, range_evidence


def _native_resolution(
    *,
    state: int,
    target: int | None,
    reason: str,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    source_instruction_ea: int | None = _NATIVE_ENTRY_EA,
    source_block_serial: int = 1,
):
    return SimpleNamespace(
        fact_id=f"resolution:{state:X}:{state_var_reg}",
        source_block_serial=source_block_serial,
        source_state_const_hex=f"0x{state:016X}",
        resolved_next_block_serial=target,
        resolution_kind="state_dispatcher_map",
        resolution_reason=reason,
        source_instruction_ea=source_instruction_ea,
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )


def _path_local_entry_fixture(
    *,
    write_value: int = _NATIVE_ENTRY_STATE,
    source_succs: tuple[int, ...] = (3,),
    entry_succs: tuple[int, ...] = (4,),
    conflicting_write: int | None = None,
    unsafe_trailing: bool = False,
    source_register: int = 8,
    source_value: int = _NATIVE_ENTRY_STATE,
    source_size: int = 4,
    duplicate_source_instruction: bool = False,
    root_predicate: PredicateKind = PredicateKind.NE,
):
    """Build the exact source -> entry -> DAG-root snapshot corridor."""

    def block(
        serial: int,
        succs: tuple[int, ...],
        insns: tuple[InsnSnapshot, ...] = (),
    ) -> BlockSnapshot:
        return BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=succs,
            preds=(),
            flags=0,
            start_ea=serial,
            insn_snapshots=insns,
        )

    state_write = InsnSnapshot(
        opcode=0,
        ea=0x180014E6B,
        operands=(),
        l=MopSnapshot(size=4, value=write_value, kind=OperandKind.NUMBER),
        d=MopSnapshot(size=4, stkoff=52, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )
    if conflicting_write is not None:
        entry_insns = (
            state_write,
            replace(
                state_write,
                ea=0x180014E6C,
                l=MopSnapshot(
                    size=4,
                    value=conflicting_write,
                    kind=OperandKind.NUMBER,
                ),
            ),
        )
    else:
        entry_insns = (state_write,)
    if unsafe_trailing:
        entry_insns += (
            InsnSnapshot(
                opcode=0,
                ea=0x180014E6C,
                operands=(),
                l=MopSnapshot(size=4, value=1, kind=OperandKind.NUMBER),
                d=MopSnapshot(size=4, reg=9, kind=OperandKind.REGISTER),
                kind=InsnKind.MOV,
            ),
        )
    source_insn = InsnSnapshot(
        opcode=0,
        ea=_NATIVE_ENTRY_EA,
        native_ea=_NATIVE_ENTRY_EA,
        operands=(),
        l=MopSnapshot(
            size=source_size,
            value=source_value,
            kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(
            size=source_size,
            reg=source_register,
            kind=OperandKind.REGISTER,
        ),
        kind=InsnKind.MOV,
    )
    source_insns = (source_insn,)
    if duplicate_source_instruction:
        source_insns += (replace(source_insn, ea=_NATIVE_ENTRY_EA),)

    graph = FlowGraph(
        blocks={
            1: block(
                1,
                source_succs,
                source_insns,
            ),
            3: block(3, entry_succs, entry_insns),
            4: block(
                4,
                (30, 20),
                (
                    InsnSnapshot(
                        opcode=0,
                        ea=4,
                        operands=(),
                        kind=InsnKind.EQUALITY_JUMP,
                        branch_predicate=root_predicate,
                        l=MopSnapshot(
                            size=4,
                            stkoff=52,
                            kind=OperandKind.STACK,
                        ),
                        r=MopSnapshot(
                            size=4,
                            value=0,
                            kind=OperandKind.NUMBER,
                        ),
                    ),
                ),
            ),
            20: block(20, (22,)),
            22: block(
                22,
                (122, 23),
                (
                    InsnSnapshot(
                        opcode=0,
                        ea=22,
                        operands=(),
                        kind=InsnKind.EQUALITY_JUMP,
                        branch_predicate=PredicateKind.NE,
                        l=MopSnapshot(
                            size=4,
                            stkoff=52,
                            kind=OperandKind.STACK,
                        ),
                        r=MopSnapshot(
                            size=4,
                            value=_NATIVE_ENTRY_STATE,
                            kind=OperandKind.NUMBER,
                        ),
                    ),
                ),
            ),
            23: block(23, ()),
            30: block(30, ()),
            # The interval row's coarse target is a dispatcher-region anchor,
            # not the walk start.  The canonical replay must begin at DAG root
            # 4 and never use this block's unrelated branch shape.
            9: block(9, (30, 23)),
            10: block(10, ()),
            122: block(122, ()),
        },
        entry_serial=1,
        func_ea=0,
    )
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=_NATIVE_ENTRY_STATE,
                target_block=9,
                dispatcher_block=4,
                compare_block=22,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=3,
        dispatcher_blocks=frozenset({3, 4, 9, 20, 22}),
        state_var_stkoff=52,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    range_evidence = ConditionChainAnalysisResult(
        dispatcher=IntervalDispatcher(
            [
                IntervalRow(
                    lo=_NATIVE_ENTRY_STATE,
                    hi=_NATIVE_ENTRY_STATE + 1,
                    target=9,
                )
            ]
        ),
        decision_dag=DecisionDag(
            32,
            {
                4: RouteComparison(4, "jnz", 0, 9, 30),
            },
            root=4,
        ),
        state_var_stkoff=52,
    )
    return graph, dispatch_map, range_evidence


def test_resolves_predecessor_target_from_exact_dispatcher_row() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x20,
                target_block=7,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="jz_taken",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2, 3}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )

    fact = resolve_predecessor_dispatcher_target(
        predecessor_block_serial=5,
        dispatcher_entry_serial=2,
        state_const=0x20,
        state_dispatcher_map=dispatch_map,
        source_state_const=0x10,
        transition_provenance_kind="global_or_state_write",
        condition_block_serial=5,
        state_var_stkoff=0x30,
    )

    assert fact is not None
    assert fact.predecessor_block_serial == 5
    assert fact.state_const == 0x20
    assert fact.target_block_serial == 7
    assert fact.resolver_kind == "state_dispatcher_map_exact_row"
    assert fact.row_kind == "handler"
    assert fact.dispatcher_block_serial == 2
    assert fact.compare_block_serial == 3
    assert fact.branch_kind == "jz_taken"
    assert fact.row_lo_inclusive == 0x20
    assert fact.row_hi_exclusive == 0x21
    assert fact.source_state_const == 0x10
    assert fact.transition_provenance_kind == "global_or_state_write"


def test_resolves_predecessor_target_from_interval_dispatcher_row() -> None:
    range_evidence = ConditionChainAnalysisResult(
        dispatcher=IntervalDispatcher(
            [
                IntervalRow(lo=0x100, hi=0x120, target=11),
                IntervalRow(lo=0x200, hi=0x201, target=12),
            ]
        )
    )

    fact = resolve_predecessor_dispatcher_target(
        predecessor_block_serial=9,
        dispatcher_entry_serial=4,
        state_const=0x118,
        range_evidence=range_evidence,
    )

    assert fact is not None
    assert fact.target_block_serial == 11
    assert fact.resolver_kind == "interval_dispatcher_row"
    assert fact.row_kind == "interval_range"
    assert fact.row_lo_inclusive == 0x100
    assert fact.row_hi_exclusive == 0x120


def test_collects_transition_target_facts_with_transition_provenance() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0xF6A20,
                target_block=8,
                dispatcher_block=4,
                compare_block=4,
                branch_kind="jz_taken",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=4,
        dispatcher_blocks=frozenset({4}),
        state_var_stkoff=0x28,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    result = TransitionResult(
        transitions=[
            StateTransition(
                from_state=0xF6A1F,
                to_state=0xF6A20,
                from_block=7,
                condition_block=7,
                is_conditional=True,
                provenance_kind="global_or_state_write",
            )
        ],
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=result,
        dispatcher_entry_serial=4,
        state_dispatcher_map=dispatch_map,
        state_var_stkoff=0x28,
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.predecessor_block_serial == 7
    assert fact.source_state_const == 0xF6A1F
    assert fact.state_const == 0xF6A20
    assert fact.target_block_serial == 8
    assert fact.transition_provenance_kind == "global_or_state_write"
    assert fact.condition_block_serial == 7
    assert fact.state_var_stkoff == 0x28


def test_resolution_native_ea_is_preserved_and_interval_handler_beats_dispatcher_exact_row() -> None:
    state = 0x16AA65E9
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=state,
                target_block=2,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="dispatcher_self_loop",
                router_kind=RouterKind.CONDITION_CHAIN,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2, 3}),
        state_var_stkoff=52,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    range_evidence = ConditionChainAnalysisResult(
        dispatcher=IntervalDispatcher(
            [
                IntervalRow(lo=state, hi=state + 1, target=7),
                IntervalRow(lo=0x1000, hi=0x1001, target=7),
            ]
        )
    )
    support = SimpleNamespace(
        source_block_serial=9,
        source_state_const_hex="0x0000000000001000",
        resolved_next_block_serial=7,
        resolution_kind="state_dispatcher_map",
        resolution_reason="resolved_exact_state",
        source_instruction_ea=None,
        state_var_stkoff=52,
        state_var_reg=None,
    )
    resolution = SimpleNamespace(
        source_block_serial=1,
        source_state_const_hex=f"0x{state:016X}",
        resolved_next_block_serial=None,
        resolution_kind="state_dispatcher_map",
        resolution_reason="target_is_dispatcher_block",
        source_instruction_ea=0x7FF855576BA0,
        state_var_stkoff=52,
        state_var_reg=None,
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, resolution),
        state_var_stkoff=52,
    )
    fact = next(
        fact for fact in facts if fact.source_instruction_ea == 0x7FF855576BA0
    )

    assert fact.target_block_serial == 7
    assert fact.resolver_kind == "interval_dispatcher_row"
    assert fact.source_instruction_ea == 0x7FF855576BA0
    assert fact.state_var_stkoff == 52
    assert fact.state_var_reg is None
    assert fact.to_dict()["source_instruction_ea"] == 0x7FF855576BA0


def test_collects_report_target_facts_for_resolved_handler_edges() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0xF6A1E,
                target_block=6,
                dispatcher_block=4,
                compare_block=4,
                branch_kind="fallthrough",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=4,
        dispatcher_blocks=frozenset({4}),
        state_var_stkoff=0x28,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    report = SimpleNamespace(
        rows=(
            SimpleNamespace(
                state_const=0xF6A20,
                handler_serial=8,
                next_state=0xF6A1E,
                conditional_states=(),
            ),
        )
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=4,
        state_dispatcher_map=dispatch_map,
        transition_report=report,
        state_var_stkoff=0x28,
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.predecessor_block_serial == 8
    assert fact.source_state_const == 0xF6A20
    assert fact.state_const == 0xF6A1E
    assert fact.target_block_serial == 6
    assert fact.transition_provenance_kind == "transition_report"


def test_collects_state_dag_target_facts_for_resolved_edges() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0xF6A1E,
                target_block=6,
                dispatcher_block=4,
                compare_block=4,
                branch_kind="fallthrough",
                router_kind=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=4,
        dispatcher_blocks=frozenset({4}),
        state_var_stkoff=0x28,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    dag = SimpleNamespace(
        edges=(
            SimpleNamespace(
                kind=SimpleNamespace(name="TRANSITION"),
                source_key=SimpleNamespace(state_const=0xF6A20, handler_serial=8),
                source_anchor=SimpleNamespace(block_serial=8),
                target_state=0xF6A1E,
            ),
        )
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=4,
        state_dispatcher_map=dispatch_map,
        dag=dag,
        state_var_stkoff=0x28,
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.predecessor_block_serial == 8
    assert fact.source_state_const == 0xF6A20
    assert fact.state_const == 0xF6A1E
    assert fact.target_block_serial == 6
    assert fact.transition_provenance_kind == "state_dag_transition"


def test_identity_selector_deduplicates_successful_handler_support() -> None:
    selector = getattr(
        predecessor_target_module,
        "select_supported_transition_identity",
        None,
    )
    assert selector is not None

    selected = selector(
        (
            _native_resolution(
                state=0x1000,
                target=7,
                reason="resolved_exact_state",
                state_var_stkoff=None,
                state_var_reg=8,
                source_instruction_ea=None,
            ),
            _native_resolution(
                state=0x1000,
                target=7,
                reason="resolved_exact_state",
                state_var_stkoff=None,
                state_var_reg=8,
                source_instruction_ea=None,
            ),
        ),
        dispatcher_topology_serials=frozenset({2, 3}),
    )

    assert selected == (None, 8)


def test_handler_serials_in_range_metadata_do_not_block_identity_support() -> None:
    dispatch_map, _range_evidence = _native_identity_dispatcher_fixture()
    # These metadata containers are intentionally shaped like the broad
    # duck-typed evidence accepted by the collector, but serial 7 is a handler
    # leaf, not a dispatcher comparison block.  It must remain eligible as a
    # successful support target for identity selection.
    range_evidence = SimpleNamespace(
        dispatcher=IntervalDispatcher(
            [
                IntervalRow(lo=0x1000, hi=0x1001, target=7),
                IntervalRow(
                    lo=_NATIVE_ENTRY_STATE,
                    hi=_NATIVE_ENTRY_STATE + 1,
                    target=7,
                ),
            ]
        ),
        condition_chain_blocks=(7,),
        decision_dag=SimpleNamespace(nodes=(7,)),
    )
    support = _native_resolution(
        state=0x1000,
        target=7,
        reason="resolved_exact_state",
        state_var_stkoff=None,
        state_var_reg=8,
        source_instruction_ea=None,
        source_block_serial=9,
    )
    candidate = _native_resolution(
        state=_NATIVE_ENTRY_STATE,
        target=None,
        reason="target_is_dispatcher_block",
        state_var_stkoff=None,
        state_var_reg=8,
        source_instruction_ea=_NATIVE_ENTRY_EA,
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        state_var_stkoff=52,
    )

    # The selected dispatcher identity is (stkoff=52, reg=None).  A raw
    # candidate carrying only (reg=8) is not enough to bridge that identity;
    # the current-snapshot alias proof is intentionally absent here.
    entry_facts = [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ]
    assert entry_facts == []


def test_native_entry_fallback_selects_only_unique_supported_identity_family() -> None:
    dispatch_map, range_evidence = _native_identity_dispatcher_fixture()
    resolutions = (
        _native_resolution(
            state=0x1000,
            target=7,
            reason="resolved_exact_state",
            state_var_stkoff=None,
            state_var_reg=8,
            source_instruction_ea=None,
        ),
        _native_resolution(
            state=0x2000,
            target=8,
            reason="resolved_exact_state",
            state_var_stkoff=None,
            state_var_reg=8,
            source_instruction_ea=None,
        ),
        _native_resolution(
            state=_NATIVE_DECOY_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=0,
        ),
        _native_resolution(
            state=_NATIVE_ENTRY_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=0,
        ),
        _native_resolution(
            state=_NATIVE_ENTRY_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=8,
        ),
        _native_resolution(
            state=_NATIVE_LATER_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=8,
            source_instruction_ea=_NATIVE_LATER_EA,
        ),
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=resolutions,
        state_var_stkoff=52,
    )

    native_entry_facts = {
        fact.state_const
        for fact in facts
        if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    }
    assert native_entry_facts == set()
    assert {
        fact.state_const
        for fact in facts
        if fact.source_instruction_ea == _NATIVE_LATER_EA
    } == set()


def test_identity_selector_abstains_for_multiple_supported_families() -> None:
    dispatch_map, range_evidence = _native_identity_dispatcher_fixture()
    resolutions = (
        _native_resolution(
            state=0x1000,
            target=7,
            reason="resolved_exact_state",
            state_var_stkoff=None,
            state_var_reg=8,
            source_instruction_ea=None,
        ),
        _native_resolution(
            state=0x2000,
            target=8,
            reason="resolved_folded_state_write",
            state_var_stkoff=52,
            state_var_reg=None,
            source_instruction_ea=None,
        ),
        _native_resolution(
            state=_NATIVE_ENTRY_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=8,
        ),
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=resolutions,
        state_var_stkoff=52,
    )

    assert all(fact.source_instruction_ea != _NATIVE_ENTRY_EA for fact in facts)
    assert {fact.state_const for fact in facts} == {0x1000, 0x2000}


def test_identity_selector_abstains_when_support_is_zero() -> None:
    dispatch_map, range_evidence = _native_identity_dispatcher_fixture()
    resolutions = (
        _native_resolution(
            state=0x3000,
            target=2,
            reason="resolved_exact_state",
            state_var_stkoff=None,
            state_var_reg=8,
            source_instruction_ea=None,
        ),
        _native_resolution(
            state=_NATIVE_ENTRY_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=8,
        ),
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=resolutions,
        state_var_stkoff=52,
    )

    assert all(fact.source_instruction_ea != _NATIVE_ENTRY_EA for fact in facts)


def test_native_dispatcher_candidate_with_missing_identity_abstains() -> None:
    dispatch_map, range_evidence = _native_identity_dispatcher_fixture()
    resolutions = (
        _native_resolution(
            state=0x1000,
            target=7,
            reason="resolved_exact_state",
            state_var_stkoff=None,
            state_var_reg=8,
            source_instruction_ea=None,
        ),
        _native_resolution(
            state=_NATIVE_ENTRY_STATE,
            target=None,
            reason="target_is_dispatcher_block",
            state_var_stkoff=None,
            state_var_reg=None,
        ),
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=resolutions,
        state_var_stkoff=52,
    )

    assert all(fact.source_instruction_ea != _NATIVE_ENTRY_EA for fact in facts)
    assert any(fact.source_instruction_ea is None for fact in facts)


def test_ordinary_successful_resolution_without_identity_is_unchanged() -> None:
    dispatch_map, _range_evidence = _native_identity_dispatcher_fixture()
    resolution = _native_resolution(
        state=0x1000,
        target=7,
        reason="resolved_exact_state",
        state_var_stkoff=None,
        state_var_reg=None,
        source_instruction_ea=None,
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=_range_evidence,
        transition_resolutions=(resolution,),
        state_var_stkoff=52,
    )

    assert len(facts) == 1
    assert facts[0].target_block_serial == 7
    assert facts[0].state_var_stkoff == 52


def _path_local_identity_resolutions():
    support = _native_resolution(
        state=0x1000,
        target=122,
        reason="resolved_exact_state",
        state_var_stkoff=None,
        state_var_reg=8,
        source_instruction_ea=None,
        source_block_serial=9,
    )
    candidate = _native_resolution(
        state=_NATIVE_ENTRY_STATE,
        target=None,
        reason="target_is_dispatcher_block",
        state_var_stkoff=None,
        state_var_reg=8,
        source_instruction_ea=_NATIVE_ENTRY_EA,
        source_block_serial=1,
    )
    return support, candidate


def test_native_entry_snapshot_fallback_accepts_exact_current_entry_path_proof() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture()
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    entry_facts = [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ]
    assert len(entry_facts) == 1
    assert entry_facts[0].target_block_serial == 122
    assert entry_facts[0].state_var_stkoff == 52
    assert entry_facts[0].state_var_reg is None


def test_native_entry_snapshot_fallback_selects_handler_map_when_replay_is_incomplete() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        root_predicate=PredicateKind.SLE
    )
    range_evidence = replace(
        range_evidence,
        handler_state_map={10: _NATIVE_ENTRY_STATE},
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            10: replace(graph.get_block(10), native_start_ea=0x180030000),
        },
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    entry_facts = [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ]
    assert len(entry_facts) == 1
    assert entry_facts[0].target_block_serial == 10
    assert entry_facts[0].target_native_ea == 0x180030000
    assert entry_facts[0].target_block_serial != 9


def test_incomplete_replay_does_not_bypass_current_entry_path_proof() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        root_predicate=PredicateKind.SLE,
        source_succs=(3, 30),
    )
    range_evidence = replace(
        range_evidence,
        handler_state_map={10: _NATIVE_ENTRY_STATE},
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            10: replace(graph.get_block(10), native_start_ea=0x180030000),
        },
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_incomplete_replay_rejects_ambiguous_handler_map_targets() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        root_predicate=PredicateKind.SLE
    )
    range_evidence = replace(
        range_evidence,
        handler_state_map={
            10: _NATIVE_ENTRY_STATE,
            122: _NATIVE_ENTRY_STATE,
        },
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            10: replace(graph.get_block(10), native_start_ea=0x180030000),
            122: replace(graph.get_block(122), native_start_ea=0x180030001),
        },
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_incomplete_replay_rejects_handler_without_current_native_identity() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        root_predicate=PredicateKind.SLE
    )
    range_evidence = replace(
        range_evidence,
        handler_state_map={10: _NATIVE_ENTRY_STATE},
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def _path_local_entry_observation():
    graph, dispatch_map, range_evidence = _path_local_entry_fixture()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            122: replace(graph.get_block(122), native_start_ea=0x180020000),
        },
    )
    support, candidate = _path_local_identity_resolutions()
    fact = next(
        fact
        for fact in collect_predecessor_dispatcher_target_facts(
            transition_result=None,
            dispatcher_entry_serial=3,
            state_dispatcher_map=dispatch_map,
            range_evidence=range_evidence,
            transition_resolutions=(support, candidate),
            flow_graph=graph,
            state_var_stkoff=52,
        )
        if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    )
    return predecessor_dispatcher_target_observation(
        fact,
        maturity="locopt",
        phase="predecessor",
    ), fact


def test_predecessor_observation_carries_unique_target_native_identity() -> None:
    observation, fact = _path_local_entry_observation()

    assert fact.target_native_ea == 0x180020000
    assert observation.source_ea == _NATIVE_ENTRY_EA
    assert observation.payload["target_native_ea"] == 0x180020000


def test_predecessor_target_identity_does_not_guess_ambiguous_instruction_eas() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture()
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            122: replace(
                graph.get_block(122),
                insn_snapshots=(
                    InsnSnapshot(opcode=0, ea=1, operands=(), native_ea=0x180020000),
                    InsnSnapshot(opcode=0, ea=2, operands=(), native_ea=0x180020001),
                ),
            ),
        },
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )
    fact = next(
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    )

    assert fact.target_native_ea is None


def test_predecessor_observation_projects_with_target_native_identity() -> None:
    observation, fact = _path_local_entry_observation()

    projected = project_predecessor_dispatcher_target_observations(
        (observation,)
    )

    assert projected == (fact,)


def test_predecessor_observation_projection_rejects_missing_target_identity() -> None:
    observation, _fact = _path_local_entry_observation()
    malformed = replace(
        observation,
        payload={**observation.payload, "target_native_ea": None},
    )

    assert project_predecessor_dispatcher_target_observations((malformed,)) == ()


def test_predecessor_observation_projection_rejects_wide_or_unsupported_facts() -> None:
    observation, _fact = _path_local_entry_observation()
    wide = replace(
        observation,
        payload={
            **observation.payload,
            "state_const": 1 << 32,
            "state_const_hex": "0x0000000100000000",
        },
    )
    unsupported = replace(
        observation,
        payload={**observation.payload, "resolver_kind": "legacy_heuristic"},
    )

    assert project_predecessor_dispatcher_target_observations((wide,)) == ()
    assert project_predecessor_dispatcher_target_observations((unsupported,)) == ()


def test_predecessor_observation_projection_rejects_conflicting_duplicates() -> None:
    observation, _fact = _path_local_entry_observation()
    conflicting = replace(
        observation,
        payload={**observation.payload, "target_native_ea": 0x180020001},
    )

    assert project_predecessor_dispatcher_target_observations(
        (observation, conflicting)
    ) == ()


def test_native_entry_snapshot_fallback_accepts_wide_low32_source_write() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        source_size=8,
        source_value=(1 << 32) | _NATIVE_ENTRY_STATE,
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    entry_facts = [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ]
    assert len(entry_facts) == 1
    assert entry_facts[0].target_block_serial == 122


def test_native_entry_snapshot_fallback_rejects_ambiguous_native_ea() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        duplicate_source_instruction=True
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_native_entry_snapshot_fallback_rejects_source_register_state_mismatch() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        source_register=7
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_native_entry_snapshot_fallback_rejects_unsafe_trailing_write() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        unsafe_trailing=True
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_native_entry_snapshot_fallback_rejects_current_entry_state_mismatch() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(write_value=0x1234)
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_native_entry_snapshot_fallback_rejects_conflicting_entry_writes() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        conflicting_write=0x1234
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_native_entry_snapshot_fallback_rejects_fork_before_dispatcher_entry() -> None:
    graph, dispatch_map, range_evidence = _path_local_entry_fixture(
        source_succs=(3, 30)
    )
    support, candidate = _path_local_identity_resolutions()

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=None,
        dispatcher_entry_serial=3,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(support, candidate),
        flow_graph=graph,
        state_var_stkoff=52,
    )

    assert [
        fact for fact in facts if fact.source_instruction_ea == _NATIVE_ENTRY_EA
    ] == []


def test_wide_alias_resolution_cannot_resurrect_through_transition_result() -> None:
    dispatch_map, range_evidence = _native_identity_dispatcher_fixture()
    wide_alias = SimpleNamespace(
        source_block_serial=7,
        source_state_const_hex="0x0000000100000001",
        resolved_next_block_serial=None,
        resolution_kind="state_dispatcher_map",
        resolution_reason="target_is_dispatcher_block",
        source_instruction_ea=_NATIVE_ENTRY_EA,
        state_var_stkoff=52,
        state_var_reg=8,
    )
    transition_result = TransitionResult(
        transitions=[
            StateTransition(
                from_state=0x10,
                to_state=1,
                from_block=7,
                provenance_ea=_NATIVE_ENTRY_EA,
            )
        ]
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=transition_result,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        transition_resolutions=(wide_alias,),
        state_var_stkoff=52,
    )

    assert facts == ()
    # The fallback EA comes from ``provenance_ea`` when the transition has no
    # dedicated source-instruction field; no unanchored route may be emitted.


def test_transition_result_uses_provenance_ea_when_source_instruction_is_absent() -> None:
    dispatch_map, range_evidence = _native_identity_dispatcher_fixture()
    transition_result = TransitionResult(
        transitions=[
            StateTransition(
                from_state=0x10,
                to_state=0x1000,
                from_block=7,
                provenance_kind="global_or_state_write",
                provenance_ea=_NATIVE_ENTRY_EA,
            )
        ]
    )

    facts = collect_predecessor_dispatcher_target_facts(
        transition_result=transition_result,
        dispatcher_entry_serial=2,
        state_dispatcher_map=dispatch_map,
        range_evidence=range_evidence,
        state_var_stkoff=52,
    )

    assert len(facts) == 1
    assert facts[0].target_block_serial == 7
    assert facts[0].source_instruction_ea == _NATIVE_ENTRY_EA
