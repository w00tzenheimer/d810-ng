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
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    collect_predecessor_dispatcher_target_facts,
    resolve_predecessor_dispatcher_target,
)
from d810.analyses.control_flow import (
    predecessor_dispatcher_target as predecessor_target_module,
)
from d810.analyses.control_flow.transition_builder import (
    StateTransition,
    TransitionResult,
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
        state_var_stkoff=8,
        state_var_reg=8,
    )
    resolution = SimpleNamespace(
        source_block_serial=1,
        source_state_const_hex=f"0x{state:016X}",
        resolved_next_block_serial=None,
        resolution_kind="state_dispatcher_map",
        resolution_reason="target_is_dispatcher_block",
        source_instruction_ea=0x7FF855576BA0,
        state_var_stkoff=8,
        state_var_reg=8,
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
    # The prior maturity's carrier identity is diagnostic only.  The typed
    # route remains valid when the current lowering observes a different
    # carrier, because native EA plus current-router corroboration is the
    # stable authority.
    assert fact.state_var_stkoff == 8
    assert fact.state_var_reg == 8
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
    assert native_entry_facts == {_NATIVE_ENTRY_STATE}
    assert {
        fact.state_const
        for fact in facts
        if fact.source_instruction_ea == _NATIVE_LATER_EA
    } == {_NATIVE_LATER_STATE}
    assert all(
        fact.state_var_reg == 8
        for fact in facts
        if fact.source_instruction_ea
    )


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
