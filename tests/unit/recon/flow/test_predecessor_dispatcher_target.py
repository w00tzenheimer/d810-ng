from types import SimpleNamespace

from d810.analyses.control_flow.bst_model import BSTAnalysisResult
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap, StateDispatcherRow
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    collect_predecessor_dispatcher_target_facts,
    resolve_predecessor_dispatcher_target,
)
from d810.analyses.control_flow.transition_builder import StateTransition, TransitionResult


def test_resolves_predecessor_target_from_exact_dispatcher_row() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x20,
                target_block=7,
                dispatcher_block=2,
                compare_block=3,
                branch_kind="jz_taken",
                source=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2, 3}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        source=RouterKind.CONDITION_CHAIN,
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
    bst_result = BSTAnalysisResult(
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
        bst_result=bst_result,
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
                source=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=4,
        dispatcher_blocks=frozenset({4}),
        state_var_stkoff=0x28,
        state_var_lvar_idx=None,
        source=RouterKind.CONDITION_CHAIN,
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


def test_collects_report_target_facts_for_resolved_handler_edges() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0xF6A1E,
                target_block=6,
                dispatcher_block=4,
                compare_block=4,
                branch_kind="fallthrough",
                source=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=4,
        dispatcher_blocks=frozenset({4}),
        state_var_stkoff=0x28,
        state_var_lvar_idx=None,
        source=RouterKind.CONDITION_CHAIN,
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
                source=RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=4,
        dispatcher_blocks=frozenset({4}),
        state_var_stkoff=0x28,
        state_var_lvar_idx=None,
        source=RouterKind.CONDITION_CHAIN,
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
