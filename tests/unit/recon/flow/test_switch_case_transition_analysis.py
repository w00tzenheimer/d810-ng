"""Tests for read-only Tigress switch case transition facts."""
from __future__ import annotations

from d810.analyses.control_flow.branch_ownership import BranchOwnershipProofKind
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap, StateDispatcherRow
from d810.analyses.control_flow.switch_case_transition_analysis import (
    SwitchCaseBody,
    SwitchCaseTransitionKind,
    collect_switch_case_transition_facts,
)


TIGRESS_VISIBLE_STATES = (
    0, 1, 3, 4, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22, 23,
)


def _dispatch_map(states: tuple[int, ...] = TIGRESS_VISIBLE_STATES) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=tuple(
            StateDispatcherRow(
                state_const=state,
                target_block=100 + state,
                dispatcher_block=50,
                compare_block=50,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
            )
            for state in states
        ),
        dispatcher_entry_block=50,
        dispatcher_blocks=frozenset({50}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
    )


def _tigress_minmaxarray_bodies() -> tuple[SwitchCaseBody, ...]:
    return (
        SwitchCaseBody(state=11, entry_block=111, state_writes=(4,)),
        SwitchCaseBody(state=4, entry_block=104, state_writes=(9, 13), predicate_kind="argc < 11", source_predicate=True),
        SwitchCaseBody(state=13, entry_block=113, state_writes=(23,)),
        SwitchCaseBody(state=23, entry_block=123, state_writes=(0, 12), predicate_kind="i < argc", source_predicate=True),
        SwitchCaseBody(state=0, entry_block=100, state_writes=(23,)),
        SwitchCaseBody(state=12, entry_block=112, state_writes=(17,)),
        SwitchCaseBody(state=17, entry_block=117, state_writes=(8, 7), predicate_kind="i < argc - 1", source_predicate=True),
        SwitchCaseBody(state=8, entry_block=108, state_writes=(1, 16), predicate_kind="big < a[i]", source_predicate=True),
        SwitchCaseBody(state=1, entry_block=101, state_writes=(16,)),
        SwitchCaseBody(state=16, entry_block=116, state_writes=(17,)),
        SwitchCaseBody(state=7, entry_block=107, state_writes=(15,)),
        SwitchCaseBody(state=15, entry_block=115, state_writes=(14, 22), predicate_kind="i < argc - 1", source_predicate=True),
        SwitchCaseBody(state=14, entry_block=114, state_writes=(18, 3), predicate_kind="small > a[i]", source_predicate=True),
        SwitchCaseBody(state=18, entry_block=118, state_writes=(3,)),
        SwitchCaseBody(state=3, entry_block=103, state_writes=(15,)),
        SwitchCaseBody(state=22, entry_block=122, state_writes=(19,)),
        SwitchCaseBody(state=9, entry_block=109, returns=(1,)),
        SwitchCaseBody(state=19, entry_block=119, returns=(0,)),
    )


def test_tigress_minmaxarray_acceptance_transitions() -> None:
    facts = collect_switch_case_transition_facts(
        dispatch_map=_dispatch_map(),
        case_bodies=_tigress_minmaxarray_bodies(),
    )

    assert {row.state_const for row in _dispatch_map().rows} == set(TIGRESS_VISIBLE_STATES)
    transitions = {
        fact.source_state: fact.next_states
        for fact in facts
        if fact.transition_kind in {
            SwitchCaseTransitionKind.DIRECT,
            SwitchCaseTransitionKind.CONDITIONAL,
        }
    }
    assert transitions == {
        11: (4,),
        4: (9, 13),
        13: (23,),
        23: (0, 12),
        0: (23,),
        12: (17,),
        17: (8, 7),
        8: (1, 16),
        1: (16,),
        16: (17,),
        7: (15,),
        15: (14, 22),
        14: (18, 3),
        18: (3,),
        3: (15,),
        22: (19,),
    }
    returns = {
        fact.source_state: fact.return_value
        for fact in facts
        if fact.transition_kind == SwitchCaseTransitionKind.RETURN_FRONTIER
    }
    assert returns == {9: 1, 19: 0}


def test_conditional_cases_require_valid_states_and_source_predicate() -> None:
    facts = collect_switch_case_transition_facts(
        dispatch_map=_dispatch_map(states=(4, 9, 13)),
        case_bodies=(
            SwitchCaseBody(
                state=4,
                entry_block=104,
                state_writes=(9, 13),
                state_write_exit_blocks=(209, 213),
                state_write_ordered_paths=((104, 209), (104, 213)),
                source_predicate=True,
            ),
        ),
    )

    assert facts[0].transition_kind == SwitchCaseTransitionKind.CONDITIONAL
    assert facts[0].proof is not None
    assert facts[0].proof.proof_kind == BranchOwnershipProofKind.REAL_DATA_DEPENDENT
    assert facts[0].proof.authorizes_nonsemantic_branch_rewrite is False
    assert facts[0].payload["arm_exit_blocks"] == (209, 213)
    assert facts[0].payload["arm_ordered_paths"] == ((104, 209), (104, 213))

    unresolved = collect_switch_case_transition_facts(
        dispatch_map=_dispatch_map(states=(4, 9)),
        case_bodies=(
            SwitchCaseBody(state=4, entry_block=104, state_writes=(9, 13), source_predicate=True),
        ),
    )[0]
    assert unresolved.transition_kind == SwitchCaseTransitionKind.UNRESOLVED
    assert unresolved.proof is not None
    assert unresolved.proof.authorizes_nonsemantic_branch_rewrite is False


def test_direct_case_facts_carry_exit_block_and_ordered_path() -> None:
    facts = collect_switch_case_transition_facts(
        dispatch_map=_dispatch_map(states=(11, 4)),
        case_bodies=(
            SwitchCaseBody(
                state=11,
                entry_block=111,
                state_writes=(4,),
                state_write_exit_blocks=(211,),
                state_write_ordered_paths=((111, 211),),
            ),
        ),
    )

    direct = next(fact for fact in facts if fact.transition_kind == SwitchCaseTransitionKind.DIRECT)
    assert direct.exit_block == 211
    assert direct.ordered_path == (111, 211)
    assert direct.to_diag_row()["payload"]["exit_block"] == 211
    assert direct.to_diag_row()["payload"]["ordered_path"] == (111, 211)


def test_alias_self_loop_and_default_rows_are_diagnostics() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(1, 10, 5, 5, "switch_case_alias", DispatcherType.SWITCH_TABLE, row_kind="handler_alias"),
            StateDispatcherRow(2, 5, 5, 5, "switch_self_loop", DispatcherType.SWITCH_TABLE, row_kind="dispatcher_self_loop"),
        ),
        dispatcher_entry_block=5,
        dispatcher_blocks=frozenset({5}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
        default_target_block=99,
        default_row_kind="dispatcher_default",
    )

    facts = collect_switch_case_transition_facts(
        dispatch_map=dispatch_map,
        case_bodies=(),
    )

    assert [fact.transition_kind for fact in facts] == [
        SwitchCaseTransitionKind.DIAGNOSTIC,
        SwitchCaseTransitionKind.DIAGNOSTIC,
        SwitchCaseTransitionKind.DIAGNOSTIC,
    ]
    assert all(fact.proof is None or not fact.proof.trusted for fact in facts)
    assert all(
        fact.proof is None or not fact.proof.authorizes_nonsemantic_branch_rewrite
        for fact in facts
    )
