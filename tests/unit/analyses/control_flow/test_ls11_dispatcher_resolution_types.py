"""Structural tests for the LS11 net-new dispatcher-resolution / semantic-
transition / automaton types (ticket d81-mt50, commits C4-C8).

These types are net-new and unwired in LS11; the tests pin their shape,
layering, and the StateTransitionFact -> SemanticTransition projection.
Pure-Python (no IDA), so they belong in tests/unit.
"""
from __future__ import annotations

import pytest

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.semantic_transition import (
    SemanticTransition,
    SemanticTransitionKind,
    StateTransitionFact,
    semantic_transition_from_fact,
)
from d810.analyses.control_flow.state_machine import SemanticGraph, StateDagView


def _make_dispatcher_map() -> StateDispatcherMap:
    row = StateDispatcherRow(
        state_const=0x1234,
        target_block=7,
        dispatcher_block=1,
        compare_block=2,
        branch_kind="jz",
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    return StateDispatcherMap(
        rows=(row,),
        dispatcher_entry_block=1,
        dispatcher_blocks=frozenset({1}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )


# --- C5: capabilities.dispatcher ------------------------------------------- #
def test_router_kind_is_str_enum() -> None:
    assert {k.value for k in RouterKind} >= {
        "switch", "equality_chain", "condition_chain", "indirect_table", "unknown",
    }
    assert "bst" not in {k.value for k in RouterKind}


# --- C6: ResolverCandidate / DispatcherResolution -------------------------- #
def test_resolver_candidate_is_ranked_evidence_not_bool() -> None:
    cand = ResolverCandidate(
        resolver_name="equality_chain",
        router_kind=RouterKind.EQUALITY_CHAIN,
        confidence=0.9,
        specificity=3,
        reasons=("matched 13 rows",),
    )
    assert not isinstance(cand, bool)
    assert cand.confidence == 0.9 and cand.specificity == 3


def test_dispatcher_resolution_wraps_map_with_provenance() -> None:
    res = DispatcherResolution(
        dispatcher_map=_make_dispatcher_map(),
        resolver_name="equality_chain",
        router_kind=RouterKind.EQUALITY_CHAIN,
        confidence=0.9,
        ranking_reason=("highest specificity",),
    )
    assert res.dispatcher_map.resolve_target(0x1234) == 7
    assert res.router_kind is RouterKind.EQUALITY_CHAIN


# --- C4 + C7: SemanticTransition + projection ------------------------------ #
def test_semantic_transition_kind_vocabulary() -> None:
    assert SemanticTransitionKind.HANDLER_WRITE.value == "handler_write"
    assert SemanticTransitionKind.UNKNOWN.value == "unknown"


def test_semantic_transition_value_identity_field_defaults_none() -> None:
    t = SemanticTransition(
        source_block_serial=23,
        source_state_const=0x41FB8FBB,
        kind=SemanticTransitionKind.HANDLER_WRITE,
    )
    assert t.subject is None  # C4 value-identity ref, unwired default


def test_projection_from_branch_fact_is_handler_write() -> None:
    fact = StateTransitionFact(
        fact_id="f1",
        source_block_serial=23,
        source_state_const=0x41FB8FBB,
        source_state_const_hex="0x41fb8fbb",
        successor_kind="branch",
    )
    t = semantic_transition_from_fact(fact)
    assert t.kind is SemanticTransitionKind.HANDLER_WRITE
    assert t.source_block_serial == 23
    assert t.evidence_fact_id == "f1"
    assert t.source_state_const_hex == "0x41fb8fbb"


def test_projection_unknown_successor_is_conservative() -> None:
    fact = StateTransitionFact(
        fact_id="f2",
        source_block_serial=9,
        source_state_const=0x10,
        successor_kind="mystery",
    )
    assert semantic_transition_from_fact(fact).kind is SemanticTransitionKind.UNKNOWN


# --- C8: automaton views --------------------------------------------------- #
def test_semantic_graph_and_dag_view_shapes() -> None:
    g = SemanticGraph(states=(1, 2, 3), edges=((1, 2), (2, 3), (3, 1)), has_cycles=True)
    assert g.has_cycles and len(g.edges) == 3
    dag = StateDagView(ordered_states=(1, 2, 3), edges=((1, 2), (2, 3)))
    assert dag.ordered_states == (1, 2, 3)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
