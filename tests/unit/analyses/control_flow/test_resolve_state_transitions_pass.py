"""unflatten pass #2: resolve_state_transitions composes the canonical portable resolver.

Locks the composition (facts_from_validated_view -> resolve_state_transitions_with_dispatcher_map)
and the seam-pending behavior (no dispatcher map -> explicit unresolved, never silent drop).
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.semantic_transition import (
    StateTransitionResolution,
    resolve_state_transitions,
)


def _view(*observations):
    return SimpleNamespace(active_observations=observations)


def _transition_obs(fact_id, block, state):
    return SimpleNamespace(
        kind="StateTransitionAnchorFact",
        fact_id=fact_id,
        payload={
            "source_block_serial": block,
            "source_state_const": state,
            "successor_kind": "branch",
        },
    )


def test_null_facts_resolve_to_empty():
    # the unflatten pass runs over a null context during shape tests
    assert resolve_state_transitions(None, None) == ()
    assert resolve_state_transitions(None, _view()) == ()


def test_facts_project_into_resolutions_unresolved_without_map():
    res = resolve_state_transitions(
        graph=None, facts=_view(_transition_obs("f1", 5, 0x100)), dispatch_map=None
    )
    assert len(res) == 1
    r = res[0]
    assert isinstance(r, StateTransitionResolution)
    assert r.source_block_serial == 5
    # map seam pending -> explicit unresolved, not a dropped/None transition
    assert r.resolved_next_block_serial is None
    assert r.resolution_reason == "no_dispatcher_rows_available"


def test_multiple_facts_all_resolved_in_order():
    res = resolve_state_transitions(
        graph=None,
        facts=_view(_transition_obs("f1", 5, 0x100), _transition_obs("f2", 9, 0x200)),
    )
    assert tuple(r.source_block_serial for r in res) == (5, 9)
