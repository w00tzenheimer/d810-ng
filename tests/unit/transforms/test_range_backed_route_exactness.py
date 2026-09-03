"""Range-backed BST route exactness at the two route-evidence consumers (d81-8xhg).

Both fixtures replicate the shape measured on ``sub_7FFB0E398850``: a signed
comparison-tree dispatcher whose table carries only wide ``[lo, hi)`` leaves,
so *every* route lookup used to be refused as "range-backed" and the entry
bridge for the initial state could never be built
(``BAILED (no entry bridge: initial_state=481287653)``).

The positive fixture is the real row that stranded ``0x1CAFDDE5``; the negative
control puts a second written constant inside the same leaf, which must keep
the refusal because the leaf is then a genuinely shared corridor.
"""

from __future__ import annotations

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.linearized_state_dag import (
    _is_range_backed_only_handoff_anchor,
)
from d810.analyses.control_flow.transition_report import (
    DispatcherTransitionReport,
    TransitionSummary,
)
from d810.transforms.minimal_unflatten_emit import (
    _explicit_singleton_route_evidence,
    _resolve_entry_state_route_resolution,
)

# Measured from the exp-yci2b diag DB (snapshot 5, dispatcher entry blk5):
# 87 rows = 42 singleton + 45 range; the initial state falls in a range leaf
# whose only written member is itself.
_INITIAL_STATE = 0x1CAFDDE5
_RANGE_LO = 0x1B7B68FD
_RANGE_HI = 0x208318D7
_LEAF = 143
_DISPATCHER_ENTRY = 146
# A second constant inside the SAME leaf -> shared corridor.
_SHARED_STATE = 0x1B7B68FE


def _range_only_dispatcher(written_states) -> IntervalDispatcher:
    """The stranding table: one wide leaf, no singleton row anywhere."""
    return IntervalDispatcher(
        [IntervalRow(_RANGE_LO, _RANGE_HI, _LEAF)],
        default_target=_DISPATCHER_ENTRY,
        compute_default=False,
        written_state_constants=written_states,
    )


def _entry_route(dispatcher):
    return _resolve_entry_state_route_resolution(
        dispatcher,
        _INITIAL_STATE,
        materialized_state_routes=(),
        condition_chain_handlers=frozenset(),
        dispatcher_entry_serial=_DISPATCHER_ENTRY,
    ).route


def test_entry_bridge_resolves_when_range_leaf_isolates_the_initial_state():
    dispatcher = _range_only_dispatcher({_INITIAL_STATE, 0x76B1AD38})
    route = _entry_route(dispatcher)
    assert route is not None
    assert int(route.target_block) == _LEAF
    assert int(route.normalized_state) == _INITIAL_STATE


def test_entry_bridge_refused_when_two_written_states_share_the_range_leaf():
    dispatcher = _range_only_dispatcher({_INITIAL_STATE, _SHARED_STATE})
    assert _entry_route(dispatcher) is None


def test_entry_bridge_refused_without_written_state_evidence():
    # Pre-d81-8xhg behaviour is preserved exactly when the table carries no
    # written-state set: a wide leaf proves nothing on its own.
    assert _entry_route(_range_only_dispatcher(())) is None


def test_route_evidence_predicate_matches_the_entry_decision():
    isolated = _range_only_dispatcher({_INITIAL_STATE})
    shared = _range_only_dispatcher({_INITIAL_STATE, _SHARED_STATE})
    assert _explicit_singleton_route_evidence(isolated, _INITIAL_STATE, _LEAF)
    assert not _explicit_singleton_route_evidence(shared, _INITIAL_STATE, _LEAF)
    # A different target is never granted by someone else's row.
    assert not _explicit_singleton_route_evidence(isolated, _INITIAL_STATE, _LEAF + 1)


def _report(handler_state_map, handler_range_map) -> DispatcherTransitionReport:
    return DispatcherTransitionReport(
        dispatcher_entry_serial=_DISPATCHER_ENTRY,
        state_var_stkoff=48,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=_INITIAL_STATE,
        handler_state_map=handler_state_map,
        handler_range_map=handler_range_map,
        condition_chain_blocks=(),
        rows=(),
        summary=TransitionSummary(0, 0, 0, 0, 0),
        diagnostics=(),
    )


def test_handoff_anchor_accepts_an_isolating_range_leaf():
    report = _report({}, {_LEAF: (_RANGE_LO, _RANGE_HI - 1)})
    dispatcher = _range_only_dispatcher({_INITIAL_STATE})
    assert not _is_range_backed_only_handoff_anchor(
        _INITIAL_STATE, _LEAF, report, dispatcher
    )


def test_handoff_anchor_still_refuses_a_shared_range_leaf():
    report = _report({}, {_LEAF: (_RANGE_LO, _RANGE_HI - 1)})
    dispatcher = _range_only_dispatcher({_INITIAL_STATE, _SHARED_STATE})
    assert _is_range_backed_only_handoff_anchor(
        _INITIAL_STATE, _LEAF, report, dispatcher
    )


def test_handoff_anchor_still_refuses_without_written_state_evidence():
    report = _report({}, {_LEAF: (_RANGE_LO, _RANGE_HI - 1)})
    assert _is_range_backed_only_handoff_anchor(
        _INITIAL_STATE, _LEAF, report, _range_only_dispatcher(())
    )


def test_handoff_anchor_singleton_path_is_unchanged():
    report = _report({}, {_LEAF: (_INITIAL_STATE, _INITIAL_STATE)})
    singleton = IntervalDispatcher(
        [IntervalRow(_INITIAL_STATE, _INITIAL_STATE + 1, _LEAF)],
        default_target=_DISPATCHER_ENTRY,
        compute_default=False,
    )
    assert not _is_range_backed_only_handoff_anchor(
        _INITIAL_STATE, _LEAF, report, singleton
    )
