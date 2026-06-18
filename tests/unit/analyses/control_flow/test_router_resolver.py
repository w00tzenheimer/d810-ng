"""Injectable dispatcher RouterResolver — configured AND/OR detected (ticket llr-oq8v).

The router kind is a first-class property: detection ranks providers by handler
coverage (condition-chain range default; exact map wins on strict range collapse),
and a configured RouterKind pins a provider regardless of coverage (falling back
to detection only when the pinned kind is unavailable).
"""
from __future__ import annotations

from d810.analyses.control_flow.interval_map import interval_dispatcher_from_state_map
from d810.analyses.control_flow.router_resolver import (
    ConditionChainRangeRouterResolver,
    ExactMapRouterResolver,
    RouterResolutionContext,
    default_resolvers,
    handler_coverage,
    select_router,
)
from d810.capabilities.dispatcher import RouterKind

ENTRY = 2  # the dispatcher entry serial (excluded from coverage; not a handler)


def _router(state_to_handler, default=None):
    return interval_dispatcher_from_state_map(state_to_handler, default_target=default)


# -- handler_coverage helper ---------------------------------------------------
def test_coverage_none_is_minus_one() -> None:
    assert handler_coverage(None, ENTRY) == -1


def test_coverage_collapsed_catchall_is_zero() -> None:
    collapsed = _router({1: ENTRY, 5: ENTRY, 9: ENTRY})  # everything -> entry
    assert handler_coverage(collapsed, ENTRY) == 0


def test_coverage_counts_distinct_handler_targets() -> None:
    assert handler_coverage(_router({1: 10, 5: 20, 9: 30}), ENTRY) == 3


# -- detection (no configured_kind) --------------------------------------------
def test_detection_exact_wins_on_condition_chain_range_collapse() -> None:
    range_router = _router({1: ENTRY, 5: ENTRY, 9: ENTRY})  # coverage 0 (collapsed)
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 5: 20, 9: 30},
        dispatcher_entry=ENTRY,
    )
    chosen = select_router(default_resolvers(), ctx)
    assert chosen is not range_router and handler_coverage(chosen, ENTRY) == 3


def test_detection_condition_chain_range_wins_when_it_outcovers() -> None:
    range_router = _router({1: 10, 3: 30, 5: 50, 7: 70})  # coverage 4
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 3: 30},
        dispatcher_entry=ENTRY,
    )
    assert select_router(default_resolvers(), ctx) is range_router


def test_detection_tie_keeps_condition_chain_range() -> None:
    range_router = _router({1: 10, 3: 30})  # coverage 2 == exact coverage 2
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 3: 30},
        dispatcher_entry=ENTRY,
    )
    assert select_router(default_resolvers(), ctx) is range_router


def test_detection_exact_only_when_no_condition_chain_range() -> None:
    ctx = RouterResolutionContext(
        condition_chain_router=None,
        state_to_handler={1: 10, 3: 30},
        dispatcher_entry=ENTRY,
    )
    chosen = select_router(default_resolvers(), ctx)
    assert chosen is not None and handler_coverage(chosen, ENTRY) == 2


# -- configuration (pin a RouterKind) ------------------------------------------
def test_configured_kind_forces_exact_over_winning_range_router() -> None:
    range_router = _router({1: 10, 3: 30, 5: 50, 7: 70})  # coverage 4
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 3: 30},
        dispatcher_entry=ENTRY,
    )
    chosen = select_router(default_resolvers(), ctx, configured_kind=RouterKind.EQUALITY_CHAIN)
    assert chosen is not range_router and handler_coverage(chosen, ENTRY) == 2


def test_configured_kind_does_not_force_collapsed_condition_chain_over_exact() -> None:
    range_router = _router({1: ENTRY, 5: ENTRY})  # coverage 0 (would lose detection)
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 5: 20, 9: 30},
        dispatcher_entry=ENTRY,
    )
    chosen = select_router(
        default_resolvers(), ctx, configured_kind=RouterKind.CONDITION_CHAIN
    )
    assert chosen is not range_router and handler_coverage(chosen, ENTRY) == 3


def test_configured_kind_prefers_noncollapsed_condition_chain() -> None:
    range_router = _router({1: 10, 5: ENTRY})  # coverage 1 (usable range evidence)
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 5: 20, 9: 30},
        dispatcher_entry=ENTRY,
    )
    assert (
        select_router(default_resolvers(), ctx, configured_kind=RouterKind.CONDITION_CHAIN)
        is range_router
    )


def test_configured_kind_absent_falls_back_to_detection() -> None:
    # exact map has no default -> it is EQUALITY_CHAIN, so a TABLE pin is unavailable;
    # selection falls back to detection (range router collapsed -> exact wins).
    range_router = _router({1: ENTRY, 5: ENTRY})
    ctx = RouterResolutionContext(
        condition_chain_router=range_router,
        state_to_handler={1: 10, 5: 20, 9: 30},
        dispatcher_entry=ENTRY,
    )
    chosen = select_router(default_resolvers(), ctx, configured_kind=RouterKind.TABLE)
    assert chosen is not range_router and handler_coverage(chosen, ENTRY) == 3


# -- candidate router_kind + abstention ----------------------------------------
def test_exact_kind_is_switch_with_default_else_equality_chain() -> None:
    with_default = ExactMapRouterResolver().applies_to(
        RouterResolutionContext(state_to_handler={1: 10}, default_target=99, dispatcher_entry=ENTRY)
    )
    no_default = ExactMapRouterResolver().applies_to(
        RouterResolutionContext(state_to_handler={1: 10}, dispatcher_entry=ENTRY)
    )
    assert with_default.router_kind is RouterKind.TABLE
    assert no_default.router_kind is RouterKind.EQUALITY_CHAIN
    assert with_default.resolver_name == "exact_map"


def test_providers_abstain_when_inputs_missing() -> None:
    empty = RouterResolutionContext()
    assert ConditionChainRangeRouterResolver().applies_to(empty) is None
    assert ExactMapRouterResolver().applies_to(empty) is None
    assert select_router(default_resolvers(), empty) is None  # nobody applies -> None


def test_condition_chain_candidate_is_ranked_evidence_not_a_bool() -> None:
    range_router = _router({1: 10, 3: 30})
    cand = ConditionChainRangeRouterResolver().applies_to(
        RouterResolutionContext(condition_chain_router=range_router, dispatcher_entry=ENTRY)
    )
    assert cand.router_kind is RouterKind.CONDITION_CHAIN
    assert cand.confidence == 2.0  # coverage as the ranking signal
