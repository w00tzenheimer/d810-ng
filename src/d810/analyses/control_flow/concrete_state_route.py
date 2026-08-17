"""Fail-closed resolution of one concrete dispatcher state.

The exact state map and the interval dispatcher are independent pieces of
evidence.  This module is the small portable boundary that combines them.  A
caller receives a route only when every available provider agrees; provider
precedence is intentionally not part of this API.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass


U32_MASK = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class ConcreteStateRoute:
    """Immutable evidence for one normalized state-to-block route."""

    normalized_state: int
    target_block: int
    source_kinds: tuple[str, ...]


def _integer(value: object) -> int | None:
    """Return an integer-like value without accepting strings or booleans."""
    if isinstance(value, bool):
        return None
    try:
        return operator.index(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _exact_target(exact_dispatcher_map: object, state: int) -> int | None:
    resolver = getattr(exact_dispatcher_map, "resolve_target", None)
    if not callable(resolver):
        return None
    try:
        target = resolver(state)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return None
    if target is None:
        return None
    return _integer(target)


def _interval_target(interval_dispatcher: object, state: int) -> int | None:
    lookup_row = getattr(interval_dispatcher, "lookup_row", None)
    if not callable(lookup_row):
        return None
    try:
        row = lookup_row(state)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return None
    if row is None:
        return None
    try:
        lo = _integer(getattr(row, "lo"))
        hi = _integer(getattr(row, "hi"))
        target = _integer(getattr(row, "target"))
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return None
    if lo is None or hi is None or target is None or not lo <= state < hi:
        return None
    return target


def resolve_concrete_state_route(
    state_value: int,
    *,
    exact_dispatcher_map: object | None = None,
    interval_dispatcher: object | None = None,
) -> ConcreteStateRoute | None:
    """Resolve *state_value* through all supplied dispatcher evidence.

    States are unsigned 32-bit values.  Boolean values are rejected because
    Python's ``bool`` subclassing of ``int`` would otherwise turn a malformed
    provider value into a real state.  Missing, malformed, or disagreeing
    provider evidence causes abstention.  The provider labels are fixed and
    sorted so the result is deterministic across call order.
    """
    normalized = _integer(state_value)
    if normalized is None:
        return None
    normalized &= U32_MASK

    targets: list[tuple[str, int]] = []
    if exact_dispatcher_map is not None:
        exact = _exact_target(exact_dispatcher_map, normalized)
        if exact is not None:
            targets.append(("exact", exact))
    if interval_dispatcher is not None:
        interval = _interval_target(interval_dispatcher, normalized)
        if interval is not None:
            targets.append(("interval", interval))

    distinct_targets = {target for _source, target in targets}
    if len(distinct_targets) != 1:
        return None
    target = next(iter(distinct_targets))
    return ConcreteStateRoute(
        normalized_state=normalized,
        target_block=target,
        source_kinds=tuple(sorted(source for source, _target in targets)),
    )


__all__ = ["ConcreteStateRoute", "resolve_concrete_state_route"]
