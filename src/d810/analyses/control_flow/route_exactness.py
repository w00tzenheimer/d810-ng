"""Single owner of the BST route-exactness decision (ticket d81-8xhg).

A comparison-tree ("BST") dispatcher recovered from a flattened function does
not emit one row per case constant.  Every leaf publishes the whole half-open
interval its comparison chain carved out, so a case whose neighbours are far
apart in the state namespace shows up as a wide ``[lo, hi)`` row rather than
the ``hi == lo + 1`` singleton an equality chain would produce.

Interval WIDTH is therefore the wrong exactness test.  The right one is
whether the row *isolates* the queried state: a range row binds state ``s`` to
its target exactly when ``s`` is the only value inside ``[lo, hi)`` that the
function ever writes to the state variable.  Two or more written members mean
the row is a genuinely shared corridor and must stay refused; zero members
mean the row says nothing about the queried value.

Every consumer of that decision (supplemental handoff anchoring, entry/route
evidence, and the interval back-fill into ``handler_state_map``) calls
:func:`is_exact_route_interval` so the three cannot drift apart.

Pure Python -- no IDA imports.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Any, Iterable, Optional

logger = getLogger(__name__)

__all__ = [
    "U32_MASK",
    "dispatcher_written_state_constants",
    "interval_isolates_state",
    "is_exact_route_interval",
    "normalize_written_state_constants",
    "written_states_in_interval",
]

U32_MASK: int = 0xFFFFFFFF

# A written-state set is recovered from live microcode, so the members can be
# any int-like the extractor produced.  Coercion failures mean "no evidence",
# never a hard error, because losing route evidence must degrade to the
# conservative (pre-d81-8xhg) refusal rather than abort recovery.
_COERCION_ERRORS = (AttributeError, TypeError, ValueError, OverflowError)


def normalize_written_state_constants(
    states: Optional[Iterable[Any]],
) -> frozenset[int]:
    """Coerce a written-state collection into a canonical ``u32`` frozenset.

    ``None`` entries and members that cannot be coerced to ``int`` are dropped:
    a malformed member is missing evidence, not a reason to fail.

    Args:
        states: Iterable of state constants, or ``None``.

    Returns:
        The masked, deduplicated state constants.

    >>> sorted(normalize_written_state_constants([1, 1 << 32 | 1, None]))
    [1]
    >>> normalize_written_state_constants(None)
    frozenset()
    """
    if states is None:
        return frozenset()
    normalized: set[int] = set()
    try:
        members = tuple(states)
    except _COERCION_ERRORS:
        return frozenset()
    for state in members:
        if state is None:
            continue
        try:
            normalized.add(int(state) & U32_MASK)
        except _COERCION_ERRORS:
            continue
    return frozenset(normalized)


def dispatcher_written_state_constants(dispatcher: Any) -> frozenset[int]:
    """Return the written-state set a dispatcher carries, if any.

    Duck-typed on purpose: route resolution accepts several dispatcher shapes
    (``IntervalDispatcher``, ``StateDispatcherMap``, test doubles).  A shape
    that carries no written-state evidence yields the empty set, which keeps
    the caller on the singleton-only path.

    Args:
        dispatcher: Any dispatcher-like object, or ``None``.

    Returns:
        The dispatcher's masked written-state constants.
    """
    if dispatcher is None:
        return frozenset()
    try:
        states = getattr(dispatcher, "written_state_constants", None)
    except _COERCION_ERRORS:
        return frozenset()
    if isinstance(states, frozenset):
        return states
    return normalize_written_state_constants(states)


def written_states_in_interval(
    *,
    lo: int,
    hi: int,
    written_states: Optional[Iterable[Any]],
) -> frozenset[int]:
    """Return the written state constants contained in ``[lo, hi)``.

    Args:
        lo: Inclusive lower bound.
        hi: Exclusive upper bound.
        written_states: Constants the function writes to the state variable.

    Returns:
        The subset of *written_states* inside the interval.
    """
    states = (
        written_states
        if isinstance(written_states, frozenset)
        else normalize_written_state_constants(written_states)
    )
    if not states:
        return frozenset()
    try:
        lo_u32 = int(lo) & U32_MASK
        hi_i = int(hi)
    except _COERCION_ERRORS:
        return frozenset()
    return frozenset(state for state in states if lo_u32 <= state < hi_i)


def interval_isolates_state(
    *,
    lo: int,
    hi: int,
    state: int,
    written_states: Optional[Iterable[Any]],
) -> bool:
    """Return True when ``state`` is the sole written constant in ``[lo, hi)``.

    This is the whole novelty of ticket d81-8xhg: it decides whether a wide
    BST leaf is unambiguous *for the queried value*, using the set of values
    that can actually occur instead of the interval's width.

    Args:
        lo: Inclusive lower bound.
        hi: Exclusive upper bound.
        state: The state constant being routed.
        written_states: Constants the function writes to the state variable.

    Returns:
        True when the intersection is exactly ``{state}``.
    """
    try:
        state_u32 = int(state) & U32_MASK
    except _COERCION_ERRORS:
        return False
    members = written_states_in_interval(lo=lo, hi=hi, written_states=written_states)
    return members == frozenset({state_u32})


def is_exact_route_interval(
    *,
    lo: int,
    hi: int,
    state: int,
    written_states: Optional[Iterable[Any]] = None,
    target: Optional[int] = None,
    site: str = "",
) -> bool:
    """Return True when the row ``[lo, hi) -> target`` exactly binds ``state``.

    Two accepting shapes:

    * a **singleton** row (``hi == lo + 1``) covering *state* -- the historical
      equality-chain evidence, accepted with or without a written-state set;
    * a **range** row covering *state* whose intersection with *written_states*
      is exactly ``{state}`` -- a BST leaf that no other reachable state value
      can enter.

    Everything else is refused, notably a range row shared by two or more
    written constants (a real corridor) and a range row containing none.

    Args:
        lo: Inclusive lower bound of the dispatcher row.
        hi: Exclusive upper bound of the dispatcher row.
        state: The state constant being routed.
        written_states: Constants the function writes to the state variable.
            ``None``/empty keeps the caller on the singleton-only behaviour.
        target: Row target, used only for the DEBUG audit line.
        site: Short caller tag, used only for the DEBUG audit line.

    Returns:
        True when the row is exact route evidence for *state*.
    """
    try:
        lo_i = int(lo)
        hi_i = int(hi)
        state_u32 = int(state) & U32_MASK
    except _COERCION_ERRORS:
        return False
    if hi_i <= lo_i:
        return False
    if not (lo_i <= state_u32 < hi_i):
        return False
    if hi_i == lo_i + 1:
        return True
    if not interval_isolates_state(
        lo=lo_i, hi=hi_i, state=state_u32, written_states=written_states
    ):
        return False
    if logger.debug_on:
        logger.debug(
            "ROUTE_EXACTNESS: %sstate 0x%08X isolated by range row "
            "[0x%08X, 0x%08X) -> target %s",
            f"{site}: " if site else "",
            state_u32,
            lo_i,
            hi_i,
            "?" if target is None else str(int(target)),
        )
    return True
