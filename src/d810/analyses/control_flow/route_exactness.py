"""Single owner of the BST route-exactness decision (tickets d81-8xhg, d81-pk0f).

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

That argument is CLOSED-WORLD: it reads "``t`` is not in the written set" as
"``t`` can never occur".  The claim is only sound when the written set is an
over-approximation of every value the state slot can hold, so the set alone is
not admissible evidence -- it must arrive with a **completeness receipt**
(:class:`WrittenStateSet`) saying the collector classified every write it saw.
When the receipt is incomplete the range branch ABSTAINS and the caller falls
back to the pre-d81-8xhg singleton-only refusal (ticket d81-pk0f).

Enlarging ``constants`` is the safe direction: a bigger set can only make the
intersection with ``[lo, hi)`` bigger, which can only turn acceptances into
refusals.  Wherever a value is uncertain the collector therefore prefers to
*include* it over dropping it, and only reports incompleteness when a write
cannot be turned into any concrete value at all.

Every consumer of that decision (supplemental handoff anchoring, entry/route
evidence, and the interval back-fill into ``handler_state_map``) calls
:func:`is_exact_route_interval` so the three cannot drift apart.

Pure Python -- no IDA imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Any, Iterable, Optional, Sequence

logger = getLogger(__name__)

__all__ = [
    "MAX_STATE_WRITES_PER_BLOCK",
    "REASON_BELOW_MIN_STATE_CONSTANT",
    "REASON_BLOCK_UNREADABLE",
    "REASON_MULTI_WRITE_BLOCK",
    "REASON_NONCONSTANT_WRITE",
    "REASON_NO_RECEIPT",
    "REASON_NO_STATE_VARIABLE",
    "REASON_UNRESOLVED_WRITE",
    "REASON_UNSUPPORTED_ALIAS",
    "StateWriteKind",
    "StateWriteObservation",
    "U32_MASK",
    "WrittenStateSet",
    "build_written_state_set",
    "coerce_written_state_set",
    "dispatcher_written_state_constants",
    "dispatcher_written_state_set",
    "interval_isolates_state",
    "is_exact_route_interval",
    "normalize_written_state_constants",
    "written_states_in_interval",
]

U32_MASK: int = 0xFFFFFFFF

# Hard cap on how many writes to the state slot a single block may contribute.
# Exceeding it means the enumeration was truncated, which is exactly the
# d81-pk0f defect (writes silently vanishing), so it costs completeness.
MAX_STATE_WRITES_PER_BLOCK: int = 64

# ---------------------------------------------------------------------------
# Incompleteness reasons.  ``complete`` is False iff at least one is present.
# ---------------------------------------------------------------------------

#: A write to the state slot whose source value could not be folded to a constant.
REASON_NONCONSTANT_WRITE = "nonconstant_write"
#: A store that may alias the state slot but whose destination could not be pinned.
REASON_UNRESOLVED_WRITE = "unresolved_write"
#: The state variable appeared in an operand form the extractor cannot decide.
REASON_UNSUPPORTED_ALIAS = "unsupported_alias"
#: No state-variable identity was recovered, so nothing could be enumerated.
REASON_NO_STATE_VARIABLE = "no_state_variable"
#: A block could not be read back from the block array.
REASON_BLOCK_UNREADABLE = "block_unreadable"
#: A block hit :data:`MAX_STATE_WRITES_PER_BLOCK` and its enumeration was truncated.
REASON_MULTI_WRITE_BLOCK = "multi_write_block"
#: A selector-only view dropped constants below the state-constant threshold.
REASON_BELOW_MIN_STATE_CONSTANT = "below_min_state_constant"
#: A bare constant collection was supplied with no receipt attesting to its closure.
REASON_NO_RECEIPT = "no_receipt"

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


class StateWriteKind(Enum):
    """How a single write to the state slot was classified.

    Only :attr:`CONSTANT` preserves completeness; every other kind means the
    collector saw a write it could not turn into a concrete value, so the
    closed-world argument behind range exactness no longer holds.
    """

    CONSTANT = "constant"
    NONCONSTANT = "nonconstant"
    UNRESOLVED = "unresolved"
    UNSUPPORTED_ALIAS = "unsupported_alias"
    TRUNCATED = "truncated"


_KIND_TO_REASON: dict[StateWriteKind, str] = {
    StateWriteKind.NONCONSTANT: REASON_NONCONSTANT_WRITE,
    StateWriteKind.UNRESOLVED: REASON_UNRESOLVED_WRITE,
    StateWriteKind.UNSUPPORTED_ALIAS: REASON_UNSUPPORTED_ALIAS,
    StateWriteKind.TRUNCATED: REASON_MULTI_WRITE_BLOCK,
}


@dataclass(frozen=True)
class StateWriteObservation:
    """One write to the state slot, as classified by the collector.

    Attributes:
        kind: Classification of the write.
        value: Folded constant for :attr:`StateWriteKind.CONSTANT`, else ``None``.
        block_serial: Block the write lives in, for diagnostics.
        insn_index: Instruction index inside the block, for diagnostics.
        detail: Free-form provenance string, for diagnostics.
    """

    kind: StateWriteKind
    value: Optional[int] = None
    block_serial: Optional[int] = None
    insn_index: Optional[int] = None
    detail: str = ""


@dataclass(frozen=True)
class WrittenStateSet:
    """The state constants a function writes, plus whether that set is closed.

    ``constants`` is an OVER-approximation of every value the state slot can
    hold; ``complete`` says the collector classified every write it saw, which
    is the precondition for reading "absent from ``constants``" as "cannot
    occur".  ``reasons`` names why it could not (ticket d81-pk0f).

    The invariant ``complete == (not reasons)`` is enforced on construction so
    a caller cannot hand-assemble a receipt that claims closure while carrying
    an unexplained write.

    >>> WrittenStateSet.exhaustive({0x1000}).complete
    True
    >>> WrittenStateSet.exhaustive({0x1000}, reasons=[REASON_NONCONSTANT_WRITE]).complete
    False
    >>> WrittenStateSet().complete
    False
    """

    constants: frozenset[int] = frozenset()
    complete: bool = False
    reasons: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "constants", normalize_written_state_constants(self.constants)
        )
        reasons = tuple(sorted({str(reason) for reason in self.reasons or ()}))
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "complete", bool(self.complete) and not reasons)

    @classmethod
    def exhaustive(
        cls,
        constants: Optional[Iterable[Any]] = None,
        *,
        reasons: Optional[Iterable[str]] = None,
    ) -> "WrittenStateSet":
        """Build a receipt that claims closure unless *reasons* says otherwise."""
        return cls(
            constants=normalize_written_state_constants(constants),
            complete=True,
            reasons=tuple(reasons or ()),
        )

    @classmethod
    def unknown(
        cls,
        *reasons: str,
        constants: Optional[Iterable[Any]] = None,
    ) -> "WrittenStateSet":
        """Build an explicitly incomplete receipt carrying *reasons*."""
        return cls(
            constants=normalize_written_state_constants(constants),
            complete=False,
            reasons=tuple(reasons) or (REASON_NO_RECEIPT,),
        )

    def with_reasons(self, *reasons: str) -> "WrittenStateSet":
        """Return this receipt with *reasons* added (and closure withdrawn)."""
        if not reasons:
            return self
        return WrittenStateSet(
            constants=self.constants,
            complete=False,
            reasons=self.reasons + tuple(reasons),
        )

    def filtered(self, min_value: int) -> "WrittenStateSet":
        """Return the ``>= min_value`` view of this set.

        Consumers that want selector-grade constants only (the legacy
        decision-DAG union) use this.  Dropping members breaks closure, so the
        result is marked incomplete with
        :data:`REASON_BELOW_MIN_STATE_CONSTANT` whenever anything was removed:
        ``MIN_STATE_CONSTANT`` is a shape heuristic, not a proof that small
        values cannot be selectors.

        Args:
            min_value: Inclusive lower bound to keep.

        Returns:
            The filtered receipt.
        """
        try:
            threshold = int(min_value)
        except _COERCION_ERRORS:
            return self
        kept = frozenset(state for state in self.constants if state >= threshold)
        if kept == self.constants:
            return self
        return WrittenStateSet(
            constants=kept,
            complete=False,
            reasons=self.reasons + (REASON_BELOW_MIN_STATE_CONSTANT,),
        )

    def in_interval(self, lo: int, hi: int) -> frozenset[int]:
        """Return the members inside the half-open interval ``[lo, hi)``."""
        try:
            lo_u32 = int(lo) & U32_MASK
            hi_i = int(hi)
        except _COERCION_ERRORS:
            return frozenset()
        return frozenset(state for state in self.constants if lo_u32 <= state < hi_i)

    def describe(self) -> str:
        """Return a one-line audit string for logs."""
        return (
            f"complete={self.complete} constants={len(self.constants)}"
            f" reasons={','.join(self.reasons) or '-'}"
        )


#: Shared "nothing was collected" receipt.
_NO_EVIDENCE = WrittenStateSet.unknown(REASON_NO_RECEIPT)


def build_written_state_set(
    observations: Sequence[StateWriteObservation],
    *,
    initial_state: Optional[int] = None,
    extra_reasons: Optional[Iterable[str]] = None,
) -> WrittenStateSet:
    """Aggregate classified writes into a completeness receipt.

    Every :attr:`StateWriteKind.CONSTANT` observation contributes its value;
    every other kind contributes an incompleteness reason.  ``initial_state``
    is added unconditionally because the prologue write is a real occurrence
    even when it lives outside the scanned shape.

    Args:
        observations: Per-write classifications produced by the collector.
        initial_state: Recovered pre-header state constant, when known.
        extra_reasons: Reasons raised outside any single write (unreadable
            blocks, missing state-variable identity).

    Returns:
        The receipt.

    >>> receipt = build_written_state_set(
    ...     [StateWriteObservation(StateWriteKind.CONSTANT, 0x1000)]
    ... )
    >>> receipt.complete, sorted(receipt.constants)
    (True, [4096])
    >>> build_written_state_set(
    ...     [StateWriteObservation(StateWriteKind.NONCONSTANT)]
    ... ).reasons
    ('nonconstant_write',)
    """
    constants: set[int] = set()
    reasons: set[str] = {str(reason) for reason in (extra_reasons or ())}
    for observation in observations or ():
        if (
            observation.kind is StateWriteKind.CONSTANT
            and observation.value is not None
        ):
            try:
                constants.add(int(observation.value) & U32_MASK)
            except _COERCION_ERRORS:
                reasons.add(REASON_NONCONSTANT_WRITE)
            continue
        reasons.add(_KIND_TO_REASON.get(observation.kind, REASON_UNRESOLVED_WRITE))
    if initial_state is not None:
        try:
            constants.add(int(initial_state) & U32_MASK)
        except _COERCION_ERRORS:
            reasons.add(REASON_NONCONSTANT_WRITE)
    return WrittenStateSet(
        constants=frozenset(constants),
        complete=not reasons,
        reasons=tuple(sorted(reasons)),
    )


def coerce_written_state_set(value: Any) -> WrittenStateSet:
    """Return *value* as a :class:`WrittenStateSet`.

    A bare collection is NOT a receipt: nothing attests that the collector
    enumerated every write behind it, so it coerces to an INCOMPLETE receipt
    carrying :data:`REASON_NO_RECEIPT`.  That keeps "no receipt" and "receipt
    says incomplete" on the same, conservative, code path (ticket d81-pk0f).

    Args:
        value: A receipt, a bare iterable of constants, or ``None``.

    Returns:
        The receipt.

    >>> coerce_written_state_set(None).complete
    False
    >>> coerce_written_state_set({1, 2}).reasons
    ('no_receipt',)
    >>> coerce_written_state_set(WrittenStateSet.exhaustive({1})).complete
    True
    """
    if isinstance(value, WrittenStateSet):
        return value
    if value is None:
        return _NO_EVIDENCE
    constants = normalize_written_state_constants(value)
    if not constants:
        return _NO_EVIDENCE
    return WrittenStateSet(
        constants=constants, complete=False, reasons=(REASON_NO_RECEIPT,)
    )


def dispatcher_written_state_set(dispatcher: Any) -> WrittenStateSet:
    """Return the completeness receipt a dispatcher carries, if any.

    Duck-typed on purpose: route resolution accepts several dispatcher shapes
    (``IntervalDispatcher``, ``StateDispatcherMap``, test doubles).  A shape
    that carries no receipt yields an incomplete one, which keeps the caller
    on the singleton-only path.

    Args:
        dispatcher: Any dispatcher-like object, or ``None``.

    Returns:
        The receipt.
    """
    if dispatcher is None:
        return _NO_EVIDENCE
    try:
        receipt = getattr(dispatcher, "written_states", None)
    except _COERCION_ERRORS:
        receipt = None
    if isinstance(receipt, WrittenStateSet):
        return receipt
    try:
        states = getattr(dispatcher, "written_state_constants", None)
    except _COERCION_ERRORS:
        return _NO_EVIDENCE
    return coerce_written_state_set(states)


def dispatcher_written_state_constants(dispatcher: Any) -> frozenset[int]:
    """Return just the constants a dispatcher carries (no completeness signal).

    Diagnostics only.  Route decisions must go through
    :func:`dispatcher_written_state_set` so they see the receipt.

    Args:
        dispatcher: Any dispatcher-like object, or ``None``.

    Returns:
        The dispatcher's masked written-state constants.
    """
    return dispatcher_written_state_set(dispatcher).constants


def written_states_in_interval(
    *,
    lo: int,
    hi: int,
    written_states: Any,
) -> frozenset[int]:
    """Return the written state constants contained in ``[lo, hi)``.

    Args:
        lo: Inclusive lower bound.
        hi: Exclusive upper bound.
        written_states: A receipt, or a bare collection of constants.

    Returns:
        The subset of *written_states* inside the interval.  Note this ignores
        completeness on purpose -- it is the membership primitive, not the
        decision; callers deciding exactness must use
        :func:`interval_isolates_state`.
    """
    return coerce_written_state_set(written_states).in_interval(lo, hi)


def interval_isolates_state(
    *,
    lo: int,
    hi: int,
    state: int,
    written_states: Any,
) -> bool:
    """Return True when ``state`` is the sole written constant in ``[lo, hi)``.

    This is the whole novelty of ticket d81-8xhg: it decides whether a wide
    BST leaf is unambiguous *for the queried value*, using the set of values
    that can actually occur instead of the interval's width.

    It is closed-world reasoning, so it ABSTAINS (returns False) unless the
    written-state receipt attests that every write to the state slot was
    classified (ticket d81-pk0f).

    Args:
        lo: Inclusive lower bound.
        hi: Exclusive upper bound.
        state: The state constant being routed.
        written_states: A receipt, or a bare collection of constants.

    Returns:
        True when the receipt is complete and the intersection is exactly
        ``{state}``.
    """
    receipt = coerce_written_state_set(written_states)
    if not receipt.complete:
        return False
    try:
        state_u32 = int(state) & U32_MASK
    except _COERCION_ERRORS:
        return False
    return receipt.in_interval(lo, hi) == frozenset({state_u32})


def is_exact_route_interval(
    *,
    lo: int,
    hi: int,
    state: int,
    written_states: Any = None,
    target: Optional[int] = None,
    site: str = "",
) -> bool:
    """Return True when the row ``[lo, hi) -> target`` exactly binds ``state``.

    Two accepting shapes:

    * a **singleton** row (``hi == lo + 1``) covering *state* -- the historical
      equality-chain evidence, accepted with or without a written-state set;
    * a **range** row covering *state* whose intersection with a COMPLETE
      written-state receipt is exactly ``{state}`` -- a BST leaf that no other
      reachable state value can enter.

    Everything else is refused, notably a range row shared by two or more
    written constants (a real corridor), a range row containing none, and a
    range row whose receipt could not account for every write to the state
    slot (ticket d81-pk0f).

    Args:
        lo: Inclusive lower bound of the dispatcher row.
        hi: Exclusive upper bound of the dispatcher row.
        state: The state constant being routed.
        written_states: A :class:`WrittenStateSet` receipt.  ``None``, a bare
            collection, or an incomplete receipt all keep the caller on the
            singleton-only behaviour.
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
    receipt = coerce_written_state_set(written_states)
    if not interval_isolates_state(
        lo=lo_i, hi=hi_i, state=state_u32, written_states=receipt
    ):
        if logger.debug_on and not receipt.complete:
            logger.debug(
                "ROUTE_EXACTNESS: %sABSTAIN on range row [0x%08X, 0x%08X) for "
                "state 0x%08X -- written-state receipt %s",
                f"{site}: " if site else "",
                lo_i,
                hi_i,
                state_u32,
                receipt.describe(),
            )
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
