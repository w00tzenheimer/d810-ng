"""Causal leaves for dispatcher state-write recovery (ticket d81-qt4v).

The unflattener's terminal record (ticket ``d81-rhu6``) names *that* a
candidate bailed; it cannot say *why* 158 dispatcher corridors stayed
residual.  The answer is one level down, at the concrete leg's per-corridor
emu-consult: each consult either proves a next-state or abstains, and the
abstentions have different, individually fixable causes -- a multi-def
give-up, a value derived from a synthetic call return, an unseeded global
read, or no reaching definition within the glue hop bound.

This module owns that record.  It is IDA-free by construction (plain block
serials, EAs and outcome tokens), so the classification and the residual
decomposition are unit-testable without a live ``mba_t``.

Facts stay append-only.  A consult is recorded when it happens, but the
events are BUILT once the partition's verdict is known, so
``contributed_to_unresolved_transition`` is written into the record rather
than back-filled onto an already-published one.

Diagnostic only: nothing here is a decision input, and no consumer in the
optimizer reads these records back.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.core import logging
from d810.core.observability import emit
from d810.core.observability_events import (
    STATE_WRITE_RESOLUTION_OUTCOMES,
    StateWriteResolutionObserved,
)
from d810.core.typing import Callable, Iterable, Mapping, Sequence

logger = logging.getLogger("d810.unflat.statewrite")

# -- cause vocabulary ---------------------------------------------------------
#: The consult proved an exact next-state and the abstract floor accepted it.
CAUSE_RESOLVED = "resolved"
#: Several reaching definitions and neither the edge nor agreement singled
#: one out (``emulator.py`` ``phi_multi_def``).
CAUSE_PHI_MULTI_DEF = "phi_multi_def"
#: The operand had no reaching definition at all (live-in seeding gap).
CAUSE_NO_REACHING_DEFS = "no_reaching_defs"
#: A stack slot at or above ``mba.minstkref`` lies in ALIASED memory, where
#: Hex-Rays builds no ``get_stk_chain`` entry under ``GC_REGS_AND_STKVARS``.
#: "ndefs=0" there is a chain-COVERAGE gap, not a missing definition: the slot
#: has a live def in every snapshot (ticket d81-cor5, plan section 6.5).
CAUSE_STACK_SLOT_IN_ALIASED_MEMORY = "stack_slot_in_aliased_memory"
#: Exactly one reaching definition, and evaluating it failed.
CAUSE_SINGLE_DEF_EVAL_FAILED = "single_def_eval_failed"
#: The value derives from a call the emulator MODELED rather than computed,
#: so it is not a proven next-state (ticket d81-0xzp).
CAUSE_SYNTHETIC_TAINT = "synthetic_taint"
#: A writable global read that the IDB does not seed.
CAUSE_GLOBAL_NOT_SEEDED = "global_not_seeded"
#: The corridor was walked up to ``_GLUE_HOP_BOUND`` blocks through
#: store-less glue and still found no defining block (ticket d81-182q).
CAUSE_NO_DEF_WITHIN_HOP_BOUND = "no_def_within_hop_bound"
#: The block the consult stepped writes no state variable.
CAUSE_NO_STATE_WRITE = "no_state_write_in_block"
#: There is no live block to step.
CAUSE_NO_LIVE_BLOCK = "no_live_block"
#: The interpreter raised; a failure means "cannot prove" -> abstain.
CAUSE_EMULATOR_RAISED = "emulator_raised"
#: A ⊤ floor under ``strict_floor``: refining on its strength is unsound.
CAUSE_TOP_FLOOR_STRICT = "top_floor_strict"
#: The emulator claimed a value the abstract floor does not contain.
CAUSE_FOLD_REJECTED = "fold_rejected"
#: An abstention whose cause the emulator did not name.
CAUSE_UNRESOLVED = "unresolved"

STATE_WRITE_RESOLUTION_CAUSES = frozenset(
    {
        CAUSE_RESOLVED,
        CAUSE_PHI_MULTI_DEF,
        CAUSE_NO_REACHING_DEFS,
        CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
        CAUSE_SINGLE_DEF_EVAL_FAILED,
        CAUSE_SYNTHETIC_TAINT,
        CAUSE_GLOBAL_NOT_SEEDED,
        CAUSE_NO_DEF_WITHIN_HOP_BOUND,
        CAUSE_NO_STATE_WRITE,
        CAUSE_NO_LIVE_BLOCK,
        CAUSE_EMULATOR_RAISED,
        CAUSE_TOP_FLOOR_STRICT,
        CAUSE_FOLD_REJECTED,
        CAUSE_UNRESOLVED,
    }
)

#: Precedence when one consult recorded several causes.  A synthetic-taint
#: rejection is decisive (the value WAS computed, and deliberately discarded),
#: so it outranks the merge give-up that a later operand happened to hit; a
#: merge give-up in turn outranks the single-def failure it can cause.
_CAUSE_PRECEDENCE: tuple[str, ...] = (
    CAUSE_SYNTHETIC_TAINT,
    CAUSE_PHI_MULTI_DEF,
    # More specific than the bare "no reaching defs" it refines: Hex-Rays
    # returned no chain because the slot is aliased, not because nothing
    # defines it (ticket d81-cor5).
    CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
    CAUSE_NO_REACHING_DEFS,
    CAUSE_GLOBAL_NOT_SEEDED,
    CAUSE_SINGLE_DEF_EVAL_FAILED,
)

#: Abstain ``reason`` strings the emulator already produces, mapped to tokens.
_REASON_CAUSES: Mapping[str, str] = {
    "no live block": CAUSE_NO_LIVE_BLOCK,
    "no state-var write in block": CAUSE_NO_STATE_WRITE,
    "history eval raised": CAUSE_EMULATOR_RAISED,
    "emulator+history could not resolve state-var write": CAUSE_UNRESOLVED,
}


def dominant_cause(causes: Iterable[str]) -> str:
    """The one cause that best explains a consult that recorded several.

    Known tokens are ranked by :data:`_CAUSE_PRECEDENCE`; an unknown token is
    kept verbatim (a newly-added emulator cause must show up in the
    decomposition rather than be silently folded into ``unresolved``).

    >>> dominant_cause([])
    'unresolved'
    >>> dominant_cause(["single_def_eval_failed", "phi_multi_def"])
    'phi_multi_def'
    """
    seen = [str(cause) for cause in causes if cause]
    if not seen:
        return CAUSE_UNRESOLVED
    for candidate in _CAUSE_PRECEDENCE:
        if candidate in seen:
            return candidate
    for candidate in seen:
        if candidate not in STATE_WRITE_RESOLUTION_CAUSES:
            return candidate
    return seen[0]


def classify_state_write_cause(
    *,
    outcome_kind: str,
    resolved: bool,
    reason: str = "",
    emulator_cause: str = "",
    corridor_exhausted: bool = False,
) -> str:
    """Name the cause of one emu-consult decision.

    ``outcome_kind`` is the emulation outcome ADT's class name
    (``ExactResult`` / ``Abstain`` / ``Unsupported``), ``resolved`` is whether
    ``fold_exact`` accepted it, ``emulator_cause`` is the token the emulator
    attached to its abstention, and ``corridor_exhausted`` says the glue walk
    ran out of hops before any block defined the operands.

    >>> classify_state_write_cause(outcome_kind="ExactResult", resolved=True)
    'resolved'
    >>> classify_state_write_cause(outcome_kind="ExactResult", resolved=False)
    'fold_rejected'
    """
    if resolved:
        return CAUSE_RESOLVED
    if corridor_exhausted:
        # The corridor question ("is there a defining block on this path at
        # all?") subsumes whatever the last consult on it happened to hit.
        return CAUSE_NO_DEF_WITHIN_HOP_BOUND
    if emulator_cause:
        return dominant_cause([emulator_cause])
    if outcome_kind == "ExactResult":
        return CAUSE_FOLD_REJECTED
    mapped = _REASON_CAUSES.get(str(reason).strip())
    if mapped is not None:
        return mapped
    return CAUSE_UNRESOLVED


def format_corridor(corridor: Sequence[int]) -> str:
    """Render one incoming corridor path, nearest block to the use first.

    >>> format_corridor((355, 397))
    '355>397'
    >>> format_corridor(())
    '-'
    """
    if not corridor:
        return "-"
    return ">".join(str(int(serial)) for serial in corridor)


class AbstainCauseLog:
    """Bounded channel a concrete emulator reports WHY it abstained through.

    The interpreter already knows the difference between "no reaching defs",
    "several reaching defs and the edge did not single one out" and "one def
    that failed to evaluate", but until now that distinction lived only in a
    DEBUG line.  The log carries it back to the consult site, so a residual
    dispatcher corridor decomposes by cause.

    Purely additive and bounded: nothing here changes an evaluation, and a
    pathological block cannot grow the log without limit.

    >>> log = AbstainCauseLog()
    >>> log.note("no_reaching_defs")
    >>> log.note("phi_multi_def", def_sites=((329, 0x1000),))
    >>> log.dominant()
    'phi_multi_def'
    >>> log.def_sites()
    ((329, 4096),)

    A second, NARROWER question -- "why did THIS instruction fail" -- is what a
    per-instruction WARNING needs, so the log also carries a cursor on the most
    recently noted cause.  :meth:`begin_step` forgets only that cursor, never
    the accumulated causes :meth:`dominant` ranks, so the block-level consult
    slice 4 ships is byte-identical.

    >>> log.begin_step()
    >>> log.latest()
    ''
    >>> log.dominant()
    'phi_multi_def'
    """

    __slots__ = ("_causes", "_def_sites", "_last")

    #: Bound on the definition sites reported for one abstention.
    MAX_DEF_SITES = 16
    #: Bound on the distinct causes one consult accumulates.
    MAX_CAUSES = 16

    def __init__(self) -> None:
        self._causes: list[str] = []
        self._def_sites: dict[str, list[tuple[int, int]]] = {}
        self._last: str = ""

    def note(
        self, cause: str, *, def_sites: Sequence[tuple[int, int]] = ()
    ) -> None:
        """Record one abstention cause and the definition sites behind it."""
        token = str(cause or "").strip()
        if not token:
            return
        if token not in self._def_sites:
            if len(self._causes) >= self.MAX_CAUSES:
                return
            self._causes.append(token)
            self._def_sites[token] = []
        self._last = token
        sites = self._def_sites[token]
        for entry in def_sites:
            if len(sites) >= self.MAX_DEF_SITES:
                break
            try:
                blk, ea = entry
                site = (int(blk), int(ea))
            except (TypeError, ValueError):
                continue
            if site not in sites:
                sites.append(site)

    def dominant(self) -> str:
        """The cause that best explains this abstention, or ``""``."""
        if not self._causes:
            return ""
        return dominant_cause(self._causes)

    def def_sites(self) -> tuple[tuple[int, int], ...]:
        """Definition sites recorded for the dominant cause."""
        return tuple(self._def_sites.get(self.dominant(), ()))

    def begin_step(self) -> None:
        """Start a new instruction: forget the CURSOR, keep the causes.

        A stale cursor would attribute the previous instruction's cause to this
        one, which is exactly the misattribution a cause token is supposed to
        end (ticket d81-c6n7).
        """
        self._last = ""

    def latest(self) -> str:
        """The cause noted most recently since the last :meth:`begin_step`."""
        return self._last

    def latest_def_sites(self) -> tuple[tuple[int, int], ...]:
        """Definition sites recorded for :meth:`latest`."""
        if not self._last:
            return ()
        return tuple(self._def_sites.get(self._last, ()))

    def clear(self) -> None:
        """Drop everything; called at the start of each consult."""
        self._causes.clear()
        self._def_sites.clear()
        self._last = ""


@dataclass(slots=True)
class StateWriteConsult:
    """One recorded emu-consult, before the partition's verdict is known."""

    corridor: tuple[int, ...]
    outcome: str
    cause: str
    reason: str = ""
    store_cells: int = 0
    folded_value: int | None = None
    def_sites: tuple[tuple[int, int], ...] = ()
    contributed_to_unresolved_transition: bool = False

    @property
    def resolved(self) -> bool:
        return self.cause == CAUSE_RESOLVED


_OUTCOME_KINDS: Mapping[str, str] = {
    "ExactResult": "exact_result",
    "Abstain": "abstain",
    "Unsupported": "unsupported",
}


def _outcome_token(outcome_kind: str, resolved: bool) -> str:
    token = _OUTCOME_KINDS.get(str(outcome_kind), "")
    if token:
        return token
    if str(outcome_kind) in STATE_WRITE_RESOLUTION_OUTCOMES:
        return str(outcome_kind)
    return "exact_result" if resolved else "abstain"


@dataclass(slots=True)
class StateWriteResolutionRecorder:
    """Collects one state-write block's per-corridor consults.

    Scoped to a single ``(block, predecessor partition)`` attempt: the caller
    records every consult, then either flushes a resolved partition or calls
    :meth:`mark_unresolved_transition` first, which flags exactly the
    abstentions whose corridor is why the transition stayed unresolved.
    """

    func_ea: int
    block_serial: int
    block_ea: int = 0
    maturity: str = ""
    session_id: str = ""
    consults: list[StateWriteConsult] = field(default_factory=list)

    #: Bound on the consults one block keeps, so a pathological corridor fan
    #: cannot turn diagnostics into a memory leak.
    MAX_CONSULTS = 256

    def note(
        self,
        *,
        corridor: Sequence[int],
        outcome_kind: str,
        resolved: bool,
        reason: str = "",
        store_cells: int = 0,
        folded_value: int | None = None,
        emulator_cause: str = "",
        def_sites: Sequence[tuple[int, int]] = (),
        corridor_exhausted: bool = False,
    ) -> StateWriteConsult | None:
        """Record one consult; the LAST record for a corridor wins.

        A glue corridor is consulted repeatedly as the walk extends it, and
        only the final verdict for that exact path is a fact about it.
        """
        path = tuple(int(serial) for serial in corridor)
        consult = StateWriteConsult(
            corridor=path,
            outcome=_outcome_token(outcome_kind, resolved),
            cause=classify_state_write_cause(
                outcome_kind=outcome_kind,
                resolved=resolved,
                reason=reason,
                emulator_cause=emulator_cause,
                corridor_exhausted=corridor_exhausted,
            ),
            reason=str(reason or ""),
            store_cells=int(store_cells),
            folded_value=None if folded_value is None else int(folded_value),
            def_sites=tuple((int(blk), int(ea)) for blk, ea in def_sites),
        )
        for index, existing in enumerate(self.consults):
            if existing.corridor == path:
                self.consults[index] = consult
                return consult
        if len(self.consults) >= self.MAX_CONSULTS:
            return None
        self.consults.append(consult)
        return consult

    def drop(self, corridor: Sequence[int]) -> bool:
        """Forget a probe that a deeper or sibling consult superseded.

        The glue walk probes a corridor prefix, then extends it; only the path
        the walk SETTLES on is a fact about that incoming edge.  Keeping the
        intermediate probes would inflate the residual decomposition with
        consults that no corridor is actually blocked on.
        """
        path = tuple(int(serial) for serial in corridor)
        for index, consult in enumerate(self.consults):
            if consult.corridor == path:
                del self.consults[index]
                return True
        return False

    def mark_corridor_exhausted(self, corridor: Sequence[int]) -> bool:
        """Re-cause one corridor as ``no_def_within_hop_bound``.

        The glue walk consults a corridor repeatedly as it extends it; only the
        walk itself knows that the FINAL failure was "no defining block within
        the hop bound" rather than whatever the last consult happened to hit.
        """
        path = tuple(int(serial) for serial in corridor)
        for consult in self.consults:
            if consult.corridor != path:
                continue
            if consult.resolved:
                return False
            consult.cause = CAUSE_NO_DEF_WITHIN_HOP_BOUND
            return True
        return False

    def mark_unresolved_transition(self) -> int:
        """Flag every abstention as a cause of an unresolved transition.

        Returns how many consults were flagged.  A resolved consult is never
        flagged: it proved its corridor, so it cannot be the reason the
        partition abstained wholesale.
        """
        marked = 0
        for consult in self.consults:
            if consult.resolved:
                continue
            consult.contributed_to_unresolved_transition = True
            marked += 1
        return marked

    def build_events(self) -> tuple[StateWriteResolutionObserved, ...]:
        """One append-only fact per recorded corridor."""
        events: list[StateWriteResolutionObserved] = []
        for consult in self.consults:
            events.append(
                StateWriteResolutionObserved(
                    func_ea=int(self.func_ea),
                    block_serial=int(self.block_serial),
                    block_ea=int(self.block_ea),
                    corridor=consult.corridor,
                    outcome=consult.outcome,
                    cause=consult.cause,
                    reason=consult.reason,
                    store_cells=consult.store_cells,
                    folded_value=consult.folded_value,
                    def_sites=consult.def_sites,
                    contributed_to_unresolved_transition=(
                        consult.contributed_to_unresolved_transition
                    ),
                    maturity=str(self.maturity),
                    session_id=str(self.session_id),
                )
            )
        return tuple(events)

    def emit(self, emit_fn: Callable[[object], object] | None = None) -> int:
        """Publish every recorded fact on the in-memory bus.

        Never raises for a diagnostic reason: a bus failure must not change an
        optimizer outcome.
        """
        publish = emit if emit_fn is None else emit_fn
        published = 0
        for event in self.build_events():
            try:
                publish(event)
            except Exception:  # noqa: BLE001 — diagnostics never break a run
                logger.debug("state-write resolution fact publish failed", exc_info=True)
                continue
            published += 1
        return published


def decompose_by_cause(
    events: Iterable[StateWriteResolutionObserved],
) -> dict[str, int]:
    """Count state-write resolution facts by cause, most frequent first."""
    counts: dict[str, int] = {}
    for event in events:
        counts[event.cause] = counts.get(event.cause, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def top_unresolved_corridors(
    events: Iterable[StateWriteResolutionObserved], *, limit: int = 10
) -> tuple[StateWriteResolutionObserved, ...]:
    """The corridors whose abstention left a transition unresolved.

    Ordered by block serial then corridor so the listing is deterministic.
    """
    contributors = [
        event for event in events if event.contributed_to_unresolved_transition
    ]
    contributors.sort(key=lambda event: (event.block_serial, event.corridor))
    return tuple(contributors[: max(0, int(limit))])


__all__ = [
    "AbstainCauseLog",
    "CAUSE_EMULATOR_RAISED",
    "CAUSE_FOLD_REJECTED",
    "CAUSE_GLOBAL_NOT_SEEDED",
    "CAUSE_NO_DEF_WITHIN_HOP_BOUND",
    "CAUSE_NO_LIVE_BLOCK",
    "CAUSE_NO_REACHING_DEFS",
    "CAUSE_NO_STATE_WRITE",
    "CAUSE_PHI_MULTI_DEF",
    "CAUSE_RESOLVED",
    "CAUSE_SINGLE_DEF_EVAL_FAILED",
    "CAUSE_STACK_SLOT_IN_ALIASED_MEMORY",
    "CAUSE_SYNTHETIC_TAINT",
    "CAUSE_TOP_FLOOR_STRICT",
    "CAUSE_UNRESOLVED",
    "STATE_WRITE_RESOLUTION_CAUSES",
    "StateWriteConsult",
    "StateWriteResolutionRecorder",
    "classify_state_write_cause",
    "decompose_by_cause",
    "dominant_cause",
    "format_corridor",
    "top_unresolved_corridors",
]
