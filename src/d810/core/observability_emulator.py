"""The emulator's gap WARNINGs as a worklist (ticket d81-c6n7, slice 5).

9,620 of the 13,031 WARNING lines in an 8-day capture come from the microcode
emulator, and the user's decision (plan section 5.5) is that every one of them
is warranted: each names a real, individually fixable evaluator gap, and
closing them is what makes unflattening resolve more dispatcher corridors.
They are not demoted.  They are made *actionable*.

Three things were missing and are added here:

1. **A stable cause token.**  ``Can't evaluate instruction: ... is not defined
   for mop_r or mop_S`` was one string for a multi-def give-up, a live-in
   seeding gap and an aliased stack slot alike; the distinction only ever
   existed in a DEBUG ``DEF-USE-DIAG`` line.
2. **Dedupe with the right key.**  The pipeline builds a fresh interpreter for
   nearly every evaluation, so an instance-scoped "warn once" set still emitted
   ~1,100 lines for 3 distinct call sites; a module-scoped one (commit
   ``3bdf758d0``) fixed the count but never reset, so a second function or a
   retry silently lost its warnings.  The key is
   ``(function, attempt, cause, site)``: a site warns once per attempt.
3. **An aggregate.**  Per plan section 3.2 the count IS a diagnostic, so the
   deduped lines are summed into one per-attempt line rather than rate-limited.

IDA-free by construction (plain EAs, block serials and cause tokens), so the
whole decision layer is unit-testable without a live ``mba``.

Diagnostic only: nothing here is a decision input, and no consumer in the
optimizer reads these records back.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.core import logging
from d810.core.observability import (
    emit,
    get_active_diag_func_ea,
    get_active_diag_path,
    get_active_emulator_gap_scope,
    get_pending_emulator_gap_scopes,
)
from d810.core.observability_events import EmulatorGapObserved
from d810.core.observability_state_write import (
    CAUSE_GLOBAL_NOT_SEEDED,
    CAUSE_NO_REACHING_DEFS,
    CAUSE_PHI_MULTI_DEF,
    CAUSE_SINGLE_DEF_EVAL_FAILED,
    CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
    CAUSE_SYNTHETIC_TAINT,
)
from d810.core.observability_unflat import (
    resolve_unflat_hint_db_path,
    unflat_why_hint,
)
from d810.core.typing import Callable, Iterable, Mapping, Sequence

logger = logging.getLogger("d810.evaluator.gaps")

# -- cause vocabulary ---------------------------------------------------------
# Tokens shared with the state-write decomposition keep ONE spelling: the same
# gap seen from the emulator and from the corridor consult must aggregate.
#: A ``call`` whose callee operand is a ``mop_v`` / ``mop_b`` the emulator does
#: not model; the result is handed out as a tainted synthetic return
#: (ticket d81-0xzp).
CAUSE_UNSUPPORTED_CALL_OPERAND = "unsupported_call_operand"
#: A named Hex-Rays helper with no model (``__ROL4__``-style intrinsics aside).
CAUSE_HELPER_NOT_IMPLEMENTED = "helper_not_implemented"
#: ``ldx`` through a null address; treated as unknown rather than ``MEMORY[0]``.
CAUSE_NULL_DEREF = "null_deref"
#: A load or global read whose address lies in no IDB segment.
CAUSE_NO_SEGMENT = "no_segment"
#: ``stx`` whose value or address operand could not be evaluated.
CAUSE_STX_OPERANDS_UNRESOLVED = "stx_operands_unresolved"
#: A ``mop_r`` / ``mop_S`` read that stayed undefined and whose finer cause the
#: interpreter did not name.
CAUSE_UNDEFINED_VARIABLE = "undefined_variable"
#: An evaluation failure the emulator could not attribute at all.
CAUSE_UNCLASSIFIED = "unclassified"

EMULATOR_GAP_CAUSES = frozenset(
    {
        CAUSE_UNSUPPORTED_CALL_OPERAND,
        CAUSE_HELPER_NOT_IMPLEMENTED,
        CAUSE_GLOBAL_NOT_SEEDED,
        CAUSE_NO_REACHING_DEFS,
        CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
        CAUSE_PHI_MULTI_DEF,
        CAUSE_SINGLE_DEF_EVAL_FAILED,
        CAUSE_SYNTHETIC_TAINT,
        CAUSE_NULL_DEREF,
        CAUSE_NO_SEGMENT,
        CAUSE_STX_OPERANDS_UNRESOLVED,
        CAUSE_UNDEFINED_VARIABLE,
        CAUSE_UNCLASSIFIED,
    }
)

#: The follow-on ticket that CLOSES each gap, so the worklist is navigable
#: from the log alone.  Diagnostic text only; nothing branches on it.
EMULATOR_GAP_TICKETS: Mapping[str, str] = {
    CAUSE_UNSUPPORTED_CALL_OPERAND: "d81-0xzp",
    CAUSE_HELPER_NOT_IMPLEMENTED: "d81-0xzp",
    CAUSE_GLOBAL_NOT_SEEDED: "d81-sbx9",
    CAUSE_PHI_MULTI_DEF: "d81-182q",
    CAUSE_STACK_SLOT_IN_ALIASED_MEMORY: "d81-cor5",
}


def is_stack_slot_in_aliased_memory(
    offset: object, minstkref: object
) -> bool:
    """Whether a stack slot lies in ALIASED memory, where there is no UD chain.

    ``mba.minstkref`` is the lowest frame offset whose address was taken.  At
    and above it Hex-Rays classifies the frame as *aliased* memory, and
    ``get_ud(GC_REGS_AND_STKVARS)[blk].get_stk_chain(off, size)`` returns
    ``None`` there -- so ``ndefs=0`` for such a slot is a chain-COVERAGE gap,
    not evidence that nothing defines it (plan section 6.5, ticket d81-cor5).

    An unknown or non-positive ``minstkref`` proves nothing, so it never claims
    the gap.

    >>> is_stack_slot_in_aliased_memory(0xD30, 0x9A0)
    True
    >>> is_stack_slot_in_aliased_memory(0x3C, 0x9A0)
    False
    >>> is_stack_slot_in_aliased_memory(0xD30, None)
    False
    """
    try:
        threshold = int(minstkref)  # type: ignore[arg-type]
        slot = int(offset)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if threshold <= 0:
        return False
    return slot >= threshold


@dataclass(slots=True)
class EmulatorGap:
    """One deduped evaluator gap within a single attempt."""

    cause: str
    site_ea: int
    block_serial: int = -1
    detail: str = ""
    def_sites: tuple[tuple[int, int], ...] = ()
    occurrences: int = 1

    def key(self) -> tuple[str, int, int]:
        """The dedupe key WITHIN an attempt: cause, site EA, block."""
        return (str(self.cause), int(self.site_ea), int(self.block_serial))


@dataclass(slots=True, weakref_slot=True)
class EmulatorGapScope:
    """Every gap one ``(function, attempt)`` recorded.

    Bounded on purpose: a pathological function must not turn diagnostics into
    a memory leak, so a scope keeps at most :data:`MAX_GAPS` distinct gaps and
    each gap at most :data:`MAX_DEF_SITES` definition sites.

    Owned by the manager-layer ``DecompilationSessionContext`` (ticket
    d81-e0uy); ``weakref_slot=True`` lets tests observe that a finished
    session's scope is ordinary garbage once dropped, not retained by any
    module-level cache.
    """

    func_ea: int
    maturity: str = ""
    attempt: int = 0
    session_id: str = ""
    #: ``True`` only for a scope a ``DecompilationSessionContext`` actually
    #: owns (set in its ``__post_init__``). Defaults ``False`` so a scope
    #: minted by :func:`emulator_gap_scope` for an unowned lookup is
    #: explicitly typed as such rather than indistinguishable from a real
    #: session's scope (ticket d81-dhs3).
    owned: bool = False
    gaps: list[EmulatorGap] = field(default_factory=list)
    _index: dict[tuple[str, int, int], EmulatorGap] = field(default_factory=dict)

    #: Bound on the distinct gaps one attempt keeps.
    MAX_GAPS = 512
    #: Bound on the definition sites one gap reports.
    MAX_DEF_SITES = 8
    #: Bound on the free-text detail carried into the log and the fact.
    MAX_DETAIL = 160

    def begin_attempt(self, *, maturity: str = "", session_id: str = "") -> None:
        """Start the next attempt: bump the number, drop the dedupe state."""
        self.attempt += 1
        if maturity:
            self.maturity = str(maturity)
        if session_id:
            self.session_id = str(session_id)
        self.gaps.clear()
        self._index.clear()

    def record(
        self,
        cause: str,
        *,
        site_ea: int = 0,
        block_serial: int = -1,
        detail: str = "",
        def_sites: Sequence[tuple[int, int]] = (),
    ) -> EmulatorGap | None:
        """Record one gap sighting.

        Returns the gap when this is its FIRST sighting in this attempt (the
        caller then warns), ``None`` when it is a repeat or the bound is hit.
        A repeat still increments ``occurrences``, so the aggregate keeps the
        count the dedupe would otherwise hide.
        """
        token = str(cause or "").strip() or CAUSE_UNCLASSIFIED
        gap = EmulatorGap(
            cause=token,
            site_ea=int(site_ea),
            block_serial=int(block_serial),
            detail=str(detail or "")[: self.MAX_DETAIL],
            def_sites=tuple(
                (int(blk), int(ea))
                for blk, ea in tuple(def_sites)[: self.MAX_DEF_SITES]
            ),
        )
        existing = self._index.get(gap.key())
        if existing is not None:
            existing.occurrences += 1
            if not existing.def_sites and gap.def_sites:
                existing.def_sites = gap.def_sites
            return None
        if len(self.gaps) >= self.MAX_GAPS:
            return None
        self._index[gap.key()] = gap
        self.gaps.append(gap)
        return gap

    def counts(self) -> dict[str, int]:
        """Sightings per cause, most frequent first (repeats included)."""
        counts: dict[str, int] = {}
        for gap in self.gaps:
            counts[gap.cause] = counts.get(gap.cause, 0) + int(gap.occurrences)
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def is_empty(self) -> bool:
        return not self.gaps

    def clear(self) -> None:
        self.gaps.clear()
        self._index.clear()


# -- the per-function scope -----------------------------------------------
#: Owned by the manager-layer DecompilationSessionContext (ticket d81-e0uy),
#: not a module dict: minted with the session, unreachable once it is
#: popped and dropped. Reached only through the registered indirection in
#: ``d810.core.observability`` (transforms/evaluator producers must not
#: import d810.manager directly).


#: Unowned scopes, keyed by ``func_ea``. Populated only when no lifecycle
#: session backs a lookup (a bare adapter under test, or a caller invoked
#: before/after a session's lifetime). A dict, not a fresh object per call:
#: ``record_emulator_gap`` and ``format_emulator_gap`` must observe the SAME
#: scope within one ``_warn_gap`` for dedupe to hold at all (ticket d81-dhs3
#: -- minting a new ``EmulatorGapScope`` per lookup silently defeated dedupe
#: between the two, and made every "no session" attempt/maturity render as
#: attempt=0/maturity="" no matter what the caller had just recorded).
#: Never claims session ownership (``owned`` stays ``False``); reclaimed
#: once a real session takes over the same ``func_ea``.
_unowned_emulator_gap_scopes: dict[int, EmulatorGapScope] = {}


def emulator_gap_scope(func_ea: int) -> EmulatorGapScope:
    """The active session's scope for ``func_ea``, or a shared unowned one.

    Returns the lifecycle-owned scope when a session owns ``func_ea``.
    Otherwise returns the SAME unowned, explicitly ``owned=False``
    ``EmulatorGapScope`` on every call for this ``func_ea`` -- callers never
    see ``None``, and dedupe still holds across repeat lookups, but the
    scope never impersonates a real session (ticket d81-dhs3).
    """
    key = int(func_ea)
    existing = get_active_emulator_gap_scope(key)
    if existing is not None:
        # A real session now owns this func_ea; forget any stale unowned
        # scope so a later gap here never dedupes against leftovers.
        _unowned_emulator_gap_scopes.pop(key, None)
        return existing
    scope = _unowned_emulator_gap_scopes.get(key)
    if scope is None:
        scope = EmulatorGapScope(func_ea=key, owned=False)
        _unowned_emulator_gap_scopes[key] = scope
    return scope


def begin_emulator_gap_attempt(
    func_ea: int, *, maturity: str = "", session_id: str = ""
) -> EmulatorGapScope:
    """Open the next attempt for ``func_ea`` and reset its dedupe state."""
    scope = emulator_gap_scope(func_ea)
    scope.begin_attempt(maturity=maturity, session_id=session_id)
    return scope


def record_emulator_gap(
    func_ea: int,
    cause: str,
    *,
    site_ea: int = 0,
    block_serial: int = -1,
    maturity: str = "",
    detail: str = "",
    def_sites: Sequence[tuple[int, int]] = (),
) -> EmulatorGap | None:
    """Record one gap sighting; ``None`` means "already warned this attempt".

    A ``maturity`` that disagrees with the scope's ROTATES the attempt first:
    the emulator crosses maturities without any explicit attempt boundary, and
    an aggregate that mixed two maturities would be unreadable.  The rotation
    flushes the previous attempt so its facts are not lost.

    Never raises for a diagnostic reason.
    """
    try:
        scope = emulator_gap_scope(func_ea)
        if maturity and scope.maturity and str(maturity) != scope.maturity:
            _flush_scope(scope, log=logger, emit_fn=None)
            scope.begin_attempt(maturity=str(maturity))
        elif maturity and not scope.maturity:
            scope.maturity = str(maturity)
            if scope.attempt == 0:
                scope.attempt = 1
        elif scope.attempt == 0:
            scope.attempt = 1
        return scope.record(
            cause,
            site_ea=site_ea,
            block_serial=block_serial,
            detail=detail,
            def_sites=def_sites,
        )
    except Exception:  # noqa: BLE001 — diagnostics never break an evaluation
        logger.debug("emulator gap record failed", exc_info=True)
        return None


def emulator_gap_counts(func_ea: int) -> dict[str, int]:
    """Sightings per cause for ``func_ea``'s current attempt."""
    scope = get_active_emulator_gap_scope(int(func_ea))
    return {} if scope is None else scope.counts()


def active_gap_db_path(func_ea: int) -> str | None:
    """The capture path a ``next=`` hint may name for ``func_ea``, or ``None``.

    ``get_active_diag_path`` names whatever DB is *currently* open, which in a
    headless batch is the FIRST function's file for every later function; the
    slice-1 resolver rejects that mismatch rather than printing a misleading
    path (ticket aa-smoo).
    """
    try:
        return resolve_unflat_hint_db_path(
            int(func_ea), get_active_diag_path(), get_active_diag_func_ea()
        )
    except Exception:  # noqa: BLE001 — a hint must never break a run
        return None


# -- rendering ----------------------------------------------------------------
def _short_maturity(maturity: str) -> str:
    name = str(maturity or "")
    return name[len("MMAT_") :] if name.startswith("MMAT_") else (name or "?")


def _render_def_sites(def_sites: Iterable[tuple[int, int]]) -> str:
    rendered = ",".join(f"blk{int(blk)}@0x{int(ea):x}" for blk, ea in def_sites)
    return f" defs={rendered}" if rendered else ""


def format_emulator_gap(
    scope: EmulatorGapScope,
    gap: EmulatorGap | None,
    *,
    db_path: str | None = None,
) -> str:
    """One dense, anchored WARNING line for a first-sighting gap.

    Carries the cause token, the function, the maturity, the attempt, the
    block, the site EA, the definition sites the emulator considered and the
    exact command to run next.  Empty when *gap* is ``None`` (a repeat).
    """
    if gap is None:
        return ""
    ticket = EMULATOR_GAP_TICKETS.get(gap.cause)
    fix = f" fix={ticket}" if ticket else ""
    block = "" if int(gap.block_serial) < 0 else f" blk={int(gap.block_serial)}"
    detail = f' detail="{gap.detail}"' if gap.detail else ""
    return (
        f"EMULATOR_GAP cause={gap.cause} func=0x{int(scope.func_ea):x} "
        f"maturity={_short_maturity(scope.maturity)} "
        f"attempt={int(scope.attempt)}{block} site=0x{int(gap.site_ea):x}"
        f"{_render_def_sites(gap.def_sites)}{fix}{detail} "
        f'next="{unflat_why_hint(scope.func_ea, db_path)}"'
    )


def format_emulator_gap_aggregate(
    scope: EmulatorGapScope,
    *,
    unresolved_state_writes: int | None = None,
    db_path: str | None = None,
) -> str:
    """One per-attempt summary line, or ``""`` when the attempt hit no gap."""
    if scope.is_empty():
        return ""
    counts = scope.counts()
    total = sum(counts.values())
    breakdown = " ".join(f"{cause}={count}" for cause, count in counts.items())
    unresolved = (
        ""
        if unresolved_state_writes is None
        else f" unresolved_state_writes={int(unresolved_state_writes)}"
    )
    return (
        f"EMULATOR_GAPS func=0x{int(scope.func_ea):x} "
        f"maturity={_short_maturity(scope.maturity)} "
        f"attempt={int(scope.attempt)} total={total} sites={len(scope.gaps)} "
        f"{breakdown}{unresolved} "
        f'next="{unflat_why_hint(scope.func_ea, db_path)}"'
    )


def build_emulator_gap_events(
    scope: EmulatorGapScope,
) -> tuple[EmulatorGapObserved, ...]:
    """One append-only fact per deduped gap in this attempt."""
    events: list[EmulatorGapObserved] = []
    for gap in scope.gaps:
        events.append(
            EmulatorGapObserved(
                func_ea=int(scope.func_ea),
                cause=gap.cause,
                site_ea=int(gap.site_ea),
                block_serial=int(gap.block_serial),
                occurrences=int(gap.occurrences),
                detail=gap.detail,
                def_sites=gap.def_sites,
                maturity=str(scope.maturity),
                attempt=int(scope.attempt),
                session_id=str(scope.session_id),
            )
        )
    return tuple(events)


def _flush_scope(
    scope: EmulatorGapScope,
    *,
    log: object | None,
    emit_fn: Callable[[object], object] | None,
    unresolved_state_writes: int | None = None,
    db_path: str | None = None,
) -> str | None:
    if scope.is_empty():
        return None
    line = format_emulator_gap_aggregate(
        scope,
        unresolved_state_writes=unresolved_state_writes,
        db_path=active_gap_db_path(scope.func_ea) if db_path is None else db_path,
    )
    publish = emit if emit_fn is None else emit_fn
    for event in build_emulator_gap_events(scope):
        try:
            publish(event)
        except Exception:  # noqa: BLE001 — diagnostics never break a run
            logger.debug("emulator gap fact publish failed", exc_info=True)
    scope.clear()
    if log is not None:
        try:
            log.warning("%s", line)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            logger.debug("emulator gap aggregate log failed", exc_info=True)
    return line


def flush_emulator_gaps(
    func_ea: int,
    *,
    log: object | None = None,
    emit_fn: Callable[[object], object] | None = None,
    unresolved_state_writes: int | None = None,
    db_path: str | None = None,
) -> str | None:
    """Publish and log this attempt's gaps, then reset the dedupe state.

    Returns the aggregate line, or ``None`` when the attempt hit no gap.  Never
    raises for a diagnostic reason.
    """
    scope = get_active_emulator_gap_scope(int(func_ea))
    if scope is None:
        return None
    try:
        return _flush_scope(
            scope,
            log=logger if log is None else log,
            emit_fn=emit_fn,
            unresolved_state_writes=unresolved_state_writes,
            db_path=db_path,
        )
    except Exception:  # noqa: BLE001 — diagnostics never break a run
        logger.debug("emulator gap flush failed", exc_info=True)
        return None


def flush_all_emulator_gaps(
    *,
    log: object | None = None,
    emit_fn: Callable[[object], object] | None = None,
) -> tuple[str, ...]:
    """Flush every tracked function; returns the aggregate lines produced.

    The per-attempt flush hangs off the terminal candidate outcome, so the LAST
    attempt of a decompilation -- the one with no terminal record after it --
    would warn and then publish nothing.  Measured on ``sub_7FFB0EB06E50``:
    attempt 6 emitted 3 WARNING lines and 0 facts.  The lifecycle coordinator
    calls this when a top-level session finishes, before the observability
    session closes, so log lines and facts reconcile exactly.

    Never raises for a diagnostic reason.
    """
    lines: list[str] = []
    for scope in get_pending_emulator_gap_scopes():
        try:
            line = _flush_scope(
                scope, log=logger if log is None else log, emit_fn=emit_fn
            )
        except Exception:  # noqa: BLE001 — diagnostics never break a run
            logger.debug("emulator gap flush-all failed", exc_info=True)
            continue
        if line:
            lines.append(line)
    return tuple(lines)


__all__ = [
    "CAUSE_GLOBAL_NOT_SEEDED",
    "CAUSE_HELPER_NOT_IMPLEMENTED",
    "CAUSE_NO_REACHING_DEFS",
    "CAUSE_NO_SEGMENT",
    "CAUSE_NULL_DEREF",
    "CAUSE_PHI_MULTI_DEF",
    "CAUSE_SINGLE_DEF_EVAL_FAILED",
    "CAUSE_STACK_SLOT_IN_ALIASED_MEMORY",
    "CAUSE_STX_OPERANDS_UNRESOLVED",
    "CAUSE_SYNTHETIC_TAINT",
    "CAUSE_UNCLASSIFIED",
    "CAUSE_UNDEFINED_VARIABLE",
    "CAUSE_UNSUPPORTED_CALL_OPERAND",
    "EMULATOR_GAP_CAUSES",
    "EMULATOR_GAP_TICKETS",
    "EmulatorGap",
    "EmulatorGapScope",
    "active_gap_db_path",
    "begin_emulator_gap_attempt",
    "build_emulator_gap_events",
    "emulator_gap_counts",
    "emulator_gap_scope",
    "flush_all_emulator_gaps",
    "flush_emulator_gaps",
    "format_emulator_gap",
    "format_emulator_gap_aggregate",
    "is_stack_slot_in_aliased_memory",
    "record_emulator_gap",
]
