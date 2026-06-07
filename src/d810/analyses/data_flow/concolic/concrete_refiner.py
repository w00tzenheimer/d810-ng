"""The concrete refiner: ``fold_exact`` (the wrongness guard) + ``refine_concrete``.

This is the fusion point where the concrete precision oracle
(:class:`~d810.analyses.data_flow.concolic.emulation.EmulationCapability`) meets the
sound abstract floor.  The guard the user demanded: an emulator's
:class:`~d810.analyses.data_flow.concolic.emulation.ExactResult` is trusted ONLY
when the abstract floor already *contains* it; a disagreement means the backend is
wrong (not merely imprecise) and the concrete claim is dropped, staying abstract.

So the concrete oracle can only ever *tighten* (resolve a value the abstract
analysis left open) and never make the result wrong: a buggy emulator costs nothing
but precision.  In S3 these run as standalone, unit-tested functions; the
``ConcolicTransitionDomain`` calls ``refine_concrete`` once instruction-level
transfer is wired in S4.  Ticket llr-iqm3 / epic llr-7ouc.  Portable: no IDA, no z3.
"""
from __future__ import annotations

from d810.core.typing import Callable

from d810.analyses.data_flow.concolic.emulation import (
    Abstain,
    ConcreteStore,
    EmulationCapability,
    EmulationOutcome,
    InsnRef,
    Unsupported,
)
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.concolic.values import (
    ConcolicValue,
    PrecisionStatus,
    reduce,
)

__all__ = ["fold_exact", "refine_concrete"]

#: Called when an ExactResult contradicts the abstract floor (an unsound backend):
#: ``(dest, claimed_exact, abstract_floor)``.  The default drops the claim silently;
#: the Hex-Rays wiring (S4) passes a callback that emits ``diagnostics.hard``.
OnUnsound = Callable[[LocationRef, int, object], None]


def fold_exact(
    value: ConcolicValue,
    outcome: EmulationOutcome,
    dest: LocationRef,
    *,
    on_unsound: OnUnsound | None = None,
) -> ConcolicValue:
    """Validate an emulation outcome against the abstract floor and fold if exact.

    * :class:`Abstain` / :class:`Unsupported` -> ``value`` unchanged (incompleteness
      is free; this is exactly the abstract-only / S2 behaviour).
    * an :class:`~d810.analyses.data_flow.concolic.emulation.ExactResult` whose value
      the abstract floor does NOT ``contain`` -> the backend disagrees with the sound
      floor; ``on_unsound`` is notified and the concrete claim is **dropped** (stay
      abstract -- the result is never made wrong).
    * an exact value the floor contains -> fold to ``CONCRETE`` (``reduce`` meets the
      singleton into the abstract component, so the floor tightens too).
    """
    if isinstance(outcome, (Abstain, Unsupported)):
        return value
    exact = outcome.value_for(dest)
    if exact is None:
        return value
    if not value.abstract.contains(exact):
        if on_unsound is not None:
            on_unsound(dest, exact, value.abstract)
        return value
    return reduce(
        ConcolicValue(
            exact, value.symbolic, value.abstract, value.width, PrecisionStatus.CONCRETE
        )
    )


def refine_concrete(
    value: ConcolicValue,
    insn: InsnRef,
    store: ConcreteStore,
    emu: EmulationCapability | None,
    *,
    on_unsound: OnUnsound | None = None,
) -> ConcolicValue:
    """Run the concrete refiner for one instruction (the plan's transfer step 2).

    With no emulator injected this is the identity (graceful degradation == the pure
    abstract analysis).  Otherwise it evaluates ``insn`` and validate-folds via
    :func:`fold_exact`.
    """
    if emu is None:
        return value
    return fold_exact(value, emu.eval_insn(insn, store), insn.dest, on_unsound=on_unsound)
