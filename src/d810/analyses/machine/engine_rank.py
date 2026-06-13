"""Engine ranking for the reduced product (P4, llr-1d8u; design §6 ranking / §7).

When >=2 engines produce a FULL machine, choose by the total order
``(soundness, specificity, confidence)``:

* **soundness** -- the reduced product (the AI spine, possibly concolic-refined) is
  ``SOUND_OVERAPPROX`` and OUTRANKS a bare ``PATTERN`` StaticShape machine.  A
  sound over-approx is never traded for a less-sound result.
* **specificity** -- the number of RESOLVED cells (rows + non-⊤ transitions); breaks
  ties so StaticShape can still win on a clean jtbl/eq-chain when it is strictly
  more specific AND no less sound (same rank).
* **confidence** -- final tiebreak.

This deliberately ranks ``SOUND_OVERAPPROX`` above ``EXACT_BOUNDED`` (unlike the
P1 ``engine_registry.SOUNDNESS_RANK``, which ranks the bounded-exact result first):
the reduced product's spine is the sound over-approx we never want to lose to a
possibly-incomplete concolic-only machine.  Design §7 is explicit on this order.

Portable: no IDA.
"""
from __future__ import annotations

from d810.analyses.control_flow.recovered_machine import RecoveredMachine, Soundness

__all__ = ["SOUND_RANK", "rank_machines", "specificity"]

#: Total-order weight for the soundness tag (design §7): the sound over-approx
#: (the reduced product) wins, then exact-bounded, then bare pattern.
SOUND_RANK: dict[Soundness, int] = {
    Soundness.SOUND_OVERAPPROX: 2,
    Soundness.EXACT_BOUNDED: 1,
    Soundness.PATTERN: 0,
}


def specificity(machine: RecoveredMachine) -> int:
    """Number of RESOLVED cells: handler rows + non-empty forking transitions.

    A forking transition with an empty ``next_states`` is a ⊤/unresolved cell and
    does NOT count toward specificity (it carries no resolved information).
    """
    rows = len(getattr(machine, "rows", ()))
    resolved_forks = sum(
        1 for t in getattr(machine, "transitions", ()) if getattr(t, "next_states", ())
    )
    return rows + resolved_forks


def _key(machine: RecoveredMachine) -> tuple[int, int, float]:
    return (
        SOUND_RANK.get(machine.soundness, 0),
        specificity(machine),
        float(machine.confidence),
    )


def rank_machines(candidates: list[RecoveredMachine]) -> RecoveredMachine | None:
    """The best machine by ``(soundness, specificity, confidence)``, or ``None``.

    ``None`` only when ``candidates`` is empty.  Ties are resolved by the lower
    fields in order; a stable ``max`` keeps the first candidate on a full tie (the
    reduced product is passed first by the orchestrator, so it wins exact ties).
    """
    if not candidates:
        return None
    return max(candidates, key=_key)
