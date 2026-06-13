"""Cross-validation policy for the reduced product (P4, llr-1d8u; design §6.4).

Where BOTH the sound AI spine and the concolic engine resolve a transition:

* **agreement** (identical ``next_states``) -> raise confidence.
* **disagreement** -> KEEP the sound (AI) result; NEVER overwrite ``next_states``
  with the concolic value (the concolic walk may be missing a path).  The conflict
  is surfaced via the machine's ``provenance`` (a ``cross_val_conflict`` flag) for
  diagnostics and LOWERS confidence, which feeds ranking (§7) but never correctness.

The confidence is monotone in the agreement fraction and penalized by conflicts,
bounded to ``[0, 1]``.

Portable: no IDA.
"""
from __future__ import annotations

from dataclasses import replace

from d810.analyses.control_flow.recovered_machine import RecoveredMachine

__all__ = ["CrossValidation", "cross_validate"]

#: Provenance flag appended when the two engines disagree on a resolved cell.
CONFLICT_FLAG = "cross_val_conflict"


class CrossValidation(tuple):
    """``(machine, confidence)`` with named accessors (lightweight result)."""

    __slots__ = ()

    def __new__(cls, machine: RecoveredMachine, confidence: float):
        return super().__new__(cls, (machine, confidence))

    @property
    def machine(self) -> RecoveredMachine:
        return self[0]

    @property
    def confidence(self) -> float:
        return self[1]


def _transition_index(machine) -> dict[tuple[int, tuple[int, ...]], tuple[int, ...]]:
    """Map ``(src_state, context) -> sorted next_states`` for resolved forks."""
    index: dict[tuple[int, tuple[int, ...]], tuple[int, ...]] = {}
    for t in getattr(machine, "transitions", ()):
        ns = getattr(t, "next_states", ())
        if not ns:
            continue
        key = (int(t.src_state), tuple(t.context))
        index[key] = tuple(sorted(int(s) for s in ns))
    return index


def cross_validate(
    spine_refined: RecoveredMachine, concolic: RecoveredMachine | None
) -> CrossValidation:
    """Agreement raises confidence; disagreement keeps the AI cell and flags it.

    Returns ``(machine, confidence)``.  ``machine`` is ``spine_refined`` with its
    ``provenance`` extended by :data:`CONFLICT_FLAG` IFF any resolved cell
    disagrees (``next_states`` are NEVER mutated).  When ``concolic`` is ``None``
    or no cells overlap, confidence is the spine's own (no signal).
    """
    if concolic is None:
        return CrossValidation(spine_refined, float(spine_refined.confidence))

    spine_idx = _transition_index(spine_refined)
    conc_idx = _transition_index(concolic)
    agree = 0
    conflict = 0
    for key, spine_ns in spine_idx.items():
        conc_ns = conc_idx.get(key)
        if conc_ns is None:
            continue  # concolic did not resolve this cell -> no cross signal
        if conc_ns == spine_ns:
            agree += 1
        else:
            conflict += 1

    total = agree + conflict
    if total == 0:
        # No overlapping resolved cells -> keep the spine confidence unchanged.
        return CrossValidation(spine_refined, float(spine_refined.confidence))

    conf = max(0.0, (agree - conflict) / total)
    out = spine_refined
    if conflict:
        prov = tuple(spine_refined.provenance) + (CONFLICT_FLAG,)
        out = replace(spine_refined, provenance=prov, confidence=conf)
    else:
        out = replace(spine_refined, confidence=conf)
    return CrossValidation(out, conf)
