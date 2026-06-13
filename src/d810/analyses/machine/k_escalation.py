"""k-switch escalation policy for the AI spine (P4, llr-1d8u; design §6.5/§11).

High ⊤-density after the AI fixpoint at the current ``k`` means the context length
cannot separate nested CFF layers, so unrelated executions still merge to ⊤.  The
fix is to raise ``k`` (2 -> 4 -> 6) BEFORE falling to concolic (DEFFAI: k=6 fully
restores 3-layer flattening).  Escalation is bounded by a schedule cap and a
wall-clock budget (design §11: k=6 ≈ seconds/function), so it never blows up.

Portable: no IDA.  ``should_escalate`` consumes the spine's own ``top_density``
(``deffai.AnalysisResult.top_density``) so the trigger reuses the proven metric.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = [
    "TOP_DENSITY_THRESHOLD",
    "should_escalate",
    "should_escalate_density",
    "KBudget",
]

#: ⊤-density above which nested CFF is assumed present (design §6.5/§11). Tunable.
TOP_DENSITY_THRESHOLD = 0.15


def should_escalate_density(top_density: float) -> bool:
    """``True`` iff ``top_density`` exceeds the nesting threshold (the raw trigger)."""
    return float(top_density) > TOP_DENSITY_THRESHOLD


def should_escalate(machine) -> bool:
    """``True`` iff the recovered machine's ⊤-cell density warrants raising ``k``.

    Reads ``machine.top_density`` when present (the spine threads its
    ``AnalysisResult.top_density`` through), else estimates density from the
    fraction of forking ``transitions`` whose ``next_states`` is empty (an empty
    fan-out is a ⊤/unresolved cell).  Returns ``False`` for a machine with no
    measurable cells (nothing to escalate).
    """
    density = getattr(machine, "top_density", None)
    if density is not None:
        return should_escalate_density(density)
    transitions = getattr(machine, "transitions", ())
    if not transitions:
        return False
    top = sum(1 for t in transitions if not getattr(t, "next_states", ()))
    return (top / len(transitions)) > TOP_DENSITY_THRESHOLD


@dataclass
class KBudget:
    """Adaptive-``k`` budget: a schedule + a wall-clock cap (design §11).

    ``schedule`` is the ascending ``k`` ladder (DEFFAI k=6 fully restores 3-layer
    CFF); ``start`` is the first ``k`` to try (design §11: start at 2).
    ``time_budget_s`` caps total escalation wall-clock.  ``exhausted`` is ``True``
    at the last schedule entry OR once the budget elapses.
    """

    schedule: tuple[int, ...] = (2, 4, 6)
    start: int = 2
    time_budget_s: float = 8.0
    _t0: float = field(default_factory=time.monotonic, repr=False)

    def reset_clock(self) -> None:
        """Restart the wall-clock budget (call before the first escalation step)."""
        self._t0 = time.monotonic()

    def schedule_from_start(self) -> tuple[int, ...]:
        """The schedule entries ``>= start`` (the actual ladder to walk)."""
        ladder = tuple(k for k in self.schedule if k >= self.start)
        return ladder if ladder else (self.start,)

    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    def exhausted(self, k: int) -> bool:
        """``True`` at the schedule's last entry OR once the wall-clock cap is hit."""
        if self.elapsed() >= self.time_budget_s:
            return True
        ladder = self.schedule_from_start()
        return int(k) >= ladder[-1]
