"""The report a modifier hands its transaction authority after a rollback.

A snapshot rollback restores the MBA the modifier writes into.  It does not
close the transaction that authorized those writes: that transaction still has
accounting to receive - coalesced supersessions, preflight drops - and a typed
rolled-back failure to record before it may close.  Closing it from inside the
modifier ended the batch underneath that hand-over, so the hand-over raised and
the rollback never completed through the path that claims to be clean.

So the modifier reports this outcome and returns, and the authority that opened
the gateway drives closure.  The module holds no IDA imports, which is what
lets the ordering be exercised without a live MBA.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["RollbackOutcome"]


@dataclass(frozen=True)
class RollbackOutcome:
    """One completed, whole-plan rollback awaiting its recorded closure.

    ``operation_count`` is the complete planned inventory.  A snapshot restores
    the pre-apply MBA, so every planned step is undone - including the steps
    that never ran - and the realization inventory reconciles as::

        applied + superseded + preflight_dropped + rolled_back == planned

    with ``applied == 0``.  A partial term would describe a plan that ended
    half-applied, which is exactly what a completed rollback did not do.
    """

    reason: str
    operation_count: int

    def __post_init__(self) -> None:
        reason = str(self.reason).strip()
        if not reason:
            raise ValueError("a rollback outcome must name why it rolled back")
        count = int(self.operation_count)
        if count < 0:
            raise ValueError("rolled-back operation count must be non-negative")
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "operation_count", count)
