"""Provider-neutral cross-maturity pass scheduling.

Passes use :class:`RunLater` to ask for a later pass run. The scheduler stores
only primitive identities plus the portable IR maturity; a backend coordinator
is responsible for translating drained records into concrete work.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.ir.maturity import IRMaturity

logger = getLogger(__name__)

_MATURITY_ORDER: dict[IRMaturity, int] = {
    IRMaturity.LIFTED: 0,
    IRMaturity.CANONICAL: 1,
    IRMaturity.LOCAL_OPTIMIZED: 2,
    IRMaturity.CALL_MODELED: 3,
    IRMaturity.GLOBAL_ANALYZED: 4,
    IRMaturity.GLOBAL_OPTIMIZED: 5,
    IRMaturity.STRUCTURED: 6,
    IRMaturity.VARIABLE_RECOVERED: 7,
}


@dataclass(frozen=True, slots=True)
class RunLater:
    """A pass-facing request to run again at a later portable maturity."""

    at: IRMaturity
    reason: str = ""


@dataclass(frozen=True, slots=True)
class PendingRun:
    """Scheduler-owned primitive record for deferred pass work."""

    func_ea: int
    pass_id: str
    at: IRMaturity
    reason: str = ""


def _maturity_rank(stage: IRMaturity) -> int | None:
    return _MATURITY_ORDER.get(stage)


def _compare_maturity(left: IRMaturity, right: IRMaturity) -> int | None:
    """Compare two maturities, returning ``None`` when ordering is unknown."""

    if left == right:
        return 0
    left_rank = _maturity_rank(left)
    right_rank = _maturity_rank(right)
    if left_rank is None or right_rank is None:
        return None
    return left_rank - right_rank


class PassScheduler:
    """Records future pass work without knowing how a backend executes it."""

    def __init__(self, *, per_func_request_budget: int = 64):
        if per_func_request_budget < 1:
            raise ValueError("per_func_request_budget must be >= 1")
        self._per_func_request_budget = per_func_request_budget
        self._pending_by_func: dict[
            int, dict[tuple[int, str, IRMaturity], PendingRun]
        ] = {}

    def request(
        self,
        *,
        func_ea: int,
        pass_id: str,
        current_maturity: IRMaturity,
        run_later: RunLater,
    ) -> bool:
        """Record a future pass run.

        Returns ``True`` when the request is accepted or already pending and
        ``False`` when maturity ordering or the per-function budget rejects it.
        """

        maturity_delta = _compare_maturity(run_later.at, current_maturity)
        if maturity_delta is not None and maturity_delta <= 0:
            logger.info(
                "rejecting run_later request for %s at %s from %s: not later",
                pass_id,
                run_later.at,
                current_maturity,
            )
            return False

        key = (int(func_ea), str(pass_id), run_later.at)
        pending_for_func = self._pending_by_func.setdefault(int(func_ea), {})
        if key in pending_for_func:
            return True

        if len(pending_for_func) >= self._per_func_request_budget:
            logger.warning(
                "rejecting run_later request for %s at %s in function %#x: "
                "per-function budget %d exceeded",
                pass_id,
                run_later.at,
                int(func_ea),
                self._per_func_request_budget,
            )
            return False

        pending_for_func[key] = PendingRun(
            func_ea=int(func_ea),
            pass_id=str(pass_id),
            at=run_later.at,
            reason=run_later.reason,
        )
        return True

    def drain(
        self,
        *,
        func_ea: int,
        current_maturity: IRMaturity,
    ) -> tuple[PendingRun, ...]:
        """Return and remove runs eligible at ``current_maturity``."""

        func_key = int(func_ea)
        pending_for_func = self._pending_by_func.get(func_key)
        if not pending_for_func:
            return ()

        drained_keys: list[tuple[int, str, IRMaturity]] = []
        drained: list[PendingRun] = []
        for key, pending in pending_for_func.items():
            maturity_delta = _compare_maturity(current_maturity, pending.at)
            if maturity_delta is not None and maturity_delta >= 0:
                drained_keys.append(key)
                drained.append(pending)

        for key in drained_keys:
            del pending_for_func[key]
        if not pending_for_func:
            del self._pending_by_func[func_key]

        return tuple(drained)

    def reset_func(self, func_ea: int) -> None:
        """Forget all pending work for one function."""

        self._pending_by_func.pop(int(func_ea), None)

    def reset_all(self) -> None:
        """Forget all pending work."""

        self._pending_by_func.clear()
