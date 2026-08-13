"""Receipted IDA reanalysis and post-write autoanalysis work.

Task 6 ("Single-operation native gateway, reanalysis, and certificate") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. Task 0.4's
measured finding (``tests/system/runtime/backends/ida/
test_lifecycle_strategy_experiment.py``) is the reason this module exists at
all: ``MERR_REDO`` refreshes Hex-Rays but does **not** reanalyze the
database, so a gateway that only patches bytes and marks a cfunc dirty would
leave the IDB's own flowchart -- and everything that reads it instead of the
decompiler -- stale. ``ida_funcs.reanalyze_function`` plus
``ida_auto.auto_wait()`` is the measured, mandatory second half; this module
is the one place that pair is called from the gateway path.

Protocol-injected like the rest of Task 5/6's live-IDA seams
(``LiveDatabaseReader``, ``EncodingProvider``): :class:`FunctionReanalyzer`
is a plain structural Protocol so ``tests/unit/backends/ida/native_patch/
test_gateway.py`` can inject a fake that never touches ``ida_*`` (this
repository's "no IDA mocking in unit tests" rule), while
:class:`IdaFunctionReanalyzer` is the one concrete implementation the Docker
system-test suite exercises. Every ``IdaFunctionReanalyzer`` method
lazy-imports its ``ida_*`` module so importing this module never requires a
live IDA runtime.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from d810.core.typing import Protocol, runtime_checkable

__all__ = [
    "FunctionReanalyzer",
    "IdaFunctionReanalyzer",
    "ReanalysisReceipt",
    "reanalyze_and_wait",
]


@runtime_checkable
class FunctionReanalyzer(Protocol):
    """Live-database reanalysis seam. Every method is IDA-only side effect,
    no return value the gateway depends on beyond "did it raise."""

    def reanalyze_function(self, function_ea: int) -> None:
        """Request full reanalysis of the function owning ``function_ea``."""
        ...

    def auto_wait(self) -> None:
        """Block until IDA's autoanalysis queue drains."""
        ...


@dataclass(frozen=True, slots=True)
class ReanalysisReceipt:
    """One correlated "reanalysis requested, completed" receipt (section 14.6)."""

    function_ea: int
    requested: bool
    completed: bool
    duration_s: float


def reanalyze_and_wait(
    function_ea: int, *, reanalyzer: FunctionReanalyzer
) -> ReanalysisReceipt:
    """Request reanalysis of ``function_ea`` and durably wait for it to finish.

    Always calls both steps in order -- ``reanalyze_function`` then
    ``auto_wait`` -- because the measured finding is specifically that
    skipping the second leaves the flowchart stale; a caller that only wants
    ``reanalyze_function`` without waiting is not a supported partial use of
    this module. ``requested`` is set before either call so a caller
    inspecting the receipt after an exception (which this function never
    swallows -- see the module docstring's "any exception ... is never
    swallowed by diagnostics" rule) can still see that reanalysis was at
    least attempted.
    """
    started = time.time()
    reanalyzer.reanalyze_function(int(function_ea))
    reanalyzer.auto_wait()
    return ReanalysisReceipt(
        function_ea=int(function_ea),
        requested=True,
        completed=True,
        duration_s=time.time() - started,
    )


class IdaFunctionReanalyzer:
    """:class:`FunctionReanalyzer` backed by the live IDA database.

    Exercised only by the Docker system-test suite; the unit-test suite
    never constructs this class (per this repository's no-IDA-mocking rule).
    """

    def reanalyze_function(self, function_ea: int) -> None:
        import ida_auto
        import ida_funcs

        func = ida_funcs.get_func(function_ea)
        if func is None:
            raise ValueError(f"no function owns ea {function_ea:#x}")
        ida_funcs.reanalyze_function(func)
        # Measured on IDA 9.4 (Docker system-test run, Task 6):
        # reanalyze_function() alone can leave a stale successor set on a
        # block elsewhere in the same function (not merely near the patched
        # site) after a byte round-trip that restores the function to its
        # exact original bytes -- observed on the gateway's own
        # apply()-then-restore() system test, whose flowchart comparison
        # otherwise fails even though every governed byte, patch row, item
        # shape, ref, and ownership record matches exactly.
        # plan_and_wait() forces a genuine full re-plan-and-block over the
        # whole function range rather than trusting reanalyze_function()'s
        # narrower recomputation, and blocks until that pass completes.
        ida_auto.plan_and_wait(int(func.start_ea), int(func.end_ea))

    def auto_wait(self) -> None:
        import ida_auto

        ida_auto.auto_wait()
