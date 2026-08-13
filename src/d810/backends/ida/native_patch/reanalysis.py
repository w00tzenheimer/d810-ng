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
    "FunctionExtentRestorer",
    "FunctionReanalyzer",
    "IdaFunctionExtentRestorer",
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


@runtime_checkable
class FunctionExtentRestorer(Protocol):
    """Re-establishes a function's pre-patch extent during restore.

    Separate from :class:`FunctionReanalyzer` because it answers a different
    question. Reanalysis asks IDA to recompute from the current bytes;
    reanalysis is exactly what *shrank* the function, so asking it again
    cannot undo that. This asserts a remembered extent over IDA's recomputed
    opinion, using ownership captured before the patch.
    """

    def restore_function_extent(self, entry_ea: int, end_ea: int) -> bool:
        """Force the function at ``entry_ea`` to end at ``end_ea``.

        Returns whether the extent afterwards matches what was asked for.
        """
        ...


class IdaFunctionExtentRestorer:
    """:class:`FunctionExtentRestorer` backed by the live IDA database.

    Exercised only by the Docker system-test suite; the unit-test suite never
    constructs this class (per this repository's no-IDA-mocking rule).
    """

    def restore_function_extent(self, entry_ea: int, end_ea: int) -> bool:
        import ida_auto
        import ida_funcs

        entry_ea, end_ea = int(entry_ea), int(end_ea)

        # Deliberately does NOT del_items + create_insn across the extent.
        # That was tried and measured worse on ``fake_jump_opaque_predicate``:
        # it left the extent unrestored and the function decompiling to
        # ``JUMPOUT(0x1800099D4)``, where asserting the extent alone restores
        # bytes and boundaries exactly. Deleting items pulls the function
        # record apart faster than re-decoding puts it back.
        func = ida_funcs.get_func(entry_ea)
        if func is None:
            if not ida_funcs.add_func(entry_ea, end_ea):
                return False
        elif int(func.end_ea) != end_ea:
            if not ida_funcs.set_func_end(entry_ea, end_ea):
                return False

        # Clear the truncation's side effects on the function record itself.
        #
        # Measured on ``fake_jump_opaque_predicate``: with bytes, boundaries
        # and items all restored exactly, the function still decompiled to
        # ``void f(int, int) { ; }``. While it was truncated mid-body it ended
        # without a ``ret``, so IDA marked it FUNC_NORET and stored a guessed
        # ``void`` prototype. Neither is derived from the bytes, so neither is
        # undone by putting the bytes back -- they have to be cleared, and
        # then the type re-guessed from the restored extent.
        restored = ida_funcs.get_func(entry_ea)
        if restored is not None and restored.flags & ida_funcs.FUNC_NORET:
            restored.flags &= ~ida_funcs.FUNC_NORET
            ida_funcs.update_func(restored)

        import ida_nalt

        ida_nalt.del_tinfo(entry_ea)

        ida_auto.plan_and_wait(entry_ea, end_ea)
        restored = ida_funcs.get_func(entry_ea)
        return restored is not None and int(restored.end_ea) == end_ea
