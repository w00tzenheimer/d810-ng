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

from d810.backends.ida.type_serialization import (
    SerializedTinfoParts,
    apply_serialized_tinfo,
    capture_serialized_tinfo,
)
from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.native_patch_plan import NativeFunctionOwnership

__all__ = [
    "FunctionExtentRestorer",
    "FunctionFlowRestorer",
    "FunctionReanalyzer",
    "IdaFunctionExtentRestorer",
    "IdaFunctionFlowRestorer",
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

    def restore_function_ownership(self, ownership: NativeFunctionOwnership) -> bool:
        """Restore exact chunks, flags, and type metadata from ``ownership``."""
        ...


@runtime_checkable
class FunctionFlowRestorer(Protocol):
    """Reconcile function-internal code refs captured before a patch."""

    def restore_function_flow_refs(self, ownership: NativeFunctionOwnership) -> bool:
        """Return whether live internal refs exactly match ``ownership``."""
        ...


class IdaFunctionFlowRestorer:
    """Restore exact internal IDA code refs after byte/extent reanalysis."""

    @staticmethod
    def _live_refs(ownership: NativeFunctionOwnership):
        import ida_xref

        def _inside(candidate_ea: int) -> bool:
            return any(
                chunk.start_ea <= candidate_ea < chunk.end_ea
                for chunk in ownership.chunk_ranges
            )

        refs: set[tuple[int, int, int, bool]] = set()
        for chunk in ownership.chunk_ranges:
            for source_ea in range(chunk.start_ea, chunk.end_ea):
                xref = ida_xref.xrefblk_t()
                ok = xref.first_from(source_ea, ida_xref.XREF_ALL)
                while ok:
                    target_ea = int(xref.to)
                    if xref.iscode and _inside(target_ea):
                        refs.add(
                            (
                                int(source_ea),
                                target_ea,
                                int(xref.type),
                                bool(xref.user),
                            )
                        )
                    ok = xref.next_from()
        return refs

    def restore_function_flow_refs(self, ownership: NativeFunctionOwnership) -> bool:
        import ida_xref

        expected = {
            (ref.source_ea, ref.target_ea, ref.xref_type, ref.user)
            for ref in ownership.flow_refs
        }
        live = self._live_refs(ownership)
        for source_ea, target_ea, _xref_type, _user in sorted(live - expected):
            ida_xref.del_cref(source_ea, target_ea, 0)
        for source_ea, target_ea, xref_type, user in sorted(expected - live):
            flags = int(xref_type) | (ida_xref.XREF_USER if user else 0)
            if not ida_xref.add_cref(source_ea, target_ea, flags):
                return False
        return self._live_refs(ownership) == expected


class IdaFunctionExtentRestorer:
    """:class:`FunctionExtentRestorer` backed by the live IDA database.

    Exercised only by the Docker system-test suite; the unit-test suite never
    constructs this class (per this repository's no-IDA-mocking rule).
    """

    @staticmethod
    def _live_chunk_ranges(func) -> tuple[tuple[int, int], ...]:
        import ida_funcs

        ranges: list[tuple[int, int]] = []
        iterator = ida_funcs.func_tail_iterator_t(func)
        ok = iterator.main()
        while ok:
            chunk = iterator.chunk()
            ranges.append((int(chunk.start_ea), int(chunk.end_ea)))
            ok = iterator.next()
        return tuple(ranges)

    @staticmethod
    def _serialized_type(entry_ea: int):
        parts = capture_serialized_tinfo(entry_ea)
        if parts is None:
            return None
        return (
            parts.type_bytes,
            parts.field_bytes,
            parts.field_comment_bytes,
        )

    def restore_function_ownership(self, ownership: NativeFunctionOwnership) -> bool:
        import ida_funcs

        entry_ea = int(ownership.owning_function_entry_ea)
        expected_chunks = tuple(
            (int(chunk.start_ea), int(chunk.end_ea)) for chunk in ownership.chunk_ranges
        )
        entry_chunks = tuple(chunk for chunk in expected_chunks if chunk[0] == entry_ea)
        if len(entry_chunks) != 1:
            return False
        entry_end_ea = entry_chunks[0][1]
        expected_tails = set(expected_chunks) - {entry_chunks[0]}

        # Deliberately does NOT del_items + create_insn across the extent.
        # That was tried and measured worse on ``fake_jump_opaque_predicate``:
        # it left the extent unrestored and the function decompiling to
        # ``JUMPOUT(0x1800099D4)``, where asserting the extent alone restores
        # bytes and boundaries exactly. Deleting items pulls the function
        # record apart faster than re-decoding puts it back.
        func = ida_funcs.get_func(entry_ea)
        if func is None:
            if not ida_funcs.add_func(entry_ea, entry_end_ea):
                return False
        elif int(func.end_ea) != entry_end_ea:
            if not ida_funcs.set_func_end(entry_ea, entry_end_ea):
                return False

        func = ida_funcs.get_func(entry_ea)
        if func is None:
            return False
        live_chunks = set(self._live_chunk_ranges(func))
        for start_ea, _end_ea in sorted(live_chunks - set(expected_chunks)):
            if start_ea == entry_ea:
                continue
            if not ida_funcs.remove_func_tail(func, start_ea):
                return False
        func = ida_funcs.get_func(entry_ea)
        if func is None:
            return False
        live_chunks = set(self._live_chunk_ranges(func))
        for start_ea, end_ea in sorted(expected_tails - live_chunks):
            if not ida_funcs.append_func_tail(func, start_ea, end_ea):
                return False

        if not ida_funcs.set_func_flags(entry_ea, ownership.function_flags):
            return False
        type_parts = None
        if ownership.type_info is not None:
            type_parts = SerializedTinfoParts(
                ownership.type_info.type_bytes,
                ownership.type_info.field_bytes,
                ownership.type_info.field_comment_bytes,
            )
        if not apply_serialized_tinfo(entry_ea, type_parts):
            return False

        restored = ida_funcs.get_func(entry_ea)
        if restored is None:
            return False
        expected_type = None
        if ownership.type_info is not None:
            expected_type = (
                ownership.type_info.type_bytes,
                ownership.type_info.field_bytes,
                ownership.type_info.field_comment_bytes,
            )
        return (
            self._live_chunk_ranges(restored) == expected_chunks
            and int(ida_funcs.get_func_flags(entry_ea)) == ownership.function_flags
            and self._serialized_type(entry_ea) == expected_type
        )
