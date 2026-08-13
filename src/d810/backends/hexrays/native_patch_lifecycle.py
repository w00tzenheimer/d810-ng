"""Cache invalidation and bounded controlled redo adapter.

Task 6 ("Single-operation native gateway, reanalysis, and certificate") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. Task 0.4's
measured cache-invalidation-radius experiment
(``tests/system/runtime/backends/ida/test_lifecycle_strategy_experiment.py::
TestCacheInvalidationRadius``, artifact
``.tmp/cfunc-cache-invalidation-radius/summary.json``) is the reason this
module exists: on IDA 9.4, after ``patch_bytes`` + ``reanalyze_function`` +
``auto_wait()`` + ``mark_cfunc_dirty(F)``, ``has_cached_cfunc(caller)`` was
still ``True`` -- **``mark_cfunc_dirty`` does not propagate to callers.** A
gateway that only invalidates its own target function serves every known
caller a stale, pre-patch cached decompilation. This module is the one place
that widens invalidation to "target plus every known caller," and the one
place a bounded, single controlled redo happens after invalidation.

Why "known callers" is a live discovery, not a plan field
--------------------------------------------------------------------------
``NativePatchPlan``/``NativePatchOperation`` (Task 2/5) never carry a caller
list -- callers are a *database* fact, not something a plan authorizes or
restores, and they can change between when a plan was captured and when it
is applied. :func:`discover_known_callers` rereads the database at
invalidation time, using the same shape-based approach
(``CF_CALL`` on a decoded referring instruction, not an xref-type constant)
that ``test_lifecycle_strategy_experiment.py::_callers_of`` already
established, so this does not depend on which xref-type enum a given IDA
build exposes.

Protocol-injected, IDA-free at import time
--------------------------------------------------------------------------
:class:`CfuncCacheInvalidator`, :class:`CallerDiscovery`, and
:class:`ControlledRedoDecompiler` are plain structural Protocols so
``tests/unit/backends/ida/native_patch/test_gateway.py`` can inject fakes
(this repository's "no IDA mocking in unit tests" rule) that never import
``ida_*``. :class:`IdaCfuncCacheInvalidator`/:class:`IdaCallerDiscovery`/
:class:`IdaControlledRedoDecompiler` are the concrete implementations the
Docker system-test suite exercises; every method lazy-imports its ``ida_*``
module.

Layering: this module lives under ``d810.backends.hexrays`` (same
top-level ``d810.backends`` layer as ``d810.backends.ida.native_patch``),
so ``gateway.py`` importing it is a same-layer, not upward, import.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol, runtime_checkable

__all__ = [
    "CacheInvalidationReceipt",
    "CallerDiscovery",
    "CfuncCacheInvalidator",
    "ControlledRedoDecompiler",
    "ControlledRedoReceipt",
    "IdaCallerDiscovery",
    "IdaCfuncCacheInvalidator",
    "IdaControlledRedoDecompiler",
    "controlled_redo",
    "discover_known_callers",
    "invalidate_target_and_callers",
]


@runtime_checkable
class CallerDiscovery(Protocol):
    def callers_of(self, function_ea: int) -> frozenset[int]: ...


@runtime_checkable
class CfuncCacheInvalidator(Protocol):
    def mark_cfunc_dirty(self, function_ea: int) -> bool:
        """Erase ``function_ea``'s cached cfunc. Returns whether an entry existed."""
        ...


@runtime_checkable
class ControlledRedoDecompiler(Protocol):
    def decompile(self, function_ea: int) -> object | None: ...


@dataclass(frozen=True, slots=True)
class CacheInvalidationReceipt:
    """Which functions were targeted for invalidation, and whether each had
    a cache entry to erase. ``target_ea`` and every EA in ``caller_eas`` are
    always present as keys of ``erased`` -- section 14.6's "Hex-Rays cache
    invalidated" receipt.
    """

    target_ea: int
    caller_eas: frozenset[int]
    erased: dict[int, bool]

    @property
    def invalidated_eas(self) -> frozenset[int]:
        return frozenset(self.erased)


@dataclass(frozen=True, slots=True)
class ControlledRedoReceipt:
    function_ea: int
    redo_count: int
    cfunc_obtained: bool


def discover_known_callers(
    function_ea: int, *, discovery: CallerDiscovery
) -> frozenset[int]:
    return frozenset(discovery.callers_of(int(function_ea)))


def invalidate_target_and_callers(
    function_ea: int,
    *,
    invalidator: CfuncCacheInvalidator,
    discovery: CallerDiscovery,
    extra_eas: frozenset[int] = frozenset(),
) -> CacheInvalidationReceipt:
    """Invalidate ``function_ea``'s cfunc cache and every known caller's.

    This is the mandatory widening the module docstring describes:
    target-only invalidation is a known-insufficient sequence (measured, not
    assumed) and must never be used as the gateway's cache-invalidation step.
    """
    caller_eas = discover_known_callers(function_ea, discovery=discovery)
    all_eas = {int(function_ea)} | caller_eas | {int(ea) for ea in extra_eas}
    erased = {ea: bool(invalidator.mark_cfunc_dirty(ea)) for ea in sorted(all_eas)}
    return CacheInvalidationReceipt(
        target_ea=int(function_ea), caller_eas=caller_eas, erased=erased
    )


def controlled_redo(
    function_ea: int, *, decompiler: ControlledRedoDecompiler, max_redo: int = 1
) -> ControlledRedoReceipt:
    """Decompile ``function_ea`` at most ``max_redo`` times after invalidation.

    Bounded on purpose: this is the "one redo" half of the measured sequence
    ("a bounded sequence of patch, reanalysis, autoanalysis completion, cache
    invalidation, and one redo" -- Task 4 Step 5's exit gate). It is not a
    retry loop; ``max_redo`` exists to make that boundedness an explicit,
    checkable parameter rather than an assumption.
    """
    if max_redo <= 0:
        raise ValueError("max_redo must be positive")
    cfunc = None
    redo_count = 0
    for _ in range(max_redo):
        redo_count += 1
        cfunc = decompiler.decompile(int(function_ea))
        if cfunc is not None:
            break
    return ControlledRedoReceipt(
        function_ea=int(function_ea),
        redo_count=redo_count,
        cfunc_obtained=cfunc is not None,
    )


class IdaCallerDiscovery:
    """:class:`CallerDiscovery` backed by the live IDA database.

    Mirrors ``test_lifecycle_strategy_experiment.py::_callers_of`` exactly:
    a call is identified by ``CF_CALL`` on the referring instruction's
    decoded feature bits, not by xref *type* constants.
    """

    def callers_of(self, function_ea: int) -> frozenset[int]:
        import idaapi
        import idautils
        import ida_funcs
        import ida_ua

        callers: set[int] = set()
        insn = ida_ua.insn_t()
        for ref_ea in idautils.CodeRefsTo(function_ea, 0):
            length = ida_ua.decode_insn(insn, ref_ea)
            if length <= 0:
                continue
            if not (insn.get_canon_feature() & idaapi.CF_CALL):
                continue
            caller_func = ida_funcs.get_func(ref_ea)
            if caller_func is None or caller_func.start_ea == function_ea:
                continue
            callers.add(int(caller_func.start_ea))
        return frozenset(callers)


class IdaCfuncCacheInvalidator:
    def mark_cfunc_dirty(self, function_ea: int) -> bool:
        import ida_hexrays

        return bool(ida_hexrays.mark_cfunc_dirty(int(function_ea)))


class IdaControlledRedoDecompiler:
    def decompile(self, function_ea: int) -> object | None:
        import ida_hexrays

        return ida_hexrays.decompile(int(function_ea))
