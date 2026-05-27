"""Live Hex-Rays dispatcher cache (E3-rewire).

Thin live adapter around the pure
``d810.recon.flow.dispatcher_analysis.analyze_dispatcher`` analyzer.
Holds:

* The mba-lift boundary (``lift(mba) -> FlowGraph``).
* Cross-maturity state -- ``_previous_type`` and
  ``_persisted_initial_state`` -- which the pure analyzer accepts as
  parameters.
* Per-(``func_ea``, ``maturity``) caching, identical to the
  pre-rewire ``DispatcherCache`` semantics.
* The Unicorn-based ``validate_with_emulation`` feature (live IDA +
  ``ida_idaapi`` / ``ida_idc`` reads) which has no portable analog.

The pure analyzer remains schema-pure -- no live ``mba_t`` or
``mop_t`` crosses the layer boundary.
"""

from __future__ import annotations

import ida_hexrays

from d810.cfg.flowgraph import OperandKind
from d810.core import getLogger
from d810.hexrays.mutation.ir_translator import lift
from d810.recon.flow.analysis_stats import summarize_dispatcher_detection
from d810.recon.flow.dispatcher_analysis import (
    DispatcherAnalysis,
    analyze_dispatcher,
)
from d810.recon.flow.dispatcher_facts import (
    BlockAnalysis,
    DispatcherStrategy,
    StateVariableCandidate,
)
from d810.recon.flow.dispatcher_kind import DispatcherType

# Optional Unicorn emulation support.
try:
    from d810.backends.emulation.common import StateTransition  # noqa: F401
    from d810.backends.emulation.oracle import EmulationOracle

    EMULATION_AVAILABLE = True
except ImportError:
    EMULATION_AVAILABLE = False
    EmulationOracle = None  # type: ignore[assignment,misc]

logger = getLogger("D810.dispatcher")


__all__ = [
    # Re-exports of pure facts (so consumers can import everything
    # they need from one place).
    "BlockAnalysis",
    "DispatcherAnalysis",
    "DispatcherStrategy",
    "DispatcherType",
    "StateVariableCandidate",
    # Live adapter + free-function helpers.
    "DispatcherCache",
    "should_skip_dispatcher",
]


class DispatcherCache:
    """Per-function dispatcher analysis cache (live Hex-Rays adapter).

    The cache is keyed by ``func_ea`` -- a single instance per
    function survives across maturity transitions and threads two
    cross-maturity facts (``previous_type``,
    ``persisted_initial_state``) into ``analyze_dispatcher`` calls.

    The pure analyzer itself is stateless and operates on a
    ``FlowGraph`` snapshot lifted from the live mba.
    """

    # Class-level cache: func_ea -> DispatcherCache.
    _cache: dict[int, "DispatcherCache"] = {}

    def __init__(self, mba: "ida_hexrays.mba_t") -> None:
        self.mba = mba
        self.func_ea = int(mba.entry_ea)
        self._analysis: DispatcherAnalysis | None = None
        self._last_maturity: int = -1
        self._previous_type: DispatcherType | None = None
        self._persisted_initial_state: int | None = None

        # Per-analysis statistics (populated each ``analyze()``).
        self.blocks_analyzed = 0
        self.blocks_skipped = 0

    @classmethod
    def get_or_create(cls, mba: "ida_hexrays.mba_t") -> "DispatcherCache":
        """Get cached instance or create a new one for this function.

        On maturity change the cache invalidates ``_analysis`` and
        promotes the prior result's ``dispatcher_type`` and
        ``initial_state`` into the cross-maturity history fields --
        the pure analyzer reads these on the next ``analyze()``.
        """
        func_ea = int(mba.entry_ea)
        if func_ea in cls._cache:
            cache = cls._cache[func_ea]
            cache.mba = mba  # refresh ref (mba object may rebind)
            if cache._last_maturity != mba.maturity:
                if cache._analysis is not None:
                    cache._previous_type = cache._analysis.dispatcher_type
                    if cache._analysis.initial_state is not None:
                        cache._persisted_initial_state = (
                            cache._analysis.initial_state
                        )
                cache._analysis = None
            return cache

        cache = cls(mba)
        cls._cache[func_ea] = cache
        return cache

    @classmethod
    def clear_cache(cls, func_ea: int | None = None) -> None:
        """Clear cache for a specific function or all functions."""
        if func_ea is None:
            cls._cache.clear()
        elif func_ea in cls._cache:
            del cls._cache[func_ea]

    def refresh(self) -> DispatcherAnalysis:
        """Force re-analysis at the current maturity."""
        self._analysis = None
        return self.analyze()

    def analyze(self) -> DispatcherAnalysis:
        """Lift the mba, run the pure analyzer, and cache the result.

        Cross-maturity facts are passed to the pure analyzer as
        explicit parameters; the pure analyzer is stateless.
        """
        if (
            self._analysis is not None
            and self._last_maturity == self.mba.maturity
        ):
            return self._analysis

        flow_graph = lift(self.mba)
        analysis = analyze_dispatcher(
            flow_graph,
            previous_dispatcher_type=self._previous_type,
            persisted_initial_state=self._persisted_initial_state,
        )

        self.blocks_analyzed = len(flow_graph.blocks)
        self.blocks_skipped = self.blocks_analyzed - len(analysis.blocks)

        self._analysis = analysis
        self._last_maturity = int(self.mba.maturity)
        return analysis

    def is_dispatcher(self, serial: int) -> bool:
        """Check if a block is flagged as a dispatcher."""
        analysis = self.analyze()
        if serial in analysis.blocks:
            return analysis.blocks[serial].is_dispatcher
        return False

    def get_block_info(self, serial: int) -> BlockAnalysis | None:
        """Get analysis info for a specific block."""
        analysis = self.analyze()
        return analysis.blocks.get(serial)

    def get_statistics(self) -> dict:
        """Get analysis statistics for performance tuning.

        Returns:
            Dict with analysis statistics including block counts,
            skip rate, dispatcher count, and per-strategy hit counts.
        """
        analysis = self.analyze()
        return summarize_dispatcher_detection(
            analysis=analysis,
            blocks_analyzed=self.blocks_analyzed,
            blocks_skipped=self.blocks_skipped,
            strategies=DispatcherStrategy,
        )

    def validate_with_emulation(
        self,
        initial_state: int | None = None,
        max_transitions: int = 20,
    ) -> list[tuple[int, int]] | None:
        """Concretely emulate the state machine via Unicorn.

        Optional ground-truth validation of the pattern-based
        dispatcher detection.  Reads function bytes from IDA and runs
        them under a Unicorn oracle from the given initial state.

        Returns:
            List of ``(from_state, to_state)`` transition tuples,
            or ``None`` when emulation is unavailable, the dispatcher
            is not a conditional chain, no state variable was
            detected, or any IDA / Unicorn step fails.  Failures are
            logged at ``DEBUG`` -- this is a best-effort validator.
        """
        if not EMULATION_AVAILABLE:
            logger.debug("Emulation not available for validation")
            return None

        analysis = self.analyze()
        if not analysis.is_conditional_chain:
            return None
        if analysis.state_variable is None:
            logger.debug("No state variable detected, cannot emulate")
            return None

        if initial_state is None:
            initial_state = analysis.initial_state
            if initial_state is None:
                logger.debug("No initial state available for emulation")
                return None

        try:
            import idaapi
            import idc

            arch = self._detect_architecture()
            oracle = EmulationOracle.create(arch)
            if not oracle.has_unicorn:
                logger.debug("Unicorn not available")
                return None

            func_start = self.func_ea
            func_end = idc.find_func_end(func_start)
            if func_end == idaapi.BADADDR:
                logger.debug("Could not determine function end")
                return None

            code_bytes = idc.get_bytes(func_start, func_end - func_start)
            if not code_bytes:
                logger.debug("Could not read function bytes")
                return None

            state_var = analysis.state_variable
            if state_var.mop.kind is OperandKind.STACK:
                frame_size = self._get_frame_size()
                native_offset = state_var.get_native_stack_offset(frame_size)
                if native_offset is None:
                    logger.debug("Could not determine native stack offset")
                    return None
                logger.info(
                    "State variable: stack offset %d (micro) -> %d (native), size=%d",
                    state_var.mop_offset,
                    native_offset,
                    state_var.mop_size,
                )
                transitions_raw = oracle.trace_state_variable(
                    code_bytes,
                    native_offset,
                    initial_state,
                    func_start,
                )
                transitions = [
                    (t.from_value, t.to_value) for t in transitions_raw
                ]
                if transitions:
                    logger.info(
                        "Emulation found %d state transitions: %s",
                        len(transitions),
                        [(hex(f), hex(t)) for f, t in transitions[:5]],
                    )
                else:
                    logger.debug("Emulation completed but no transitions found")
                return transitions if transitions else None

            if state_var.mop.kind is OperandKind.REGISTER:
                logger.debug(
                    "State variable in register %d -- register tracing "
                    "not yet implemented",
                    state_var.mop_offset,
                )
                return None

            logger.debug(
                "Unsupported state variable kind: %s", state_var.mop.kind
            )
            return None

        except ImportError as e:
            logger.debug("IDA imports not available: %s", e)
            return None
        except Exception as e:
            logger.debug("Emulation validation error: %s", e)
            return None

    def _detect_architecture(self) -> str:
        """Detect architecture from IDA database."""
        try:
            import idaapi

            info = idaapi.get_inf_structure()
            if info.is_64bit():
                proc_name = idaapi.get_idp_name()
                if proc_name and "arm" in proc_name.lower():
                    return "arm64"
                return "x86_64"
            if info.is_32bit():
                return "x86"
            return "x86_64"
        except Exception:
            return "x86_64"

    def _get_frame_size(self) -> int:
        """Get the stack frame size from the live mba.

        Tries several known attributes; falls back to ``0x100`` if
        none are present (rare; older / partial mba states).
        """
        for attr in ("stacksize", "frsize", "argsize", "tmpstk_size"):
            val = getattr(self.mba, attr, None)
            if val and val > 0:
                return int(val)
        return 0x100


def should_skip_dispatcher(
    mba: "ida_hexrays.mba_t",
    blk: "ida_hexrays.mblock_t",
) -> bool:
    """Check if a block should be skipped for switch-table style patching.

    Used to avoid cascading unreachability when dealing with
    conditional-chain dispatchers (nested jnz/jz comparisons).  Only
    returns ``True`` for ``CONDITIONAL_CHAIN`` dispatchers --
    switch-table style requires modifying dispatcher blocks.
    """
    cache = DispatcherCache.get_or_create(mba)
    analysis = cache.analyze()

    if not analysis.is_conditional_chain:
        return False
    if cache.is_dispatcher(blk.serial):
        return True
    return False
