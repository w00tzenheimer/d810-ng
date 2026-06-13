"""Machine-recovery engines capability Protocol (portable; ticket llr-iy9i).

The reduced-product orchestrator (``d810.analyses.machine.orchestrator.recover_machine``)
composes a sound AI **spine** with a **concolic** refinement of its ⊤ cells, and ranks
the result against full engine machines (design §6).  The heavy engines BOTH need the
live function microcode:

* the concolic ``ConcolicEmulationEngine`` executes the dispatcher (live ``mba`` + the
  Hex-Rays interpreter), and
* the DEFFAI ``SpineEngine`` adapter, while the fixpoint itself is portable, anchors on
  the live state cell + a live block evaluator.

So the adapters that bind those live oracles live in ``d810.backends.hexrays`` (they
import ``ida_hexrays``); this capability is the PORTABLE seam the
``RecoverDispatcher`` pass reads via ``capabilities.optional(MachineRecoveryEnginesCapability)``
to obtain them without an upward backend import.  ``None`` from any builder ⇒ the
orchestrator simply omits that leg (degrades to the byte-equivalent §1a no-spine path),
so the capability being absent is always safe.

All cross-boundary types are the portable contract types (``FlowGraph``,
``DispatcherAnchors``, ``RecoveredMachine``) or ``Any`` for live operands, keeping the
Protocol IDA-free (``portable-core-no-ida``).
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol

__all__ = ["MachineRecoveryEnginesCapability"]


class MachineRecoveryEnginesCapability(Protocol):
    """Backend boundary providing the live-mba recovery engines to the orchestrator.

    A concrete backend (the Hex-Rays implementation) builds the spine + concolic
    adapters from the live ``mba`` it was constructed with.  Every method returns
    ``None`` when the leg is unavailable / disabled, so the orchestrator can always
    fall back to the sound static path.
    """

    def spine_engine(self) -> Any:
        """Return the AI ``SpineEngine`` adapter, or ``None``.

        The adapter wraps ``deffai.analyze_kswitch`` and exposes the
        ``SpineEngine`` Protocol (``recover(graph, anchors, caps, *, k) ->
        SpineResult | None``) the orchestrator drives with k-escalation.
        """
        ...

    def concolic_resolver(self, graph: Any, anchors: Any) -> Any:
        """Return a ``(src_state, context) -> ConcolicCellValue | None`` resolver.

        The resolver looks up the concolic engine's per-state next-state evidence
        for refining a spine ⊤ cell through the §7 completeness gate.  ``None`` when
        the concolic engine did not recover a machine for ``graph``/``anchors``.

        Args:
            graph: The portable :class:`~d810.ir.flowgraph.FlowGraph`. ``Any`` for
                layer discipline.
            anchors: The shared :class:`~d810.analyses.control_flow.machine_recovery_engine.DispatcherAnchors`.
        """
        ...

    def concolic_machine(self, graph: Any, anchors: Any) -> Any:
        """Return the concolic engine's FULL ``RecoveredMachine``, or ``None``.

        The complete EXACT_BOUNDED machine (the old emulation engine behind the
        contract) the orchestrator admits as a ranking candidate (design §6 step 6)
        and cross-validates the spine against (design §6.4).
        """
        ...
