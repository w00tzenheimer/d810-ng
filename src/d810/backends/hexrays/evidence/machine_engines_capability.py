"""Hex-Rays implementation of ``MachineRecoveryEnginesCapability`` (ticket llr-iy9i).

Binds the live-mba recovery engines the reduced-product orchestrator
(``d810.analyses.machine.orchestrator.recover_machine``) composes:

* **concolic** -- :class:`ConcolicEmulationEngine` executes the dispatcher on the
  live ``mba`` (the proven old-engine recovery behind the contract).  It is anchored
  via :func:`dispatcher_anchor_discovery.discover_anchors` (the SELECTOR slot, fixing
  the high_fan_in / switch_case_ollvm identity-switch mis-ID), so the concolic walk
  seeds the right state cell.
* **spine** -- the DEFFAI ``analyze_kswitch`` adapter (the sound AI over-approx).
  Wired behind :class:`DeffaiSpineEngine`; returns ``None`` (abstains) until its
  CTG→``RecoveredMachine`` projection is proven, so the orchestrator falls to the
  concolic + static §1a candidates by construction (no regression while it lands).

The concolic machine is recovered ONCE per ``(graph, anchors)`` and memoized so the
three capability methods (machine / resolver / cross-val source) share one walk.

IDA-dependent (``ida_hexrays`` via the engines) -> Hex-Rays backend; the contract it
satisfies (:class:`MachineRecoveryEnginesCapability`) is portable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import ida_hexrays

from d810.analyses.control_flow.dispatcher_recovery import (
    MIN_STATE_CONSTANT,
    build_dispatch_map_any_kind,
)
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import RecoveredMachine
from d810.analyses.machine.refinement_gate import ConcolicCellValue
from d810.backends.hexrays.evidence.concolic_emulation_engine import (
    ConcolicEmulationEngine,
)
from d810.backends.hexrays.evidence.dispatcher_anchor_discovery import discover_anchors
from d810.backends.hexrays.evidence.emulation_dispatcher_resolver import (
    EmulationDispatcherResolver,
)
from d810.backends.hexrays.evidence.deffai_spine_engine import DeffaiSpineEngine
from d810.core.logging import getLogger
from d810.ir.flowgraph import FlowGraph

logger = getLogger("D810.backends.machine_engines_capability")

__all__ = ["HexRaysMachineRecoveryEnginesCapability"]


@dataclass
class HexRaysMachineRecoveryEnginesCapability:
    """Provide the live-mba spine + concolic engines to the orchestrator.

    ``mba`` is the live function microcode bound at construction (re-bound each
    decompilation -- staleness rule, P2 §11).  ``min_state_constant`` is threaded so
    the selector-anchoring prelim uses the SAME threshold detection used (a known
    detect/recover divergence bug class).  ``concolic_enabled`` carries the project
    opt-in (config ``emulation_dispatcher``); when ``False`` the concolic leg is
    inert and the orchestrator uses spine + static only.
    """

    mba: ida_hexrays.mba_t
    min_state_constant: int = MIN_STATE_CONSTANT
    concolic_enabled: bool = True
    spine_enabled: bool = True
    # memo: one concolic walk shared by machine() / resolver() / cross-val
    _cache: dict = field(default_factory=dict, repr=False)

    # -- MachineRecoveryEnginesCapability ----------------------------------------
    def spine_engine(self):
        """The DEFFAI AI spine adapter, or ``None`` when disabled / unavailable."""
        if not self.spine_enabled:
            return None
        return DeffaiSpineEngine(mba=self.mba, min_state_constant=self.min_state_constant)

    def concolic_resolver(self, graph, anchors):
        """A ``(src_state, context) -> ConcolicCellValue | None`` over the walk.

        Looks up the concolic machine's forking transition for ``src_state`` and
        wraps its ``next_states`` as a :class:`ConcolicCellValue`.  The §7 gate (b)
        validates it against the spine's floor before any refinement, so this only
        SUPPLIES candidate values -- it never decides soundness.
        """
        machine = self.concolic_machine(graph, anchors)
        if machine is None:
            return None
        by_state: dict[int, frozenset[int]] = {}
        for t in machine.transitions:
            ns = frozenset(int(s) for s in t.next_states)
            if ns:
                by_state[int(t.src_state)] = ns

        def _resolver(src_state: int, context: tuple[int, ...]):
            ns = by_state.get(int(src_state))
            if not ns:
                return None
            return ConcolicCellValue(next_states=ns)

        return _resolver

    def concolic_machine(self, graph, anchors) -> RecoveredMachine | None:
        """The concolic engine's FULL ``RecoveredMachine`` (memoized), or ``None``."""
        if not self.concolic_enabled:
            return None
        key = id(graph)
        if key in self._cache:
            return self._cache[key]
        machine = self._recover_concolic(graph, anchors)
        self._cache[key] = machine
        return machine

    # -- internals ----------------------------------------------------------------
    def _recover_concolic(
        self, graph: FlowGraph, anchors: DispatcherAnchors | None
    ) -> RecoveredMachine | None:
        """Selector-anchor the dispatcher, then execute it with the concolic engine.

        Prefers :func:`discover_anchors` (selector slot -- fixes identity-switch
        mis-ID) over the orchestrator's recovery-derived anchors; falls back to the
        passed ``anchors`` when discovery abstains.  Returns ``None`` (abstain) on
        any failure so the orchestrator drops to the static §1a candidate.
        """
        try:
            prelim = build_dispatch_map_any_kind(
                graph, min_state_constant=self.min_state_constant
            )
            sel_anchors = discover_anchors(self.mba, graph, prelim)
            if sel_anchors is None:
                sel_anchors = anchors
            if logger.debug_on and sel_anchors is not None:
                logger.debug(
                    "machine_engines: concolic consult entry=%s stkoff=%s lvar=%s "
                    "init=%s (prelim_rows=%s)",
                    sel_anchors.dispatcher_entry_block,
                    sel_anchors.state_var_stkoff,
                    sel_anchors.state_var_lvar_idx,
                    sel_anchors.initial_states,
                    len(prelim.rows) if prelim is not None else None,
                )
            if sel_anchors is None:
                return None
            engine = ConcolicEmulationEngine(mba=self.mba, enabled=True)
            machine = engine.recover(graph, sel_anchors)
            if machine is None:
                # The selector anchor (discover_anchors Strategy 1, e.g. the jtbl
                # selector slot) can land on a value the walk cannot seed (the
                # switched temp, not the state accumulator). Retry with the proven
                # dominant-self-update anchor (the old engine's _discover), which is
                # the anchor the legacy EmulatedDispatcherUnflattener used.
                dom = self._dominant_self_update_anchors(graph)
                if dom is not None and dom != sel_anchors:
                    if logger.debug_on:
                        logger.debug(
                            "machine_engines: selector anchor abstained; retry "
                            "dominant entry=%s stkoff=%s init=%s",
                            dom.dispatcher_entry_block,
                            dom.state_var_stkoff,
                            dom.initial_states,
                        )
                    machine = engine.recover(graph, dom)
            if logger.debug_on:
                logger.debug(
                    "machine_engines: concolic result rows=%s transitions=%s",
                    len(machine.rows) if machine is not None else None,
                    len(machine.transitions) if machine is not None else None,
                )
            return machine
        except Exception:  # noqa: BLE001 -- live emulation is best-effort -> abstain
            logger.debug("machine_engines: concolic recovery raised", exc_info=True)
            return None

    def _dominant_self_update_anchors(
        self, graph: FlowGraph
    ) -> DispatcherAnchors | None:
        """Anchors from the old engine's dominant-self-update discovery, or ``None``.

        The proven Slice-5 ``_discover`` that the legacy
        ``EmulatedDispatcherUnflattener`` anchored on (the accumulator slot + the
        compare-loop entry).  Used as the concolic retry anchor when the
        selector-slot anchor abstains.
        """
        disc = EmulationDispatcherResolver(mba=self.mba)._discover(graph)
        if disc is None:
            return None
        return DispatcherAnchors(
            dispatcher_entry_block=int(disc.entry),
            state_var_stkoff=int(disc.stkoff),
            state_var_lvar_idx=None,
            initial_states=(int(disc.initial_state),),
            live_mba=self.mba,
        )
