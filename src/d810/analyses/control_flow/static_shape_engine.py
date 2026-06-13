"""``StaticShapeEngine`` -- today's resolver chain behind the engine contract (P1).

Design §5: "StaticShapeEngine = today's resolver chain refactored behind the
contract." It runs the EXACT same ranked ``resolve_dispatcher`` over
``default_dispatcher_resolvers() + extra_dispatcher_resolvers()`` that
``build_dispatch_map_any_kind`` runs, then lifts the resulting ``StateDispatcherMap``
into a ``RecoveredMachine`` tagged ``Soundness.PATTERN``. Behavior-neutral by
construction: same chain, same ranking, same map; only the wrapper type differs.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.analyses.control_flow.recovered_machine import RecoveredMachine, Soundness
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.dispatcher_recovery import (
    MIN_STATE_CONSTANT,
    default_dispatcher_resolvers,
    extra_dispatcher_resolvers,
)
from d810.analyses.control_flow.dispatcher_resolver import resolve_dispatcher

__all__ = ["StaticShapeEngine"]


@dataclass(frozen=True, slots=True)
class StaticShapeEngine:
    """Pattern-shape recovery engine (equality-chain / switch-table / indirect).

    ``min_state_constant`` is threaded into the equality-chain resolver exactly as
    ``build_dispatch_map_any_kind`` does (dispatcher_recovery.py:494). Defaults to
    the module threshold so existing callers stay byte-identical.
    """

    name: str = "static_shape"
    min_state_constant: int = MIN_STATE_CONSTANT

    def recover(
        self,
        graph: FlowGraph,
        anchors: DispatcherAnchors | None = None,
        caps: object | None = None,
    ) -> RecoveredMachine | None:
        if graph is None:
            return None
        resolvers = (
            default_dispatcher_resolvers(min_state_constant=self.min_state_constant)
            + extra_dispatcher_resolvers()
        )
        resolution = resolve_dispatcher(graph, resolvers)
        if resolution is None:
            return None
        return RecoveredMachine.from_state_dispatcher_map(
            resolution.dispatcher_map,
            soundness=Soundness.PATTERN,
            confidence=float(resolution.confidence),
            provenance=(resolution.resolver_name, *resolution.ranking_reason),
        )
