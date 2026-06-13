"""Engine contract: ``MachineRecoveryEngine`` + ``DispatcherAnchors`` (P1, llr-5knz).

Generalizes the ``DispatcherResolver`` Protocol (dispatcher_resolver.py) one level
up: a resolver recognizes one *shape*; an engine recovers a whole machine by ANY
mechanism (pattern / abstract interpretation / concolic) behind one contract
(design §5). ``recover(graph, anchors, caps) -> RecoveredMachine | None``.

LEAF module (like dispatcher_resolver.py): imports only the contract value types +
the portable FlowGraph. The StaticShape engine impl lives in a SEPARATE module
(static_shape_engine.py) that may import the resolver chain; this Protocol module
must not, so the contract stays a cycle-free leaf.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol, runtime_checkable
from d810.ir.flowgraph import FlowGraph
from d810.analyses.control_flow.recovered_machine import RecoveredMachine

__all__ = ["DispatcherAnchors", "MachineRecoveryEngine"]


@dataclass(frozen=True, slots=True)
class DispatcherAnchors:
    """Pre-computed structural anchors a heavy engine needs (design §6 step 1).

    The shared anchor step (P4) computes these ONCE and hands them to every engine
    so AbstractInterp/Concolic don't each re-derive the dispatcher entry + state
    cell. ``StaticShapeEngine`` IGNORES this in P1 (it re-derives via the existing
    resolver chain) so the contract is satisfiable with anchors absent. ``live_mba``
    is opaque (``object``) -- this is a portable-core module (portable-core-no-ida);
    a concolic engine narrows it behind a backend capability, never by importing IDA.
    """

    dispatcher_entry_block: int | None = None
    state_var_stkoff: int | None = None
    state_var_lvar_idx: int | None = None
    initial_states: tuple[int, ...] = ()
    live_mba: object | None = None


@runtime_checkable
class MachineRecoveryEngine(Protocol):
    """One pluggable recovery engine. ``recover`` returns the contract or ``None``."""

    name: str

    def recover(
        self,
        graph: FlowGraph,
        anchors: DispatcherAnchors,
        caps: object | None = None,
    ) -> RecoveredMachine | None:
        """Recover a ``RecoveredMachine`` from ``graph`` (``None`` == abstains).

        ``anchors`` are shared pre-computed structural facts (may be empty in P1).
        ``caps`` is the capability bundle (e.g. ``context.capabilities``) the engine
        may consult; ``object | None`` keeps this leaf module dependency-free. P1's
        StaticShapeEngine uses neither.
        """
        ...
