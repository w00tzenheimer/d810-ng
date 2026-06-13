"""Engine registry generalizing the resolver chain (P1, llr-5knz).

Where ``dispatcher_recovery._EXTRA_DISPATCHER_RESOLVERS`` is a registry of
resolver *shapes*, this is a registry of recovery *engines* (design §8: "resolver
chain -> engine registry"). P1 ships ONE engine (``StaticShapeEngine``); P2/P3
register Concolic/AbstractInterp here. ``recover_machine_via_engines`` ranks
engine results by ``(soundness_rank, confidence)`` -- the soundness tag (design
§4) is the NEW ranking dimension the bare resolver chain lacked.

INERT IN P1: no production call site invokes this yet (the orchestrator that does
is P4 llr-1d8u). It is importable + unit-tested now, exactly like
``passes/unflatten/state_machine.py`` shipped its passes additively.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.ir.flowgraph import FlowGraph
from d810.analyses.control_flow.recovered_machine import RecoveredMachine, Soundness
from d810.analyses.control_flow.machine_recovery_engine import (
    DispatcherAnchors,
    MachineRecoveryEngine,
)
from d810.analyses.control_flow.static_shape_engine import StaticShapeEngine
from d810.analyses.control_flow.dispatcher_recovery import MIN_STATE_CONSTANT

__all__ = [
    "Soundness",  # re-export for ranking convenience
    "default_engines",
    "register_extra_engine",
    "clear_extra_engines",
    "extra_engines",
    "recover_machine_via_engines",
    "SOUNDNESS_RANK",
]

# Ranking weight for the soundness tag. Higher == preferred when confidence ties.
# A SOUND over-approximation is preferred over a PATTERN guess; an EXACT_BOUNDED
# result (only produced when completeness-gated, design §7) outranks both. P1 only
# ever produces PATTERN, so this map is exercised but order-irrelevant until P2/P3.
SOUNDNESS_RANK: dict[Soundness, int] = {
    Soundness.EXACT_BOUNDED: 30,
    Soundness.SOUND_OVERAPPROX: 20,
    Soundness.PATTERN: 10,
}

_EXTRA_ENGINES: list[MachineRecoveryEngine] = []


def default_engines(
    *, min_state_constant: int = MIN_STATE_CONSTANT
) -> tuple[MachineRecoveryEngine, ...]:
    """The portable engine set. P1: StaticShape only (wraps the resolver chain)."""
    return (StaticShapeEngine(min_state_constant=min_state_constant),)


def register_extra_engine(engine: MachineRecoveryEngine) -> None:
    """Register a backend/heavy engine. Idempotent by ``name`` (mirrors
    register_extra_dispatcher_resolver, dispatcher_recovery.py:455)."""
    name = getattr(engine, "name", None)
    if name is not None:
        _EXTRA_ENGINES[:] = [
            e for e in _EXTRA_ENGINES if getattr(e, "name", None) != name
        ]
    _EXTRA_ENGINES.append(engine)


def clear_extra_engines() -> None:
    """Drop all registered engines (per-run reset / test isolation)."""
    _EXTRA_ENGINES.clear()


def extra_engines() -> tuple[MachineRecoveryEngine, ...]:
    return tuple(_EXTRA_ENGINES)


def recover_machine_via_engines(
    graph: FlowGraph | None,
    engines: tuple[MachineRecoveryEngine, ...],
    *,
    anchors: DispatcherAnchors | None = None,
    caps: object | None = None,
) -> RecoveredMachine | None:
    """Run every engine, rank results by ``(soundness_rank, confidence)``, return best.

    P1 contract: with ONLY ``StaticShapeEngine`` registered this returns exactly
    ``StaticShapeEngine.recover(graph)`` -- a single result, no ranking effect. The
    ranking exists so P4 can compose the sound AbstractInterp spine over the
    PATTERN/EXACT engines (design §6). NOT the reduced-product refinement itself
    (that is P4 + the §7 soundness gate); this is only the registry/selection seam.
    """
    if graph is None:
        return None
    anchors = anchors or DispatcherAnchors()
    results: list[RecoveredMachine] = []
    for engine in engines:
        machine = engine.recover(graph, anchors, caps)
        if machine is not None:
            results.append(machine)
    if not results:
        return None
    results.sort(
        key=lambda m: (SOUNDNESS_RANK.get(m.soundness, 0), m.confidence),
        reverse=True,
    )
    return results[0]
