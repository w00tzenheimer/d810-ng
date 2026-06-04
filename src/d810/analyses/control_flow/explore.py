"""The ``explore()`` verb (S5a) — a pure, dependency-injected edge builder.

``explore`` walks the per-handler state-write *sites*, resolves each site's
next-state :class:`AbstractValue` via an injected ``resolve_state`` callable (the
S3 :func:`d810.analyses.data_flow.resolve.resolve` ladder, closed over its IDA
tiers by the higher layer), enumerates the ``(guard, const)`` cases of that value
(:func:`d810.analyses.data_flow.abstract_value.cases`), and routes each const
through an injected :class:`DispatcherModel` (S1/S2) to emit one
:class:`StateTransitionEdge` per outcome.

It is the consumer the S0–S3 seam was built for, but it is *additive and
unwired*: no live structurer / recovery path calls it here, so the golden output
is untouched by construction.  The core is IDA-free — both the router and the
resolver are injected, so the whole verb is a pure function of its arguments and
unit-testable with fakes.

The route -> edge lifting mirrors the
:class:`~d810.analyses.data_flow.abstract_value.RouteResult` ADT:

* :class:`Block` -> a single ``RESOLVED`` edge.
* :class:`RouteOneOf` -> one ``RESOLVED`` edge per fan-out target.
* :class:`EntersDispatcher` -> a nested marker edge (the inner model is carried;
  scope handling is a later slice — S5a only *records* the re-entry).
* :class:`Unknown` -> one ``UNRESOLVED`` edge carrying the surfaced reason
  (never a silently dropped edge).
* ``⊤`` (an :class:`AbstractValue` with no enumerable case) -> one ``UNRESOLVED``
  edge (``"top_unresolved_state"``) — an explicit gap, no invented target.

STANDING RULE: every serialized block/serial carries its EA.
:class:`StateTransitionEdge` therefore holds ``from_ea`` / ``to_ea`` alongside
the serials, populated from the :class:`Block` route results (which already carry
their EA) and from the per-site ``from_ea`` the caller threads in.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Callable, Iterable, Optional

from d810.analyses.data_flow.abstract_value import (
    AbstractValue,
    Block,
    EntersDispatcher,
    RouteOneOf,
    Unknown,
    cases,
)

__all__ = [
    "Resolution",
    "WriteSite",
    "StateTransitionEdge",
    "StateTransitionView",
    "explore",
]

logger = getLogger(__name__)

#: A sentinel target serial for an edge that did not resolve to a concrete block.
UNKNOWN_TARGET = -1


class Resolution(str, Enum):
    """How an emitted edge's target was determined.

    ``RESOLVED`` — routed to a concrete block (``Block`` / ``RouteOneOf`` member).
    ``UNRESOLVED`` — the router or the resolver surfaced an explicit gap
    (``Unknown(reason)`` or ``⊤``); the edge records the reason instead of being
    silently dropped.
    ``ENTERS_DISPATCHER`` — the route re-enters a (possibly inner) dispatcher; a
    marker edge whose ``model`` is carried for a later scope-handling slice.
    """

    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    ENTERS_DISPATCHER = "ENTERS_DISPATCHER"


#: One handler state-write site: ``(from_handler, state_var, site)`` plus the
#: optional EA of the source handler (standing rule).  ``state_var`` and ``site``
#: are opaque tokens the injected ``resolve_state`` interprets (the facade never
#: reads a vendor-specific variable encoding).
@dataclass(frozen=True, slots=True)
class WriteSite:
    """A per-handler next-state write site explored into transition edges.

    Args:
        from_handler: the source handler block serial.
        state_var: the variable written (opaque — the resolver reads it).
        site: the program point of the write (opaque — the resolver reads it).
        from_ea: optional EA of the source handler block (standing rule).
    """

    from_handler: int
    state_var: object
    site: object
    from_ea: int | None = None


@dataclass(frozen=True, slots=True)
class StateTransitionEdge:
    """One recovered transition edge (``from_handler -> to_block``).

    Carries the routing ``guard`` (``None`` when unconditional), the
    :class:`Resolution`, an optional ``reason`` (for ``UNRESOLVED`` gaps), and an
    optional inner ``model`` (for ``ENTERS_DISPATCHER`` markers).  EAs are carried
    alongside both serials (standing rule); ``to_serial`` is :data:`UNKNOWN_TARGET`
    for an unresolved edge.
    """

    from_serial: int
    to_serial: int
    guard: object | None = None
    resolution: Resolution = Resolution.RESOLVED
    reason: str | None = None
    from_ea: int | None = None
    to_ea: int | None = None
    model: object | None = None


@dataclass(frozen=True, slots=True)
class StateTransitionView:
    """The result of :func:`explore`: resolved + unresolved transition edges.

    ``resolved`` holds ``RESOLVED`` and ``ENTERS_DISPATCHER`` edges (each names a
    concrete target or an inner model); ``unresolved`` holds the explicit gaps
    (``Unknown`` / ``⊤``).  Both are tuples so the view is an immutable,
    deterministic snapshot.  :meth:`edges` yields the union in emission order.
    """

    resolved: tuple[StateTransitionEdge, ...] = field(default_factory=tuple)
    unresolved: tuple[StateTransitionEdge, ...] = field(default_factory=tuple)

    def edges(self) -> tuple[StateTransitionEdge, ...]:
        """All edges, resolved first then unresolved (deterministic order)."""
        return self.resolved + self.unresolved


def explore(
    write_sites: Iterable[WriteSite],
    *,
    model,
    resolve_state: Callable[[object, object], AbstractValue],
) -> StateTransitionView:
    """Build the state-transition edge set from per-handler write sites.

    For each site: resolve the next-state value (injected ``resolve_state``),
    enumerate its ``(guard, const)`` cases, and route each const through the
    injected :class:`DispatcherModel` (``model.route``), lifting each
    :class:`~d810.analyses.data_flow.abstract_value.RouteResult` to one or more
    :class:`StateTransitionEdge` values.  A value with no enumerable case (``⊤``)
    yields a single ``UNRESOLVED`` edge — an explicit gap, never an invented
    target.

    Pure and IDA-free: ``model`` and ``resolve_state`` are injected, so the verb
    is a deterministic function of its arguments.

    Args:
        write_sites: the per-handler ``(from_handler, state_var, site)`` records.
        model: a :class:`DispatcherModel` (``route(value) -> RouteResult``).
        resolve_state: ``(state_var, site) -> AbstractValue`` — the resolve ladder.

    Returns:
        A :class:`StateTransitionView` of resolved + unresolved edges.
    """
    debug = logger.debug_on
    resolved: list[StateTransitionEdge] = []
    unresolved: list[StateTransitionEdge] = []

    for ws in write_sites:
        av = resolve_state(ws.state_var, ws.site)
        site_cases = cases(av)
        if not site_cases:
            # ``⊤`` (or an empty powerset): an explicit, surfaced gap.
            if debug:
                logger.debug(
                    "explore %d: %r resolved to ⊤ -> unresolved", ws.from_handler, av
                )
            unresolved.append(
                _unresolved_edge(ws, guard=None, reason="top_unresolved_state")
            )
            continue
        for guard, const in site_cases:
            rr = model.route(const)
            _lift(ws, guard, rr, resolved, unresolved, debug)

    return StateTransitionView(
        resolved=tuple(resolved), unresolved=tuple(unresolved)
    )


def _lift(
    ws: WriteSite,
    guard: object | None,
    rr,
    resolved: list[StateTransitionEdge],
    unresolved: list[StateTransitionEdge],
    debug: bool,
) -> None:
    """Lift one :class:`RouteResult` into the appropriate edge(s)."""
    if isinstance(rr, Block):
        resolved.append(_block_edge(ws, guard, rr, Resolution.RESOLVED))
        return
    if isinstance(rr, RouteOneOf):
        for target in rr.targets:
            resolved.append(_block_edge(ws, guard, target, Resolution.RESOLVED))
        return
    if isinstance(rr, EntersDispatcher):
        to_serial = (
            int(rr.entry_serial) if rr.entry_serial is not None else UNKNOWN_TARGET
        )
        resolved.append(
            StateTransitionEdge(
                from_serial=ws.from_handler,
                to_serial=to_serial,
                guard=guard,
                resolution=Resolution.ENTERS_DISPATCHER,
                from_ea=ws.from_ea,
                to_ea=rr.entry_ea,
                model=rr.model,
            )
        )
        return
    if isinstance(rr, Unknown):
        if debug:
            logger.debug(
                "explore %d: route unresolved (%s)", ws.from_handler, rr.reason
            )
        unresolved.append(_unresolved_edge(ws, guard=guard, reason=rr.reason))
        return
    # Defensive: an unrecognized route shape is an explicit gap, not a drop.
    unresolved.append(
        _unresolved_edge(ws, guard=guard, reason="unrecognized_route_result")
    )


def _block_edge(
    ws: WriteSite, guard: object | None, target: Block, resolution: Resolution
) -> StateTransitionEdge:
    return StateTransitionEdge(
        from_serial=ws.from_handler,
        to_serial=int(target.serial),
        guard=guard,
        resolution=resolution,
        from_ea=ws.from_ea,
        to_ea=None if target.ea is None else int(target.ea),
    )


def _unresolved_edge(
    ws: WriteSite, *, guard: object | None, reason: Optional[str]
) -> StateTransitionEdge:
    return StateTransitionEdge(
        from_serial=ws.from_handler,
        to_serial=UNKNOWN_TARGET,
        guard=guard,
        resolution=Resolution.UNRESOLVED,
        reason=reason,
        from_ea=ws.from_ea,
    )
