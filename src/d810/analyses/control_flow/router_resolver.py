"""Injectable dispatcher-router resolution (ticket llr-oq8v / concolic S4).

Replaces the baked-in ``_select_s1a_router`` if/else in ``LowerStateMachine`` with a
**resolver chain**: each provider declares the :class:`RouterKind` it can produce and
returns ranked :class:`ResolverCandidate` evidence (NOT a bool); :func:`select_router`
picks a router by **configuration AND/OR detection**:

* **configured** -- caller pins a :class:`RouterKind`; the matching provider wins.
* **detected**   -- no pin: rank the candidates (default signal = handler coverage,
  with a per-provider priority breaking ties) and take the top.

This is the dispatcher-scoped *proof engine* the fact/proof end-state generalises (see
``.claude/handoffs/2026-06-07-fact-proof-architecture-gap-analysis.md``): ``applies_to``
produces ranked evidence, ``resolve`` materialises the chosen router.  New providers
(switch-table, the authoritative concolic fixpoint) drop in without touching the
selector.

Default detection (no ``configured_kind``) reproduces the old coverage rule -- bst is
the default, the exact map wins only when it strictly out-covers bst -- so wiring it in
is behaviour-neutral on the current corpus; ``configured_kind`` is the new override.

Portable: operates on already-recovered router objects + the exact ``state -> handler``
map; no IDA, no z3.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping, Protocol, Sequence

from d810.analyses.control_flow.dispatcher_resolution import ResolverCandidate
from d810.analyses.control_flow.interval_map import interval_dispatcher_from_state_map
from d810.capabilities.dispatcher import RouterKind

__all__ = [
    "RouterResolutionContext",
    "DispatcherRouterResolver",
    "BstRangeRouterResolver",
    "ExactMapRouterResolver",
    "handler_coverage",
    "select_router",
    "default_resolvers",
]

#: Per-provider tie-break priority (the ``specificity`` of the candidate).  Higher =
#: preferred when handler coverage is equal.  bst > exact reproduces the old rule's
#: "ties keep bst_evidence.dispatcher".
_PRIORITY_BST = 10
_PRIORITY_EXACT = 5


@dataclass(frozen=True)
class RouterResolutionContext:
    """The already-recovered inputs a router resolver ranks over (portable).

    ``bst_router`` is the pre-mutation comparison-BST dispatcher object (or ``None``);
    ``state_to_handler`` / ``default_target`` are the exact recovered map; all serials
    are plain ints so this stays IDA-free.
    """

    bst_router: object | None = None
    state_to_handler: Mapping[int, int] | None = None
    default_target: int | None = None
    dispatcher_entry: int | None = None


def handler_coverage(router: object, entry: int | None) -> int:
    """Distinct handler targets a built router resolves, EXCLUDING the dispatcher entry.

    A comparison tree that collapsed to a single catch-all routes only to the entry
    (coverage 0); a healthy router covers one target per handler.  ``-1`` for ``None``
    so any real router strictly out-covers the absence of one.  Duck-typed on ``_rows``
    so it works for any interval-router object.
    """
    if router is None:
        return -1
    targets = {
        int(r.target)
        for r in getattr(router, "_rows", ())
        if getattr(r, "target", None) is not None
    }
    if entry is not None:
        targets.discard(int(entry))
    return len(targets)


def _exact_map_coverage(
    state_to_handler: Mapping[int, int], default_target: int | None, entry: int | None
) -> int:
    """Coverage of the exact-map router WITHOUT building it (matches the built count)."""
    targets = {int(t) for t in state_to_handler.values() if t is not None}
    if default_target is not None:
        targets.add(int(default_target))
    if entry is not None:
        targets.discard(int(entry))
    return len(targets)


class DispatcherRouterResolver(Protocol):
    """A router provider: rank evidence (``applies_to``) then materialise (``resolve``)."""

    name: str

    def applies_to(self, ctx: RouterResolutionContext) -> ResolverCandidate | None:
        """Ranked evidence this provider can resolve ``ctx`` (``None`` = abstains)."""
        ...

    def resolve(self, ctx: RouterResolutionContext) -> object | None:
        """Materialise the router object (called only on the selected provider)."""
        ...


@dataclass(frozen=True)
class BstRangeRouterResolver:
    """The pre-mutation comparison-BST dispatcher (carries wide RANGE rows + default)."""

    name: str = "bst_range"

    def applies_to(self, ctx: RouterResolutionContext) -> ResolverCandidate | None:
        if ctx.bst_router is None:
            return None
        cov = handler_coverage(ctx.bst_router, ctx.dispatcher_entry)
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=RouterKind.BST,
            confidence=float(cov),
            specificity=_PRIORITY_BST,
            reasons=("range-bst evidence", f"coverage={cov}"),
        )

    def resolve(self, ctx: RouterResolutionContext) -> object | None:
        return ctx.bst_router


@dataclass(frozen=True)
class ExactMapRouterResolver:
    """The recovered exact ``state -> handler`` map as single-value interval rows.

    Authoritative when the comparison tree COLLAPSED (e.g. an OLLVM -fla equality
    chain degrading to ``[0,2^32)->entry``): there the exact map strictly out-covers
    the collapsed bst.  ``RouterKind`` is ``SWITCH`` when a default is present (switch
    table) else ``EQUALITY_CHAIN``.
    """

    name: str = "exact_map"

    def applies_to(self, ctx: RouterResolutionContext) -> ResolverCandidate | None:
        if not ctx.state_to_handler:
            return None
        cov = _exact_map_coverage(
            ctx.state_to_handler, ctx.default_target, ctx.dispatcher_entry
        )
        kind = RouterKind.SWITCH if ctx.default_target is not None else RouterKind.EQUALITY_CHAIN
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=kind,
            confidence=float(cov),
            specificity=_PRIORITY_EXACT,
            reasons=("exact state->handler map", f"coverage={cov}"),
        )

    def resolve(self, ctx: RouterResolutionContext) -> object | None:
        if not ctx.state_to_handler:
            return None
        return interval_dispatcher_from_state_map(
            ctx.state_to_handler, default_target=ctx.default_target
        )


def default_resolvers() -> tuple[DispatcherRouterResolver, ...]:
    """The §1a provider set: range-bst (default) + exact-map (collapse authority)."""
    return (BstRangeRouterResolver(), ExactMapRouterResolver())


def select_router(
    resolvers: Sequence[DispatcherRouterResolver],
    ctx: RouterResolutionContext,
    *,
    configured_kind: RouterKind | None = None,
) -> object | None:
    """Pick and materialise a router from ``resolvers`` over ``ctx``.

    ``configured_kind`` set -> restrict to providers producing that kind (a pin); if
    none produce it, fall back to detection (the pin is a preference, never a hard
    failure).  Detection ranks by ``(confidence, specificity)`` descending -- coverage
    dominates, the per-provider priority breaks ties.  Returns the selected provider's
    materialised router, or ``None`` when nobody applies.
    """
    ranked = [
        (resolver, candidate)
        for resolver in resolvers
        if (candidate := resolver.applies_to(ctx)) is not None
    ]
    if not ranked:
        return None
    if configured_kind is not None:
        forced = [rc for rc in ranked if rc[1].router_kind == configured_kind]
        if forced:
            ranked = forced
    resolver, _ = max(
        ranked, key=lambda rc: (rc[1].confidence, rc[1].specificity)
    )
    return resolver.resolve(ctx)
