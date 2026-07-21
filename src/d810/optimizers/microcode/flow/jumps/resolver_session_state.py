"""Session-owned evidence for the computed-goto resolver.

This module deliberately knows only the named resolver attachment, portable
identity, and live-index result.  It never imports manager code or retains an
MBA object, keeping the resolver usable from callback-local adapters without
reintroducing function-EA global state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    ComputedGotoResolution,
    NativePreanalysisSessionState,
    ResolverPortableEvidence,
    ResolverSessionOwner,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import (
    BoundBlock,
    RebindStatus,
    StableBlockIdentity,
)


@dataclass(frozen=True, slots=True)
class ReboundBootstrapRoute:
    """A uniquely rebound bootstrap edge for the current MBA generation."""

    evidence: BootstrapRouteEvidence
    source: BoundBlock
    handler: BoundBlock
    generation: int


@dataclass(slots=True)
class ResolverMaterializationState:
    """One bounded computed-goto materialization run in a session."""

    resolution: object
    rounds: int = 0
    entry_bridge_materialized: bool = False
    state_route_rounds: int = 0


@dataclass(slots=True)
class ResolverSessionState:
    """Resolver-local live bindings for one lifecycle session.

    ``native_preanalysis`` is the context-owned portable authority.  This
    attachment contains only callback-local binding data and temporary resolver
    objects, so its lifecycle cannot silently become a second evidence store.
    """

    native_preanalysis: NativePreanalysisSessionState
    native_key: NativePreanalysisKey
    identity_index: MbaBlockIdentityIndex | None = None
    materialization: ResolverMaterializationState | None = None
    materialized: bool = False
    indirect_label_materialized: bool = False
    indirect_dispatcher_materialized: bool = False
    snippet_capture_active: bool = False
    snippet_capture_profile_ea: int | None = None
    preopt_union_import_active: bool = False
    pending_preopt_reimport: bool = False
    pending_prepatch_materialization: object | None = None
    preopt_union_imported_mbas: set[tuple[int, int, int]] = field(default_factory=set)
    preopt_union_mutated_mbas: set[tuple[int, int, int]] = field(default_factory=set)
    attempted_mbas: set[tuple[int, int, int, int]] = field(default_factory=set)

    @property
    def evidence_generation(self) -> int:
        """Read the first-class context generation; never duplicate it here."""
        return self.native_preanalysis.evidence_generation

    @property
    def portable_evidence(self) -> ResolverPortableEvidence:
        """Expose the lifecycle-owned aggregate without duplicating its fields."""
        return self.native_preanalysis.resolver_evidence_for(self.native_key)

    @property
    def materialized_transfers(self) -> tuple[MaterializedIndirectTransfer, ...]:
        """Read transfers from the canonical portable fact aggregate."""
        facts = self.native_preanalysis.facts
        return () if facts is None else facts.transfers

    @property
    def boundary_ports(self) -> DetachedSnippetBoundaryPorts:
        """Read resolver boundary ports from the canonical fact aggregate."""
        facts = self.native_preanalysis.facts
        return (
            DetachedSnippetBoundaryPorts((), ())
            if facts is None
            else facts.boundary_ports
        )

    def begin_materialization(self, resolution: object) -> None:
        """Start the one resolver materialization state for this session."""
        if self.materialization is not None:
            raise RuntimeError("resolver materialization is already active")
        if isinstance(resolution, ComputedGotoResolution):
            self.native_preanalysis.set_computed_goto_resolution(
                self.native_key,
                resolution,
            )
        self.materialized = False
        self.materialization = ResolverMaterializationState(resolution=resolution)

    @property
    def is_materialized(self) -> bool:
        """Return whether this resolver owns the current function's profile."""
        return self.materialization is not None or self.materialized

    def complete_materialization(self) -> None:
        """Publish the fixed point without preserving a callback-local session."""
        self.materialization = None
        self.materialized = True

    def bind_current_mba(self, index: MbaBlockIdentityIndex) -> None:
        """Attach current-only lookup data after regenerated MBA construction."""
        if index.evidence_generation != self.native_preanalysis.evidence_generation:
            raise ValueError(
                "MBA identity index evidence generation must match resolver evidence"
            )
        self.identity_index = index

    def begin_snippet_capture(self, function_ea: int) -> bool:
        """Enter one callback-local detached-snippet capture section."""
        if self.snippet_capture_active:
            return False
        self.snippet_capture_active = True
        self.snippet_capture_profile_ea = int(function_ea)
        return True

    def finish_snippet_capture(self) -> None:
        self.snippet_capture_active = False
        self.snippet_capture_profile_ea = None

    def release_live_bindings(self) -> None:
        """Drop every current-MBA binding when the top-level session ends."""
        self.identity_index = None
        self.materialization = None
        self.snippet_capture_active = False
        self.snippet_capture_profile_ea = None
        self.preopt_union_import_active = False
        self.pending_preopt_reimport = False
        self.pending_prepatch_materialization = None
        self.preopt_union_imported_mbas.clear()
        self.preopt_union_mutated_mbas.clear()
        self.attempted_mbas.clear()

    def invalidate_current_mba_binding(self) -> None:
        """Drop only the generation-local index after a structural mutation."""
        self.identity_index = None

    def rebind_bootstrap_route(
        self,
        *,
        source_identity: StableBlockIdentity,
        state: int,
        prefer_imported_handler: bool = False,
    ) -> ReboundBootstrapRoute | None:
        """Return the route only when both identities bind uniquely and currently."""
        key = source_identity, int(state)
        evidence = self.native_preanalysis.bootstrap_routes.get(key)
        index = self.identity_index
        if (
            evidence is None
            or key in self.native_preanalysis.conflicted_bootstrap_keys
            or index is None
        ):
            return None
        source = index.rebind_identity(evidence.source_identity)
        handler = index.rebind_imported_identity(evidence.handler_identity)
        if not prefer_imported_handler or handler.status is RebindStatus.MISSING:
            handler = index.rebind_identity(evidence.handler_identity)
        if source.block is None or handler.block is None:
            return None
        return ReboundBootstrapRoute(
            evidence=evidence,
            source=source.block,
            handler=handler.block,
            generation=self.native_preanalysis.evidence_generation,
        )

    def bound_bootstrap_routes(self) -> tuple[BootstrapRouteEvidence, ...]:
        """Return routes rebound in the PREOPT generation owning the live MBA."""
        evidence = self.native_preanalysis
        bound_generation = evidence.bound_preopt_generation
        if bound_generation is None:
            return ()
        routes = {
            route
            for key in evidence.rebound_bootstrap_keys
            for route in (evidence.bootstrap_routes.get(key),)
            if route is not None
            and key not in evidence.conflicted_bootstrap_keys
            and evidence.rebound_bootstrap_generations.get(key) == bound_generation
        }
        return tuple(
            sorted(
                routes,
                key=lambda route: (
                    int(route.source_anchor_ea),
                    int(route.state),
                    int(route.handler_anchor_ea),
                ),
            )
        )


def resolver_session_state(session: object) -> ResolverSessionState:
    """Get a resolver's callback-local attachment for one lifecycle session."""
    if not isinstance(session, ResolverSessionOwner):
        raise TypeError("resolver session state requires a typed lifecycle owner")
    native_preanalysis = session.native_preanalysis
    state = session.resolver_attachment
    if state is None:
        state = ResolverSessionState(
            native_preanalysis=native_preanalysis,
            native_key=session.native_key,
        )
        session.resolver_attachment = state
    if not isinstance(state, ResolverSessionState):
        raise TypeError("resolver session extension key is not ResolverSessionState")
    if state.native_preanalysis is not native_preanalysis:
        raise TypeError("resolver session binding belongs to another lifecycle")
    if state.native_key != session.native_key:
        raise TypeError("resolver session native key belongs to another lifecycle")
    return state


__all__ = [
    "BootstrapRouteBindingEvidence",
    "BootstrapRouteEvidence",
    "BootstrapRouteProofKind",
    "ReboundBootstrapRoute",
    "ResolverSessionState",
    "resolver_session_state",
]
