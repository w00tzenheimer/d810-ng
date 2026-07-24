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
    CurrentMbaIdentityBindingSnapshot,
    MbaBlockHandle,
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
    preopt_union_imported_mbas: set[tuple[int, int, int]] = field(default_factory=set)
    preopt_union_mutated_mbas: set[tuple[int, int, int]] = field(default_factory=set)
    attempted_mbas: set[tuple[int, int, int, int]] = field(default_factory=set)
    current_mba_token: int | None = None
    current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = None
    current_imported_root_handles: tuple[tuple[int, MbaBlockHandle], ...] = ()

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

    def bind_current_imported_publication(
        self,
        mba_token: int,
        binding: CurrentMbaIdentityBindingSnapshot,
    ) -> bool:
        """Bind one receipt-backed imported publication to exactly one live MBA.

        Synthetic EAs are maturity-local coordinates, not portable evidence.
        The binding therefore lives beside the current identity index and is
        rejected automatically when a regenerated MBA presents another token.
        """
        token = int(mba_token)
        if token <= 0:
            raise ValueError("current MBA token must be positive")
        if not isinstance(binding, CurrentMbaIdentityBindingSnapshot):
            raise TypeError(
                "current imported publication requires an identity snapshot"
            )
        if any(
            block_binding.stable_identity.native_key != self.native_key
            for block_binding in binding.block_bindings
        ):
            raise ValueError(
                "current imported publication belongs to another native identity"
            )
        if self.current_mba_token != token:
            self.current_imported_root_handles = ()
        changed = (
            self.current_mba_token != token
            or self.current_mba_identity_binding != binding
        )
        self.current_mba_token = token
        self.current_mba_identity_binding = binding
        return changed

    def current_mba_identity_binding_for(
        self,
        mba_token: int,
    ) -> CurrentMbaIdentityBindingSnapshot | None:
        """Return full imported identity only for the live MBA that published it."""
        if self.current_mba_token != int(mba_token):
            return None
        return self.current_mba_identity_binding

    def imported_instruction_origins_for(
        self,
        mba_token: int,
    ) -> tuple[tuple[int, int], ...]:
        """Project current point origins from the atomic publication binding."""
        binding = self.current_mba_identity_binding_for(mba_token)
        return () if binding is None else binding.instruction_origins

    def bind_current_imported_root_handles(
        self,
        mba_token: int,
        roots: tuple[tuple[int, MbaBlockHandle], ...],
    ) -> None:
        """Retain importer-selected root ownership for only the current MBA.

        Shared handler bodies can be cloned into several union templates.  A
        native EA alone then identifies the semantic handler but not the one
        importer-owned root selected for that handler.  The gateway-created
        handle carries that current-generation ownership without persisting a
        block serial or inventing a cross-maturity identity.
        """
        token = int(mba_token)
        if token <= 0 or self.current_mba_token != token:
            raise ValueError("imported roots require the current MBA token")
        by_target: dict[int, MbaBlockHandle] = {}
        for target_ea, handle in roots:
            target_ea = int(target_ea)
            if target_ea <= 0 or handle.stable_identity is None:
                raise ValueError("imported roots require native identities")
            if not handle.stable_identity.native_ranges.contains(target_ea):
                raise ValueError("imported root identity must contain its target EA")
            previous = by_target.get(target_ea)
            if previous is not None and previous != handle:
                raise ValueError("one imported target cannot have multiple roots")
            by_target[target_ea] = handle
        self.current_imported_root_handles = tuple(sorted(by_target.items()))

    def imported_root_handles_for(
        self,
        mba_token: int,
    ) -> tuple[tuple[int, MbaBlockHandle], ...]:
        """Return importer-selected roots only for their live MBA generation."""
        if self.current_mba_token != int(mba_token):
            return ()
        return self.current_imported_root_handles

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
        self.preopt_union_imported_mbas.clear()
        self.preopt_union_mutated_mbas.clear()
        self.attempted_mbas.clear()
        self.current_mba_token = None
        self.current_mba_identity_binding = None
        self.current_imported_root_handles = ()

    def invalidate_current_mba_binding(self) -> None:
        """Drop only the generation-local index after a structural mutation."""
        self.identity_index = None
        self.current_imported_root_handles = ()

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
        """Return routes owned by the live MBA's normalized generation."""
        evidence = self.native_preanalysis
        bound_generation = (
            evidence.normalization_published_postvalidated_generation
        )
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
    "ReboundBootstrapRoute",
    "ResolverSessionState",
    "resolver_session_state",
]
