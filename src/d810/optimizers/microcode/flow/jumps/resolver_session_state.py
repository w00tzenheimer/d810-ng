"""Session-owned evidence for the computed-goto resolver.

This module deliberately knows only the session extension surface, portable
identity, and live-index result.  It never imports manager code or retains an
MBA object, keeping the resolver usable from callback-local adapters without
reintroducing function-EA global state.
"""

from __future__ import annotations

import os
from dataclasses import MISSING, dataclass, field, fields, replace
from d810.core import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    NativePreanalysisSessionState,
    RESOLVER_SESSION_STATE_EXTENSION_KEY,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    PortableMaterializedStateRoute,
    TerminalReturnCarrierRequest,
    is_conditional_handler_bridge_kind,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import (
    BoundBlock,
    NativeEaInterval,
    RebindStatus,
    StableBlockIdentity,
)

logger = getLogger(__name__)


_CONDITIONAL_BRIDGE_IDENTITY_FIELDS = (
    "source_jmp_ea",
    "source_block_ea",
    "materialized_anchor_eas",
    "target_eas",
    "resolver_kind",
)


def _merge_compatible_conditional_bridge_evidence(
    existing: MaterializedIndirectTransfer,
    incoming: MaterializedIndirectTransfer,
) -> MaterializedIndirectTransfer | None:
    """Refresh one predicate without discarding an earlier exact arm proof.

    A regenerated MBA can retain the native predicate and its two targets after
    losing the concrete dispatcher state carried by each arm.  That weaker
    snapshot is compatible evidence, not a replacement for the earlier CALLS
    proof.  Conflicting non-null arm facts remain separate so downstream
    consumers abstain instead of silently selecting either generation.
    """
    for name in _CONDITIONAL_BRIDGE_IDENTITY_FIELDS:
        if getattr(existing, name) != getattr(incoming, name):
            return None
    enriched: dict[str, object] = {}
    for item in fields(MaterializedIndirectTransfer):
        if item.name in _CONDITIONAL_BRIDGE_IDENTITY_FIELDS:
            continue
        if item.default is MISSING:
            return None
        old_value = getattr(existing, item.name)
        new_value = getattr(incoming, item.name)
        if new_value == item.default:
            continue
        if old_value == item.default:
            enriched[item.name] = new_value
            continue
        if old_value != new_value:
            return None
    return replace(existing, **enriched) if enriched else existing


# The session survives callback-local module reloads, so its extension key
# must too.  A private object() key creates a second resolver state after a
# reload and silently loses the preflight's materialization evidence.
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
    resolution: object | None = None
    materialization: ResolverMaterializationState | None = None
    materialized: bool = False
    materialized_transfers: tuple[MaterializedIndirectTransfer, ...] = ()
    portable_state_routes: tuple[PortableMaterializedStateRoute, ...] = ()
    portable_dispatcher_region_identity: StableBlockIdentity | None = None
    terminal_return_carrier_requests: tuple[TerminalReturnCarrierRequest, ...] = ()
    call_result_carriers: tuple[object, ...] = ()
    call_abi_proofs: dict[int, object] = field(default_factory=dict)
    indirect_label_materialized: bool = False
    indirect_dispatcher_materialized: bool = False
    snippet_capture_active: bool = False
    snippet_capture_profile_ea: int | None = None
    preopt_union_preparation: object | None = None
    prepatch_preopt_union_source: object | None = None
    preopt_union_import_active: bool = False
    pending_preopt_reimport: bool = False
    pending_prepatch_materialization: object | None = None
    preopt_union_imported_mbas: set[tuple[int, int, int]] = field(default_factory=set)
    preopt_union_mutated_mbas: set[tuple[int, int, int]] = field(default_factory=set)
    attempted_mbas: set[tuple[int, int, int, int]] = field(default_factory=set)
    bootstrap_route_bindings: dict[
        tuple[StableBlockIdentity, int], BootstrapRouteBindingEvidence
    ] = field(default_factory=dict)

    @property
    def evidence_generation(self) -> int:
        """Read the first-class context generation; never duplicate it here."""
        return self.native_preanalysis.evidence_generation

    def merge_bootstrap_route(self, evidence: BootstrapRouteEvidence) -> bool:
        """Delegate portable evidence ownership to the lifecycle context."""
        changed = self.native_preanalysis.merge_bootstrap_route(evidence)
        if changed:
            # The prior index may address a pre-redo MBA and is never usable
            # for the new evidence generation.
            self.identity_index = None
            if evidence.key not in self.native_preanalysis.bootstrap_routes:
                self.bootstrap_route_bindings.pop(evidence.key, None)
        return changed

    def begin_materialization(self, resolution: object) -> None:
        """Start the one resolver materialization state for this session."""
        if self.materialization is not None:
            raise RuntimeError("resolver materialization is already active")
        self.resolution = resolution
        self.materialized = False
        self.materialization = ResolverMaterializationState(resolution=resolution)

    @property
    def is_materialized(self) -> bool:
        """Return whether this resolver owns the current function's profile."""
        return self.materialization is not None or self.materialized

    def merge_materialized_transfers(
        self,
        transfers: tuple[MaterializedIndirectTransfer, ...],
    ) -> bool:
        """Merge portable facts, refreshing source-keyed predicate snapshots."""
        trace_merge = os.environ.get("RHAD_TRANSFER_TRACE_SESSION_STATE") == "1"
        if trace_merge and transfers:
            import traceback

            caller = " > ".join(
                frame.name for frame in traceback.extract_stack(limit=6)[:-1]
            )
            logger.info(
                "RESOLVER_TRANSFER_MERGE generation=%d count=%d caller=%s",
                self.evidence_generation,
                len(transfers),
                caller,
            )
        merged = list(self.materialized_transfers)
        for transfer in transfers:
            resolver_kind = str(getattr(transfer, "resolver_kind", ""))
            if is_conditional_handler_bridge_kind(resolver_kind):
                matching_indices = [
                    index
                    for index, existing in enumerate(merged)
                    if is_conditional_handler_bridge_kind(
                        str(getattr(existing, "resolver_kind", ""))
                    )
                    and int(existing.source_jmp_ea) == int(transfer.source_jmp_ea)
                ]
                if (
                    len(matching_indices) == 1
                    and merged[matching_indices[0]] == transfer
                ):
                    continue
                if matching_indices:
                    combined = transfer
                    compatible_indices: list[int] = []
                    for index in matching_indices:
                        candidate = _merge_compatible_conditional_bridge_evidence(
                            merged[index],
                            combined,
                        )
                        if candidate is None:
                            continue
                        combined = candidate
                        compatible_indices.append(index)
                    if not compatible_indices:
                        if transfer not in merged:
                            merged.append(transfer)
                        continue
                    first_index = compatible_indices[0]
                    if trace_merge:
                        previous = merged[first_index]
                        changed_fields = tuple(
                            item.name
                            for item in fields(MaterializedIndirectTransfer)
                            if getattr(previous, item.name)
                            != getattr(combined, item.name)
                        )
                        logger.info(
                            "RESOLVER_TRANSFER_REPLACE generation=%d "
                            "source=0x%X before=%s after=%s changed_fields=%s",
                            self.evidence_generation,
                            int(combined.source_jmp_ea),
                            previous.resolver_kind,
                            combined.resolver_kind,
                            changed_fields,
                        )
                    merged[first_index] = combined
                    for duplicate_index in reversed(compatible_indices[1:]):
                        del merged[duplicate_index]
                    continue
            if transfer not in merged:
                if trace_merge:
                    logger.info(
                        "RESOLVER_TRANSFER_APPEND generation=%d source=0x%X " "kind=%s",
                        self.evidence_generation,
                        int(transfer.source_jmp_ea),
                        transfer.resolver_kind,
                    )
                merged.append(transfer)
        merged = tuple(merged)
        if merged == self.materialized_transfers:
            return False
        self.materialized_transfers = merged
        self.native_preanalysis.mark_evidence_changed()
        self.identity_index = None
        return True

    def merge_terminal_return_carrier_requests(
        self,
        requests: tuple[TerminalReturnCarrierRequest, ...],
    ) -> bool:
        """Merge exact carrier-capture evidence into this session only."""
        merged = tuple(
            dict.fromkeys((*self.terminal_return_carrier_requests, *requests))
        )
        if merged == self.terminal_return_carrier_requests:
            return False
        self.terminal_return_carrier_requests = merged
        self.native_preanalysis.mark_evidence_changed()
        self.identity_index = None
        return True

    def merge_portable_state_routes(
        self,
        routes: tuple[PortableMaterializedStateRoute, ...],
    ) -> bool:
        """Merge serial-free logical edges and advance evidence generation."""
        merged = tuple(dict.fromkeys((*self.portable_state_routes, *routes)))
        if merged == self.portable_state_routes:
            return False
        self.portable_state_routes = merged
        self.native_preanalysis.mark_evidence_changed()
        self.identity_index = None
        return True

    def merge_portable_dispatcher_region_identity(
        self,
        identity: StableBlockIdentity,
    ) -> bool:
        """Merge serial-free native ownership for the complete dispatcher."""
        previous = self.portable_dispatcher_region_identity
        merged = StableBlockIdentity.from_intervals(
            (
                *(previous.native_ranges.intervals if previous is not None else ()),
                *identity.native_ranges.intervals,
            ),
            native_key=self.native_key,
        )
        if merged == previous:
            return False
        self.portable_dispatcher_region_identity = merged
        self.native_preanalysis.mark_evidence_changed()
        self.identity_index = None
        return True

    def complete_materialization(self) -> None:
        """Publish the fixed point without preserving a callback-local session."""
        self.materialization = None
        self.materialized = True

    def discover_static_native_bootstrap_route(
        self,
        *,
        source_anchor_ea: int,
        state_constant: int,
        handler_anchor_ea: int,
    ) -> bool:
        """Record manager-owned native evidence without consulting a live MBA.

        Static preflight proves exact native instruction anchors.  Singleton EA
        identities are therefore the portable authority at discovery time;
        PREOPT must still rebind both identities uniquely before mutation.
        """
        source_anchor_ea = int(source_anchor_ea)
        handler_anchor_ea = int(handler_anchor_ea)
        if source_anchor_ea <= 0 or handler_anchor_ea <= 0:
            return False
        source_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_anchor_ea, source_anchor_ea + 1),),
            native_key=self.native_key,
        )
        handler_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_anchor_ea, handler_anchor_ea + 1),),
            native_key=self.native_key,
        )
        return self.merge_bootstrap_route(
            BootstrapRouteEvidence(
                source_identity=source_identity,
                source_anchor_ea=source_anchor_ea,
                state=int(state_constant),
                handler_identity=handler_identity,
                handler_anchor_ea=handler_anchor_ea,
                proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
            )
        )

    def request_controlled_redo(self) -> bool:
        """Allow exactly one generated-MBA redo for the current evidence generation."""
        return self.native_preanalysis.request_controlled_redo()

    def request_generated_restart(self) -> bool:
        """Stage a CALLS-discovered restart for the owning controller."""
        return self.native_preanalysis.request_generated_restart()

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

    def cache_call_result_carriers(self, carriers: tuple[object, ...]) -> None:
        """Retain serial-free LOCOPT carrier evidence for this session only."""
        self.call_result_carriers = tuple(carriers)

    def clear_call_result_carriers(self) -> None:
        self.call_result_carriers = ()

    def finish_snippet_capture(self) -> None:
        self.snippet_capture_active = False
        self.snippet_capture_profile_ea = None

    def release_live_bindings(self) -> None:
        """Drop every current-MBA binding when the top-level session ends."""
        self.identity_index = None
        self.materialization = None
        self.call_result_carriers = ()
        self.snippet_capture_active = False
        self.snippet_capture_profile_ea = None
        self.preopt_union_preparation = None
        self.prepatch_preopt_union_source = None
        self.preopt_union_import_active = False
        self.pending_preopt_reimport = False
        self.pending_prepatch_materialization = None
        self.preopt_union_imported_mbas.clear()
        self.preopt_union_mutated_mbas.clear()
        self.attempted_mbas.clear()
        self.bootstrap_route_bindings.clear()

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

    def record_bootstrap_route_binding(
        self,
        binding: BootstrapRouteBindingEvidence,
    ) -> bool:
        """Retain a serial-free PREOPT binding for the current evidence epoch."""
        key = binding.route.key
        evidence = self.native_preanalysis
        if (
            evidence.bootstrap_routes.get(key) != binding.route
            or key in evidence.conflicted_bootstrap_keys
            or evidence.rebound_bootstrap_generations.get(key)
            != int(binding.evidence_generation)
        ):
            return False
        self.bootstrap_route_bindings[key] = binding
        return True

    def bound_bootstrap_route_bindings(
        self,
    ) -> tuple[BootstrapRouteBindingEvidence, ...]:
        """Return serial-free bindings for the PREOPT epoch owning this MBA."""
        bound_generation = self.native_preanalysis.bound_preopt_generation
        if bound_generation is None:
            return ()
        bindings = {
            binding
            for key, binding in self.bootstrap_route_bindings.items()
            if binding.evidence_generation == bound_generation
            and self.native_preanalysis.bootstrap_routes.get(key) == binding.route
            and key not in self.native_preanalysis.conflicted_bootstrap_keys
        }
        return tuple(
            sorted(
                bindings,
                key=lambda binding: (
                    int(binding.route.source_anchor_ea),
                    int(binding.route.state),
                    int(binding.route.handler_anchor_ea),
                ),
            )
        )


def resolver_session_state(session: object) -> ResolverSessionState:
    """Get a resolver's callback-local attachment for one lifecycle session."""
    extensions = getattr(session, "extensions", None)
    if not isinstance(extensions, dict):
        raise TypeError("resolver session state requires a lifecycle extensions dict")
    native_preanalysis = getattr(session, "native_preanalysis", None)
    if not isinstance(native_preanalysis, NativePreanalysisSessionState):
        raise TypeError("resolver session state requires lifecycle native evidence")
    state = extensions.get(RESOLVER_SESSION_STATE_EXTENSION_KEY)
    if state is None:
        native_key = getattr(session, "native_key", None)
        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("resolver session state requires lifecycle native key")
        state = ResolverSessionState(
            native_preanalysis=native_preanalysis,
            native_key=native_key,
        )
        extensions[RESOLVER_SESSION_STATE_EXTENSION_KEY] = state
    if not isinstance(state, ResolverSessionState):
        raise TypeError("resolver session extension key is not ResolverSessionState")
    if state.native_preanalysis is not native_preanalysis:
        raise TypeError("resolver session binding belongs to another lifecycle")
    if state.native_key != getattr(session, "native_key", None):
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
