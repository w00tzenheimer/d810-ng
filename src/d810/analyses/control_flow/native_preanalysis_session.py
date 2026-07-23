"""Portable evidence owned by one top-level decompilation session.

This module intentionally contains no live MBA, Hex-Rays, manager, or
optimizer dependency.  The lifecycle coordinator owns one instance directly;
live adapters may attach a current-generation index separately, but may not
become the authority for evidence generation or restart decisions.
"""

from __future__ import annotations

import os
import traceback
from dataclasses import MISSING, dataclass, field, fields, replace
from enum import Enum

from d810.analyses.control_flow.call_abi import StackCallAbiProof
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
    normalize_detached_snippet_boundary_ports,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    PortableMaterializedStateRoute,
    PortableStateWriteRouteEvidence,
    TerminalReturnCarrierRequest,
    is_conditional_handler_bridge_kind,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeCfg,
    NativeSemanticClosure,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.core.native_preanalysis_key import (
    NativePreanalysisKey,
    NativePreanalysisKeyMismatch,
)
from d810.core import getLogger
from d810.core.typing import Callable, Mapping, NamedTuple, Protocol, runtime_checkable
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity

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
    """Refresh one predicate without discarding an earlier exact arm proof."""
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


@dataclass(frozen=True, slots=True)
class NativePreanalysisFacts:
    """Normalized portable evidence for one exact native-analysis identity."""

    key: NativePreanalysisKey
    native_cfg: NativeCfg
    semantic_closure: NativeSemanticClosure | None
    transfers: tuple[MaterializedIndirectTransfer, ...]
    boundary_ports: DetachedSnippetBoundaryPorts

    def __post_init__(self) -> None:
        if not isinstance(self.key, NativePreanalysisKey):
            raise TypeError("native preanalysis facts require a native key")
        if not isinstance(self.native_cfg, NativeCfg):
            raise TypeError("native preanalysis facts require a native CFG")
        if self.semantic_closure is not None and not isinstance(
            self.semantic_closure,
            NativeSemanticClosure,
        ):
            raise TypeError("semantic closure must be portable native evidence")
        if not all(
            isinstance(transfer, MaterializedIndirectTransfer)
            for transfer in self.transfers
        ):
            raise TypeError("native preanalysis transfers must be portable facts")
        normalized_transfers = tuple(
            sorted(
                set(self.transfers),
                key=lambda transfer: (
                    int(transfer.source_jmp_ea),
                    int(transfer.source_block_ea),
                    tuple(int(ea) for ea in transfer.materialized_anchor_eas),
                    tuple(int(ea) for ea in transfer.target_eas),
                    str(transfer.resolver_kind),
                    repr(transfer),
                ),
            )
        )
        normalized_ports = normalize_detached_snippet_boundary_ports(
            tuple(self.boundary_ports.direct),
            tuple(self.boundary_ports.conditional),
        )
        object.__setattr__(self, "transfers", normalized_transfers)
        object.__setattr__(self, "boundary_ports", normalized_ports)

    def require_key(self, expected: NativePreanalysisKey) -> None:
        """Reject evidence captured for another input/function/profile/SDK."""
        if self.key == expected:
            return
        raise NativePreanalysisKeyMismatch(
            expected,
            self.key,
            expected.mismatch_fields(self.key),
        )


class BootstrapRouteProofKind(Enum):
    """Authority used to publish one bootstrap state route."""

    STATIC_NATIVE = "static_native"
    CALLS_LIVE = "calls_live"


@dataclass(frozen=True, slots=True)
class BootstrapRouteEvidence:
    """Serial-free route preserved while an MBA is regenerated."""

    source_identity: StableBlockIdentity
    source_anchor_ea: int
    state: int
    handler_identity: StableBlockIdentity
    handler_anchor_ea: int
    proof_kind: BootstrapRouteProofKind

    def __post_init__(self) -> None:
        source_anchor_ea = int(self.source_anchor_ea)
        handler_anchor_ea = int(self.handler_anchor_ea)
        if not self.source_identity.native_ranges.contains(source_anchor_ea):
            raise ValueError("bootstrap source anchor is outside source identity")
        if not self.handler_identity.native_ranges.contains(handler_anchor_ea):
            raise ValueError("bootstrap handler anchor is outside handler identity")
        object.__setattr__(self, "source_anchor_ea", source_anchor_ea)
        object.__setattr__(self, "handler_anchor_ea", handler_anchor_ea)
        object.__setattr__(self, "state", int(self.state))

    @property
    def key(self) -> tuple[StableBlockIdentity, int]:
        return self.source_identity, int(self.state)

    def diagnostic_payload(
        self, *, generation: int, rebound: bool
    ) -> dict[str, object]:
        return {
            "source_ea": f"0x{self.source_anchor_ea:X}",
            "state": f"0x{int(self.state):X}",
            "handler_ea": f"0x{self.handler_anchor_ea:X}",
            "generation": int(generation),
            "proof_kind": self.proof_kind.value,
            "rebound": bool(rebound),
        }


@dataclass(frozen=True, slots=True)
class BootstrapRouteBindingEvidence:
    """Serial-free binding of one bootstrap route in a later live snapshot."""

    route: BootstrapRouteEvidence
    source_identity: StableBlockIdentity
    handler_identity: StableBlockIdentity
    evidence_generation: int

    def __post_init__(self) -> None:
        if not self.source_identity.native_ranges.contains(
            int(self.route.source_anchor_ea)
        ):
            raise ValueError("bound bootstrap source identity lost its anchor")
        if not self.handler_identity.native_ranges.contains(
            int(self.route.handler_anchor_ea)
        ):
            raise ValueError("bound bootstrap handler identity lost its anchor")
        generation = int(self.evidence_generation)
        if generation < 0:
            raise ValueError("bootstrap binding generation must be non-negative")
        object.__setattr__(self, "evidence_generation", generation)


@dataclass(frozen=True, slots=True)
class CallResultCarrier:
    """Serial-free call-result carrier captured before later restoration."""

    call_ea: int
    carrier_ea: int
    branch_ea: int
    callee_ea: int
    carrier_ida_stkoff: int
    value_size: int
    branch_opcode: int


class ComputedGotoPatchPlan(NamedTuple):
    """Portable native byte-patch plan for one computed-goto site."""

    jmp_ea: int
    block_entry: int
    patch_start: int
    patch_bytes: bytes
    region_end: int
    insn_heads: tuple[int, ...]
    new_block_eas: tuple[int, ...]
    target_eas: tuple[int, ...] = ()
    condition_code: int | None = None
    true_target_ea: int | None = None
    false_target_ea: int | None = None
    selector_register_name: str | None = None
    selector_compare_constant: int | None = None
    selector_state_on_left: bool | None = None
    source_register_values: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class ComputedGotoResolution:
    """Portable targets and native delivery evidence for one function."""

    function_ea: int
    jmp_targets: Mapping[int, tuple[int, ...]]
    reachable_eas: tuple[int, ...]
    arch: str
    executed_insns: int
    seeds_run: int
    stop_reasons: tuple[str, ...] = field(default_factory=tuple)
    patch_plans: tuple[ComputedGotoPatchPlan, ...] = field(default_factory=tuple)
    block_entries: tuple[int, ...] = field(default_factory=tuple)
    function_context_register_values: tuple[tuple[str, int], ...] = field(
        default_factory=tuple
    )
    corridor_register_snapshots: tuple[tuple[int, tuple[tuple[str, int], ...]], ...] = (
        field(default_factory=tuple)
    )
    dispatcher_context_register_values: tuple[tuple[str, int], ...] = field(
        default_factory=tuple
    )
    native_stack_frame_offsets: tuple[tuple[int, tuple[int, ...]], ...] = field(
        default_factory=tuple
    )
    conditional_state_choices: tuple[MaterializedIndirectTransfer, ...] = field(
        default_factory=tuple
    )

    @property
    def site_count(self) -> int:
        return len(self.jmp_targets)

    @property
    def target_count(self) -> int:
        return sum(len(targets) for targets in self.jmp_targets.values())


@dataclass(frozen=True, slots=True)
class PreoptUnionPreparationResult:
    """EA-keyed outcome of one production PREOPT union preparation."""

    function_ea: int
    prepared: bool
    published: bool
    primary_seed_ea: int | None = None
    seed_eas: tuple[int, ...] = ()
    native_ranges: tuple[tuple[int, int], ...] = ()
    imported_block_entry_eas: tuple[int, ...] = ()
    entry_consumer_routes: tuple[MaterializedIndirectTransfer, ...] = ()
    entry_consumer_port_diagnostic: tuple[tuple[str, object], ...] = ()
    abstention_reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PrepatchPreoptUnionSource:
    """PREOPT source captured before native byte delivery changes reachability."""

    primary_seed_ea: int
    seed_eas: tuple[int, ...]
    seed_native_ranges: tuple[tuple[int, tuple[tuple[int, int], ...]], ...]
    native_ranges: tuple[tuple[int, int], ...]
    imported_block_entry_eas: tuple[int, ...]
    cfg: NativeCfg
    closure: NativeSemanticClosure


@dataclass(frozen=True, slots=True)
class ResolverPortableEvidence:
    """Typed resolver facts owned by one exact lifecycle identity."""

    key: NativePreanalysisKey
    state_routes: tuple[PortableMaterializedStateRoute, ...] = ()
    state_write_routes: tuple[PortableStateWriteRouteEvidence, ...] = ()
    dispatcher_region_identity: StableBlockIdentity | None = None
    terminal_return_carrier_requests: tuple[TerminalReturnCarrierRequest, ...] = ()
    call_result_carriers: tuple[CallResultCarrier, ...] = ()
    call_abi_proofs: tuple[tuple[int, StackCallAbiProof], ...] = ()
    bootstrap_route_bindings: tuple[
        tuple[tuple[StableBlockIdentity, int], BootstrapRouteBindingEvidence], ...
    ] = ()
    computed_goto_resolution: ComputedGotoResolution | None = None
    preopt_union_preparation: PreoptUnionPreparationResult | None = None
    prepatch_preopt_union_source: PrepatchPreoptUnionSource | None = None
    preopt_entry_bridges: tuple[EntryBridgeEvidence, ...] = ()

    def require_key(self, expected: NativePreanalysisKey) -> None:
        """Reject resolver evidence captured for another native identity."""
        if self.key == expected:
            return
        raise NativePreanalysisKeyMismatch(
            expected,
            self.key,
            expected.mismatch_fields(self.key),
        )


@dataclass(frozen=True, slots=True)
class EvidenceLifecycleTransition:
    operation: str
    previous_generation: int
    resulting_generation: int
    evidence_family: str
    outcome: str
    reason: str


@dataclass(slots=True)
class NativePreanalysisSessionState:
    """First-class portable evidence and epoch authority for a lifecycle."""

    evidence_generation: int = 0
    portable_evidence_ready_generation: int | None = None
    normalization_staged_generation: int | None = None
    normalization_validated_generation: int | None = None
    normalization_published_postvalidated_generation: int | None = None
    canonical_semantic_plan_generation: int | None = None
    semantic_fragment_staged_generation: int | None = None
    semantic_fragment_validated_generation: int | None = None
    semantic_fragment_published_postvalidated_generation: int | None = None
    receipt_committed_generation: int | None = None
    facts: NativePreanalysisFacts | None = None
    resolver_evidence: ResolverPortableEvidence | None = None
    bootstrap_routes: dict[tuple[StableBlockIdentity, int], BootstrapRouteEvidence] = (
        field(default_factory=dict)
    )
    conflicted_bootstrap_keys: set[tuple[StableBlockIdentity, int]] = field(
        default_factory=set
    )
    rebound_bootstrap_keys: set[tuple[StableBlockIdentity, int]] = field(
        default_factory=set
    )
    rebound_bootstrap_generations: dict[tuple[StableBlockIdentity, int], int] = field(
        default_factory=dict
    )
    published_bootstrap_keys: set[tuple[StableBlockIdentity, int]] = field(
        default_factory=set
    )
    transfer_inventory_revision: int = 0
    published_transfer_inventory_revision: int | None = None
    state_write_route_inventory_revision: int = 0
    published_state_write_route_inventory_revision: int | None = None
    bound_state_write_route_generation: int | None = None
    redo_generation: int | None = None
    pending_generated_restart_generation: int | None = None
    event_observer: Callable[[EvidenceLifecycleTransition], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        generation = int(self.evidence_generation)
        if generation < 0:
            raise ValueError("portable evidence generation must be non-negative")
        self.evidence_generation = generation
        if self.portable_evidence_ready_generation is None and generation > 0:
            self.portable_evidence_ready_generation = generation
        marker_names = (
            "portable_evidence_ready_generation",
            "normalization_staged_generation",
            "normalization_validated_generation",
            "normalization_published_postvalidated_generation",
            "canonical_semantic_plan_generation",
            "semantic_fragment_staged_generation",
            "semantic_fragment_validated_generation",
            "semantic_fragment_published_postvalidated_generation",
            "receipt_committed_generation",
        )
        for name in marker_names:
            value = getattr(self, name)
            if value is None:
                continue
            value = int(value)
            if value <= 0:
                raise ValueError("lifecycle generation markers must be positive")
            if value > generation:
                raise ValueError(
                    "lifecycle generation cannot exceed portable evidence"
                )
            setattr(self, name, value)
        if (
            self.portable_evidence_ready_generation is not None
            and self.portable_evidence_ready_generation != generation
        ):
            raise ValueError(
                "portable evidence-ready generation must equal current evidence"
            )

        normalization_order = (
            self.normalization_published_postvalidated_generation or 0,
            self.normalization_validated_generation or 0,
            self.normalization_staged_generation or 0,
            self.portable_evidence_ready_generation or 0,
        )
        if normalization_order != tuple(sorted(normalization_order)):
            raise ValueError("invalid normalization lifecycle generation order")

        semantic_order = (
            self.receipt_committed_generation or 0,
            self.semantic_fragment_published_postvalidated_generation or 0,
            self.semantic_fragment_validated_generation or 0,
            self.semantic_fragment_staged_generation or 0,
            self.canonical_semantic_plan_generation or 0,
            self.normalization_published_postvalidated_generation or 0,
        )
        if semantic_order != tuple(sorted(semantic_order)):
            raise ValueError("invalid semantic lifecycle generation order")

    def _require_current_portable_evidence(self) -> int:
        generation = int(self.evidence_generation)
        if (
            generation <= 0
            or self.portable_evidence_ready_generation != generation
        ):
            raise RuntimeError(
                "lifecycle transition requires the current portable evidence generation"
            )
        return generation

    def _mark_lifecycle_generation(
        self,
        *,
        attribute: str,
        operation: str,
        evidence_family: str,
        prerequisite_attribute: str | None = None,
        prerequisite_error: str = "",
    ) -> bool:
        generation = self._require_current_portable_evidence()
        if (
            prerequisite_attribute is not None
            and getattr(self, prerequisite_attribute) != generation
        ):
            raise RuntimeError(prerequisite_error)
        previous = getattr(self, attribute)
        if previous == generation:
            return False
        setattr(self, attribute, generation)
        self._observe_transition(
            operation=operation,
            previous_generation=0 if previous is None else int(previous),
            evidence_family=evidence_family,
            reason=f"{operation.replace('_', ' ')} for portable generation {generation}",
        )
        return True

    def mark_normalization_staged(self) -> bool:
        """Record construction of a detached normalization fragment."""
        return self._mark_lifecycle_generation(
            attribute="normalization_staged_generation",
            operation="normalization_staged",
            evidence_family="frontend_normalization",
        )

    def mark_normalization_validated(self) -> bool:
        """Record successful validation of the staged normalization fragment."""
        return self._mark_lifecycle_generation(
            attribute="normalization_validated_generation",
            operation="normalization_validated",
            evidence_family="frontend_normalization",
            prerequisite_attribute="normalization_staged_generation",
            prerequisite_error=(
                "normalization validation requires the current staged generation"
            ),
        )

    def mark_normalization_published_and_postvalidated(self) -> bool:
        """Advance normalization authority only after publication postvalidation."""
        return self._mark_lifecycle_generation(
            attribute="normalization_published_postvalidated_generation",
            operation="normalization_published_postvalidated",
            evidence_family="frontend_normalization",
            prerequisite_attribute="normalization_validated_generation",
            prerequisite_error=(
                "normalization publication requires the current validated generation"
            ),
        )

    def abort_normalization(self, *, reason: str) -> bool:
        """Discard current transient normalization state without moving authority."""
        generation = self._require_current_portable_evidence()
        if (
            self.normalization_staged_generation != generation
            and self.normalization_validated_generation != generation
        ):
            return False
        published = self.normalization_published_postvalidated_generation
        self.normalization_staged_generation = published
        self.normalization_validated_generation = published
        self._observe_transition(
            operation="normalization_aborted",
            previous_generation=generation,
            evidence_family="frontend_normalization",
            outcome="aborted",
            reason=str(reason),
        )
        return True

    def needs_normalization_publication(self) -> bool:
        """Return whether current portable evidence lacks normalized authority."""
        return (
            self.normalization_published_postvalidated_generation
            != self.evidence_generation
        )

    def mark_canonical_semantic_plan_ready(self) -> bool:
        """Record a canonical pass plan over the current normalized generation."""
        return self._mark_lifecycle_generation(
            attribute="canonical_semantic_plan_generation",
            operation="canonical_semantic_plan_ready",
            evidence_family="semantic_lowering",
            prerequisite_attribute=(
                "normalization_published_postvalidated_generation"
            ),
            prerequisite_error=(
                "canonical semantic planning requires current normalized authority"
            ),
        )

    def mark_semantic_fragment_staged(self) -> bool:
        """Record detached construction of the current canonical semantic plan."""
        return self._mark_lifecycle_generation(
            attribute="semantic_fragment_staged_generation",
            operation="semantic_fragment_staged",
            evidence_family="semantic_lowering",
            prerequisite_attribute="canonical_semantic_plan_generation",
            prerequisite_error=(
                "semantic fragment staging requires the current canonical plan"
            ),
        )

    def mark_semantic_fragment_validated(self) -> bool:
        """Record successful validation of the staged semantic fragment."""
        return self._mark_lifecycle_generation(
            attribute="semantic_fragment_validated_generation",
            operation="semantic_fragment_validated",
            evidence_family="semantic_lowering",
            prerequisite_attribute="semantic_fragment_staged_generation",
            prerequisite_error=(
                "semantic fragment validation requires the current staged generation"
            ),
        )

    def mark_semantic_fragment_published_and_postvalidated(self) -> bool:
        """Advance semantic authority only after publication postvalidation."""
        return self._mark_lifecycle_generation(
            attribute="semantic_fragment_published_postvalidated_generation",
            operation="semantic_fragment_published_postvalidated",
            evidence_family="semantic_lowering",
            prerequisite_attribute="semantic_fragment_validated_generation",
            prerequisite_error=(
                "semantic fragment publication requires the current validated generation"
            ),
        )

    def mark_receipt_committed(self) -> bool:
        """Record the receipt only after semantic publication postvalidation."""
        return self._mark_lifecycle_generation(
            attribute="receipt_committed_generation",
            operation="receipt_committed",
            evidence_family="semantic_lowering",
            prerequisite_attribute=(
                "semantic_fragment_published_postvalidated_generation"
            ),
            prerequisite_error=(
                "receipt commit requires current postvalidated semantic publication"
            ),
        )

    def abort_semantic_fragment(self, *, reason: str) -> bool:
        """Discard current transient semantic state without moving authority."""
        generation = self._require_current_portable_evidence()
        if (
            self.semantic_fragment_staged_generation != generation
            and self.semantic_fragment_validated_generation != generation
        ):
            return False
        published = self.semantic_fragment_published_postvalidated_generation
        self.semantic_fragment_staged_generation = published
        self.semantic_fragment_validated_generation = published
        self._observe_transition(
            operation="semantic_fragment_aborted",
            previous_generation=generation,
            evidence_family="semantic_lowering",
            outcome="aborted",
            reason=str(reason),
        )
        return True

    def _observe_transition(
        self,
        *,
        operation: str,
        previous_generation: int,
        evidence_family: str,
        outcome: str = "accepted",
        reason: str = "",
    ) -> None:
        observer = self.event_observer
        if observer is None:
            return
        try:
            observer(
                EvidenceLifecycleTransition(
                    operation=operation,
                    previous_generation=int(previous_generation),
                    resulting_generation=int(self.evidence_generation),
                    evidence_family=evidence_family,
                    outcome=outcome,
                    reason=reason,
                )
            )
        except Exception:
            logger.debug("evidence lifecycle observer failed", exc_info=True)

    def _resolver_evidence_for(
        self,
        key: NativePreanalysisKey,
    ) -> ResolverPortableEvidence:
        evidence = self.resolver_evidence
        if evidence is None:
            evidence = ResolverPortableEvidence(key=key)
            self.resolver_evidence = evidence
            return evidence
        evidence.require_key(key)
        return evidence

    def resolver_evidence_for(
        self,
        key: NativePreanalysisKey,
    ) -> ResolverPortableEvidence:
        """Return the typed resolver aggregate for one exact native identity."""
        return self._resolver_evidence_for(key)

    def _replace_resolver_evidence(
        self,
        key: NativePreanalysisKey,
        *,
        evidence_family: str,
        evidence_reason: str,
        advance_generation: bool = True,
        **changes: object,
    ) -> bool:
        current = self._resolver_evidence_for(key)
        updated = replace(current, **changes)
        if updated == current:
            return False
        self.resolver_evidence = updated
        if advance_generation:
            self.mark_evidence_changed(
                evidence_family=evidence_family,
                reason=evidence_reason,
            )
        return True

    def merge_portable_state_routes(
        self,
        key: NativePreanalysisKey,
        routes: tuple[PortableMaterializedStateRoute, ...],
    ) -> bool:
        """Merge serial-free logical routes into lifecycle-owned evidence."""
        for route in routes:
            for identity in (
                route.source_identity,
                route.target_identity,
                route.source_handler_identity,
                route.source_handler_region_identity,
            ):
                if identity is not None and identity.native_key != key:
                    raise NativePreanalysisKeyMismatch(
                        key,
                        identity.native_key,
                        key.mismatch_fields(identity.native_key),
                    )
        current = self._resolver_evidence_for(key)
        merged = tuple(dict.fromkeys((*current.state_routes, *routes)))
        return self._replace_resolver_evidence(
            key,
            evidence_family="portable_state_routes",
            evidence_reason="portable state-route evidence changed",
            state_routes=merged,
        )

    def merge_state_write_routes(
        self,
        key: NativePreanalysisKey,
        routes: tuple[PortableStateWriteRouteEvidence, ...],
    ) -> bool:
        """Merge native write-to-delivery route authority into the lifecycle."""
        for route in routes:
            for identity in (
                route.write_identity,
                route.delivery_identity,
                route.target_identity,
            ):
                if identity.native_key != key:
                    raise NativePreanalysisKeyMismatch(
                        key,
                        identity.native_key,
                        key.mismatch_fields(identity.native_key),
                    )
        current = self._resolver_evidence_for(key)
        merged = tuple(dict.fromkeys((*current.state_write_routes, *routes)))
        changed = self._replace_resolver_evidence(
            key,
            evidence_family="state_write_routes",
            evidence_reason="native state-write route evidence changed",
            state_write_routes=merged,
        )
        if changed:
            self.state_write_route_inventory_revision += 1
        return changed

    def merge_portable_dispatcher_region_identity(
        self,
        key: NativePreanalysisKey,
        identity: StableBlockIdentity,
    ) -> bool:
        """Merge the portable native region owned by one dispatcher."""
        if identity.native_key != key:
            raise NativePreanalysisKeyMismatch(
                key,
                identity.native_key,
                key.mismatch_fields(identity.native_key),
            )
        current = self._resolver_evidence_for(key)
        previous = current.dispatcher_region_identity
        merged = StableBlockIdentity.from_intervals(
            (
                *(previous.native_ranges.intervals if previous is not None else ()),
                *identity.native_ranges.intervals,
            ),
            native_key=key,
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="dispatcher_region_identity",
            evidence_reason="portable dispatcher-region identity changed",
            dispatcher_region_identity=merged,
        )

    def merge_terminal_return_carrier_requests(
        self,
        key: NativePreanalysisKey,
        requests: tuple[TerminalReturnCarrierRequest, ...],
    ) -> bool:
        """Merge exact return-carrier requests under lifecycle ownership."""
        current = self._resolver_evidence_for(key)
        merged = tuple(
            dict.fromkeys((*current.terminal_return_carrier_requests, *requests))
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="terminal_return_carrier_requests",
            evidence_reason="terminal return-carrier evidence changed",
            terminal_return_carrier_requests=merged,
        )

    def merge_call_abi_proof(
        self,
        key: NativePreanalysisKey,
        *,
        call_ea: int,
        proof: StackCallAbiProof,
    ) -> bool:
        """Install one native-call-EA keyed ABI proof deterministically."""
        if not isinstance(proof, StackCallAbiProof):
            raise TypeError("resolver call ABI evidence requires a typed proof")
        current = self._resolver_evidence_for(key)
        proofs = dict(current.call_abi_proofs)
        proofs[int(call_ea)] = proof
        merged = tuple(sorted(proofs.items()))
        return self._replace_resolver_evidence(
            key,
            evidence_family="call_abi_proofs",
            evidence_reason="call ABI evidence changed",
            advance_generation=False,
            call_abi_proofs=merged,
        )

    def merge_call_result_carriers(
        self,
        key: NativePreanalysisKey,
        carriers: tuple[CallResultCarrier, ...],
    ) -> bool:
        """Retain serial-free call-result facts without requesting a redo."""
        if not all(isinstance(carrier, CallResultCarrier) for carrier in carriers):
            raise TypeError("resolver call-result evidence requires typed carriers")
        current = self._resolver_evidence_for(key)
        merged = tuple(dict.fromkeys((*current.call_result_carriers, *carriers)))
        return self._replace_resolver_evidence(
            key,
            evidence_family="call_result_carriers",
            evidence_reason="call-result carrier evidence changed",
            advance_generation=False,
            call_result_carriers=merged,
        )

    def clear_call_result_carriers(self, key: NativePreanalysisKey) -> bool:
        """Acknowledge call-result facts consumed by a later live maturity."""
        current = self._resolver_evidence_for(key)
        return self._replace_resolver_evidence(
            key,
            evidence_family="call_result_carriers",
            evidence_reason="call-result carrier evidence cleared",
            advance_generation=False,
            call_result_carriers=(),
        )

    def set_computed_goto_resolution(
        self,
        key: NativePreanalysisKey,
        resolution: ComputedGotoResolution,
    ) -> bool:
        """Publish the native computed-goto result without advancing an epoch."""
        if not isinstance(resolution, ComputedGotoResolution):
            raise TypeError("computed-goto resolution must be portable evidence")
        return self._replace_resolver_evidence(
            key,
            evidence_family="computed_goto_resolution",
            evidence_reason="computed-goto resolution changed",
            advance_generation=False,
            computed_goto_resolution=resolution,
        )

    def set_preopt_union_preparation(
        self,
        key: NativePreanalysisKey,
        preparation: PreoptUnionPreparationResult | None,
    ) -> bool:
        """Replace the portable PREOPT preparation outcome."""
        if preparation is not None and not isinstance(
            preparation,
            PreoptUnionPreparationResult,
        ):
            raise TypeError("PREOPT union preparation must be portable evidence")
        return self._replace_resolver_evidence(
            key,
            evidence_family="preopt_union_preparation",
            evidence_reason="PREOPT union preparation changed",
            advance_generation=False,
            preopt_union_preparation=preparation,
        )

    def set_prepatch_preopt_union_source(
        self,
        key: NativePreanalysisKey,
        source: PrepatchPreoptUnionSource | None,
    ) -> bool:
        """Replace the serial-free native source used by PREOPT regeneration."""
        if source is not None and not isinstance(source, PrepatchPreoptUnionSource):
            raise TypeError("prepatch PREOPT source must be portable evidence")
        return self._replace_resolver_evidence(
            key,
            evidence_family="prepatch_preopt_union_source",
            evidence_reason="prepatch PREOPT union source changed",
            advance_generation=False,
            prepatch_preopt_union_source=source,
        )

    def merge_preopt_entry_bridge_evidence(
        self,
        key: NativePreanalysisKey,
        evidence: EntryBridgeEvidence,
    ) -> bool:
        """Retain serial-free PREOPT entry choices across regeneration."""
        if not isinstance(evidence, EntryBridgeEvidence):
            raise TypeError("PREOPT entry bridge must be portable evidence")
        current = self._resolver_evidence_for(key)

        def semantic_identity(row: EntryBridgeEvidence) -> tuple[int, ...]:
            return (
                int(row.conditional_tail_ea or row.predicate_ea),
                int(row.source_store_ea),
                int(row.condition_code),
                int(row.taken_state_constant),
                int(row.fallthrough_state_constant),
            )

        if evidence not in current.preopt_entry_bridges and any(
            semantic_identity(row) == semantic_identity(evidence)
            for row in current.preopt_entry_bridges
        ):
            self._observe_transition(
                operation="evidence_coalesced",
                previous_generation=int(self.evidence_generation),
                evidence_family="preopt_entry_bridge",
                reason=(
                    "equivalent stable entry bridge observed after maturity-local "
                    "block splitting"
                ),
            )
            return False
        merged = tuple(
            sorted(
                set((*current.preopt_entry_bridges, evidence)),
                key=lambda row: (
                    int(row.conditional_tail_ea or row.predicate_ea),
                    int(row.source_store_ea),
                    int(row.taken_state_constant),
                    int(row.fallthrough_state_constant),
                ),
            )
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="preopt_entry_bridge",
            evidence_reason="PREOPT entry-bridge evidence changed",
            preopt_entry_bridges=merged,
        )

    def record_bootstrap_route_binding(
        self,
        key: NativePreanalysisKey,
        binding: BootstrapRouteBindingEvidence,
    ) -> bool:
        """Retain a serial-free PREOPT binding under lifecycle ownership."""
        for identity in (
            binding.route.source_identity,
            binding.route.handler_identity,
            binding.source_identity,
            binding.handler_identity,
        ):
            if identity.native_key != key:
                raise NativePreanalysisKeyMismatch(
                    key,
                    identity.native_key,
                    key.mismatch_fields(identity.native_key),
                )
        route_key = binding.route.key
        if (
            self.bootstrap_routes.get(route_key) != binding.route
            or route_key in self.conflicted_bootstrap_keys
            or self.rebound_bootstrap_generations.get(route_key)
            != int(binding.evidence_generation)
        ):
            return False
        current = self._resolver_evidence_for(key)
        bindings = dict(current.bootstrap_route_bindings)
        if bindings.get(route_key) == binding:
            return False
        bindings[route_key] = binding
        merged = tuple(
            sorted(
                bindings.items(),
                key=lambda item: (
                    int(item[0][1]),
                    item[0][0].native_ranges.diagnostic_label(),
                ),
            )
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="bootstrap_route_bindings",
            evidence_reason="PREOPT bootstrap-route binding changed",
            advance_generation=False,
            bootstrap_route_bindings=merged,
        )

    def bound_bootstrap_route_bindings(
        self,
        key: NativePreanalysisKey,
    ) -> tuple[BootstrapRouteBindingEvidence, ...]:
        """Return bindings owned by the postvalidated normalization epoch."""
        current = self._resolver_evidence_for(key)
        bound_generation = self.normalization_published_postvalidated_generation
        if bound_generation is None:
            return ()
        bindings = {
            binding
            for route_key, binding in current.bootstrap_route_bindings
            if binding.evidence_generation == bound_generation
            and self.bootstrap_routes.get(route_key) == binding.route
            and route_key not in self.conflicted_bootstrap_keys
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

    def merge_native_facts(
        self,
        key: NativePreanalysisKey,
        *,
        native_cfg: NativeCfg | None = None,
        semantic_closure: NativeSemanticClosure | None = None,
        transfers: tuple[MaterializedIndirectTransfer, ...] | None = None,
        boundary_ports: DetachedSnippetBoundaryPorts | None = None,
    ) -> bool:
        """Merge one complete portable view through the lifecycle authority."""
        current = self.facts
        facts = NativePreanalysisFacts(
            key=key,
            native_cfg=(
                native_cfg
                if native_cfg is not None
                else NativeCfg({})
                if current is None
                else current.native_cfg
            ),
            semantic_closure=(
                semantic_closure
                if semantic_closure is not None
                else None
                if current is None
                else current.semantic_closure
            ),
            transfers=(
                transfers
                if transfers is not None
                else ()
                if current is None
                else current.transfers
            ),
            boundary_ports=(
                boundary_ports
                if boundary_ports is not None
                else (
                    DetachedSnippetBoundaryPorts((), ())
                    if current is None
                    else current.boundary_ports
                )
            ),
        )
        return self.merge_facts(key, facts)

    def merge_materialized_transfers(
        self,
        key: NativePreanalysisKey,
        transfers: tuple[MaterializedIndirectTransfer, ...],
    ) -> bool:
        """Merge portable transfers, refreshing compatible predicate snapshots."""
        trace_merge = os.environ.get("RHAD_TRANSFER_TRACE_SESSION_STATE") == "1"
        if trace_merge and transfers:
            caller = " > ".join(
                frame.name for frame in traceback.extract_stack(limit=6)[:-1]
            )
            logger.info(
                "RESOLVER_TRANSFER_MERGE generation=%d count=%d caller=%s",
                self.evidence_generation,
                len(transfers),
                caller,
            )
        current = () if self.facts is None else self.facts.transfers
        merged = list(current)
        for transfer in transfers:
            resolver_kind = str(transfer.resolver_kind)
            if is_conditional_handler_bridge_kind(resolver_kind):
                matching_indices = [
                    index
                    for index, existing in enumerate(merged)
                    if is_conditional_handler_bridge_kind(str(existing.resolver_kind))
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
                        "RESOLVER_TRANSFER_APPEND generation=%d source=0x%X kind=%s",
                        self.evidence_generation,
                        int(transfer.source_jmp_ea),
                        transfer.resolver_kind,
                    )
                merged.append(transfer)
        normalized = tuple(merged)
        if normalized == current:
            return False
        return self.merge_native_facts(key, transfers=normalized)

    def discover_static_native_bootstrap_route(
        self,
        key: NativePreanalysisKey,
        *,
        source_anchor_ea: int,
        state_constant: int,
        handler_anchor_ea: int,
    ) -> bool:
        """Record exact native bootstrap anchors as serial-free evidence."""
        source_anchor_ea = int(source_anchor_ea)
        handler_anchor_ea = int(handler_anchor_ea)
        if source_anchor_ea <= 0 or handler_anchor_ea <= 0:
            return False
        source_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_anchor_ea, source_anchor_ea + 1),),
            native_key=key,
        )
        handler_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_anchor_ea, handler_anchor_ea + 1),),
            native_key=key,
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

    def merge_facts(
        self,
        key: NativePreanalysisKey,
        facts: NativePreanalysisFacts,
    ) -> bool:
        """Install changed normalized facts and advance their evidence epoch."""
        facts.require_key(key)
        if self.facts == facts:
            return False
        if self.facts is None:
            transfer_inventory_changed = bool(facts.transfers)
        else:
            transfer_inventory_changed = self.facts.transfers != facts.transfers
        self.facts = facts
        if transfer_inventory_changed:
            self.transfer_inventory_revision += 1
        self.mark_evidence_changed(
            evidence_family="native_facts",
            reason="normalized native facts changed",
        )
        return True

    def mark_evidence_changed(self, *, evidence_family: str, reason: str) -> None:
        """Advance a bound epoch, or coalesce first-pass native evidence.

        Flowchart discovery can establish several mutually-dependent native
        facts before the first PREOPT MBA exists.  They all describe the same
        requested rebuild and therefore share generation one.  Once PREOPT has
        bound that generation, a later fact is a real new epoch and may request
        its own controlled redo.
        """
        previous_generation = int(self.evidence_generation)
        if (
            self.normalization_published_postvalidated_generation is None
            and self.evidence_generation > 0
        ):
            self.portable_evidence_ready_generation = self.evidence_generation
            self._observe_transition(
                operation="evidence_coalesced",
                previous_generation=previous_generation,
                evidence_family=evidence_family,
                reason=(
                    f"{reason}; first-pass evidence shares the pending PREOPT generation"
                ),
            )
            return
        restart_pending = self.pending_generated_restart_generation is not None
        self.evidence_generation += 1
        self.portable_evidence_ready_generation = self.evidence_generation
        self.redo_generation = None
        self.pending_generated_restart_generation = (
            self.evidence_generation if restart_pending else None
        )
        self._observe_transition(
            operation="evidence_changed",
            previous_generation=previous_generation,
            evidence_family=evidence_family,
            reason=reason,
        )

    def merge_bootstrap_route(self, evidence: BootstrapRouteEvidence) -> bool:
        """Merge only changed portable evidence and invalidate PREOPT binding."""
        key = evidence.key
        current = self.bootstrap_routes.get(key)
        if current == evidence:
            return False
        if (
            current is not None
            and current.proof_kind is BootstrapRouteProofKind.STATIC_NATIVE
        ):
            if evidence.proof_kind is not BootstrapRouteProofKind.STATIC_NATIVE:
                return False
        if current is not None and current != evidence:
            self.conflicted_bootstrap_keys.add(key)
            self.bootstrap_routes.pop(key, None)
            self.rebound_bootstrap_keys.discard(key)
            self.rebound_bootstrap_generations.pop(key, None)
            self.published_bootstrap_keys.discard(key)
        else:
            self.bootstrap_routes[key] = evidence
        self.mark_evidence_changed(
            evidence_family="bootstrap_routes",
            reason="portable bootstrap-route evidence changed",
        )
        return True

    def mark_bootstrap_route_rebound(self, evidence: BootstrapRouteEvidence) -> bool:
        """Record that a unique PREOPT binding consumed this exact route."""
        key = evidence.key
        if (
            self.bootstrap_routes.get(key) != evidence
            or key in self.conflicted_bootstrap_keys
            or self.rebound_bootstrap_generations.get(key) == self.evidence_generation
        ):
            return False
        self.rebound_bootstrap_keys.add(key)
        self.rebound_bootstrap_generations[key] = self.evidence_generation
        # Publication is generation-scoped even though the portable route key
        # is stable across rebuilds.
        self.published_bootstrap_keys.discard(key)
        return True

    def pending_rebound_bootstrap_routes(
        self,
    ) -> tuple[BootstrapRouteEvidence, ...]:
        """Return rebound routes that still need snapshot-bound diagnostics."""
        pending: list[BootstrapRouteEvidence] = []
        for key in sorted(
            self.rebound_bootstrap_keys - self.published_bootstrap_keys,
            key=lambda item: (
                int(item[1]),
                item[0].native_ranges.diagnostic_label(),
            ),
        ):
            evidence = self.bootstrap_routes.get(key)
            if evidence is None or key in self.conflicted_bootstrap_keys:
                continue
            pending.append(evidence)
        return tuple(pending)

    def mark_rebound_bootstrap_routes_published(
        self,
        routes: tuple[BootstrapRouteEvidence, ...],
    ) -> None:
        """Acknowledge only routes whose snapshot event was emitted."""
        for route in routes:
            key = route.key
            if (
                self.bootstrap_routes.get(key) == route
                and key in self.rebound_bootstrap_keys
                and key not in self.conflicted_bootstrap_keys
            ):
                self.published_bootstrap_keys.add(key)

    def pending_materialized_transfers_for_publication(
        self,
    ) -> tuple[MaterializedIndirectTransfer, ...]:
        """Return the current complete inventory once per evidence generation."""
        if (
            self.published_transfer_inventory_revision
            == self.transfer_inventory_revision
            or self.facts is None
            or not self.facts.transfers
        ):
            return ()
        return self.facts.transfers

    def mark_materialized_transfers_published(
        self,
        transfers: tuple[MaterializedIndirectTransfer, ...],
    ) -> None:
        """Acknowledge only an event containing the exact current inventory."""
        if self.facts is not None and transfers == self.facts.transfers:
            self.published_transfer_inventory_revision = (
                self.transfer_inventory_revision
            )

    def pending_state_write_routes_for_publication(
        self,
    ) -> tuple[PortableStateWriteRouteEvidence, ...]:
        """Return the current portable route inventory once per revision."""
        current = self.resolver_evidence
        if (
            self.published_state_write_route_inventory_revision
            == self.state_write_route_inventory_revision
            or current is None
            or not current.state_write_routes
        ):
            return ()
        return current.state_write_routes

    def mark_state_write_routes_published(
        self,
        routes: tuple[PortableStateWriteRouteEvidence, ...],
    ) -> None:
        """Acknowledge only an event containing the exact current inventory."""
        current = self.resolver_evidence
        if current is not None and routes == current.state_write_routes:
            self.published_state_write_route_inventory_revision = (
                self.state_write_route_inventory_revision
            )

    def needs_state_write_route_binding(self) -> bool:
        """Return whether this evidence generation still needs live routing."""
        current = self.resolver_evidence
        return bool(
            current is not None
            and current.state_write_routes
            and self.bound_state_write_route_generation != self.evidence_generation
        )

    def mark_state_write_routes_bound(self) -> None:
        """Acknowledge complete live binding for the current evidence epoch."""
        if (
            self.resolver_evidence is not None
            and self.resolver_evidence.state_write_routes
        ):
            self.bound_state_write_route_generation = self.evidence_generation

    def request_controlled_redo(self) -> bool:
        """Allow exactly one redo request for a changed evidence generation."""
        if self.redo_generation == self.evidence_generation:
            return False
        self.redo_generation = self.evidence_generation
        return True

    @property
    def has_pending_generated_restart(self) -> bool:
        """Whether CALLS staged a controller-owned generated-MBA restart."""
        return self.pending_generated_restart_generation == self.evidence_generation

    def request_generated_restart(self) -> bool:
        """Stage one CALLS-discovered restart for a later flowchart callback.

        ``hxe_calls_done`` has no documented microcode-error return contract.
        The owning decompile controller must initiate a follow-up pass; its
        flowchart callback then consumes this request and returns ``MERR_REDO``.
        """
        generation = int(self.evidence_generation)
        if not self.request_controlled_redo():
            self._observe_transition(
                operation="generated_restart_requested",
                previous_generation=generation,
                evidence_family="controller_restart",
                outcome="declined",
                reason="evidence generation already owns a controlled redo",
            )
            return False
        self.pending_generated_restart_generation = self.evidence_generation
        self._observe_transition(
            operation="generated_restart_requested",
            previous_generation=generation,
            evidence_family="controller_restart",
            reason="CALLS staged a controller-owned generated-MBA restart",
        )
        return True

    def consume_generated_restart(self) -> bool:
        """Consume the current generation's staged flowchart restart once."""
        if not self.has_pending_generated_restart:
            return False
        generation = int(self.evidence_generation)
        self.pending_generated_restart_generation = None
        self._observe_transition(
            operation="generated_restart_consumed",
            previous_generation=generation,
            evidence_family="controller_restart",
            reason="flowchart consumed the staged generated-MBA restart",
        )
        return True

    def needs_bootstrap_route_binding(self) -> bool:
        """Whether a current portable route still lacks a live PREOPT bind."""
        return any(
            key not in self.conflicted_bootstrap_keys
            and self.rebound_bootstrap_generations.get(key) != self.evidence_generation
            for key in self.bootstrap_routes
        )


@runtime_checkable
class FragmentPublicationLifecycleAuthority(Protocol):
    """Generation authority driven only by validated fragment publication."""

    evidence_generation: int

    def mark_normalization_staged(self) -> bool: ...

    def mark_normalization_validated(self) -> bool: ...

    def mark_normalization_published_and_postvalidated(self) -> bool: ...

    def abort_normalization(self, *, reason: str) -> bool: ...

    def mark_semantic_fragment_staged(self) -> bool: ...

    def mark_semantic_fragment_validated(self) -> bool: ...

    def mark_semantic_fragment_published_and_postvalidated(self) -> bool: ...

    def mark_receipt_committed(self) -> bool: ...

    def abort_semantic_fragment(self, *, reason: str) -> bool: ...


@runtime_checkable
class ResolverEvidenceAttachment(Protocol):
    """Lower-layer view of a resolver attachment bound to lifecycle evidence."""

    native_preanalysis: NativePreanalysisSessionState
    native_key: NativePreanalysisKey
    indirect_label_materialized: bool
    indirect_dispatcher_materialized: bool

    def invalidate_current_mba_binding(self) -> None:
        """Drop the attachment's generation-local live lookup."""

    def release_live_bindings(self) -> None:
        """Drop all callback-local state at top-level session completion."""


@runtime_checkable
class ResolverSessionOwner(Protocol):
    """Typed lifecycle context capable of owning one resolver attachment."""

    native_preanalysis: NativePreanalysisSessionState
    native_key: NativePreanalysisKey
    resolver_attachment: ResolverEvidenceAttachment | None


@runtime_checkable
class ResolverLifecycleSession(ResolverSessionOwner, Protocol):
    """Known lifecycle session fields consumed by lower-layer callbacks."""

    native_preanalysis_depth: int

    @property
    def identity_key(self) -> str:
        """Return the durable live-binding owner identifier."""


def attached_resolver_session_state(
    session: object,
) -> ResolverEvidenceAttachment | None:
    """Return the existing named resolver attachment without reflection."""
    if not isinstance(session, ResolverSessionOwner):
        raise TypeError("resolver attachment requires a typed lifecycle owner")
    attachment = session.resolver_attachment
    if attachment is not None and not isinstance(
        attachment,
        ResolverEvidenceAttachment,
    ):
        raise TypeError("lifecycle resolver attachment is not a typed port")
    return attachment


__all__ = [
    "BootstrapRouteBindingEvidence",
    "BootstrapRouteEvidence",
    "BootstrapRouteProofKind",
    "CallResultCarrier",
    "ComputedGotoPatchPlan",
    "ComputedGotoResolution",
    "FragmentPublicationLifecycleAuthority",
    "NativePreanalysisFacts",
    "NativePreanalysisSessionState",
    "PreoptUnionPreparationResult",
    "PrepatchPreoptUnionSource",
    "ResolverEvidenceAttachment",
    "ResolverPortableEvidence",
    "ResolverLifecycleSession",
    "ResolverSessionOwner",
    "attached_resolver_session_state",
]
