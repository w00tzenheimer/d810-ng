"""Portable evidence owned by one top-level decompilation session.

This module intentionally contains no live MBA, Hex-Rays, manager, or
optimizer dependency.  The lifecycle coordinator owns one instance directly;
live adapters may attach a current-generation index separately, but may not
become the authority for evidence generation or restart decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
    normalize_detached_snippet_boundary_ports,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeCfg,
    NativeSemanticClosure,
)
from d810.core.native_preanalysis_key import (
    NativePreanalysisKey,
    NativePreanalysisKeyMismatch,
)
from d810.core.typing import Final
from d810.ir.block_identity import StableBlockIdentity


# Lower-layer callbacks may read an already-created resolver attachment through
# this stable key, but only the resolver/manager layers may construct it.  That
# keeps Hex-Rays adapters from importing upward into d810.optimizers.
RESOLVER_SESSION_STATE_EXTENSION_KEY: Final = (
    "d810.optimizers.microcode.flow.jumps.resolver_session_state"
)


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


def attached_resolver_session_state(session: object) -> object | None:
    """Return the existing resolver attachment without creating an authority."""
    extensions = getattr(session, "extensions", None)
    if not isinstance(extensions, dict):
        return None
    return extensions.get(RESOLVER_SESSION_STATE_EXTENSION_KEY)


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


@dataclass(slots=True)
class NativePreanalysisSessionState:
    """First-class portable evidence and epoch authority for a lifecycle."""

    evidence_generation: int = 0
    bound_preopt_generation: int | None = None
    facts: NativePreanalysisFacts | None = None
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
    redo_generation: int | None = None
    pending_generated_restart_generation: int | None = None

    def merge_facts(
        self,
        key: NativePreanalysisKey,
        facts: NativePreanalysisFacts,
    ) -> bool:
        """Install changed normalized facts and advance their evidence epoch."""
        facts.require_key(key)
        if self.facts == facts:
            return False
        self.facts = facts
        self.mark_evidence_changed()
        return True

    def mark_evidence_changed(self) -> None:
        """Advance a bound epoch, or coalesce first-pass native evidence.

        Flowchart discovery can establish several mutually-dependent native
        facts before the first PREOPT MBA exists.  They all describe the same
        requested rebuild and therefore share generation one.  Once PREOPT has
        bound that generation, a later fact is a real new epoch and may request
        its own controlled redo.
        """
        if self.bound_preopt_generation is None and self.evidence_generation > 0:
            return
        restart_pending = self.pending_generated_restart_generation is not None
        self.evidence_generation += 1
        self.redo_generation = None
        self.pending_generated_restart_generation = (
            self.evidence_generation if restart_pending else None
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
        self.mark_evidence_changed()
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
        if not self.request_controlled_redo():
            return False
        self.pending_generated_restart_generation = self.evidence_generation
        return True

    def consume_generated_restart(self) -> bool:
        """Consume the current generation's staged flowchart restart once."""
        if not self.has_pending_generated_restart:
            return False
        self.pending_generated_restart_generation = None
        return True

    def needs_preopt_binding(self) -> bool:
        return self.bound_preopt_generation != self.evidence_generation

    def mark_preopt_bound(self) -> bool:
        """Record the current generation's exact-once PREOPT bind."""
        if not self.needs_preopt_binding():
            return False
        self.bound_preopt_generation = self.evidence_generation
        return True


__all__ = [
    "BootstrapRouteBindingEvidence",
    "BootstrapRouteEvidence",
    "BootstrapRouteProofKind",
    "NativePreanalysisFacts",
    "NativePreanalysisSessionState",
    "RESOLVER_SESSION_STATE_EXTENSION_KEY",
    "attached_resolver_session_state",
]
