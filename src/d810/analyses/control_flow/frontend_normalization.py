"""Portable evidence for faithful early frontend normalization.

Native providers may recover an indirect transfer before a decompiler frontend
can represent it faithfully.  The records in this module retain only stable
native identity, semantic edge roles, and proof obligations.  Provider names
remain diagnostic metadata and never select behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.control_flow.native_semantic_closure import (
    NativeRange,
    NativeSemanticClosure,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole


_BADADDR = 0xFFFFFFFFFFFFFFFF


class FrontendNormalizationEvidenceRejected(ValueError):
    """Portable frontend-normalization evidence is incomplete or ambiguous."""


class NativeTransferShape(str, Enum):
    """Semantic topology proved for one native indirect transfer."""

    DIRECT = "direct"
    CONDITIONAL = "conditional"


def _identifier(value: str, description: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise FrontendNormalizationEvidenceRejected(
            f"{description} must not be empty"
        )
    return normalized


def _native_ea(value: int, description: str) -> int:
    normalized = int(value)
    if not 0 <= normalized < _BADADDR:
        raise FrontendNormalizationEvidenceRejected(
            f"{description} must be a native EA"
        )
    return normalized


def _identity_contains(
    identity: StableBlockIdentity,
    ea: int,
) -> bool:
    return identity.native_ranges.contains(int(ea))


@dataclass(frozen=True, slots=True)
class NativeTransferEndpoint:
    """One semantic destination of a native indirect transfer proof."""

    role: SemanticEdgeRole
    identity: StableBlockIdentity
    anchor_ea: int

    def __post_init__(self) -> None:
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("native transfer endpoint requires a semantic edge role")
        if not isinstance(self.identity, StableBlockIdentity):
            raise TypeError("native transfer endpoint requires stable block identity")
        anchor_ea = _native_ea(self.anchor_ea, "native transfer target anchor")
        if not _identity_contains(self.identity, anchor_ea):
            raise FrontendNormalizationEvidenceRejected(
                "native transfer target anchor is outside its identity"
            )
        object.__setattr__(self, "anchor_ea", anchor_ea)


@dataclass(frozen=True, slots=True)
class NativeIndirectTransferProof:
    """Complete portable proof for one direct or conditional native transfer."""

    proof_id: str
    atomic_group_id: str
    shape: NativeTransferShape
    source_identity: StableBlockIdentity
    source_anchor_ea: int
    endpoints: tuple[NativeTransferEndpoint, ...]
    predicate_anchor_ea: int | None = None
    condition_producer_ea: int | None = None
    flag_corridor: tuple[StableBlockIdentity, ...] = ()
    permitted_flag_write_eas: frozenset[int] = frozenset()
    diagnostic_provenance: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        proof_id = _identifier(self.proof_id, "native transfer proof id")
        atomic_group_id = _identifier(
            self.atomic_group_id,
            "native transfer atomic group id",
        )
        if not isinstance(self.shape, NativeTransferShape):
            raise TypeError("native transfer proof requires a NativeTransferShape")
        if not isinstance(self.source_identity, StableBlockIdentity):
            raise TypeError("native transfer proof requires stable source identity")
        source_anchor_ea = _native_ea(
            self.source_anchor_ea,
            "native transfer source anchor",
        )
        if not _identity_contains(self.source_identity, source_anchor_ea):
            raise FrontendNormalizationEvidenceRejected(
                "native transfer source anchor is outside its identity"
            )

        endpoints = tuple(self.endpoints)
        if any(not isinstance(endpoint, NativeTransferEndpoint) for endpoint in endpoints):
            raise TypeError("native transfer proof contains an invalid endpoint")
        if any(
            endpoint.identity.native_key != self.source_identity.native_key
            for endpoint in endpoints
        ):
            raise FrontendNormalizationEvidenceRejected(
                "native transfer endpoints require one native identity key"
            )
        endpoint_roles = tuple(endpoint.role for endpoint in endpoints)
        if len(set(endpoint_roles)) != len(endpoint_roles):
            raise FrontendNormalizationEvidenceRejected(
                "native transfer endpoints require unique semantic roles"
            )

        predicate_anchor_ea = (
            None
            if self.predicate_anchor_ea is None
            else _native_ea(
                self.predicate_anchor_ea,
                "native transfer predicate anchor",
            )
        )
        condition_producer_ea = (
            None
            if self.condition_producer_ea is None
            else _native_ea(
                self.condition_producer_ea,
                "native transfer condition producer",
            )
        )
        flag_corridor = tuple(self.flag_corridor)
        if any(
            not isinstance(identity, StableBlockIdentity)
            for identity in flag_corridor
        ):
            raise TypeError("native transfer flag corridor requires stable identities")
        if any(
            identity.native_key != self.source_identity.native_key
            for identity in flag_corridor
        ):
            raise FrontendNormalizationEvidenceRejected(
                "native transfer flag corridor requires one native identity key"
            )
        if len(set(flag_corridor)) != len(flag_corridor):
            raise FrontendNormalizationEvidenceRejected(
                "native transfer flag corridor cannot repeat a block identity"
            )
        permitted_flag_write_eas = frozenset(
            _native_ea(ea, "permitted native flag writer")
            for ea in self.permitted_flag_write_eas
        )

        if self.shape is NativeTransferShape.DIRECT:
            if endpoint_roles != (SemanticEdgeRole.DIRECT,):
                raise FrontendNormalizationEvidenceRejected(
                    "direct native transfer requires one direct endpoint"
                )
            if (
                predicate_anchor_ea is not None
                or condition_producer_ea is not None
                or flag_corridor
                or permitted_flag_write_eas
            ):
                raise FrontendNormalizationEvidenceRejected(
                    "direct native transfer cannot carry conditional proof data"
                )
        else:
            conditional_roles = frozenset(
                {
                    SemanticEdgeRole.CONDITIONAL_TAKEN,
                    SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                }
            )
            if frozenset(endpoint_roles) != conditional_roles or len(endpoints) != 2:
                raise FrontendNormalizationEvidenceRejected(
                    "conditional native transfer requires both conditional roles"
                )
            if len({endpoint.anchor_ea for endpoint in endpoints}) != 2:
                raise FrontendNormalizationEvidenceRejected(
                    "conditional native transfer requires distinct destinations"
                )
            if predicate_anchor_ea is None or condition_producer_ea is None:
                raise FrontendNormalizationEvidenceRejected(
                    "conditional native transfer requires producer and predicate anchors"
                )
            if not _identity_contains(self.source_identity, predicate_anchor_ea):
                raise FrontendNormalizationEvidenceRejected(
                    "native transfer predicate anchor is outside its source identity"
                )
            if not flag_corridor:
                raise FrontendNormalizationEvidenceRejected(
                    "conditional native transfer requires a flag corridor"
                )
            if not _identity_contains(flag_corridor[0], condition_producer_ea):
                raise FrontendNormalizationEvidenceRejected(
                    "flag corridor must start at its condition producer"
                )
            if not _identity_contains(flag_corridor[-1], predicate_anchor_ea):
                raise FrontendNormalizationEvidenceRejected(
                    "flag corridor must end at its predicate consumer"
                )
            if condition_producer_ea not in permitted_flag_write_eas:
                raise FrontendNormalizationEvidenceRejected(
                    "flag corridor must permit its condition producer"
                )
            if any(
                not any(_identity_contains(identity, ea) for identity in flag_corridor)
                for ea in permitted_flag_write_eas
            ):
                raise FrontendNormalizationEvidenceRejected(
                    "permitted flag writers must belong to the proof corridor"
                )

        provenance: list[tuple[str, str]] = []
        for key, value in self.diagnostic_provenance:
            provenance.append(
                (
                    _identifier(key, "diagnostic provenance key"),
                    _identifier(value, "diagnostic provenance value"),
                )
            )

        object.__setattr__(self, "proof_id", proof_id)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(self, "source_anchor_ea", source_anchor_ea)
        object.__setattr__(self, "endpoints", endpoints)
        object.__setattr__(self, "predicate_anchor_ea", predicate_anchor_ea)
        object.__setattr__(
            self,
            "condition_producer_ea",
            condition_producer_ea,
        )
        object.__setattr__(self, "flag_corridor", flag_corridor)
        object.__setattr__(
            self,
            "permitted_flag_write_eas",
            permitted_flag_write_eas,
        )
        object.__setattr__(self, "diagnostic_provenance", tuple(provenance))

    @property
    def native_key(self) -> NativePreanalysisKey:
        return self.source_identity.native_key


@dataclass(frozen=True, slots=True)
class FrontendNormalizationEvidence:
    """One generation of provider-neutral early normalization evidence."""

    native_key: NativePreanalysisKey
    generation: int
    atomic_group_id: str
    transfer_proofs: tuple[NativeIndirectTransferProof, ...]
    semantic_closure: NativeSemanticClosure | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("frontend evidence requires a native preanalysis key")
        generation = int(self.generation)
        if generation <= 0:
            raise FrontendNormalizationEvidenceRejected(
                "frontend evidence generation must be positive"
            )
        atomic_group_id = _identifier(
            self.atomic_group_id,
            "frontend evidence atomic group id",
        )
        transfer_proofs = tuple(self.transfer_proofs)
        if not transfer_proofs or any(
            not isinstance(proof, NativeIndirectTransferProof)
            for proof in transfer_proofs
        ):
            raise FrontendNormalizationEvidenceRejected(
                "frontend evidence requires native transfer proofs"
            )
        if any(proof.native_key != self.native_key for proof in transfer_proofs):
            raise FrontendNormalizationEvidenceRejected(
                "frontend evidence proof native key mismatch"
            )
        if any(
            proof.atomic_group_id != atomic_group_id for proof in transfer_proofs
        ):
            raise FrontendNormalizationEvidenceRejected(
                "frontend evidence proofs require one atomic group"
            )
        proof_ids = tuple(proof.proof_id for proof in transfer_proofs)
        if len(set(proof_ids)) != len(proof_ids):
            raise FrontendNormalizationEvidenceRejected(
                "frontend evidence contains duplicate proof ids"
            )
        source_keys = tuple(
            (proof.source_identity, proof.source_anchor_ea)
            for proof in transfer_proofs
        )
        if len(set(source_keys)) != len(source_keys):
            raise FrontendNormalizationEvidenceRejected(
                "frontend evidence contains duplicate source authority"
            )
        if self.semantic_closure is not None and not isinstance(
            self.semantic_closure,
            NativeSemanticClosure,
        ):
            raise TypeError("frontend evidence semantic closure is not portable")

        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(
            self,
            "transfer_proofs",
            tuple(sorted(transfer_proofs, key=lambda proof: proof.proof_id)),
        )


def native_anchor_matches(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    anchor_ea: int,
) -> tuple[BlockSnapshot, ...]:
    """Return every live snapshot block matching one portable native anchor."""
    anchor_ea = int(anchor_ea)
    if not identity.native_ranges.contains(anchor_ea):
        return ()
    return tuple(
        block
        for block in graph.blocks.values()
        if anchor_ea
        in {
            int(block.start_ea),
            *(
                int(instruction.ea)
                for instruction in block.insn_snapshots
                if 0 <= int(instruction.ea) < _BADADDR
            ),
        }
    )


def unique_block_for_native_anchor(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    anchor_ea: int,
) -> BlockSnapshot | None:
    """Bind a portable native anchor only when the current graph is unambiguous."""
    matches = native_anchor_matches(graph, identity, anchor_ea)
    return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True, slots=True)
class DetachedSemanticClosureImportRequest:
    """Portable request to stage one missing native semantic closure."""

    native_key: NativePreanalysisKey
    generation: int
    atomic_group_id: str
    required_entry_eas: tuple[int, ...]
    native_ranges: tuple[NativeRange, ...]
    proof_ids: tuple[str, ...]
    semantic_closure: NativeSemanticClosure

    def __post_init__(self) -> None:
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("detached import request requires a native key")
        generation = int(self.generation)
        if generation <= 0:
            raise FrontendNormalizationEvidenceRejected(
                "detached import generation must be positive"
            )
        atomic_group_id = _identifier(
            self.atomic_group_id,
            "detached import atomic group id",
        )
        required_entry_eas = tuple(
            sorted(
                {
                    _native_ea(ea, "detached import entry")
                    for ea in self.required_entry_eas
                }
            )
        )
        native_ranges = tuple(self.native_ranges)
        proof_ids = tuple(
            sorted(
                {
                    _identifier(proof_id, "detached import proof id")
                    for proof_id in self.proof_ids
                }
            )
        )
        if not required_entry_eas or not proof_ids:
            raise FrontendNormalizationEvidenceRejected(
                "detached import requires entries and proof ids"
            )
        if not native_ranges or any(
            not isinstance(native_range, NativeRange)
            for native_range in native_ranges
        ):
            raise FrontendNormalizationEvidenceRejected(
                "detached import requires portable native ranges"
            )
        if not isinstance(self.semantic_closure, NativeSemanticClosure):
            raise TypeError("detached import requires a native semantic closure")
        if native_ranges != tuple(self.semantic_closure.native_ranges):
            raise FrontendNormalizationEvidenceRejected(
                "detached import ranges must equal its proven semantic closure"
            )
        if any(
            not any(
                int(native_range.start_ea) <= entry_ea < int(native_range.end_ea)
                for native_range in native_ranges
            )
            for entry_ea in required_entry_eas
        ):
            raise FrontendNormalizationEvidenceRejected(
                "detached import entry is outside its proven closure"
            )
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(self, "required_entry_eas", required_entry_eas)
        object.__setattr__(self, "native_ranges", native_ranges)
        object.__setattr__(self, "proof_ids", proof_ids)


def plan_detached_semantic_closure_import(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
) -> DetachedSemanticClosureImportRequest | None:
    """Plan one closure import when a proved target is absent from the graph."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("detached closure planning requires a FlowGraph")
    if not isinstance(evidence, FrontendNormalizationEvidence):
        raise TypeError(
            "detached closure planning requires frontend normalization evidence"
        )

    missing_entries: set[int] = set()
    proof_ids: set[str] = set()
    for proof in evidence.transfer_proofs:
        for endpoint in proof.endpoints:
            matches = native_anchor_matches(
                graph,
                endpoint.identity,
                endpoint.anchor_ea,
            )
            if len(matches) > 1:
                raise FrontendNormalizationEvidenceRejected(
                    f"native target 0x{endpoint.anchor_ea:X} is ambiguous"
                )
            if matches:
                continue
            missing_entries.add(int(endpoint.anchor_ea))
            proof_ids.add(proof.proof_id)

    if not missing_entries:
        return None
    closure = evidence.semantic_closure
    if closure is None:
        raise FrontendNormalizationEvidenceRejected(
            "missing native targets require a proven semantic closure"
        )
    return DetachedSemanticClosureImportRequest(
        native_key=evidence.native_key,
        generation=evidence.generation,
        atomic_group_id=evidence.atomic_group_id,
        required_entry_eas=tuple(missing_entries),
        native_ranges=tuple(closure.native_ranges),
        proof_ids=tuple(proof_ids),
        semantic_closure=closure,
    )


__all__ = [
    "DetachedSemanticClosureImportRequest",
    "FrontendNormalizationEvidence",
    "FrontendNormalizationEvidenceRejected",
    "NativeIndirectTransferProof",
    "NativeTransferEndpoint",
    "NativeTransferShape",
    "native_anchor_matches",
    "plan_detached_semantic_closure_import",
    "unique_block_for_native_anchor",
]
