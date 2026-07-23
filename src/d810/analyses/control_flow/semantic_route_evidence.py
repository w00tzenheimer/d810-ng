"""Provider-neutral state-machine route proofs for canonical lowering."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity


_BADADDR = 0xFFFFFFFFFFFFFFFF


class SemanticRouteEvidenceRejected(ValueError):
    """Canonical route evidence is incomplete, ambiguous, or inconsistent."""


class SemanticRouteShape(str, Enum):
    """Complete semantic control-flow shape proved for one route owner."""

    DIRECT = "direct"
    CONDITIONAL = "conditional"


class SemanticRouteProofKind(str, Enum):
    """Provider-independent reason a canonical route is authoritative."""

    STATE_ASSIGNMENT = "state_assignment"
    STATE_CHOICE = "state_choice"
    BOOTSTRAP = "bootstrap"
    TERMINAL_RETURN = "terminal_return"


def _identifier(value: str, description: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise SemanticRouteEvidenceRejected(f"{description} must not be empty")
    return normalized


def _native_ea(value: int, description: str) -> int:
    normalized = int(value)
    if not 0 <= normalized < _BADADDR:
        raise SemanticRouteEvidenceRejected(f"{description} must be a native EA")
    return normalized


@dataclass(frozen=True, slots=True)
class SemanticRouteDestination:
    """One state-selected destination in a canonical route proof."""

    role: SemanticEdgeRole
    state_constant: int
    target_identity: StableBlockIdentity
    target_anchor_ea: int
    terminal: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("semantic route destination requires an edge role")
        if not isinstance(self.target_identity, StableBlockIdentity):
            raise TypeError("semantic route destination requires stable identity")
        target_anchor_ea = _native_ea(
            self.target_anchor_ea,
            "semantic route target anchor",
        )
        if not self.target_identity.native_ranges.contains(target_anchor_ea):
            raise SemanticRouteEvidenceRejected(
                "semantic route target anchor is outside its identity"
            )
        object.__setattr__(self, "state_constant", int(self.state_constant))
        object.__setattr__(self, "target_anchor_ea", target_anchor_ea)
        object.__setattr__(self, "terminal", bool(self.terminal))


@dataclass(frozen=True, slots=True)
class SemanticStateWriteProof:
    """Exact portable state assignment and its delivery corridor."""

    identity: StableBlockIdentity
    instruction_ea: int
    state_variable: StorageIdentity
    width: int
    state_constant: int
    corridor_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.identity, StableBlockIdentity):
            raise TypeError("semantic state write requires stable identity")
        instruction_ea = _native_ea(
            self.instruction_ea,
            "semantic state-write instruction",
        )
        if not self.identity.native_ranges.contains(instruction_ea):
            raise SemanticRouteEvidenceRejected(
                "semantic state-write instruction is outside its identity"
            )
        if not isinstance(self.state_variable, StorageIdentity):
            raise TypeError("semantic state write requires storage identity")
        width = int(self.width)
        if not 1 <= width <= 8:
            raise SemanticRouteEvidenceRejected(
                "semantic state-write width must be 1..8 bytes"
            )
        corridor = tuple(int(ea) for ea in self.corridor_instruction_eas)
        if (
            not corridor
            or corridor != tuple(sorted(set(corridor)))
            or corridor[0] != instruction_ea
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic state-write corridor must begin at its exact write"
            )
        object.__setattr__(self, "instruction_ea", instruction_ea)
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "state_constant", int(self.state_constant))
        object.__setattr__(self, "corridor_instruction_eas", corridor)


@dataclass(frozen=True, slots=True)
class SemanticRouteProof:
    """One complete state-machine route proof in stable native coordinates."""

    proof_id: str
    atomic_group_id: str
    proof_kind: SemanticRouteProofKind
    shape: SemanticRouteShape
    source_identity: StableBlockIdentity
    source_anchor_ea: int
    destinations: tuple[SemanticRouteDestination, ...]
    source_owner_identity: StableBlockIdentity | None = None
    source_owner_anchor_ea: int | None = None
    state_write: SemanticStateWriteProof | None = None
    predicate_anchor_ea: int | None = None
    diagnostic_provenance: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        proof_id = _identifier(self.proof_id, "semantic route proof id")
        atomic_group_id = _identifier(
            self.atomic_group_id,
            "semantic route atomic group id",
        )
        if not isinstance(self.proof_kind, SemanticRouteProofKind):
            raise TypeError("semantic route proof requires a typed proof kind")
        if not isinstance(self.shape, SemanticRouteShape):
            raise TypeError("semantic route proof requires a typed route shape")
        if not isinstance(self.source_identity, StableBlockIdentity):
            raise TypeError("semantic route proof requires stable source identity")
        source_anchor_ea = _native_ea(
            self.source_anchor_ea,
            "semantic route source anchor",
        )
        if not self.source_identity.native_ranges.contains(source_anchor_ea):
            raise SemanticRouteEvidenceRejected(
                "semantic route source anchor is outside its identity"
            )

        destinations = tuple(self.destinations)
        if not destinations or any(
            not isinstance(destination, SemanticRouteDestination)
            for destination in destinations
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic route proof requires destinations"
            )
        native_key = self.source_identity.native_key
        if any(
            destination.target_identity.native_key != native_key
            for destination in destinations
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic route proof identities require one native key"
            )
        roles = tuple(destination.role for destination in destinations)
        if len(set(roles)) != len(roles):
            raise SemanticRouteEvidenceRejected(
                "semantic route proof requires unique destination roles"
            )

        predicate_anchor_ea = (
            None
            if self.predicate_anchor_ea is None
            else _native_ea(
                self.predicate_anchor_ea,
                "semantic route predicate anchor",
            )
        )
        if self.shape is SemanticRouteShape.DIRECT:
            if roles != (SemanticEdgeRole.DIRECT,):
                raise SemanticRouteEvidenceRejected(
                    "direct semantic route requires one direct destination"
                )
            if predicate_anchor_ea is not None:
                raise SemanticRouteEvidenceRejected(
                    "direct semantic route cannot carry a predicate"
                )
        else:
            expected_roles = frozenset(
                {
                    SemanticEdgeRole.CONDITIONAL_TAKEN,
                    SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                }
            )
            if len(destinations) != 2 or frozenset(roles) != expected_roles:
                raise SemanticRouteEvidenceRejected(
                    "conditional semantic route requires both conditional roles"
                )
            if predicate_anchor_ea is None or not (
                self.source_identity.native_ranges.contains(predicate_anchor_ea)
            ):
                raise SemanticRouteEvidenceRejected(
                    "conditional semantic route requires a source-owned predicate"
                )
            if len({item.target_anchor_ea for item in destinations}) != 2:
                raise SemanticRouteEvidenceRejected(
                    "conditional semantic route requires distinct destinations"
                )

        source_owner_identity = self.source_owner_identity
        source_owner_anchor_ea = self.source_owner_anchor_ea
        if source_owner_identity is None:
            if source_owner_anchor_ea is not None:
                raise SemanticRouteEvidenceRejected(
                    "semantic route owner anchor requires owner identity"
                )
        else:
            if not isinstance(source_owner_identity, StableBlockIdentity):
                raise TypeError("semantic route owner requires stable identity")
            if source_owner_identity.native_key != native_key:
                raise SemanticRouteEvidenceRejected(
                    "semantic route owner belongs to another native key"
                )
            if source_owner_anchor_ea is None:
                raise SemanticRouteEvidenceRejected(
                    "semantic route owner requires an anchor"
                )
            source_owner_anchor_ea = _native_ea(
                source_owner_anchor_ea,
                "semantic route owner anchor",
            )
            if not source_owner_identity.native_ranges.contains(source_owner_anchor_ea):
                raise SemanticRouteEvidenceRejected(
                    "semantic route owner anchor is outside its identity"
                )

        state_write = self.state_write
        if state_write is not None:
            if not isinstance(state_write, SemanticStateWriteProof):
                raise TypeError("semantic route state write has the wrong type")
            if state_write.identity.native_key != native_key:
                raise SemanticRouteEvidenceRejected(
                    "semantic route state write belongs to another native key"
                )
        if self.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT:
            if state_write is None:
                raise SemanticRouteEvidenceRejected(
                    "state assignment requires its exact state write"
                )
            if (
                len(destinations) != 1
                or destinations[0].state_constant != state_write.state_constant
            ):
                raise SemanticRouteEvidenceRejected(
                    "state assignment destination state constant must match its write"
                )
        if self.proof_kind is SemanticRouteProofKind.TERMINAL_RETURN and not all(
            destination.terminal for destination in destinations
        ):
            raise SemanticRouteEvidenceRejected(
                "terminal-return route requires terminal destinations"
            )

        provenance: list[tuple[str, str]] = []
        for key, value in self.diagnostic_provenance:
            provenance.append(
                (
                    _identifier(key, "semantic route provenance key"),
                    _identifier(value, "semantic route provenance value"),
                )
            )
        object.__setattr__(self, "proof_id", proof_id)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(self, "source_anchor_ea", source_anchor_ea)
        object.__setattr__(self, "destinations", destinations)
        object.__setattr__(self, "source_owner_anchor_ea", source_owner_anchor_ea)
        object.__setattr__(self, "predicate_anchor_ea", predicate_anchor_ea)
        object.__setattr__(self, "diagnostic_provenance", tuple(provenance))

    @property
    def native_key(self) -> NativePreanalysisKey:
        return self.source_identity.native_key


@dataclass(frozen=True, slots=True)
class CanonicalSemanticEvidence:
    """One atomic generation of provider-neutral semantic route proofs."""

    native_key: NativePreanalysisKey
    generation: int
    atomic_group_id: str
    route_proofs: tuple[SemanticRouteProof, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("canonical semantic evidence requires a native key")
        generation = int(self.generation)
        if generation <= 0:
            raise SemanticRouteEvidenceRejected(
                "canonical semantic evidence generation must be positive"
            )
        atomic_group_id = _identifier(
            self.atomic_group_id,
            "canonical semantic atomic group id",
        )
        route_proofs = tuple(self.route_proofs)
        if not route_proofs or any(
            not isinstance(proof, SemanticRouteProof) for proof in route_proofs
        ):
            raise SemanticRouteEvidenceRejected(
                "canonical semantic evidence requires route proofs"
            )
        if any(proof.native_key != self.native_key for proof in route_proofs):
            raise SemanticRouteEvidenceRejected(
                "canonical semantic route native key mismatch"
            )
        if any(proof.atomic_group_id != atomic_group_id for proof in route_proofs):
            raise SemanticRouteEvidenceRejected(
                "canonical semantic routes require one atomic group"
            )
        proof_ids = tuple(proof.proof_id for proof in route_proofs)
        if len(set(proof_ids)) != len(proof_ids):
            raise SemanticRouteEvidenceRejected(
                "canonical semantic evidence contains duplicate proof ids"
            )
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(
            self,
            "route_proofs",
            tuple(sorted(route_proofs, key=lambda proof: proof.proof_id)),
        )


@dataclass(frozen=True, slots=True)
class BoundSemanticBlock:
    """One current-graph serial accompanied by its stable native anchor."""

    serial: int
    identity: StableBlockIdentity
    anchor_ea: int


@dataclass(frozen=True, slots=True)
class BoundSemanticRouteDestination:
    """One current-graph destination retaining its portable proof."""

    evidence: SemanticRouteDestination
    block: BoundSemanticBlock


@dataclass(frozen=True, slots=True)
class BoundSemanticRoute:
    """One route proof fully rebound into the current normalized graph."""

    evidence: SemanticRouteProof
    source: BoundSemanticBlock
    destinations: tuple[BoundSemanticRouteDestination, ...]
    source_owner: BoundSemanticBlock | None = None
    state_write_block: BoundSemanticBlock | None = None


@dataclass(frozen=True, slots=True)
class BoundCanonicalSemanticEvidence:
    """All routes in one atomic group rebound without partial acceptance."""

    evidence: CanonicalSemanticEvidence
    routes: tuple[BoundSemanticRoute, ...]

    @property
    def atomic_group_id(self) -> str:
        return self.evidence.atomic_group_id


def _unique_bound_block(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    anchor_ea: int,
) -> BoundSemanticBlock | None:
    anchor_ea = int(anchor_ea)
    matches = tuple(
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
        and identity.native_ranges.contains(anchor_ea)
    )
    if len(matches) != 1:
        return None
    return BoundSemanticBlock(
        serial=int(matches[0].serial),
        identity=identity,
        anchor_ea=anchor_ea,
    )


def bind_canonical_semantic_evidence(
    graph: FlowGraph,
    evidence: CanonicalSemanticEvidence,
) -> BoundCanonicalSemanticEvidence | None:
    """Bind one complete atomic group or abstain without a partial result."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("semantic route binding requires a FlowGraph")
    if not isinstance(evidence, CanonicalSemanticEvidence):
        raise TypeError("semantic route binding requires canonical evidence")
    routes: list[BoundSemanticRoute] = []
    for proof in evidence.route_proofs:
        source = _unique_bound_block(
            graph,
            proof.source_identity,
            proof.source_anchor_ea,
        )
        if source is None:
            return None
        destinations: list[BoundSemanticRouteDestination] = []
        for destination in proof.destinations:
            block = _unique_bound_block(
                graph,
                destination.target_identity,
                destination.target_anchor_ea,
            )
            if block is None:
                return None
            destinations.append(
                BoundSemanticRouteDestination(
                    evidence=destination,
                    block=block,
                )
            )
        source_owner = None
        if proof.source_owner_identity is not None:
            source_owner = _unique_bound_block(
                graph,
                proof.source_owner_identity,
                int(proof.source_owner_anchor_ea),
            )
            if source_owner is None:
                return None
        state_write_block = None
        if proof.state_write is not None:
            state_write_block = _unique_bound_block(
                graph,
                proof.state_write.identity,
                proof.state_write.instruction_ea,
            )
            if state_write_block is None:
                return None
        routes.append(
            BoundSemanticRoute(
                evidence=proof,
                source=source,
                destinations=tuple(destinations),
                source_owner=source_owner,
                state_write_block=state_write_block,
            )
        )
    return BoundCanonicalSemanticEvidence(
        evidence=evidence,
        routes=tuple(routes),
    )


__all__ = [
    "BoundCanonicalSemanticEvidence",
    "BoundSemanticBlock",
    "BoundSemanticRoute",
    "BoundSemanticRouteDestination",
    "CanonicalSemanticEvidence",
    "SemanticRouteDestination",
    "SemanticRouteEvidenceRejected",
    "SemanticRouteProof",
    "SemanticRouteProofKind",
    "SemanticRouteShape",
    "SemanticStateWriteProof",
    "bind_canonical_semantic_evidence",
]
