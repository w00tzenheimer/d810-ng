"""Provider-neutral state-machine route proofs for canonical lowering."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
)


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


class SemanticPredicateKind(str, Enum):
    """Portable strategy for realizing one complete conditional predicate."""

    PRESERVE_LIVE = "preserve_live"
    STORAGE_EQUALS = "storage_equals"


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
class SemanticCorridorPoint:
    """One stable native block and exact instruction anchor in a proof corridor."""

    identity: StableBlockIdentity
    anchor_ea: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, StableBlockIdentity):
            raise TypeError("semantic corridor point requires stable identity")
        anchor_ea = _native_ea(
            self.anchor_ea,
            "semantic corridor point anchor",
        )
        if not self.identity.native_ranges.contains(anchor_ea):
            raise SemanticRouteEvidenceRejected(
                "semantic corridor point anchor is outside its identity"
            )
        object.__setattr__(self, "anchor_ea", anchor_ea)

    @property
    def native_key(self) -> NativePreanalysisKey:
        return self.identity.native_key


@dataclass(frozen=True, slots=True)
class SemanticPredicateProof:
    """Complete portable predicate and its interference corridor."""

    kind: SemanticPredicateKind
    origin: SemanticCorridorPoint
    consumer: SemanticCorridorPoint
    corridor: tuple[SemanticCorridorPoint, ...]
    storage_identity: StorageIdentity | None = None
    width: int = 0
    compare_constant: int | None = None
    true_is_taken: bool | None = None
    permitted_write_eas: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SemanticPredicateKind):
            raise TypeError("semantic predicate requires a typed kind")
        if not isinstance(self.origin, SemanticCorridorPoint) or not isinstance(
            self.consumer,
            SemanticCorridorPoint,
        ):
            raise TypeError("semantic predicate requires corridor endpoints")
        corridor = tuple(self.corridor)
        if not corridor or any(
            not isinstance(point, SemanticCorridorPoint) for point in corridor
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic predicate requires an explicit corridor"
            )
        if corridor[0] != self.origin:
            raise SemanticRouteEvidenceRejected(
                "semantic predicate corridor must begin at its origin"
            )
        if corridor[-1] != self.consumer:
            raise SemanticRouteEvidenceRejected(
                "semantic predicate corridor must end at its consumer"
            )
        if len(set(corridor)) != len(corridor):
            raise SemanticRouteEvidenceRejected(
                "semantic predicate corridor cannot repeat a point"
            )
        native_key = self.origin.native_key
        if self.consumer.native_key != native_key or any(
            point.native_key != native_key for point in corridor
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic predicate corridor requires one native key"
            )
        permitted_write_eas = frozenset(
            _native_ea(ea, "permitted semantic predicate writer")
            for ea in self.permitted_write_eas
        )
        if any(
            not any(point.identity.native_ranges.contains(ea) for point in corridor)
            for ea in permitted_write_eas
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic predicate writers must belong to its corridor"
            )

        storage_identity = self.storage_identity
        width = int(self.width)
        compare_constant = self.compare_constant
        true_is_taken = self.true_is_taken
        if self.kind is SemanticPredicateKind.PRESERVE_LIVE:
            if self.origin != self.consumer or len(corridor) != 1:
                raise SemanticRouteEvidenceRejected(
                    "live predicate must be source-owned"
                )
            if (
                storage_identity is not None
                or width != 0
                or compare_constant is not None
                or permitted_write_eas
            ):
                raise SemanticRouteEvidenceRejected(
                    "live predicate cannot carry synthesized storage proof"
                )
            if true_is_taken not in (True, False):
                raise SemanticRouteEvidenceRejected(
                    "live predicate requires explicit arm orientation"
                )
        else:
            if not isinstance(storage_identity, StorageIdentity):
                raise SemanticRouteEvidenceRejected(
                    "storage predicate requires portable storage identity"
                )
            if not 1 <= width <= 8:
                raise SemanticRouteEvidenceRejected(
                    "storage predicate width must be 1..8 bytes"
                )
            if compare_constant is None or not (
                0 <= int(compare_constant) < (1 << (width * 8))
            ):
                raise SemanticRouteEvidenceRejected(
                    "storage predicate constant must fit its width"
                )
            if true_is_taken is not None:
                raise SemanticRouteEvidenceRejected(
                    "storage predicate destinations must already use semantic polarity"
                )
            compare_constant = int(compare_constant)

        object.__setattr__(self, "corridor", corridor)
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "compare_constant", compare_constant)
        object.__setattr__(self, "true_is_taken", true_is_taken)
        object.__setattr__(
            self,
            "permitted_write_eas",
            permitted_write_eas,
        )

    @property
    def native_key(self) -> NativePreanalysisKey:
        return self.origin.native_key


@dataclass(frozen=True, slots=True)
class SemanticCarrierProof:
    """One portable state carrier definition, uses, and interference corridor."""

    carrier_id: str
    definition: SemanticCorridorPoint
    consumers: tuple[SemanticCorridorPoint, ...]
    corridor: tuple[SemanticCorridorPoint, ...]
    storage_identity: StorageIdentity
    width: int
    state_values: tuple[int, ...]
    permitted_write_eas: frozenset[int]

    def __post_init__(self) -> None:
        carrier_id = _identifier(self.carrier_id, "semantic carrier id")
        if not isinstance(self.definition, SemanticCorridorPoint):
            raise TypeError("semantic carrier requires a definition point")
        consumers = tuple(self.consumers)
        if not consumers or any(
            not isinstance(consumer, SemanticCorridorPoint) for consumer in consumers
        ):
            raise SemanticRouteEvidenceRejected("semantic carrier requires consumers")
        if len(set(consumers)) != len(consumers):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier cannot repeat a consumer"
            )
        corridor = tuple(self.corridor)
        if not corridor or any(
            not isinstance(point, SemanticCorridorPoint) for point in corridor
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier requires an explicit corridor"
            )
        if corridor[0] != self.definition:
            raise SemanticRouteEvidenceRejected(
                "semantic carrier corridor must begin at its definition"
            )
        if any(consumer not in corridor for consumer in consumers):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier corridor must contain every consumer"
            )
        if corridor[-1] != consumers[-1]:
            raise SemanticRouteEvidenceRejected(
                "semantic carrier corridor must end at its final consumer"
            )
        if len(set(corridor)) != len(corridor):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier corridor cannot repeat a point"
            )
        native_key = self.definition.native_key
        if any(point.native_key != native_key for point in (*consumers, *corridor)):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier corridor requires one native key"
            )
        if not isinstance(self.storage_identity, StorageIdentity):
            raise TypeError("semantic carrier requires portable storage identity")
        width = int(self.width)
        if not 1 <= width <= 8:
            raise SemanticRouteEvidenceRejected(
                "semantic carrier width must be 1..8 bytes"
            )
        state_values = tuple(int(value) for value in self.state_values)
        if not state_values or len(set(state_values)) != len(state_values):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier requires unique state values"
            )
        max_value = 1 << (width * 8)
        if any(not 0 <= value < max_value for value in state_values):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier state values must fit its width"
            )
        permitted_write_eas = frozenset(
            _native_ea(ea, "permitted semantic carrier writer")
            for ea in self.permitted_write_eas
        )
        if self.definition.anchor_ea not in permitted_write_eas:
            raise SemanticRouteEvidenceRejected(
                "semantic carrier must permit its definition write"
            )
        if any(
            not any(point.identity.native_ranges.contains(ea) for point in corridor)
            for ea in permitted_write_eas
        ):
            raise SemanticRouteEvidenceRejected(
                "semantic carrier writers must belong to its corridor"
            )
        object.__setattr__(self, "carrier_id", carrier_id)
        object.__setattr__(self, "consumers", consumers)
        object.__setattr__(self, "corridor", corridor)
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "state_values", state_values)
        object.__setattr__(
            self,
            "permitted_write_eas",
            permitted_write_eas,
        )

    @property
    def native_key(self) -> NativePreanalysisKey:
        return self.definition.native_key


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
    predicate: SemanticPredicateProof | None = None
    carriers: tuple[SemanticCarrierProof, ...] = ()
    terminal_return_carrier: TerminalReturnCarrierEvidence | None = None
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

        predicate = self.predicate
        carriers = tuple(self.carriers)
        if predicate is not None and not isinstance(
            predicate,
            SemanticPredicateProof,
        ):
            raise TypeError("semantic route predicate has the wrong type")
        if any(not isinstance(carrier, SemanticCarrierProof) for carrier in carriers):
            raise TypeError("semantic route contains an invalid carrier proof")
        if len({carrier.carrier_id for carrier in carriers}) != len(carriers):
            raise SemanticRouteEvidenceRejected(
                "semantic route contains duplicate carrier proofs"
            )
        if predicate is not None and predicate.native_key != native_key:
            raise SemanticRouteEvidenceRejected(
                "semantic route predicate belongs to another native key"
            )
        if any(carrier.native_key != native_key for carrier in carriers):
            raise SemanticRouteEvidenceRejected(
                "semantic route carrier belongs to another native key"
            )
        terminal_return_carrier = self.terminal_return_carrier
        if terminal_return_carrier is not None:
            if not isinstance(
                terminal_return_carrier,
                TerminalReturnCarrierEvidence,
            ):
                raise TypeError("semantic terminal-return carrier has the wrong type")
            if terminal_return_carrier.native_key != native_key:
                raise SemanticRouteEvidenceRejected(
                    "semantic terminal-return carrier belongs to another native key"
                )
        if self.shape is SemanticRouteShape.DIRECT:
            if roles != (SemanticEdgeRole.DIRECT,):
                raise SemanticRouteEvidenceRejected(
                    "direct semantic route requires one direct destination"
                )
            if predicate is not None or carriers:
                raise SemanticRouteEvidenceRejected(
                    "direct semantic route cannot carry conditional proof data"
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
            if predicate is None:
                raise SemanticRouteEvidenceRejected(
                    "conditional semantic route requires a predicate proof"
                )
            source_point = SemanticCorridorPoint(
                self.source_identity,
                source_anchor_ea,
            )
            if predicate.consumer != source_point:
                raise SemanticRouteEvidenceRejected(
                    "conditional predicate consumer must be the route source"
                )
            if len({item.target_anchor_ea for item in destinations}) != 2:
                raise SemanticRouteEvidenceRejected(
                    "conditional semantic route requires distinct destinations"
                )
            if predicate.kind is SemanticPredicateKind.STORAGE_EQUALS:
                if len(carriers) != 1:
                    raise SemanticRouteEvidenceRejected(
                        "storage predicate requires one carrier proof"
                    )
                carrier = carriers[0]
                if source_point not in carrier.consumers:
                    raise SemanticRouteEvidenceRejected(
                        "storage predicate carrier must reach the route source"
                    )
                destination_states = {
                    int(destination.state_constant) for destination in destinations
                }
                if set(carrier.state_values) != destination_states:
                    raise SemanticRouteEvidenceRejected(
                        "carrier state values must match destination states"
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
        if self.proof_kind is SemanticRouteProofKind.TERMINAL_RETURN:
            if (
                self.shape is not SemanticRouteShape.DIRECT
                or len(destinations) != 1
                or not destinations[0].terminal
                or terminal_return_carrier is None
                or state_write is None
            ):
                raise SemanticRouteEvidenceRejected(
                    "terminal-return route requires one terminal destination, "
                    "state write, and return carrier"
                )
            request = terminal_return_carrier.request
            destination = destinations[0]
            if (
                destination.target_anchor_ea != int(request.terminal_target_ea)
                or destination.target_anchor_ea
                not in destination.target_identity.exact_instruction_eas
                or destination.target_anchor_ea
                not in terminal_return_carrier.terminal_identity.exact_instruction_eas
                or destination.state_constant != int(request.state_constant)
                or state_write.instruction_ea != terminal_return_carrier.state_write_ea
                or state_write.instruction_ea
                not in state_write.identity.exact_instruction_eas
                or state_write.instruction_ea
                not in terminal_return_carrier.capture_identity.exact_instruction_eas
                or state_write.state_constant != int(request.state_constant)
                or state_write.state_variable
                != StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    int(request.state_var_reg),
                )
            ):
                raise SemanticRouteEvidenceRejected(
                    "terminal-return carrier must match its route, target, and state write"
                )
        elif terminal_return_carrier is not None:
            raise SemanticRouteEvidenceRejected(
                "only a terminal-return route may carry return semantics"
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
        object.__setattr__(self, "predicate", predicate)
        object.__setattr__(self, "carriers", carriers)
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
class BoundSemanticPredicate:
    """One complete predicate proof rebound into the current graph."""

    evidence: SemanticPredicateProof
    origin: BoundSemanticBlock
    consumer: BoundSemanticBlock
    corridor: tuple[BoundSemanticBlock, ...]


@dataclass(frozen=True, slots=True)
class BoundSemanticCarrier:
    """One complete carrier proof rebound into the current graph."""

    evidence: SemanticCarrierProof
    definition: BoundSemanticBlock
    consumers: tuple[BoundSemanticBlock, ...]
    corridor: tuple[BoundSemanticBlock, ...]


@dataclass(frozen=True, slots=True)
class BoundSemanticRoute:
    """One route proof fully rebound into the current normalized graph."""

    evidence: SemanticRouteProof
    source: BoundSemanticBlock
    destinations: tuple[BoundSemanticRouteDestination, ...]
    source_owner: BoundSemanticBlock | None = None
    state_write_block: BoundSemanticBlock | None = None
    predicate: BoundSemanticPredicate | None = None
    carriers: tuple[BoundSemanticCarrier, ...] = ()


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


def _bound_corridor_point(
    graph: FlowGraph,
    point: SemanticCorridorPoint,
) -> BoundSemanticBlock | None:
    return _unique_bound_block(
        graph,
        point.identity,
        point.anchor_ea,
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
        bound_predicate = None
        if proof.predicate is not None:
            predicate_origin = _bound_corridor_point(
                graph,
                proof.predicate.origin,
            )
            predicate_consumer = _bound_corridor_point(
                graph,
                proof.predicate.consumer,
            )
            predicate_corridor = tuple(
                _bound_corridor_point(graph, point)
                for point in proof.predicate.corridor
            )
            if (
                predicate_origin is None
                or predicate_consumer is None
                or any(block is None for block in predicate_corridor)
            ):
                return None
            bound_predicate = BoundSemanticPredicate(
                evidence=proof.predicate,
                origin=predicate_origin,
                consumer=predicate_consumer,
                corridor=tuple(predicate_corridor),
            )
        bound_carriers: list[BoundSemanticCarrier] = []
        for carrier in proof.carriers:
            carrier_definition = _bound_corridor_point(
                graph,
                carrier.definition,
            )
            carrier_consumers = tuple(
                _bound_corridor_point(graph, consumer) for consumer in carrier.consumers
            )
            carrier_corridor = tuple(
                _bound_corridor_point(graph, point) for point in carrier.corridor
            )
            if (
                carrier_definition is None
                or any(block is None for block in carrier_consumers)
                or any(block is None for block in carrier_corridor)
            ):
                return None
            bound_carriers.append(
                BoundSemanticCarrier(
                    evidence=carrier,
                    definition=carrier_definition,
                    consumers=tuple(carrier_consumers),
                    corridor=tuple(carrier_corridor),
                )
            )
        routes.append(
            BoundSemanticRoute(
                evidence=proof,
                source=source,
                destinations=tuple(destinations),
                source_owner=source_owner,
                state_write_block=state_write_block,
                predicate=bound_predicate,
                carriers=tuple(bound_carriers),
            )
        )
    return BoundCanonicalSemanticEvidence(
        evidence=evidence,
        routes=tuple(routes),
    )


__all__ = [
    "BoundCanonicalSemanticEvidence",
    "BoundSemanticCarrier",
    "BoundSemanticBlock",
    "BoundSemanticPredicate",
    "BoundSemanticRoute",
    "BoundSemanticRouteDestination",
    "CanonicalSemanticEvidence",
    "SemanticCarrierProof",
    "SemanticCorridorPoint",
    "SemanticPredicateKind",
    "SemanticPredicateProof",
    "SemanticRouteDestination",
    "SemanticRouteEvidenceRejected",
    "SemanticRouteProof",
    "SemanticRouteProofKind",
    "SemanticRouteShape",
    "SemanticStateWriteProof",
    "bind_canonical_semantic_evidence",
]
